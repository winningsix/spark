/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql.execution.exchange

import scala.collection.mutable

import org.apache.spark.SparkEnv
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{CoalesceExec, CollectLimitExec, CollectTailExec, SparkPlan, TakeOrderedAndProjectExec}
import org.apache.spark.sql.execution.joins.{CartesianProductExec, ShuffledHashJoinExec}

/**
 * Opt-in (SPARK-57399). Rewrites EVERY [[ShuffleExchangeExec]] in a
 * batch physical plan to `pipelined = true`, so each shuffle is served by the configured
 * pipelined shuffle manager and the concurrent-stage scheduler runs the map and reduce stages
 * together. This is the minimal SQL entry point that lets a batch query exercise a
 * pipelined execution path; a production version would be a targeted,
 * cost/shape-aware replacement rather than a blanket rewrite.
 *
 * Enabled only when `spark.sql.shuffle.localPipelined.enabled=true`. It runs in the non-AQE
 * `preparations` list, so it also requires AQE to be off (under AQE the plan is hidden behind
 * an opaque `AdaptiveSparkPlanExec` leaf and this rule sees no exchanges).
 *
 * Rewriting ALL visible shuffles (not just hash-partitioning ones) keeps the job all-pipelined.
 * A manager with executor-owned prepared inboxes may additionally support a hidden regular
 * boundary above the pipeline; other unmaterialized mixed shapes are rejected by DAGScheduler.
 * SinglePartition and RangePartitioning exchanges pipeline fine -- the channel transport only
 * routes by `partitioner.getPartition(key)` and does not care which partitioning produced the
 * id (SinglePartition is the numPartitions == 1 degenerate case).
 *
 * These shapes make the rule leave the whole plan regular:
 *   - shuffle reuse when the configured manager does not support fan-out. A fan-out-capable
 *     manager preserves exchange reuse by routing every reader to the same pipelined exchange.
 *     Reused broadcast exchanges never consume the pipelined transport and do not block rewrite.
 *   - an UNSUPPORTED CONSUMER reading a shuffle (see [[readsShuffleThroughUnsupportedConsumer]]):
 *     an operator that would drain a shuffle in a way the channel transport cannot serve, or that
 *     builds its own hidden regular shuffle. If such an operator sits above any shuffle the rule
 *     leaves the WHOLE plan regular unless the configured manager explicitly supports the hidden
 *     regular boundary above a pipeline.
 *     The query runs correctly, just not pipelined. The unsupported consumers are:
 *       - `CoalesceExec` (user `.coalesce(n)`): its `CoalescedRDD` makes ONE reduce task drain
 *         SEVERAL reduce partitions sequentially. The single-threaded writer parks on a full
 *         bounded queue filling a later partition before emitting an earlier one's markers, so a
 *         reader draining partitions in order deadlocks the writer with no timeout escape;
 *         `coalesce`'s narrow-merge contract also cannot be honored by re-hashing to `n`.
 *       - `CartesianProductExec`: its `UnsafeCartesianRDD` reads each left (child) partition once
 *         per right partition, so N reduce tasks mint N readers on the SAME rendezvous queue for
 *         one `(shuffleId, epoch, pid)` -- rows and end-of-stream markers split
 *         nondeterministically (wrong results), a reader short of `numMaps` markers hangs, and
 *         the first to finish abandons the queue and discards the others' data. The fan-out check
 *         does not catch it (one consumer RDD, computed many times), nor the width-1 require.
 *       - `CollectLimitExec` / `CollectTailExec` / `TakeOrderedAndProjectExec`: each builds a
 *         hidden regular (`pipelined = false`) shuffle inside `doExecute` via
 *         `prepareShuffleDependency`, invisible to this plan walk. A flipped exchange below one of
 *         them would sit under that unmaterialized regular boundary and the job would hard-fail at
 *         submission unless the manager supports executor-owned prepared receive. (`.collect()`
 *         on a limit takes `executeTake` and never hits `doExecute`; `.write` / `.toLocalIterator`
 *         / a non-root position do.)
 */
object EnablePipelinedShuffle extends Rule[SparkPlan] {

  override def apply(plan: SparkPlan): SparkPlan = {
    // Shared environment gate (opt-in flag and manager-specific deployment requirements),
    // identical to the AQE rule's -- see PipelinedShuffleEligibility for why it is a correctness
    // gate. Under normal query preparation AQE hides the exchanges from this rule; AQE full-plan
    // mode also invokes it directly after the adaptive plan is visible.
    if (!PipelinedShuffleEligibility.enabled(plan, conf)) return plan

    val shuffles = plan.collectWithSubqueries { case s: ShuffleExchangeExec => s }
    if (shuffles.isEmpty) return plan

    // Treat the main plan and each subquery as separate execution scopes. Reuse inside one scope
    // is concurrent fan-out; reuse whose selected exchange lives in another scope is a sequential
    // consumer and needs retained replay instead of an additional current-job reader inbox.
    val scopes = plan +: plan.subqueriesAll
    val directExchanges = scopes.flatMap(_.collect { case s: ShuffleExchangeExec => s })
    val reuseTargetByChildKey = mutable.HashMap.empty[Int, ShuffleExchangeExec]
    val sameScopeReuseCountByExchangeKey = mutable.HashMap.empty[Int, Int]
    val sequentialReplayCountByExchangeKey = mutable.HashMap.empty[Int, Int]
    scopes.foreach { scope =>
      val scopeExchanges = scope.collect { case s: ShuffleExchangeExec => s }
      val reused = scope.collect {
        case r @ ReusedExchangeExec(_, _: ShuffleExchangeExec) => r
      }
      reused.foreach { reusedExchange =>
        val reusedChild = reusedExchange.child.asInstanceOf[ShuffleExchangeExec]
        // AQE's result-stage codegen may copy the direct exchange while ReusedExchangeExec, a
        // leaf, still wraps the pre-codegen instance. Fall back to canonical identity so the
        // final transport rewrite reconnects both branches to the actual direct exchange.
        val target = scopeExchanges.find(_.pipelinedReuseKey == reusedChild.pipelinedReuseKey)
          .orElse(scopeExchanges.find(_.canonicalized == reusedChild.canonicalized))
          .orElse(directExchanges.find(
            _.pipelinedReuseKey == reusedChild.pipelinedReuseKey))
          .orElse(directExchanges.find(_.canonicalized == reusedChild.canonicalized))
          .getOrElse(reusedChild)
        reuseTargetByChildKey.update(reusedChild.pipelinedReuseKey, target)
        if (scopeExchanges.exists(_.pipelinedReuseKey == target.pipelinedReuseKey)) {
          sameScopeReuseCountByExchangeKey.update(
            target.pipelinedReuseKey,
            sameScopeReuseCountByExchangeKey.getOrElse(target.pipelinedReuseKey, 0) + 1)
        } else {
          sequentialReplayCountByExchangeKey.update(
            target.pipelinedReuseKey,
            sequentialReplayCountByExchangeKey.getOrElse(target.pipelinedReuseKey, 0) + 1)
        }
      }
    }
    val supportsFanOut = SparkEnv.get.pipelinedShuffleManager.supportsFanOut
    val supportsSequentialReplay =
      SparkEnv.get.pipelinedShuffleManager.supportsSequentialReplay

    def rewriteExchanges(asPipelined: Boolean): SparkPlan = {
      val rewrittenByExchangeKey = mutable.HashMap.empty[Int, ShuffleExchangeExec]
      def rewritten(exchange: ShuffleExchangeExec): ShuffleExchangeExec = {
        rewrittenByExchangeKey.getOrElseUpdate(exchange.pipelinedReuseKey, {
          val copied = if (exchange.pipelined == asPipelined) {
            exchange
          } else {
            val result = exchange.copy(pipelined = asPipelined)
            result.copyPipelinedTransportStateFrom(exchange)
            result
          }
          if (asPipelined) {
            copied.setPipelinedReaderRouteMultiplicity(
              1 + sameScopeReuseCountByExchangeKey.getOrElse(exchange.pipelinedReuseKey, 0))
            sequentialReplayCountByExchangeKey.get(exchange.pipelinedReuseKey).foreach {
              copied.addPipelinedSequentialReplays
            }
          }
          copied
        })
      }
      plan.transformUpWithSubqueries {
        // ReusedExchangeExec is a leaf in the SparkPlan tree, so its wrapped exchange is not
        // visited by an ordinary transformUp. Rewire it explicitly to the same copied instance.
        case r @ ReusedExchangeExec(_, s: ShuffleExchangeExec) =>
          r.copy(child = rewritten(reuseTargetByChildKey.getOrElse(s.pipelinedReuseKey, s)))
        case s: ShuffleExchangeExec => rewritten(s)
      }
    }

    def rewriteAsRegular(): SparkPlan = {
      val regularPlan = rewriteExchanges(asPipelined = false)
      PipelinedShuffleEligibility.disableHiddenShuffles(regularPlan)
      regularPlan
    }

    // A shuffled hash join drains and retains its build input before touching its streamed input.
    // Prepared receive may admit fewer reduce tasks than the shuffle width to bound those hash
    // maps. Map writers interleave reducer shards, however, so data for the inactive reducers can
    // consume every bounded writer/raw permit and prevent the active reducers from ever seeing
    // EOS. There is no work-conserving in-memory ordering that breaks that cycle: the missing
    // shards must either be durably staged or all readers must be resident. Keep the whole
    // non-AQE plan regular unless the transport explicitly supports that contract.
    val hasMemoryRetainingConsumer = plan.collectWithSubqueries {
      case _: ShuffledHashJoinExec => true
    }.nonEmpty
    if (hasMemoryRetainingConsumer &&
        !PipelinedShuffleEligibility.supportsMemoryRetainingConsumer) {
      logDebug("EnablePipelinedShuffle: plan has a shuffled hash join but the configured " +
        "transport cannot safely admit a memory-retaining consumer; leaving it regular.")
      return rewriteAsRegular()
    }

    if ((sameScopeReuseCountByExchangeKey.nonEmpty && !supportsFanOut) ||
        (sequentialReplayCountByExchangeKey.nonEmpty && !supportsSequentialReplay)) {
      // Not a warning: this is a normal, expected fallback (reuse is routine optimizer output,
      // e.g. self-joins), the query still runs correctly as a regular shuffle, and the user has
      // nothing to act on. Log at DEBUG as diagnostic ("why this query did not go pipelined")
      // rather than WARN, which would fire on every reuse-bearing query and read as a fault.
      logDebug("EnablePipelinedShuffle: plan has a reused shuffle exchange but the configured " +
        "manager lacks fan-out or sequential replay; leaving it regular.")
      return rewriteAsRegular()
    }

    // An operator that would read a shuffle in a way the configured transport cannot serve, or that
    // builds its own hidden regular shuffle, forces the whole plan regular (see class doc). Like
    // the reuse fallback this is a normal, expected outcome, so log at DEBUG rather than WARN.
    val supportsUnmaterializedRegularBoundary =
      SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary
    if (readsShuffleThroughUnsupportedConsumer(plan, supportsUnmaterializedRegularBoundary)) {
      logDebug("EnablePipelinedShuffle: a shuffle is read through an operator the configured " +
        "transport cannot serve (coalesce / cartesian product / a limit operator that builds a " +
        "hidden shuffle); leaving the plan regular.")
      return rewriteAsRegular()
    }

    rewriteExchanges(asPipelined = true)
  }

  /**
   * True if any [[ShuffleExchangeExec]] in `plan` is read by an operator the configured transport
   * cannot serve. The unsupported operators (see class doc for why each is fatal) are
   * `CoalesceExec`, `CartesianProductExec`, and, when the manager cannot prepare a regular
   * boundary above a pipeline, the limit operators `CollectLimitExec` / `CollectTailExec` /
   * `TakeOrderedAndProjectExec`. For each such operator anywhere in the plan, check whether a
   * shuffle is reachable below it.
   *
   * The reachability walk descends through EVERY child of a non-exchange node -- not only unary
   * children -- so a shuffle behind a `UnionExec`/join (a `BinaryExecNode`) beneath the operator
   * is still found. It stops at the FIRST [[ShuffleExchangeExec]] on each path: a shuffle deeper
   * than that first one is not read by this operator (the intervening exchange's own reader reads
   * one reduce partition per task), so it is not this operator's concern.
   */
  private def readsShuffleThroughUnsupportedConsumer(
      plan: SparkPlan,
      supportsUnmaterializedRegularBoundary: Boolean): Boolean = {
    def reachesShuffle(p: SparkPlan): Boolean = p match {
      case _: ShuffleExchangeExec => true
      case other => other.children.exists(reachesShuffle)
    }
    def isUnsupportedConsumer(p: SparkPlan): Boolean = p match {
      case _: CoalesceExec | _: CartesianProductExec => true
      case _: CollectLimitExec | _: CollectTailExec | _: TakeOrderedAndProjectExec =>
        !supportsUnmaterializedRegularBoundary
      case _ => false
    }
    plan.exists {
      case p if isUnsupportedConsumer(p) => p.children.exists(reachesShuffle)
      case _ => false
    }
  }
}
