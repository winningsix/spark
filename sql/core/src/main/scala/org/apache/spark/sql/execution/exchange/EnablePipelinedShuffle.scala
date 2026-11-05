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
import org.apache.spark.sql.catalyst.optimizer.BuildLeft
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.sql.internal.SQLConf

/**
 * Selects pipelined exchanges for opt-in batch queries using the configured transport.
 * Local channel execution requires the complete group to fit local capacity. Distributed
 * execution preserves shuffled-hash-join build boundaries when supported by the transport.
 * Unsupported consumers and exchange reuse retain regular execution unless the transport can
 * serve them. Streaming queries use their own exchange-selection rule.
 *
 * This rule runs during non-AQE preparation and in the opt-in AQE full-plan path once the
 * adaptive plan is visible. [[PipelinedShuffleEligibility]] owns the shared eligibility checks.
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

    def rewriteExchanges(shouldPipeline: ShuffleExchangeExec => Boolean): SparkPlan = {
      val rewrittenByExchangeKey = mutable.HashMap.empty[Int, ShuffleExchangeExec]
      def rewritten(exchange: ShuffleExchangeExec): ShuffleExchangeExec = {
        rewrittenByExchangeKey.getOrElseUpdate(exchange.pipelinedReuseKey, {
          val asPipelined = shouldPipeline(exchange)
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

    if ((sameScopeReuseCountByExchangeKey.nonEmpty && !supportsFanOut) ||
        (sequentialReplayCountByExchangeKey.nonEmpty && !supportsSequentialReplay)) {
      // Not a warning: this is a normal, expected fallback (reuse is routine optimizer output,
      // e.g. self-joins), the query still runs correctly as a regular shuffle, and the user has
      // nothing to act on. Log at DEBUG as diagnostic ("why this query did not go pipelined")
      // rather than WARN, which would fire on every reuse-bearing query and read as a fault.
      logDebug("EnablePipelinedShuffle: plan has a reused shuffle exchange but the configured " +
        "manager lacks fan-out or sequential replay; leaving it regular.")
      return rewriteExchanges(_ => false)
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
      return rewriteExchanges(_ => false)
    }

    if (SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor &&
        !PipelinedShuffleEligibility.fitsLocalCapacity(plan, shuffles.map(_.id).toSet)) {
      return rewriteExchanges(_ => false)
    }

    // A shuffled hash join retains its build relation while it consumes the streamed side. Keep
    // every shuffle in each build subtree regular by default, so those smaller inputs materialize
    // before the corresponding probe pipeline starts. The experimental nested-probe mode keeps
    // only the immediate build frontiers regular. Exchanges on the streamed spine pipeline.
    // This asymmetric boundary lets a sampled reader build from durable input while an
    // unadmitted probe route applies real credit backpressure; it therefore needs neither an
    // all-reader memory reservation nor pre-attachment disk staging. A reused exchange is keyed
    // by pipelinedReuseKey so one physical exchange never receives contradictory transport modes.
    val memoryRetainingJoins = plan.collectWithSubqueries {
      case join: ShuffledHashJoinExec => join
    }
    if (memoryRetainingJoins.nonEmpty && supportsUnmaterializedRegularBoundary) {
      val pipelineNestedProbes = conf.getConf(SQLConf.PIPELINED_SHUFFLE_NESTED_PROBE_ENABLED)
      // A durable exchange cuts the consumer's build dependency. Exchanges below that cut
      // belong to another execution segment and need not all be materialized. Still protect
      // every join's own build frontier, including joins nested inside another build subtree.
      def buildFrontier(node: SparkPlan): Seq[Int] = node match {
        case exchange: ShuffleExchangeExec => Seq(exchange.pipelinedReuseKey)
        case ReusedExchangeExec(_, exchange: ShuffleExchangeExec) =>
          Seq(exchange.pipelinedReuseKey)
        case other => other.children.flatMap(buildFrontier)
      }
      val regularBuildExchangeKeys: Set[Int] = memoryRetainingJoins.iterator.flatMap { join =>
        val buildPlan = if (join.buildSide == BuildLeft) join.left else join.right
        if (pipelineNestedProbes) {
          buildFrontier(buildPlan)
        } else {
          buildPlan.collect {
            case exchange: ShuffleExchangeExec => exchange.pipelinedReuseKey
            case ReusedExchangeExec(_, exchange: ShuffleExchangeExec) =>
              exchange.pipelinedReuseKey
          }
        }
      }.toSet
      logDebug("EnablePipelinedShuffle: using regular build inputs and pipelined streamed " +
        "inputs for shuffled hash joins.")
      return rewriteExchanges(exchange =>
        !regularBuildExchangeKeys.contains(exchange.pipelinedReuseKey))
    }

    rewriteExchanges(_ => true)
  }

  /** Check all child branches for a shuffle read through an unsupported consumer. */
  private def readsShuffleThroughUnsupportedConsumer(
      plan: SparkPlan,
      supportsUnmaterializedRegularBoundary: Boolean): Boolean = {
    def reachesShuffle(p: SparkPlan): Boolean = p match {
      case _: ShuffleExchangeExec => true
      case other => other.children.exists(reachesShuffle)
    }
    plan.exists {
      case p if PipelinedShuffleEligibility.isUnsupportedConsumer(
          p, supportsUnmaterializedRegularBoundary) =>
        p.children.exists(reachesShuffle)
      case _ => false
    }
  }
}
