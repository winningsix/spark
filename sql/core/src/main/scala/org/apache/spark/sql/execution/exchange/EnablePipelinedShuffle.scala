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

import org.apache.spark.{SparkContext, SparkEnv}
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
      return rewriteExchanges(capacityLimited(plan, exchange =>
        !regularBuildExchangeKeys.contains(exchange.pipelinedReuseKey)))
    }

    rewriteExchanges(capacityLimited(plan, _ => true))
  }

  /**
   * Bound each connected pipelined group by the cluster's concurrent task capacity.
   *
   * Group admission must place every task of every stage that reads a pipelined exchange at
   * the same time (plus a minimum window for each pure producer). A long chain of pipelined
   * joins therefore needs several times the available slots and can never be admitted. This
   * mixes batch and pipelined execution instead: exchanges are kept pipelined bottom-up (the
   * deepest exchanges move the most data) while the resulting group's reader demand fits the
   * budget; an exchange that would exceed it is materialized as a regular shuffle, which cuts
   * the group into independently admitted segments. Stage task counts are taken from the
   * exchanges' partition counts.
   */
  private def capacityLimited(
      plan: SparkPlan,
      base: ShuffleExchangeExec => Boolean): ShuffleExchangeExec => Boolean = {
    val fraction = conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val budget = if (fraction <= 0 ||
        SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor) {
      0
    } else {
      SparkContext.getActive.map { sc =>
        val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
        math.floor(slots * fraction).toInt
      }.getOrElse(0)
    }
    if (budget <= 0) return base

    // Assign stage ids by walking exchange boundaries. A stage is the plan root, a subquery
    // root, a broadcast build or an exchange's child; an exchange edge connects its producer
    // stage (rooted at the exchange child) to the consumer stage that contains the exchange.
    case class Edge(key: Int, consumer: Int, consumerTasks: Int, depth: Int)
    val producerOf = mutable.HashMap.empty[Int, Int]
    val exchangeOf = mutable.HashMap.empty[Int, ShuffleExchangeExec]
    val edges = mutable.ArrayBuffer.empty[Edge]
    // Materialized boundaries (broadcast builds, subqueries): (producer stage, consumer stage).
    val barriers = mutable.ArrayBuffer.empty[(Int, Int)]
    var nextStage = 0
    def newStage(): Int = { nextStage += 1; nextStage }
    def visit(node: SparkPlan, stage: Int, depth: Int): Unit = node match {
      case e: ShuffleExchangeExec =>
        edges += Edge(e.pipelinedReuseKey, stage, e.outputPartitioning.numPartitions, depth)
        if (!producerOf.contains(e.pipelinedReuseKey)) {
          val producer = newStage()
          producerOf(e.pipelinedReuseKey) = producer
          exchangeOf(e.pipelinedReuseKey) = e
          visit(e.child, producer, depth + 1)
        }
      case ReusedExchangeExec(_, e: ShuffleExchangeExec) =>
        edges += Edge(e.pipelinedReuseKey, stage, e.outputPartitioning.numPartitions, depth)
      case b: BroadcastExchangeLike =>
        val build = newStage()
        barriers += ((build, stage))
        visit(b.child, build, depth + 1)
      case other =>
        other.children.foreach(visit(_, stage, depth))
        other.subqueries.foreach { sub =>
          val subStage = newStage()
          barriers += ((subStage, stage))
          visit(sub, subStage, depth + 1)
        }
    }
    visit(plan, newStage(), 0)

    val parent = mutable.HashMap.empty[Int, Int]
    def find(x: Int): Int = {
      val p = parent.getOrElse(x, x)
      if (p == x) x else { val r = find(p); parent(x) = r; r }
    }
    // Reader width per consumer stage over its kept pipelined inputs.
    val readerTasks = mutable.HashMap.empty[Int, Int]
    val kept = mutable.HashSet.empty[Int]
    val rejected = mutable.HashSet.empty[Int]
    // Deepest exchanges first; each reuse key is decided once for all of its consumers.
    edges.groupBy(_.key).toSeq.sortBy { case (_, es) => -es.map(_.depth).max }.foreach {
      case (key, es) if exchangeOf.contains(key) && base(exchangeOf(key)) =>
        val producer = producerOf(key)
        val stages = (producer +: es.map(_.consumer)).distinct
        val roots = stages.map(find).distinct
        // Tentatively merge: demand over the union of the affected groups.
        val merged = roots.flatMap(r => (1 to nextStage).filter(find(_) == r)).distinct
        val widths = mutable.HashMap.empty[Int, Int] ++= merged.flatMap(s => readerTasks.get(s).map(s -> _))
        es.foreach(e => widths(e.consumer) = widths.getOrElse(e.consumer, 0) max e.consumerTasks)
        val total = (merged ++ es.map(_.consumer)).distinct.iterator
          .map(s => widths.get(s).map(_.toLong).getOrElse(1L)).sum
        if (total <= budget) {
          kept += key
          es.foreach(e => readerTasks(e.consumer) =
            readerTasks.getOrElse(e.consumer, 0) max e.consumerTasks)
          stages.tail.foreach(s => parent(find(s)) = find(stages.head))
        } else {
          rejected += key
        }
      case _ =>
    }
    // A group is admitted only after all of its stages are submitted, and a stage is submitted
    // only after its materialized parents finish. So no member may depend, through a regular
    // exchange or another materialized boundary, on a member of its own group. Cutting a group
    // can create such a path (e.g. through a reused exchange); detach the dependent reader.
    var conflict = true
    while (conflict) {
      val group = mutable.HashMap.empty[Int, Int]
      def root(x: Int): Int = {
        val p = group.getOrElse(x, x)
        if (p == x) x else { val r = root(p); group(x) = r; r }
      }
      val members = mutable.HashSet.empty[Int]
      edges.filter(e => kept(e.key) && producerOf.contains(e.key)).foreach { e =>
        members += producerOf(e.key) += e.consumer
        val (a, b) = (root(producerOf(e.key)), root(e.consumer))
        if (a != b) group(a) = b
      }
      val inputs = (edges.iterator.filter(e => producerOf.contains(e.key)).map { e =>
        e.consumer -> (producerOf(e.key), kept(e.key))
      } ++ barriers.iterator.map { case (p, c) => c -> (p, false) }).toSeq
        .groupBy(_._1).view.mapValues(_.map(_._2)).toMap
      def dependsRegularlyOnOwnGroup(stage: Int): Boolean = {
        val seen = mutable.HashSet.empty[(Int, Boolean)]
        def walk(s: Int, crossed: Boolean): Boolean = {
          if (!seen.add((s, crossed))) return false
          (crossed && members(s) && root(s) == root(stage)) ||
            inputs.getOrElse(s, Nil).exists { case (p, pipelined) => walk(p, crossed || !pipelined) }
        }
        inputs.getOrElse(stage, Nil).exists { case (p, pipelined) => walk(p, !pipelined) }
      }
      val bad = members.toSeq.sorted.find(dependsRegularlyOnOwnGroup)
      conflict = bad.isDefined
      bad.foreach { stage =>
        val keys = edges.filter(e => e.consumer == stage && kept(e.key)).map(_.key)
        val detach = if (keys.nonEmpty) keys else {
          edges.filter(e => kept(e.key) && producerOf.get(e.key).contains(stage)).map(_.key)
        }
        kept --= detach
        rejected ++= detach
      }
    }
    if (rejected.nonEmpty) {
      logDebug(s"EnablePipelinedShuffle: ${rejected.size} exchange(s) kept regular so every " +
        s"pipelined group fits $budget concurrent slots.")
    }
    exchange => base(exchange) && !rejected.contains(exchange.pipelinedReuseKey)
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
