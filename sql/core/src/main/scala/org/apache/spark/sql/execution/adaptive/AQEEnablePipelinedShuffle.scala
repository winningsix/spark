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

package org.apache.spark.sql.execution.adaptive

import scala.collection.mutable

import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{BinaryExecNode, SparkPlan}
import org.apache.spark.sql.execution.exchange.{EnablePipelinedShuffle, PipelinedShuffleEligibility, ReusedExchangeExec, ShuffleExchangeExec}
import org.apache.spark.sql.execution.joins.ShuffledJoin
import org.apache.spark.sql.execution.reuse.ReuseExchangeAndSubquery

/**
 * Opt-in channel shuffle rewrite under AQE. Candidates have no stats-sensitive consumer above
 * them, or are the symmetric shuffle inputs of a join with no such consumer above the join.
 * A SinglePartition candidate can extend the candidate chain into its child.
 *
 * Pipelined exchanges remain inline rather than becoming ShuffleQueryStageExec nodes, so they
 * give up AQE coalescing and skew optimization. If any shuffle would remain regular, skip the
 * rewrite: a mixed plan can lose its materialized outputs between actions, and the pipelined
 * group cannot recover those outputs. Reused exchanges and unsupported consumers also retain
 * regular execution. The shared environment gate excludes streaming, RDD and cache boundaries.
 */
object AQEEnablePipelinedShuffle extends Rule[SparkPlan] {

  override def apply(plan: SparkPlan): SparkPlan = {
    // Shared environment gate (opt-in flag and manager-specific deployment requirements),
    // identical to the non-AQE rule's -- see PipelinedShuffleEligibility for why it is a
    // correctness gate that must not drift between the two rules.
    if (!PipelinedShuffleEligibility.enabled(plan, conf)) return plan

    if (conf.pipelinedShuffleFullPlanAQEEnabled) {
      // AQE normally discovers equivalent exchanges when it creates materialized query stages.
      // Pipelined exchanges deliberately do not become query stages, so waiting for that cache
      // would duplicate their producers. Preserve the same exchange-reuse decision first, then
      // let the distributed transport attach every logical consumer to the shared producer.
      // This changes only exchange wrappers and transport flags; join algorithms and build sides
      // are untouched.
      EnablePipelinedShuffle.apply(ReuseExchangeAndSubquery(plan))
    } else {
      flipEligibleExchanges(plan)
    }
  }

  /**
   * The plan-shape core of the rule, factored out of [[apply]]'s environment guards (opt-in flag,
   * manager deployment requirements) so it can be unit-tested on a hand-built plan directly.
   * Collects eligible exchanges and returns the plan with each flipped to `pipelined = true`.
   */
  private[adaptive] def flipEligibleExchanges(plan: SparkPlan): SparkPlan = {
    val shared = if (conf.exchangeReuseEnabled) duplicatedShuffleForms(plan) else Set.empty[Any]
    // Collect the exchanges to flip BY IDENTITY (SparkPlan.id, unique per instance), not by the
    // node itself: TreeNode overrides hashCode but not equals, so a HashSet[ShuffleExchangeExec]
    // matches structurally, and the transformDown below would then flip EVERY exchange
    // structurally equal to a collected one -- including a twin the collector deliberately left
    // regular on a blocked path. That twin, if it sits below a regular boundary, makes
    // classifyJobShuffleShape reject the whole job. Keying on the instance id flips exactly the
    // nodes the collector chose, regardless of spark.sql.exchange.reuse (duplicatedShuffleForms,
    // the only other guard, is empty when reuse is off). transformDown matches each ORIGINAL node
    // before rebuilding it, so its id is the same instance id the collector recorded.
    val toFlip = mutable.HashSet.empty[Int]
    collectCandidates(plan, blocked = false, shared, toFlip)
    if (toFlip.isEmpty) return plan

    // A regular prefix can lose its files between actions. The scheduler cannot recover that
    // prefix inside a running pipelined group. Keep the entire plan regular if any
    // exchange stays regular, including sibling branches and materialized query stages.
    def hasRegularPrefix(p: SparkPlan): Boolean = p match {
      case s: ShuffleExchangeExec =>
        (!s.pipelined && !toFlip.contains(s.id)) || hasRegularPrefix(s.child)
      case q: QueryStageExec => hasRegularPrefix(q.plan)
      case r: ReusedExchangeExec => hasRegularPrefix(r.child)
      case other => other.children.exists(hasRegularPrefix)
    }
    if (hasRegularPrefix(plan)) return plan
    if (!PipelinedShuffleEligibility.fitsLocalCapacity(plan, toFlip.toSet)) return plan

    // transformDown, NOT transformUp: candidates can be nested (a SinglePartition candidate
    // above a hash candidate). transformUp rebuilds children first, so by the time it
    // reaches the upper candidate that node is a NEW instance whose (already flipped) child
    // no longer matches the collected original structurally, and the upper flip is silently
    // dropped -- leaving a regular exchange above a pipelined one, which the scheduler then
    // rejects. transformDown hands each candidate to the pattern before its subtree is
    // rebuilt, so both nested flips apply.
    plan.transformDown {
      case s: ShuffleExchangeExec if toFlip.contains(s.id) => s.copy(pipelined = true)
    }
  }

  private def isCandidate(s: ShuffleExchangeExec, shared: Set[Any]): Boolean =
    !s.pipelined && !shared.contains(s.canonicalized)

  /**
   * Top-down walk collecting exchanges to flip. `blocked` is true once the path from the
   * root has crossed a stats-sensitive node.
   */
  private def collectCandidates(
      plan: SparkPlan,
      blocked: Boolean,
      shared: Set[Any],
      out: mutable.HashSet[Int]): Unit = plan match {
    case s: ShuffleExchangeExec =>
      val flipped = !blocked && isCandidate(s, shared)
      if (flipped) {
        out += s.id
      }
      // A flipped SinglePartition exchange keeps the walk going: AQE makes no decision at
      // it (it cannot be coalesced or skew-split), so free candidates BELOW it flip too,
      // forming a pipelined chain: all exchanges in such a chain must flip together (a
      // SinglePartition exchange cannot be coalesced or skew-split, so AQE makes no decision
      // at it and free candidates below it flip too). Below any OTHER exchange (flipped or
      // not) the walk stops: what is underneath either materializes as the prefix or feeds
      // a regular exchange whose stats AQE uses, and keeps full AQE treatment either way.
      if (flipped &&
          s.outputPartitioning == org.apache.spark.sql.catalyst.plans.physical.SinglePartition) {
        collectCandidates(s.child, blocked = false, shared, out)
      }

    case _: QueryStageExec => // already materialized; a leaf here

    case j: ShuffledJoin if !blocked =>
      // Flip the join's immediate shuffle inputs only as a symmetric pair.
      val leftCandidate = immediateShuffleInput(j.left, shared)
      val rightCandidate = immediateShuffleInput(j.right, shared)
      (leftCandidate, rightCandidate) match {
        case (Some(l), Some(r)) =>
          out += l.id
          out += r.id
        case _ => // asymmetric (a broadcast side, a materialized stage, no clean input): skip
      }
      // Anything deeper is below a join input; blocked either way.

    case p if isStatsSensitive(p) =>
      p.children.foreach(collectCandidates(_, blocked = true, shared, out))

    case p =>
      p.children.foreach(collectCandidates(_, blocked, shared, out))
  }

  /**
   * The single eligible [[ShuffleExchangeExec]] at the top of one join input, looking
   * through unary non-stats-sensitive forwarders. None if the input is anything else.
   */
  private def immediateShuffleInput(
      plan: SparkPlan,
      shared: Set[Any]): Option[ShuffleExchangeExec] = plan match {
    case s: ShuffleExchangeExec => Some(s).filter(isCandidate(_, shared))
    case _: QueryStageExec => None
    case p if isStatsSensitive(p) => None
    case p if p.children.size == 1 => immediateShuffleInput(p.children.head, shared)
    case _ => None
  }

  /** Block candidates below stats consumers and operators unsupported by the channel. */
  private def isStatsSensitive(plan: SparkPlan): Boolean = plan match {
    case _: BinaryExecNode => true
    case _: ShuffleExchangeExec => true
    case p if PipelinedShuffleEligibility.isUnsupportedConsumer(p) => true
    case _ => false
  }

  /**
   * Canonicalized forms of shuffle exchanges occurring more than once across the plan,
   * materialized stages, and subquery plans -- flipping one of these loses stage reuse.
   *
   * `ShuffleExchangeExec.pipelined` is deliberately excluded from canonicalization because it is
   * transport metadata, so regular and pipelined structural twins are counted as duplicates here.
   * This keeps AQE's targeted flip conservative while full-plan mode delegates reuse handling to
   * EnablePipelinedShuffle and the configured manager capabilities.
   */
  private def duplicatedShuffleForms(plan: SparkPlan): Set[Any] = {
    val counts = mutable.HashMap.empty[Any, Int]
    def inc(s: ShuffleExchangeExec): Unit = {
      val c = s.canonicalized
      counts.update(c, counts.getOrElse(c, 0) + 1)
    }
    def visit(p: SparkPlan): Unit = p.foreach {
      case s: ShuffleExchangeExec => inc(s)
      case q: ShuffleQueryStageExec =>
        q.plan match {
          case s: ShuffleExchangeExec => inc(s)
          case r: ReusedExchangeExec =>
            r.child match {
              case s: ShuffleExchangeExec => inc(s)
              case _ =>
            }
          case _ =>
        }
      case _ =>
    }
    visit(plan)
    plan.subqueriesAll.foreach(visit)
    counts.filter(_._2 > 1).keys.toSet
  }
}
