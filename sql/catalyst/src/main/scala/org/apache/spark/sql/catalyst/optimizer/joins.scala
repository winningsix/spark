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

package org.apache.spark.sql.catalyst.optimizer

import scala.annotation.tailrec
import scala.util.control.NonFatal

import org.apache.spark.internal.Logging
import org.apache.spark.internal.LogKeys.{HASH_JOIN_KEYS, JOIN_CONDITION}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.AggregateExpression
import org.apache.spark.sql.catalyst.planning.{ExtractEquiJoinKeys, ExtractFiltersAndInnerJoins, ExtractSingleColumnNullAwareAntiJoin}
import org.apache.spark.sql.catalyst.plans._
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.logical.statsEstimation.EstimationUtils
import org.apache.spark.sql.catalyst.rules._
import org.apache.spark.sql.catalyst.trees.TreePattern._
import org.apache.spark.sql.catalyst.util.UnsafeRowUtils
import org.apache.spark.sql.errors.QueryCompilationErrors
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.StringType
import org.apache.spark.unsafe.types.UTF8String
import org.apache.spark.util.Utils

/**
 * Reorder the joins and push all the conditions into join, so that the bottom ones have at least
 * one condition.
 *
 * The order of joins will not be changed if all of them already have at least one condition.
 *
 * If star schema detection is enabled, reorder the star join plans based on heuristics.
 */
object ReorderJoin extends Rule[LogicalPlan] with PredicateHelper {
  /**
   * Join a list of plans together and push down the conditions into them.
   *
   * The joined plan are picked from left to right, prefer those has at least one join condition.
   *
   * @param input a list of LogicalPlans to inner join and the type of inner join.
   * @param conditions a list of condition for join.
   */
  @tailrec
  final def createOrderedJoin(
      input: Seq[(LogicalPlan, InnerLike)],
      conditions: Seq[Expression]): LogicalPlan = {
    assert(input.size >= 2)
    if (input.size == 2) {
      val (joinConditions, others) = conditions.partition(canEvaluateWithinJoin)
      val ((left, leftJoinType), (right, rightJoinType)) = (input(0), input(1))
      val innerJoinType = (leftJoinType, rightJoinType) match {
        case (Inner, Inner) => Inner
        case (_, _) => Cross
      }
      val join = Join(left, right, innerJoinType,
        joinConditions.reduceLeftOption(And), JoinHint.NONE)
      if (others.nonEmpty) {
        Filter(others.reduceLeft(And), join)
      } else {
        join
      }
    } else {
      val (left, _) :: rest = input.toList
      // find out the first join that have at least one join condition
      val conditionalJoin = rest.find { planJoinPair =>
        val plan = planJoinPair._1
        val refs = left.outputSet ++ plan.outputSet
        conditions
          .filterNot(l => l.references.nonEmpty && canEvaluate(l, left))
          .filterNot(r => r.references.nonEmpty && canEvaluate(r, plan))
          .exists(_.references.subsetOf(refs))
      }
      // pick the next one if no condition left
      val (right, innerJoinType) = conditionalJoin.getOrElse(rest.head)

      val joinedRefs = left.outputSet ++ right.outputSet
      val (joinConditions, others) = conditions.partition(
        e => e.references.subsetOf(joinedRefs) && canEvaluateWithinJoin(e))
      val joined = Join(left, right, innerJoinType,
        joinConditions.reduceLeftOption(And), JoinHint.NONE)

      // should not have reference to same logical plan
      createOrderedJoin(Seq((joined, Inner)) ++ rest.filterNot(_._1 eq right), others)
    }
  }

  def apply(plan: LogicalPlan): LogicalPlan = plan.transformWithPruning(
    _.containsPattern(INNER_LIKE_JOIN), ruleId) {
    case p @ ExtractFiltersAndInnerJoins(input, conditions)
        if input.size > 2 && conditions.nonEmpty =>
      val reordered = if (conf.starSchemaDetection && !conf.cboEnabled) {
        val starJoinPlan = StarSchemaDetection.reorderStarJoins(input, conditions)
        if (starJoinPlan.nonEmpty) {
          val rest = input.filterNot(starJoinPlan.contains(_))
          createOrderedJoin(starJoinPlan ++ rest, conditions)
        } else {
          createOrderedJoin(input, conditions)
        }
      } else {
        createOrderedJoin(input, conditions)
      }

      if (p.sameOutput(reordered)) {
        reordered
      } else {
        // Reordering the joins have changed the order of the columns.
        // Inject a projection to make sure we restore to the expected ordering.
        Project(p.output, reordered)
      }
  }
}

/**
 * 1. Elimination of outer joins, if the predicates can restrict the result sets so that
 * all null-supplying rows are eliminated
 *
 * - full outer -> inner if both sides have such predicates
 * - left outer -> inner if the right side has such predicates
 * - right outer -> inner if the left side has such predicates
 * - full outer -> left outer if only the left side has such predicates
 * - full outer -> right outer if only the right side has such predicates
 *
 * 2. Removes outer join if aggregate is from streamed side and duplicate agnostic
 *
 * {{{
 *   SELECT DISTINCT f1 FROM t1 LEFT JOIN t2 ON t1.id = t2.id  ==>  SELECT DISTINCT f1 FROM t1
 * }}}
 *
 * {{{
 *   SELECT t1.c1, max(t1.c2) FROM t1 LEFT JOIN t2 ON t1.c1 = t2.c1 GROUP BY t1.c1  ==>
 *   SELECT t1.c1, max(t1.c2) FROM t1 GROUP BY t1.c1
 * }}}
 *
 * 3. Remove outer join if:
 *   - For a left outer join with only left-side columns being selected and the right side join
 *     keys are unique.
 *   - For a right outer join with only right-side columns being selected and the left side join
 *     keys are unique.
 *
 * {{{
 *   SELECT t1.* FROM t1 LEFT JOIN (SELECT DISTINCT c1 as c1 FROM t) t2 ON t1.c1 = t2.c1  ==>
 *   SELECT t1.* FROM t1
 * }}}
 *
 * This rule should be executed before pushing down the Filter
 */
object EliminateOuterJoin extends Rule[LogicalPlan] with PredicateHelper {

  /**
   * Returns whether the expression returns null or false when all inputs are nulls.
   */
  private def canFilterOutNull(e: Expression): Boolean = {
    if (!e.deterministic || SubqueryExpression.hasCorrelatedSubquery(e)) return false
    val attributes = e.references.toSeq
    val emptyRow = new GenericInternalRow(attributes.length)
    val boundE = BindReferences.bindReference(e, attributes)
    if (boundE.exists(_.isInstanceOf[Unevaluable])) return false

    // some expressions, like map(), may throw an exception when dealing with null values.
    // therefore, we need to handle exceptions.
    try {
      val v = boundE.eval(emptyRow)
      v == null || v == false
    } catch {
      case NonFatal(e) =>
        // cannot filter out null if `where` expression throws an exception with null input
        false
    }
  }

  private def buildNewJoinType(filter: Filter, join: Join): JoinType = {
    val conditions = splitConjunctivePredicates(filter.condition) ++ filter.constraints
    val leftConditions = conditions.filter(_.references.subsetOf(join.left.outputSet))
    val rightConditions = conditions.filter(_.references.subsetOf(join.right.outputSet))

    lazy val leftHasNonNullPredicate = leftConditions.exists(canFilterOutNull)
    lazy val rightHasNonNullPredicate = rightConditions.exists(canFilterOutNull)

    join.joinType match {
      case RightOuter if leftHasNonNullPredicate => Inner
      case LeftOuter if rightHasNonNullPredicate => Inner
      case FullOuter if leftHasNonNullPredicate && rightHasNonNullPredicate => Inner
      case FullOuter if leftHasNonNullPredicate => LeftOuter
      case FullOuter if rightHasNonNullPredicate => RightOuter
      case o => o
    }
  }

  private def allDuplicateAgnostic(a: Aggregate): Boolean = {
    a.groupOnly || a.aggregateExpressions.flatMap { e =>
      e.collect {
        case ae: AggregateExpression => ae
      }
    }.forall(ae => ae.isDistinct || EliminateDistinct.isDuplicateAgnostic(ae.aggregateFunction))
  }

  def apply(plan: LogicalPlan): LogicalPlan = plan.transformWithPruning(
    _.containsPattern(OUTER_JOIN), ruleId) {
    case f @ Filter(condition, j @ Join(_, _, RightOuter | LeftOuter | FullOuter, _, _)) =>
      val newJoinType = buildNewJoinType(f, j)
      if (j.joinType == newJoinType) f else Filter(condition, j.copy(joinType = newJoinType))

    case a @ Aggregate(_, _, Join(left, _, LeftOuter, _, _), _)
        if a.references.subsetOf(left.outputSet) && allDuplicateAgnostic(a) =>
      a.copy(child = left)
    case a @ Aggregate(_, _, Join(_, right, RightOuter, _, _), _)
        if a.references.subsetOf(right.outputSet) && allDuplicateAgnostic(a) =>
      a.copy(child = right)
    case a @ Aggregate(_, _, p @ Project(projectList, Join(left, _, LeftOuter, _, _)), _)
        if projectList.forall(_.deterministic) && p.references.subsetOf(left.outputSet) &&
          allDuplicateAgnostic(a) =>
      a.copy(child = p.copy(child = left))
    case a @ Aggregate(_, _, p @ Project(projectList, Join(_, right, RightOuter, _, _)), _)
        if projectList.forall(_.deterministic) && p.references.subsetOf(right.outputSet) &&
          allDuplicateAgnostic(a) =>
      a.copy(child = p.copy(child = right))

    case p @ Project(_, ExtractEquiJoinKeys(LeftOuter, _, rightKeys, _, _, left, right, _))
        if right.distinctKeys.exists(_.subsetOf(ExpressionSet(rightKeys))) &&
          p.references.subsetOf(left.outputSet) =>
      p.copy(child = left)
    case p @ Project(_, ExtractEquiJoinKeys(RightOuter, leftKeys, _, _, _, left, right, _))
        if left.distinctKeys.exists(_.subsetOf(ExpressionSet(leftKeys))) &&
          p.references.subsetOf(right.outputSet) =>
      p.copy(child = right)
  }
}

/**
 * PythonUDF in join condition can't be evaluated if it refers to attributes from both join sides.
 * See `ExtractPythonUDFs` for details. This rule will detect un-evaluable PythonUDF and pull them
 * out from join condition.
 */
object ExtractPythonUDFFromJoinCondition extends Rule[LogicalPlan] with PredicateHelper {

  private def hasUnevaluablePythonUDF(expr: Expression, j: Join): Boolean = {
    expr.exists { e =>
      PythonUDF.isScalarPythonUDF(e) && !canEvaluate(e, j.left) && !canEvaluate(e, j.right)
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan.transformUpWithPruning(
    _.containsAllPatterns(PYTHON_UDF, JOIN)) {
    case j @ Join(_, _, joinType, Some(cond), _) if hasUnevaluablePythonUDF(cond, j) =>
      if (!joinType.isInstanceOf[InnerLike]) {
        // The current strategy supports only InnerLike join because for other types,
        // it breaks SQL semantic if we run the join condition as a filter after join. If we pass
        // the plan here, it'll still get a an invalid PythonUDF RuntimeException with message
        // `requires attributes from more than one child`, we throw firstly here for better
        // readable information.
        throw QueryCompilationErrors.usePythonUDFInJoinConditionUnsupportedError(joinType)
      }
      // If condition expression contains python udf, it will be moved out from
      // the new join conditions.
      val (udf, rest) = splitConjunctivePredicates(cond).partition(hasUnevaluablePythonUDF(_, j))
      val newCondition = if (rest.isEmpty) {
        logWarning(log"The join condition:${MDC(JOIN_CONDITION, cond)} " +
          log"of the join plan contains PythonUDF only," +
          log" it will be moved out and the join plan will be turned to cross join.")
        None
      } else {
        Some(rest.reduceLeft(And))
      }
      val newJoin = j.copy(condition = newCondition)
      joinType match {
        case _: InnerLike => Filter(udf.reduceLeft(And), newJoin)
        case _ =>
          throw QueryCompilationErrors.usePythonUDFInJoinConditionUnsupportedError(joinType)
      }
  }
}

sealed abstract class BuildSide

case object BuildRight extends BuildSide

case object BuildLeft extends BuildSide

trait JoinSelectionHelper extends Logging {

  def getBroadcastBuildSide(
      join: Join,
      hintOnly: Boolean,
      conf: SQLConf): Option[BuildSide] = {
    def shouldBuildLeft(): Boolean = {
      if (hintOnly) {
        hintToBroadcastLeft(join.hint)
      } else {
        canBroadcastBySize(join.left, conf) && !hintToNotBroadcastLeft(join.hint)
      }
    }
    def shouldBuildRight(): Boolean = {
      if (hintOnly) {
        hintToBroadcastRight(join.hint)
      } else {
        canBroadcastBySize(join.right, conf) && !hintToNotBroadcastRight(join.hint)
      }
    }
    getBuildSide(
      canBuildBroadcastLeft(join.joinType) && shouldBuildLeft(),
      canBuildBroadcastRight(join.joinType) && shouldBuildRight(),
      join.left,
      join.right
    )
  }

  def getShuffleHashJoinBuildSide(
      join: Join,
      hintOnly: Boolean,
      conf: SQLConf): Option[BuildSide] = {
    def shouldBuildLeft(): Boolean = {
      if (hintOnly) {
        hintToShuffleHashJoinLeft(join.hint)
      } else {
        (!preferSortMergeJoin(conf) && canBuildLocalHashMapBySize(join.left, conf) &&
          muchSmaller(join.left, join.right, conf)) || forceApplyShuffledHashJoin(conf)
      }
    }
    def shouldBuildRight(): Boolean = {
      if (hintOnly) {
        hintToShuffleHashJoinRight(join.hint)
      } else {
        (!preferSortMergeJoin(conf) && canBuildLocalHashMapBySize(join.right, conf) &&
          muchSmaller(join.right, join.left, conf)) || forceApplyShuffledHashJoin(conf)
      }
    }
    getBuildSide(
      canBuildShuffledHashJoinLeft(join.joinType) && shouldBuildLeft() &&
        (hintOnly || !pipelinedHashJoinPolicy(conf) || join.joinType != LeftOuter),
      canBuildShuffledHashJoinRight(join.joinType) && shouldBuildRight() &&
        (hintOnly || !pipelinedHashJoinPolicy(conf) || join.joinType != RightOuter),
      join.left,
      join.right
    )
  }

  def getBroadcastNestedLoopJoinBuildSide(hint: JoinHint, joinType: JoinType): Option[BuildSide] = {
    if (hintToNotBroadcastAndReplicateLeft(hint) || joinType == LeftSingle) {
      Some(BuildRight)
    } else if (hintToNotBroadcastAndReplicateRight(hint)) {
      Some(BuildLeft)
    } else {
      None
    }
  }

  def getSmallerSide(left: LogicalPlan, right: LogicalPlan): BuildSide = {
    val conf = SQLConf.get
    if (hashJoinSizeEstimate(right, conf) <= hashJoinSizeEstimate(left, conf)) {
      BuildRight
    } else {
      BuildLeft
    }
  }

  /**
   * Matches a plan whose output should be small enough to be used in broadcast join.
   */
  def canBroadcastBySize(plan: LogicalPlan, conf: SQLConf): Boolean = {
    val autoBroadcastJoinThreshold = if (plan.stats.isRuntime) {
      conf.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
        .getOrElse(conf.autoBroadcastJoinThreshold)
    } else if (pipelinedHashJoinPolicy(conf)) {
      // A tiny build side keyed on a low-cardinality column (for example a filtered nation or
      // region table) would co-partition the whole probe side into one or a few shuffle
      // partitions. Broadcasting it instead keeps the probe side evenly parallel.
      math.max(conf.autoBroadcastJoinThreshold,
        conf.getConf(SQLConf.PIPELINED_HASH_JOIN_POLICY_BROADCAST_THRESHOLD))
    } else {
      conf.autoBroadcastJoinThreshold
    }
    plan.stats.sizeInBytes >= 0 && plan.stats.sizeInBytes <= autoBroadcastJoinThreshold
  }

  def canBuildBroadcastLeft(joinType: JoinType): Boolean = {
    joinType match {
      case _: InnerLike | RightOuter => true
      case _ => false
    }
  }

  def canBuildBroadcastRight(joinType: JoinType): Boolean = {
    joinType match {
      case _: InnerLike | LeftOuter | LeftSingle | LeftSemi | LeftAnti | _: ExistenceJoin => true
      case _ => false
    }
  }

  def canBuildShuffledHashJoinLeft(joinType: JoinType): Boolean = {
    joinType match {
      case _: InnerLike | LeftOuter | FullOuter | RightOuter => true
      case _ => false
    }
  }

  def canBuildShuffledHashJoinRight(joinType: JoinType): Boolean = {
    joinType match {
      case _: InnerLike | LeftOuter | LeftSingle | FullOuter | RightOuter |
           LeftSemi | LeftAnti | _: ExistenceJoin => true
      case _ => false
    }
  }

  protected def hashJoinSupported
      (leftKeys: Seq[Expression], rightKeys: Seq[Expression]): Boolean = {
    val result = leftKeys.concat(rightKeys).forall(e => UnsafeRowUtils.isBinaryStable(e.dataType))
    if (!result) {
      val keysNotSupportingHashJoin = leftKeys.concat(rightKeys).filterNot(
        e => UnsafeRowUtils.isBinaryStable(e.dataType))
      logWarning(log"Hash based joins are not supported due to joining on keys that don't " +
        log"support binary equality. Keys not supporting hash joins: " +
        log"${
          MDC(HASH_JOIN_KEYS, keysNotSupportingHashJoin.map(
            e => e.toString + " due to DataType: " + e.dataType.typeName).mkString(", "))
        }")
    }
    result
  }

  /**
   * The build side a broadcast hash join would use, or `None` when one is ruled out by the join
   * shape or by a hint.
   *
   * `Some` does not promise the planner picks a broadcast hash join: a `SHUFFLE_MERGE` or
   * `SHUFFLE_REPLICATE_NL` hint is tried before the sizes are consulted, join keys no hash join
   * supports send it to a sort merge join, and AQE re-estimates the sizes at runtime. Within the
   * broadcast decision itself this does follow the planner's precedence: a hinted broadcast first,
   * a hinted shuffle hash join as a veto, then the sizes. Callers that only need to know whether a
   * broadcast hash join is possible should use `canPlanAsBroadcastHashJoin`.
   */
  def getBroadcastHashJoinBuildSide(join: Join, conf: SQLConf): Option[BuildSide] = join match {
    case ExtractEquiJoinKeys(_, leftKeys, rightKeys, _, _, _, _, _) =>
      // A shuffle hash hint outranks a size-based broadcast, so it vetoes one. Keys no hash join
      // supports cannot honor that hint either, so it does not veto here; the sizes then still
      // produce an answer, which over-approximates `JoinSelection` (it falls through to a sort
      // merge join). That over-approximation predates this method and is kept deliberately, so
      // that `canPlanAsBroadcastHashJoin` keeps its truth table.
      val noShufflePlannedBefore = !hashJoinSupported(leftKeys, rightKeys) ||
        getShuffleHashJoinBuildSide(join, hintOnly = true, conf).isEmpty
      getBroadcastBuildSide(join, hintOnly = true, conf).orElse {
        if (noShufflePlannedBefore) getBroadcastBuildSide(join, hintOnly = false, conf) else None
      }
    // `JoinSelection` always builds from the right for this shape. A negative threshold preserves
    // the original unbounded NAAJ behavior, while zero disables the broadcast hash optimization.
    case j @ ExtractSingleColumnNullAwareAntiJoin(_, _) =>
      val threshold = conf.nullAwareAntiJoinBroadcastThreshold
      val rightSize = j.right.stats.sizeInBytes
      if (threshold < 0 || (threshold > 0 && rightSize >= 0 && rightSize <= threshold)) {
        Some(BuildRight)
      } else {
        None
      }
    case _ => None
  }

  def canPlanAsBroadcastHashJoin(join: Join, conf: SQLConf): Boolean =
    getBroadcastHashJoinBuildSide(join, conf).isDefined

  def canPruneLeft(joinType: JoinType): Boolean = joinType match {
    case Inner | LeftSemi | RightOuter => true
    case _ => false
  }

  def canPruneRight(joinType: JoinType): Boolean = joinType match {
    case Inner | LeftSemi | LeftOuter => true
    case _ => false
  }

  def hintToBroadcastLeft(hint: JoinHint): Boolean = {
    hint.leftHint.exists(_.strategy.contains(BROADCAST))
  }

  def hintToBroadcastRight(hint: JoinHint): Boolean = {
    hint.rightHint.exists(_.strategy.contains(BROADCAST))
  }

  def hintToNotBroadcastLeft(hint: JoinHint): Boolean = {
    hint.leftHint.flatMap(_.strategy).exists {
      case NO_BROADCAST_HASH => true
      case NO_BROADCAST_AND_REPLICATION => true
      case _ => false
    }
  }

  def hintToNotBroadcastRight(hint: JoinHint): Boolean = {
    hint.rightHint.flatMap(_.strategy).exists {
      case NO_BROADCAST_HASH => true
      case NO_BROADCAST_AND_REPLICATION => true
      case _ => false
    }
  }

  def hintToShuffleHashJoinLeft(hint: JoinHint): Boolean = {
    hint.leftHint.exists(_.strategy.contains(SHUFFLE_HASH))
  }

  def hintToShuffleHashJoinRight(hint: JoinHint): Boolean = {
    hint.rightHint.exists(_.strategy.contains(SHUFFLE_HASH))
  }

  def hintToShuffleHashJoin(hint: JoinHint): Boolean = {
    hintToShuffleHashJoinLeft(hint) || hintToShuffleHashJoinRight(hint)
  }

  def hintToSortMergeJoin(hint: JoinHint): Boolean = {
    hint.leftHint.exists(_.strategy.contains(SHUFFLE_MERGE)) ||
      hint.rightHint.exists(_.strategy.contains(SHUFFLE_MERGE))
  }

  def hintToShuffleReplicateNL(hint: JoinHint): Boolean = {
    hint.leftHint.exists(_.strategy.contains(SHUFFLE_REPLICATE_NL)) ||
      hint.rightHint.exists(_.strategy.contains(SHUFFLE_REPLICATE_NL))
  }

  def hintToNotBroadcastAndReplicate(hint: JoinHint): Boolean = {
    hintToNotBroadcastAndReplicateLeft(hint) || hintToNotBroadcastAndReplicateRight(hint)
  }

  def hintToNotBroadcastAndReplicateLeft(hint: JoinHint): Boolean = {
    hint.leftHint.exists(_.strategy.contains(NO_BROADCAST_AND_REPLICATION))
  }

  def hintToNotBroadcastAndReplicateRight(hint: JoinHint): Boolean = {
    hint.rightHint.exists(_.strategy.contains(NO_BROADCAST_AND_REPLICATION))
  }

  private def getBuildSide(
      canBuildLeft: Boolean,
      canBuildRight: Boolean,
      left: LogicalPlan,
      right: LogicalPlan): Option[BuildSide] = {
    if (canBuildLeft && canBuildRight) {
      // returns the smaller side base on its estimated physical size, if we want to build the
      // both sides.
      Some(getSmallerSide(left, right))
    } else if (canBuildLeft) {
      Some(BuildLeft)
    } else if (canBuildRight) {
      Some(BuildRight)
    } else {
      None
    }
  }

  /**
   * Matches a plan whose single partition should be small enough to build a hash table.
   *
   * Note: this assume that the number of partition is fixed, requires additional work if it's
   * dynamic.
   */
  private def canBuildLocalHashMapBySize(plan: LogicalPlan, conf: SQLConf): Boolean = {
    val localMapThreshold = if (pipelinedHashJoinPolicy(conf)) {
      Some(conf.getConf(SQLConf.PIPELINED_HASH_JOIN_POLICY_LOCAL_MAP_THRESHOLD))
    } else {
      conf.getConf(SQLConf.MAX_SHUFFLE_HASH_JOIN_LOCAL_MAP_THRESHOLD)
    }
    localMapThreshold match {
      case Some(threshold) =>
        val size = hashJoinSizeEstimate(plan, conf)
        !plan.isStreaming && threshold > 0 && size < conf.defaultSizeInBytes &&
          size <= BigInt(threshold) * conf.numShufflePartitions
      case None =>
        plan.stats.sizeInBytes < conf.autoBroadcastJoinThreshold * conf.numShufflePartitions
    }
  }

  /**
   * Returns true if the data size of plan a multiplied by SHUFFLE_HASH_JOIN_FACTOR
   * is smaller than plan b.
   *
   * The cost to build hash map is higher than sorting, we should only build hash map on a table
   * that is much smaller than other one. Since we does not have the statistic for number of rows,
   * use the size of bytes here as estimation.
   */
  private def muchSmaller(a: LogicalPlan, b: LogicalPlan, conf: SQLConf): Boolean = {
    val factor = if (pipelinedHashJoinPolicy(conf)) {
      conf.getConf(SQLConf.PIPELINED_HASH_JOIN_POLICY_FACTOR)
    } else {
      conf.getConf(SQLConf.SHUFFLE_HASH_JOIN_FACTOR)
    }
    hashJoinSizeEstimate(a, conf) * factor <= hashJoinSizeEstimate(b, conf)
  }

  /**
   * Whether the pipelined-execution hash join policy applies to this query.
   *
   * A sort is a pipeline breaker: a sort-merge join cannot emit a row until both inputs are
   * fully sorted, which defeats concurrent producer/consumer execution and forces large
   * sorts to spill. Pipelined execution already materializes every shuffled-hash-join build
   * subtree before its probe pipeline starts, so the build side is a bounded, durable input
   * and the large side can stream through the probe without sorting. When distributed
   * pipelined shuffle is enabled for the query and this policy is on, static join selection
   * therefore prefers a shuffled hash join whenever the (join-aware) estimated build input
   * fits the policy's per-partition threshold and is at least the policy factor smaller than
   * the streamed side. It never builds the preserved side of an outer join, whose hash table
   * must also track matches. Regular (non-pipelined) queries are unaffected.
   */
  private def pipelinedHashJoinPolicy(conf: SQLConf): Boolean =
    conf.pipelinedHashJoinPolicyEnabled

  private def preferSortMergeJoin(conf: SQLConf): Boolean =
    conf.preferSortMergeJoin && !pipelinedHashJoinPolicy(conf)

  /** Row estimate used by the pipelined hash join policy (filter- and join-aware). */
  def pipelinedPolicyRowEstimate(plan: LogicalPlan, conf: SQLConf): BigInt =
    hashJoinSizeEstimate(plan, conf) / EstimationUtils.getSizePerRow(plan.output).max(1)

  /**
   * Size estimate used only for static shuffled-hash-join selection (and, under the pipelined
   * hash join policy, to skip saturated runtime bloom filters).
   *
   * Without CBO, an equi-join's sizeInBytes is the product of its children's sizes and a filter
   * keeps its child's size, which makes every join output ineligible as a hash-join build side
   * and makes a filtered fact table look as large as an unfiltered one. When
   * SQLConf.HASH_JOIN_EQUI_JOIN_SIZE_ESTIMATE or the pipelined hash join policy is enabled:
   *  - a filter scales its child's rows by a heuristic selectivity;
   *  - an inner equi-join is treated as a key/foreign-key join: it keeps the larger input's rows
   *    scaled by the fraction of base rows that survive the smaller input's filters (a filtered
   *    dimension filters the fact side);
   *  - a semi join keeps its left rows scaled by the right side's fraction, and an anti or outer
   *    join keeps its preserved side's rows;
   * all scaled by output row width and capped by the logical sizeInBytes. This only changes
   * which side may be built; it does not alter logical statistics used by any other rule.
   */
  private def hashJoinSizeEstimate(plan: LogicalPlan, conf: SQLConf): BigInt = {
    if (!conf.getConf(SQLConf.HASH_JOIN_EQUI_JOIN_SIZE_ESTIMATE) &&
        !pipelinedHashJoinPolicy(conf)) {
      return plan.stats.sizeInBytes
    }
    def width(p: LogicalPlan): BigInt = EstimationUtils.getSizePerRow(p.output)
    def rows(p: LogicalPlan): BigInt = estimate(p) / width(p).max(1)
    def scale(n: BigInt, f: Double): BigInt = (BigDecimal(n) * BigDecimal(f)).toBigInt.max(1)
    // Fraction of the underlying base rows that survive filters (and filtered dimension joins).
    // A foreign-key join keeps the larger side's rows scaled by the smaller side's fraction.
    def fraction(p: LogicalPlan): Double = p match {
      case Filter(condition, child) => fraction(child) * filterSelectivity(condition)
      case Project(_, child) => fraction(child)
      case ExtractEquiJoinKeys(joinType, _, _, _, _, left, right, _) => joinType match {
        case Inner | LeftSemi => fraction(left) * fraction(right)
        case LeftAnti | LeftOuter => fraction(left)
        case RightOuter => fraction(right)
        case _ => 1.0
      }
      case _ => 1.0
    }
    def estimate(p: LogicalPlan): BigInt = {
      val estimated = p match {
        case j @ ExtractEquiJoinKeys(joinType, _, _, _, _, left, right, _) => joinType match {
          case Inner =>
            val (l, r) = (rows(left), rows(right))
            val smaller = if (l >= r) right else left
            scale(l.max(r), fraction(smaller)) * width(j)
          case LeftSemi => scale(rows(left), fraction(right)) * width(j)
          case LeftAnti | LeftOuter => rows(left) * width(j)
          case RightOuter => rows(right) * width(j)
          case _ => p.stats.sizeInBytes
        }
        case Project(_, child) => rows(child) * width(p)
        case Filter(condition, child) => scale(rows(child), filterSelectivity(condition)) * width(p)
        case _ => p.stats.sizeInBytes
      }
      estimated.min(p.stats.sizeInBytes)
    }
    estimate(plan)
  }

  /**
   * Heuristic selectivity of a filter condition, used only by [[hashJoinSizeEstimate]].
   * Without column statistics, a filtered scan is otherwise estimated at its full size, which
   * makes a heavily filtered fact table look larger than an unfiltered one and picks the wrong
   * hash-join build side. Null checks are free; equality, IN lists, ranges and pattern
   * matches each reduce the estimate by a fixed factor.
   */
  private def filterSelectivity(condition: Expression): Double = {
    def selectivity(e: Expression): Double = e match {
      case And(left, right) => selectivity(left) * selectivity(right)
      case Or(left, right) =>
        val (l, r) = (selectivity(left), selectivity(right))
        math.min(1.0, l + r - l * r)
      case Not(child) => math.max(0.5, 1.0 - selectivity(child))
      case _: IsNotNull => 1.0
      // Without column statistics an equality may hit a low-cardinality column (e.g. a flag),
      // so stay conservative: underestimating a hash build side risks an executor OOM.
      // Single-character string codes are typically status flags with a tiny domain.
      case EqualTo(_, Literal(v: UTF8String, _: StringType)) if v.numChars() <= 1 => 0.5
      case EqualTo(Literal(v: UTF8String, _: StringType), _) if v.numChars() <= 1 => 0.5
      case _: EqualTo | _: EqualNullSafe => 0.25
      case in: In => math.min(1.0, 0.25 * in.list.size)
      case in: InSet => math.min(1.0, 0.25 * in.hset.size)
      case _: LessThan | _: LessThanOrEqual | _: GreaterThan | _: GreaterThanOrEqual => 0.5
      case _: Like | _: StartsWith | _: EndsWith | _: Contains => 0.25
      case _ => 1.0
    }
    math.max(0.001, selectivity(condition))
  }

  /**
   * Returns whether a shuffled hash join should be force applied.
   * The config key is hard-coded because it's testing only and should not be exposed.
   */
  private def forceApplyShuffledHashJoin(conf: SQLConf): Boolean = {
    Utils.isTesting &&
      conf.getConfString("spark.sql.join.forceApplyShuffledHashJoin", "false") == "true"
  }
}
