package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight, JoinSelectionHelper}
import org.apache.spark.sql.catalyst.plans.JoinType
import org.apache.spark.sql.catalyst.plans.physical.{BroadcastDistribution, Distribution}
import org.apache.spark.sql.catalyst.plans.logical.{Filter, Join, JoinHint, LogicalPlan, Project}
import org.apache.spark.sql.execution.{FilterExec, ProjectExec, SortExec, SparkPlan}
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.catalyst.expressions.aggregate.{Average, Count, Final, Max, Min, Sum}
import org.apache.spark.sql.types.{BooleanType, ByteType, DateType, DecimalType, DoubleType, FloatType, IntegerType, LongType, ShortType, TimestampType}
import org.apache.spark.sql.execution.exchange.{BroadcastExchangeExec, ENSURE_REQUIREMENTS, Exchange, ReusedExchangeExec, ShuffleExchangeExec, ValidateRequirements}
import org.apache.spark.sql.execution.joins.{BroadcastHashJoinExec, ShuffledJoin}
import org.apache.spark.sql.internal.SQLConf

/** Let AQE measure a filtered key set before submitting an expensive probe shuffle. */
private[adaptive] object ProbeShuffleAfterBuild extends JoinSelectionHelper with PredicateHelper {
  private def edge(plan: SparkPlan): Option[ShuffleExchangeExec] = plan match {
    case sort: SortExec if !sort.global => edge(sort.child)
    case stage: ShuffleQueryStageExec if !stage.isMaterialized => edge(stage.plan)
    case exchange: ShuffleExchangeExec if !exchange.pipelined &&
        exchange.shuffleOrigin == ENSURE_REQUIREMENTS &&
        !exchange.child.exists(p => p.isInstanceOf[Exchange] || p.isInstanceOf[QueryStageExec]) =>
      Some(exchange)
    case _ => None
  }

  private def scan(plan: LogicalPlan, allowProbeSubquery: Boolean): Option[LogicalRelation] = plan match {
    case Project(columns, child) if columns.forall(_.isInstanceOf[Attribute]) => scan(child, allowProbeSubquery)
    case Filter(condition, child) if condition.deterministic &&
        (allowProbeSubquery || !SubqueryExpression.hasSubquery(condition)) => scan(child, allowProbeSubquery)
    case relation: LogicalRelation if !relation.isStreaming => Some(relation)
    case _ => None
  }

  private def filtersOtherColumn(plan: LogicalPlan, key: Expression): Boolean = plan.exists {
    case Filter(condition, _) => splitConjunctivePredicates(condition).exists {
      case EqualTo(column: Attribute, value: Literal) => value.value != null && !column.semanticEquals(key)
      case EqualTo(value: Literal, column: Attribute) => value.value != null && !column.semanticEquals(key)
      case _ => false
    }
    case _ => false
  }

  // A dimension carrying output values can still broadcast after its filters have run.
  // Use independent non-null-rejection predicates as a conservative signal to measure it.
  private def selectivePayload(plan: LogicalPlan, key: Expression): Boolean = {
    val columns = plan.collect { case Filter(condition, _) =>
      splitConjunctivePredicates(condition).collect {
        case e if !e.isInstanceOf[IsNotNull] && e.deterministic &&
            !SubqueryExpression.hasSubquery(e) && e.references.size == 1 &&
            !e.references.head.semanticEquals(key) => e.references.head.exprId
      }
    }.flatten
    columns.distinct.size > 1
  }

  private def runtimeFilteredKeys(build: ShuffleExchangeExec, key: Expression): Boolean = {
    val integral = build.output.forall(a => a.dataType match {
      case ByteType | ShortType | IntegerType | LongType => true
      case _ => false
    })
    integral && build.child.exists {
      case f: FilterExec => splitConjunctivePredicates(f.condition).exists {
        case BloomFilterMightContain(_: PlanExpression[_], value) =>
          value.references.size == 1 && !value.references.head.semanticEquals(key)
        case _ => false
      }
      case _ => false
    }
  }

  private def eligible(buildPlan: SparkPlan, probePlan: SparkPlan, keys: Seq[Expression], payload: Boolean = false): Boolean = {
    val conf = SQLConf.get
    (for {
      build <- edge(buildPlan) if keys.size == 1 && build.output.exists(_.semanticEquals(keys.head)) &&
        (if (payload) build.output.size > 1 else build.output.size == 1)
      probe <- edge(probePlan)
      buildSource <- build.child.logicalLink.orElse(build.logicalLink)
      probeSource <- probe.child.logicalLink.orElse(probe.logicalLink)
      hasRuntimeFilter = payload && conf.getConfString(
        "spark.sql.adaptive.measureRuntimeFilteredBuild.enabled", "false").toBoolean &&
        runtimeFilteredKeys(build, keys.head)
      dimension <- scan(buildSource, allowProbeSubquery = hasRuntimeFilter)
      if hasRuntimeFilter || (filtersOtherColumn(buildSource, keys.head) &&
        (!payload || selectivePayload(buildSource, keys.head)))
      fact <- scan(probeSource, allowProbeSubquery = true)
      if dimension.stats.sizeInBytes > 0 && dimension.stats.sizeInBytes < fact.stats.sizeInBytes &&
        fact.stats.sizeInBytes != conf.getConf(SQLConf.DEFAULT_SIZE_IN_BYTES) &&
        fact.stats.sizeInBytes >= conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD)
    } yield ()).nonEmpty
  }

  private def stripSort(p: SparkPlan): SparkPlan = p match {
    case s: SortExec if !s.global => s.child
    case other => other
  }

  def probeEdge(p: SparkPlan): Option[ShuffleExchangeExec] = stripSort(p) match {
    case e: ShuffleExchangeExec if !e.pipelined && e.shuffleOrigin == ENSURE_REQUIREMENTS &&
        !e.child.exists {
          case s: ShuffleExchangeExec => s.pipelined
          case ReusedExchangeExec(_, s: ShuffleExchangeExec) => s.pipelined
          case _ => false
        } => Some(e)
    case _ => None
  }

  private def groupedBuild(p: SparkPlan, keys: Seq[Expression]): Option[BaseAggregateExec] =
    stripSort(p) match {
      case f: FilterExec if f.condition.deterministic && !SubqueryExpression.hasSubquery(f.condition) =>
        groupedBuild(f.child, keys)
      case p: ProjectExec if p.projectList.forall(_.isInstanceOf[Attribute]) =>
        groupedBuild(p.child, keys)
      case a: BaseAggregateExec if keys.size == 1 && a.groupingExpressions.size == 1 &&
          a.groupingExpressions.head.semanticEquals(keys.head) && a.aggregateExpressions.nonEmpty &&
          a.aggregateExpressions.forall(e => e.mode == Final && (e.aggregateFunction match {
            case _: Average | _: Count | _: Sum | _: Min | _: Max => true
            case _ => false
          })) && a.output.forall(_.dataType match {
            case BooleanType | ByteType | ShortType | IntegerType | LongType | DateType |
                TimestampType | DoubleType | FloatType | _: DecimalType => true
            case _ => false
          }) => Some(a)
      case _ => None
    }

  private def rollup(build: SparkPlan, probe: SparkPlan, keys: Seq[Expression]): Boolean =
    SQLConf.get.getConfString("spark.sql.adaptive.measureGroupedBuildBeforeProbe.enabled","false")
      .toBoolean && probeEdge(probe).nonEmpty && groupedBuild(build,keys).exists { a =>
        probeEdge(a.child).exists(_.child.exists {
          case child: BaseAggregateExec => child.groupingExpressions.size > a.groupingExpressions.size
          case _ => false
        })
      }

  def buildChild(plan: SparkPlan): Option[Int] =
    QualifiedStageBuild.side(plan).orElse(originalBuildChild(plan))

  private def originalBuildChild(plan: SparkPlan): Option[Int] = plan match {
    case join: ShuffledJoin if !join.isSkewJoin &&
        join.logicalLink.collect { case j: Join => j.hint }.contains(JoinHint.NONE) =>
      if (canBuildBroadcastLeft(join.joinType) && (eligible(join.left, join.right, join.leftKeys) || rollup(join.left,join.right,join.leftKeys))) {
        Some(0)
      } else if (canBuildBroadcastRight(join.joinType) && (eligible(join.right, join.left, join.rightKeys) || rollup(join.right,join.left,join.rightKeys))) {
        Some(1)
      } else None
    case _ => None
  }
  def payloadBuildChild(plan: SparkPlan): Option[Int] = plan match {
    case join: ShuffledJoin if !join.isSkewJoin &&
        join.logicalLink.collect { case j: Join => j.hint }.contains(JoinHint.NONE) =>
      val sides = Seq(
        canBuildBroadcastLeft(join.joinType) && eligible(join.left,join.right,join.leftKeys,payload = true),
        canBuildBroadcastRight(join.joinType) && eligible(join.right,join.left,join.rightKeys,payload = true))
      if (sides.count(identity) == 1) Some(sides.indexOf(true)) else None
    case _ => None
  }

  case class Candidate(leftKey: ExprId, rightKey: ExprId, joinType: JoinType)
  def identityOf(plan: SparkPlan): Option[Candidate] = plan match {
    case j: ShuffledJoin if !j.isSkewJoin => (j.leftKeys, j.rightKeys) match {
      case (Seq(l: Attribute), Seq(r: Attribute)) => Some(Candidate(l.exprId, r.exprId, j.joinType))
      case _ => None
    }
    case _ => None
  }

  private def materialized(plan: SparkPlan): Option[ShuffleQueryStageExec] = plan match {
    case s: SortExec if !s.global => materialized(s.child)
    case s: AQEShuffleReadExec => materialized(s.child)
    case s: ShuffleQueryStageExec if s.isMaterialized => Some(s)
    case _ => None
  }

  def broadcastMeasuredBuild(plan: SparkPlan, candidates: Map[Candidate, Int],
      limit: Long, distribution: Distribution, alreadySubmitted: SparkPlan => Boolean): SparkPlan = {
    if (candidates.isEmpty || limit <= 0) return plan
    val reused = plan.collectWithSubqueries {
      case ReusedExchangeExec(_, e: ShuffleExchangeExec) => e.canonicalized
    }.toSet
    val revised = plan.transformUp {
      case j: ShuffledJoin if j.logicalLink.collect { case x: Join => x.hint }.contains(JoinHint.NONE) =>
        val replacement = for {
          id <- identityOf(j)
          index <- candidates.get(id)
          original = stripSort(j.children(index))
          keys = if (index == 0) j.leftKeys else j.rightKeys
          grouped = groupedBuild(original, keys)
          stage <- materialized(original).orElse(grouped.flatMap(a => materialized(a.child)))
          stats <- stage.computeStats() if stats.isRuntime && stats.sizeInBytes >= 0 &&
            stats.sizeInBytes <= limit
          if grouped.forall { a =>
            // A final grouped aggregate produces at most one row per partial input row.
            // Each fixed-width output fits an eight-byte slot plus any long decimal payload.
            val width = UnsafeRow.calculateBitSetWidthInBytes(a.output.size) +
              a.output.map(x => 8 + (if (x.dataType.defaultSize > 8) 16 else 0)).sum
            stats.rowCount.exists(_ * width <= limit)
          }
          probe <- probeEdge(j.children(1 - index)) if !reused(probe.canonicalized) &&
            !alreadySubmitted(probe.canonicalized)
        } yield {
          val side = if (index == 0) BuildLeft else BuildRight
          val inputs = if (index == 0) Seq(original, probe.child) else Seq(probe.child, original)
          val join = BroadcastHashJoinExec(j.leftKeys, j.rightKeys, j.joinType, side, j.condition,
            inputs.head, inputs.last)
          val mode = join.requiredChildDistribution(index).asInstanceOf[BroadcastDistribution].mode
          val broadcast = BroadcastExchangeExec(mode, original)
          original.logicalLink.foreach(broadcast.setLogicalLink)
          val result = join.withNewChildren(inputs.updated(index, broadcast))
          j.logicalLink.foreach(result.setLogicalLink)
          result
        }
        replacement.getOrElse(j)
    }
    if ((revised ne plan) && ValidateRequirements.validate(revised, distribution)) revised else plan
  }
}
