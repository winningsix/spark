package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions.Attribute
import org.apache.spark.sql.catalyst.expressions.aggregate.Final
import org.apache.spark.sql.catalyst.optimizer.BuildRight
import org.apache.spark.sql.catalyst.plans.LeftOuter
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.joins.{ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types._

class GroupedOuterHashExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectQueryStageOptimizerRule(_ => GroupedOuterHash)
}

/** A final aggregate produces at most one row per input row. Estimate the largest local
  * build table from that bound and the measured size of each coalesced shuffle read. */
private[adaptive] object GroupedOuterHash extends Rule[SparkPlan] {
  private def fixed(t: DataType): Boolean = t match {
    case IntegerType | LongType | DoubleType | DateType => true
    case d: DecimalType => d.precision <= Decimal.MAX_LONG_DIGITS
    case _ => false
  }

  private def fits(p: SparkPlan): Boolean = p match {
    case a: HashAggregateExec if a.groupingExpressions.nonEmpty &&
        a.aggregateExpressions.forall(_.mode == Final) && a.output.forall(k => fixed(k.dataType)) =>
      val budget = conf.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
        .getOrElse(conf.autoBroadcastJoinThreshold)
      val input = a.child match {
        case AQEShuffleReadExec(stage: ShuffleQueryStageExec,specs) if stage.isMaterialized =>
          val bytes = specs.collect { case c: CoalescedPartitionSpec if c.dataSize.exists(_ >= 0) =>
            c.dataSize.get }
          Option.when(bytes.nonEmpty && bytes.size == specs.size)((stage,bytes))
        case stage: ShuffleQueryStageExec if stage.isMaterialized =>
          stage.mapStats.map(s => (stage,s.bytesByPartitionId.toIndexedSeq))
        case _ => None
      }
      input.exists { case (stage,sizes) =>
        val bytes = sizes.iterator.map(BigInt(_)).sum
        // The fixed-width output has a null bitset, word slots, and a hash-entry allowance.
        val rowBytes = 8L * ((a.output.size + 63) / 64 + a.output.size) + 24L
        bytes > 0 && budget > 0 && stage.computeStats().exists(s => s.isRuntime &&
          s.rowCount.exists(n => n > 0 && n * rowBytes * sizes.max <= bytes * budget))
      }
    case _ => false
  }

  private def choose(p: SparkPlan): SparkPlan = p match {
    case p: ProjectExec => p.withNewChildren(Seq(choose(p.child)))
    case p: FilterExec => p.withNewChildren(Seq(choose(p.child)))
    case j @ SortMergeJoinExec(lk,rk,LeftOuter,None,l,r: SortExec,false)
        if !r.global && rk.nonEmpty && rk.forall {
          case a: Attribute => a.dataType == IntegerType || a.dataType == LongType
          case _ => false
        } && j.logicalLink.exists { case x: Join => x.hint == JoinHint.NONE; case _ => false } &&
          fits(r.child) =>
      val probe = l match {case s: SortExec if !s.global => s.child; case other => other}
      val hash = ShuffledHashJoinExec(lk,rk,LeftOuter,BuildRight,None,choose(probe),r.child)
      if (hash.output != j.output || hash.outputPartitioning != j.outputPartitioning) j
      else {hash.copyTagsFrom(j);hash}
    case _ => p
  }

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConfString("spark.sql.adaptive.groupedOuterHash.enabled","false").toBoolean) return plan
    plan.transformUp {
      case top: TakeOrderedAndProjectExec if top.requiredChildOrdering.forall(_.isEmpty) =>
        top.withNewChildren(Seq(choose(top.child)))
    }
  }
}
