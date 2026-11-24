package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions.Attribute
import org.apache.spark.sql.catalyst.optimizer.BuildRight
import org.apache.spark.sql.catalyst.plans.{Inner, LeftAnti}
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{CoalescedPartitionSpec, FilterExec, ProjectExec, SortExec, SparkPlan}
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.joins.{BroadcastHashJoinExec, ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{IntegerType, LongType}

class MeasuredAntiHashExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectQueryStageOptimizerRule(_ => MeasuredAntiHash)
}

private[adaptive] object MeasuredAntiHash extends Rule[SparkPlan] {
  private case class Read(bytes: Seq[Long], stage: ShuffleQueryStageExec)

  private def input(p: SparkPlan): Option[Read] = p match {
    case AQEShuffleReadExec(s: ShuffleQueryStageExec, specs) if s.isMaterialized =>
      val bytes = specs.collect { case c: CoalescedPartitionSpec if c.dataSize.exists(_ >= 0) =>
        c.dataSize.get }
      Option.when(bytes.nonEmpty && bytes.size == specs.size)(Read(bytes,s))
    case s: ShuffleQueryStageExec if s.isMaterialized =>
      s.mapStats.map(_.bytesByPartitionId.toIndexedSeq).filter(x => x.nonEmpty && x.forall(_ >= 0))
        .map(Read(_,s))
    case _ => None
  }

  private def fits(left: Read, right: Read): Boolean = {
    val compressed = right.bytes.iterator.map(BigInt(_)).sum
    val probe = left.bytes.iterator.map(BigInt(_)).sum
    val budget = conf.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
      .getOrElse(conf.autoBroadcastJoinThreshold)
    left.bytes.size == right.bytes.size && budget > 0 && compressed > 0 && probe > compressed &&
      right.stage.computeStats().exists { stats =>
        stats.isRuntime && stats.rowCount.exists { n =>
          // Estimate each coalesced reader's table, including 16 bytes per hash entry.
          val total = stats.sizeInBytes + 16 * n
          total > 0 && total * right.bytes.max <= BigInt(budget) * compressed
        }
      }
  }

  private def choose(p: SparkPlan): SparkPlan = p match {
    case j @ SortMergeJoinExec(lk,rk,LeftAnti,None,l: SortExec,r: SortExec,false)
        if !l.global && !r.global && rk.nonEmpty && rk.forall {
          case a: Attribute => a.dataType == IntegerType || a.dataType == LongType
          case _ => false
        } && r.output.forall(a => rk.exists(_.semanticEquals(a))) &&
          j.logicalLink.exists { case x: Join => x.hint == JoinHint.NONE; case _ => false } =>
      val selected = for {
        left <- input(l.child)
        right <- input(r.child) if fits(left,right)
        hash = ShuffledHashJoinExec(lk,rk,LeftAnti,BuildRight,None,l.child,r.child)
        if hash.output == j.output && hash.outputPartitioning == j.outputPartitioning
      } yield {
        hash.copyTagsFrom(j)
        hash
      }
      selected.getOrElse(j)
    case p: ProjectExec => p.withNewChildren(Seq(choose(p.child)))
    case p: FilterExec => p.withNewChildren(Seq(choose(p.child)))
    case j: BroadcastHashJoinExec if j.joinType == Inner && j.buildSide == BuildRight =>
      j.withNewChildren(Seq(choose(j.left),j.right))
    case _ => p
  }

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConfString("spark.sql.adaptive.measuredAntiHash.enabled","false").toBoolean) return plan
    plan.transformUp {
      case a: HashAggregateExec if a.requiredChildOrdering.forall(_.isEmpty) =>
        a.withNewChildren(Seq(choose(a.child)))
    }
  }
}
