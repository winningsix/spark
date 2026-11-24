package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint, LogicalPlan}
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.{SortExec, SparkPlan}
import org.apache.spark.sql.execution.exchange.{ReusedExchangeExec, ShuffleExchangeExec}
import org.apache.spark.sql.execution.joins.ShuffledJoin

private[adaptive] object QualifiedStageBuild {
  private val smallResult = TreeNodeTag[Boolean]("org.apache.spark.sql.filteredGroupStage")
  def mark(p: LogicalPlan): LogicalPlan = { p.setTagValue(smallResult,true); p }

  private def marked(p: SparkPlan): Boolean = p match {
    case s: SortExec if !s.global => marked(s.child)
    case s: ShuffleQueryStageExec => marked(s.plan)
    case r: ReusedExchangeExec => marked(r.child)
    case e: ShuffleExchangeExec if !e.pipelined =>
      e.logicalLink.exists(_.getTagValue(smallResult).contains(true))
    case _ => false
  }

  def side(p: SparkPlan): Option[Int] = p match {
    case j: ShuffledJoin if j.joinType == Inner && !j.isSkewJoin && j.condition.isEmpty &&
        j.logicalLink.collect {case l: Join => l.hint}.contains(JoinHint.NONE) =>
      val matched = j.children.indices.filter(i =>
        marked(j.children(i)) && ProbeShuffleAfterBuild.probeEdge(j.children(1-i)).nonEmpty)
      if (matched.size == 1) Some(matched.head) else None
    case _ => None
  }
}
