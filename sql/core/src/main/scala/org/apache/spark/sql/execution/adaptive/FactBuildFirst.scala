package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint}
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.exchange.{ENSURE_REQUIREMENTS, Exchange, ReusedExchangeExec, ShuffleExchangeLike}
import org.apache.spark.sql.execution.joins.ShuffledJoin
import org.apache.spark.sql.internal.SQLConf

private[adaptive] object FactBuildFirst {
  val measure = TreeNodeTag[Boolean]("adaptive.measureReorderedInnerJoin")
  private val held = TreeNodeTag[Int]("adaptive.deferredPrunedFactScan")

  def ordinal(plan: SparkPlan): Option[Int] = {
    val conf = SQLConf.get
    val mode = conf.getConfString("spark.sql.optimizer.measuredFactJoinOrder","off")
    if (!mode.startsWith("measure") || conf.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
        .getOrElse(conf.autoBroadcastJoinThreshold) <= 0) return None
    plan match {
      case j: ShuffledJoin if j.joinType == Inner && !j.isSkewJoin =>
        j.getTagValue(held).orElse {
          val tagged = j.logicalLink.exists {
            case l: Join => l.hint == JoinHint.NONE && l.getTagValue(measure).contains(true)
            case _ => false
          }
          if (!tagged) return None
          val edges = j.left.collect {case x: Exchange => x}
          val leaf = edges.size == 1 && edges.head.isInstanceOf[ShuffleExchangeLike] &&
              edges.head.asInstanceOf[ShuffleExchangeLike].shuffleOrigin == ENSURE_REQUIREMENTS &&
              !edges.head.nodeName.toLowerCase(java.util.Locale.ROOT).contains("pipelined") &&
              !j.left.exists {
                case _: QueryStageExec | _: ReusedExchangeExec => true
                case e: org.apache.spark.sql.execution.exchange.ShuffleExchangeExec => e.pipelined
                case _ => false
              }
          if (leaf) {
            j.setTagValue(held,1)
            Some(1)
          } else None
        }
      case _ => None
    }
  }
}
