package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.optimizer.BuildLeft
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.sql.internal.SQLConf

private[adaptive] object RoutePrunedFactJoin extends Rule[SparkPlan] {
  val target = TreeNodeTag[Boolean]("adaptive.sharedPruningFactJoin")
  val setting = "spark.sql.execution.sharedFactProbeTransport"

  override def apply(plan: SparkPlan): SparkPlan = {
    val mode = conf.getConfString(setting,"default")
    if (!Set("block","pipeline").contains(mode) || !PipelinedShuffleEligibility.enabled(plan,conf)) return plan
    val pairs = plan.collect {
      case j: ShuffledHashJoinExec if j.joinType == Inner && j.buildSide == BuildLeft &&
          !j.isSkewJoin && j.logicalLink.exists(_.getTagValue(target).contains(true)) =>
        (j.left,j.right)
    }.collect { case (l: ShuffleExchangeExec,r: ShuffleExchangeExec)
        if Seq(l,r).forall(e => e.shuffleOrigin == ENSURE_REQUIREMENTS &&
          e.outputPartitioning.isInstanceOf[HashPartitioning] && !e.child.exists(_.isInstanceOf[Exchange])) => (l,r) }
    if (pairs.size != 1) return plan
    val (build,probe) = pairs.head
    val edges = plan.collectWithSubqueries { case e: ShuffleExchangeExec => e }
    if (edges.exists(_.pipelined) || Seq(build,probe).exists { e =>
        edges.count(_.canonicalized == e.canonicalized) != 1 ||
          plan.exists {
            case ReusedExchangeExec(_,x) => x.canonicalized == e.canonicalized
            case _ => false
          }
      }) return plan
    val sc = plan.session.sparkContext
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val fraction = conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val reserve = sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1)
    if (!sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled",false) ||
        !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled",false)) return plan
    val width = Seq((if (fraction > 0) (slots*fraction).toInt else slots), slots-reserve,
      build.outputPartitioning.numPartitions,probe.outputPartitioning.numPartitions).min
    if (width<=0) return plan
    val result=plan.transformUp { case e: ShuffleExchangeExec if (e eq build) || (e eq probe) =>
      val part=e.outputPartitioning.asInstanceOf[HashPartitioning]
      val replacement=e.copy(outputPartitioning=part.copy(numPartitions=width),
        shuffleOrigin=REPARTITION_BY_NUM,pipelined=(e eq probe) && mode=="pipeline")
      replacement.copyTagsFrom(e)
      e.logicalLink.foreach(replacement.setLogicalLink)
      replacement
    }
    if (ValidateRequirements.validate(result)) result else plan
  }
}
