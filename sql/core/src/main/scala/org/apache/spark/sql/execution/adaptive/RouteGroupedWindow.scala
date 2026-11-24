package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions.aggregate.Average
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{SortExec,SparkPlan}
import org.apache.spark.sql.execution.aggregate.{BaseAggregateExec,HashAggregateExec}
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.execution.window.WindowExec

class GroupedWindowTransportExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = {
    ext.injectQueryPostPlannerStrategyRule(_ => AlignWindowGroups)
    ext.injectQueryStagePrepRule(_ => RouteGroupedWindow)
  }
}

private[adaptive] object AlignWindowGroups extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    if (conf.getConfString("spark.sql.execution.groupedThresholdTransport","default")!="local") return plan
    plan.transformUp { case w: WindowExec if w.orderSpec.isEmpty && w.partitionSpec.size==1 &&
        w.windowExpression.exists(_.exists(_.isInstanceOf[Average])) =>
      w.child match {
        case a: HashAggregateExec if !a.isStreaming && a.requiredChildDistributionExpressions.isDefined &&
            a.groupingExpressions.size>w.partitionSpec.size &&
            w.partitionSpec.forall(k => a.groupingExpressions.exists(_.semanticEquals(k))) &&
            w.partitionSpec.forall(k => k.references.subsetOf(a.child.outputSet)) =>
          val grouped=a.copy(requiredChildDistributionExpressions=Some(w.partitionSpec))
          grouped.copyTagsFrom(a)
          a.logicalLink.foreach(grouped.setLogicalLink)
          w.withNewChildren(Seq(grouped))
        case _ => w
      }
    }
  }
}

private[adaptive] object RouteGroupedWindow extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    val mode=conf.getConfString("spark.sql.execution.groupedThresholdTransport","default")
    if (mode!="block" && mode!="pipeline") return plan
    val live=mode=="pipeline"
    if (live && !PipelinedShuffleEligibility.enabled(plan,conf)) return plan
    val exchanges=plan.collectWithSubqueries {case e: ShuffleExchangeExec => e}
    if (exchanges.exists(_.pipelined)) return plan
    // Only the exchange immediately feeding a store-level (group-level) whole-partition
    // average of completed multi-key groups may change. Keep every other exchange ordinary.
    val matches=plan.collect { case w: WindowExec if w.orderSpec.isEmpty &&
      w.partitionSpec.size==1 && w.windowExpression.exists(_.exists(_.isInstanceOf[Average])) =>
      w.child match {
        case sort: SortExec if !sort.global => sort.child
        case c => c
      }
    }.collect {case e: ShuffleExchangeExec if e.shuffleOrigin==ENSURE_REQUIREMENTS &&
      e.outputPartitioning.isInstanceOf[HashPartitioning] &&
      e.child.exists {case g: BaseAggregateExec => g.groupingExpressions.size>1
        case _ => false} => e}
    if (matches.size!=1 || exchanges.count(_.canonicalized==matches.head.canonicalized)!=1) return plan
    val e=matches.head
    val sc=plan.session.sparkContext;val slots=sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val fraction=conf.getConf(org.apache.spark.sql.internal.SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val writerWindow=sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1)
    val h=e.outputPartitioning.asInstanceOf[HashPartitioning]
    if (!sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled",false) ||
        !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled",false)) return plan
    val available=(if(fraction>0) (slots*fraction).toInt else slots).min(slots-writerWindow)
    if (available<=0) return plan
    // Choose the same physical hash width for the two transports within the slot budget.
    val bucketCount=h.numPartitions.toLong
    val bucketsPerReader=(bucketCount+available-1)/available
    val width=((bucketCount+bucketsPerReader-1)/bucketsPerReader).toInt
    if (width<1 || plan.exists {case ReusedExchangeExec(_,x) => x.canonicalized==e.canonicalized
      case _ => false}) return plan
    val partitioning=HashPartitioning(h.expressions,width)
    val replacement=e.copy(outputPartitioning=partitioning,pipelined=live)
    replacement.copyTagsFrom(e);e.logicalLink.foreach(replacement.setLogicalLink)
    val result=plan.transformUp {case x: ShuffleExchangeExec if x eq e => replacement}
    if (ValidateRequirements.validate(result)) result else plan
  }
}
