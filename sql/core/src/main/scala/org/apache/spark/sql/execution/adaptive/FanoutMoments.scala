package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSession,SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression,CentralMomentAgg}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation,LogicalRelation}
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.internal.SQLConf

class FanoutMomentsExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit={
    ext.injectPreCBORule(_=>FanoutMoments)
    ext.injectQueryStagePrepRule(_=>FanoutMoments.route)
  }
}

private[adaptive] object FanoutMoments extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.fanoutPrunedMomentGroups"
  private val tag=TreeNodeTag[Boolean]("spark.partitionInputBeforeMoments")

  private def eligible(a:Aggregate):Boolean=a.groupingExpressions.size>=2 &&
    a.groupingExpressions.forall(_.isInstanceOf[Attribute]) &&
    a.aggregateExpressions.exists(_.exists {
      case e:AggregateExpression=>e.aggregateFunction.isInstanceOf[CentralMomentAgg]
      case _=>false
    }) && a.child.exists(_.isInstanceOf[Join]) && a.child.exists {
      case l:LogicalRelation=>l.relation match {
        case h:HadoopFsRelation=>h.partitionSchema.nonEmpty
        case _=>false
      }
      case _=>false
    }

  override def apply(p:LogicalPlan):LogicalPlan={
    if(p.isStreaming || !Set("block","live").contains(conf.getConfString(setting,"off"))) return p
    val targets=p.collect {case a:Aggregate if eligible(a)=>a}
    if(targets.size!=2 || !targets.head.aggregateExpressions.exists(_.exists(_.isInstanceOf[AggregateExpression])) ||
        targets.head.groupingExpressions.map(_.dataType)!=targets.last.groupingExpressions.map(_.dataType)) return p
    val sc=SparkSession.active.sparkContext
    val slots=sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val fraction=conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val quota=if(fraction>0) (slots*fraction).toInt else slots
    val width=Seq(conf.numShufflePartitions,quota/targets.size,
      (slots-sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1))/targets.size).min
    if(width<2) return p
    p.transformUp {case a:Aggregate if targets.exists(_ eq a) && !a.child.isInstanceOf[RepartitionByExpression]=>
      val partition=RepartitionByExpression(a.groupingExpressions,a.child,Some(width))
      partition.setTagValue(tag,true)
      a.copy(child=partition)
    }
  }

  val route:Rule[SparkPlan]=new Rule[SparkPlan] {
    override def apply(p:SparkPlan):SparkPlan={
      if(conf.getConfString(setting,"off")!="live" || !PipelinedShuffleEligibility.enabled(p,conf)) return p
      val sc=SparkSession.active.sparkContext
      if(!sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled",false) ||
          !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled",false)) return p
      val choices=p.collect {case op if op.logicalLink.nonEmpty=>op.logicalLink.get}
        .flatMap(_.collect {case r:RepartitionByExpression if r.getTagValue(tag).contains(true)=>
          r.partitionExpressions.collect {case x:Attribute=>x.exprId}->r.numPartitions}).toSet
      val all=p.collectWithSubqueries {case e:ShuffleExchangeExec=>e}
      // A shared shuffle must remain available to its other readers.
      val candidates=all.filter(e=>e.shuffleOrigin==REPARTITION_BY_NUM && !e.pipelined &&
        (e.outputPartitioning match {
          case h:HashPartitioning if h.expressions.forall(_.isInstanceOf[Attribute])=>
            choices.contains(h.expressions.map(_.asInstanceOf[Attribute].exprId)->h.numPartitions)
          case _=>false
        }) && all.count(_.canonicalized==e.canonicalized)==1 &&
        !p.exists {case r:ReusedExchangeExec=>r.child.canonicalized==e.canonicalized;case _=>false})
      if(candidates.isEmpty) return p
      val next=p.transformUp {case e:ShuffleExchangeExec if candidates.exists(_ eq e)=>
        val v=e.copy(pipelined=true);v.copyTagsFrom(e);e.logicalLink.foreach(v.setLogicalLink);v}
      if(ValidateRequirements.validate(next)) next else p
    }
  }
}
