package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSession,SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{Average,AggregateExpression}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.internal.SQLConf

class NestedGroupTransportExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit={
    ext.injectPreCBORule(_=>NestedGroupTransport)
    ext.injectQueryStagePrepRule(_=>NestedGroupTransport.route)
  }
}

private[adaptive] object NestedGroupTransport extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.routeNestedGroupShuffle"
  private val selected=TreeNodeTag[Boolean]("spark.exchangeBetweenGroupAndAverage")

  private def inner(p:LogicalPlan):Option[Aggregate]=p match {
    case a:Aggregate=>Some(a)
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>inner(c)
    case _=>None
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    if(!p.isStreaming && Set("block","live").contains(conf.getConfString(setting,"off"))) {
      p.foreach {
        case a:Aggregate if a.groupingExpressions.size==1 && a.aggregateExpressions.exists(_.exists {
          case e:AggregateExpression=>e.aggregateFunction.isInstanceOf[Average]
          case _=>false
        })=>inner(a.child).foreach { g=>
          if(g.groupingExpressions.size>=2 && g.groupingExpressions.forall(_.isInstanceOf[Attribute]) &&
              g.groupingExpressions.exists(k=> !g.aggregateExpressions.exists(v=>v.references.contains(k.asInstanceOf[Attribute]))) &&
              g.child.exists(_.isInstanceOf[Join])) g.setTagValue(selected,true)
        }
        case _=>()
      }
    }
    p
  }

  val route:Rule[SparkPlan]=new Rule[SparkPlan] {
    override def apply(p:SparkPlan):SparkPlan={
      val mode=conf.getConfString(setting,"off")
      if(!Set("block","live").contains(mode) || !PipelinedShuffleEligibility.enabled(p,conf)) return p
      val sc=SparkSession.active.sparkContext
      if(!sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled",false) ||
        !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled",false)) return p
      val slots=sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
      val fraction=conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
      val width=Seq(conf.numShufflePartitions,if(fraction>0)(slots*fraction).toInt else slots,
        slots-sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1)).min
      if(width<1) return p
      val keys=p.collect {case op if op.logicalLink.isDefined=>op.logicalLink.get}
        .flatMap(_.collect {case a:Aggregate if a.getTagValue(selected).contains(true)=>
          a.groupingExpressions.collect {case c:Attribute=>c.exprId}}).distinct
      val exchanges=p.collectWithSubqueries {case e:ShuffleExchangeExec=>e}
      val matches=exchanges.collect {
        case e:ShuffleExchangeExec if e.shuffleOrigin==ENSURE_REQUIREMENTS &&
            e.child.isInstanceOf[BaseAggregateExec] && e.outputPartitioning.isInstanceOf[HashPartitioning] &&
            keys.contains(e.outputPartitioning.asInstanceOf[HashPartitioning].expressions.collect {
              case a:Attribute=>a.exprId
            })=>e
      }
      if(matches.size!=1 || exchanges.exists(_.pipelined)) return p
      val edge=matches.head
      if(exchanges.count(_.canonicalized==edge.canonicalized)!=1 ||
          p.exists {case r:ReusedExchangeExec=>r.child.canonicalized==edge.canonicalized;case _=>false}) return p
      val part=edge.outputPartitioning.asInstanceOf[HashPartitioning]
      val updated=edge.copy(outputPartitioning=part.copy(numPartitions=width),
        shuffleOrigin=REPARTITION_BY_NUM,pipelined=mode=="live")
      updated.copyTagsFrom(edge);edge.logicalLink.foreach(updated.setLogicalLink)
      val next=p.transformUp {case e:ShuffleExchangeExec if e eq edge=>updated}
      if(ValidateRequirements.validate(next)) next else p
    }
  }
}
