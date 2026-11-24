package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSession,SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression,Sum}
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.{FilterExec,ProjectExec,SparkPlan}
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.execution.window.WindowExec
import org.apache.spark.sql.internal.SQLConf

class GroupedWindowExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit={
    ext.injectQueryPostPlannerStrategyRule(_=>GroupedWindow)
    ext.injectQueryStagePrepRule(_=>GroupedWindow.transport)
  }
}

/** Cluster the daily aggregate by its window partition so the cumulative sum can consume
 * those partitions directly. Sort order and all original grouping expressions are retained.
 */
private[adaptive] object GroupedWindow extends Rule[SparkPlan] {
  val setting="spark.sql.adaptive.colocateGroupedRunningSum"
  private val tagged=TreeNodeTag[Boolean]("spark.colocatedRunningSumAggregate")

  private def cumulative(w:WindowExec):Boolean=w.windowExpression.nonEmpty && w.windowExpression.forall {
    case Alias(WindowExpression(a:AggregateExpression,WindowSpecDefinition(_,_,SpecifiedWindowFrame(RowFrame,UnboundedPreceding,CurrentRow))),_) =>
      a.aggregateFunction.isInstanceOf[Sum] && !a.isDistinct
    case _=>false
  }

  private def change(p:SparkPlan,keys:Seq[Attribute],ordered:Seq[Attribute]):Option[SparkPlan]=p match {
    case a:HashAggregateExec if !a.isStreaming && a.aggregateExpressions.nonEmpty &&
        a.requiredChildDistributionExpressions.exists { required =>
          required.size==keys.size+ordered.size && (keys++ordered).forall(k=>required.exists(_.semanticEquals(k)))
        } && a.groupingExpressions.size==keys.size+ordered.size &&
        (keys++ordered).forall(k=>a.groupingExpressions.exists(_.semanticEquals(k))) =>
      val agg=a.copy(requiredChildDistributionExpressions=Some(keys))
      agg.copyTagsFrom(a);a.logicalLink.foreach(agg.setLogicalLink);agg.setTagValue(tagged,true)
      Some(agg)
    case f:FilterExec=>change(f.child,keys,ordered).map(x=>f.withNewChildren(Seq(x)))
    case project:ProjectExec=>
      val columns=project.projectList.collect {case a:Attribute=>a.exprId->a;case a@Alias(k:Attribute,_)=>a.exprId->k}.toMap
      if (!(keys++ordered).forall(k=>columns.contains(k.exprId))) None
      else change(project.child,keys.map(k=>columns(k.exprId)),ordered.map(k=>columns(k.exprId)))
        .map(x=>project.withNewChildren(Seq(x)))
    case _=>None
  }

  override def apply(plan:SparkPlan):SparkPlan={
    if (!Set("aligned","block","live").contains(conf.getConfString(setting,"off"))) return plan
    align(plan)
  }

  private[adaptive] def align(plan:SparkPlan): SparkPlan = {
    plan.transformUp {
      case w:WindowExec if cumulative(w) && w.partitionSpec.nonEmpty && w.orderSpec.nonEmpty &&
          w.partitionSpec.forall(_.isInstanceOf[Attribute]) && w.orderSpec.forall(_.child.isInstanceOf[Attribute]) =>
        val keys=w.partitionSpec.map(_.asInstanceOf[Attribute])
        val times=w.orderSpec.map(_.child.asInstanceOf[Attribute])
        if ((keys++times).map(_.exprId).distinct.size!=keys.size+times.size) w
        else change(w.child,keys,times).map(x=>w.withNewChildren(Seq(x))).getOrElse(w)
    }
  }

  val transport:Rule[SparkPlan]=new Rule[SparkPlan] {
    override def apply(plan:SparkPlan):SparkPlan={
      val mode=conf.getConfString(setting,"off")
      if (!Set("block","live").contains(mode)) return plan
      val sc=SparkSession.active.sparkContext
      val live=mode=="live"
      if (live && (!PipelinedShuffleEligibility.enabled(plan,conf) ||
          !sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled",false) ||
          !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled",false))) return plan
      val targets=plan.collect {case a:HashAggregateExec if a.getTagValue(tagged).contains(true)=>a.child}
        .collect {case e:ShuffleExchangeExec if e.shuffleOrigin==ENSURE_REQUIREMENTS &&
          e.outputPartitioning.isInstanceOf[HashPartitioning] && !e.pipelined=>e}
      if(targets.isEmpty) return plan
      val slots=sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
      val fraction=conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
      val width=math.min(if(fraction>0)(slots*fraction).toInt else slots,
        slots-sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1))/targets.size
      if(width<2) return plan
      val edges=plan.collectWithSubqueries {case e:ShuffleExchangeExec=>e}
      val unique=targets.filter(e=>edges.count(_.canonicalized==e.canonicalized)==1 && !plan.exists {
        case r:ReusedExchangeExec=>r.child.canonicalized==e.canonicalized; case _=>false
      })
      val next=plan.transformUp {case e:ShuffleExchangeExec if unique.exists(_ eq e)=>
        val h=e.outputPartitioning.asInstanceOf[HashPartitioning]
        val out=e.copy(outputPartitioning=h.copy(numPartitions=width.min(h.numPartitions)),shuffleOrigin=REPARTITION_BY_NUM,pipelined=live)
        out.copyTagsFrom(e);e.logicalLink.foreach(out.setLogicalLink);out
      }
      if ((next eq plan) || ValidateRequirements.validate(next)) next else plan
    }
  }
}

/** Keep the daily aggregation and its running sum in the same partitions on both
 * inputs of a full outer time-series join. The existing join retains its keys.
 */
private[adaptive] object AlignJoinedRunningSums extends Rule[SparkPlan] {
  import org.apache.spark.sql.catalyst.plans.FullOuter
  import org.apache.spark.sql.execution.joins.ShuffledJoin

  private def branch(plan:SparkPlan, keys:Seq[Expression]):Option[SparkPlan] = plan match {
    case p:ProjectExec =>
      val aliases=p.projectList.collect {
        case a:Attribute => a.exprId -> a
        case a @ Alias(k:Attribute,_) => a.exprId -> k
      }.toMap
      val mapped=keys.collect { case a:Attribute if aliases.contains(a.exprId) => aliases(a.exprId) }
      if (mapped.size!=keys.size) None else branch(p.child,mapped).map(c=>p.withNewChildren(Seq(c)))
    case w:WindowExec =>
      val axes=w.partitionSpec ++ w.orderSpec.map(_.child)
      val aliases=w.child match {
        case a:HashAggregateExec=>a.resultExpressions.collect {
          case out @ Alias(k:Attribute,_)=>out.exprId -> k
        }.toMap
        case _=>Map.empty[ExprId,Attribute]
      }
      val groupingKeys=keys.map {
        case a:Attribute=>aliases.getOrElse(a.exprId,a)
        case e=>e
      }
      if (axes.size!=groupingKeys.size || !axes.forall(k=>groupingKeys.exists(_.semanticEquals(k)))) None
      else {
        val aligned=GroupedWindow.align(w)
        Option.when(!aligned.fastEquals(w))(aligned)
      }
    case _=>None
  }

  override def apply(plan:SparkPlan):SparkPlan = plan.transformUp {
    case j:ShuffledJoin if j.joinType==FullOuter =>
      (branch(j.left,j.leftKeys),branch(j.right,j.rightKeys)) match {
        case (Some(l),Some(r))=>j.withNewChildren(Seq(l,r))
        case _=>j
      }
  }
}
