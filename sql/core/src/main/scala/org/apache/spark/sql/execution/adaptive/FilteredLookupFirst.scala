package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.optimizer.BuildRight
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation,LogicalRelation}
import org.apache.spark.sql.execution.joins.{BroadcastHashJoinExec,SortMergeJoinExec}

class FilteredLookupFirstExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit={
    ext.injectPreCBORule(_=>FilteredLookupFirst)
    ext.injectQueryPostPlannerStrategyRule(_=>FilteredLookupFirst.measureSelected)
  }
}

private[adaptive] object FilteredLookupFirst extends Rule[LogicalPlan] with PredicateHelper {
  val setting="spark.sql.optimizer.joinSelectedKeysToLookupFirst"
  private val measure=TreeNodeTag[Boolean]("spark.measureSelectedKeysBeforeLookup")

  val measureSelected:Rule[SparkPlan]=new Rule[SparkPlan]{
    override def apply(p:SparkPlan):SparkPlan=p.transformUp {
      case j:BroadcastHashJoinExec if j.joinType==Inner && j.buildSide==BuildRight && !j.isSkewJoin &&
          !j.isNullAwareAntiJoin && j.logicalLink.exists(_.getTagValue(measure).contains(true)) &&
          !j.left.isInstanceOf[QueryStageExec] && !j.left.logicalLink.exists(_.isInstanceOf[LogicalQueryStage])=>
        val next=SortMergeJoinExec(j.leftKeys,j.rightKeys,Inner,j.condition,j.left,j.right)
        next.copyTagsFrom(j);j.logicalLink.foreach(next.setLogicalLink);next
    }
  }

  private def bare(p:LogicalPlan):LogicalPlan=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>c
    case other=>other
  }
  private def scan(p:LogicalPlan):Boolean=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>scan(c)
    case Filter(cond,c) if cond.deterministic=>scan(c)
    case l:LogicalRelation=>l.relation.isInstanceOf[HadoopFsRelation]
    case _=>false
  }
  private def connects(e:Expression,l:LogicalPlan,r:LogicalPlan):Boolean=e match {
    case EqualTo(a:Attribute,b:Attribute)=>(l.outputSet.contains(a) && r.outputSet.contains(b)) ||
        (l.outputSet.contains(b) && r.outputSet.contains(a))
    case _=>false
  }
  private def rewrite(outer:Join,mode:String):Option[LogicalPlan]=for {
    geo <- outer.condition if scan(outer.right)
    Join(middle,lookup,Inner,Some(lk),JoinHint.NONE)<-Some(bare(outer.left))
    if scan(lookup) && splitConjunctivePredicates(geo).size>1 &&
      splitConjunctivePredicates(geo).forall(connects(_,lookup,outer.right))
    Join(selected:Aggregate,fact,Inner,Some(fk),JoinHint.NONE)<-Some(bare(middle))
    if scan(fact) && selected.groupingExpressions.nonEmpty &&
      selected.aggregateExpressions.forall(_.isInstanceOf[Attribute]) &&
      selected.exists(_.isInstanceOf[Union]) && connects(lk,selected,lookup) && connects(fk,selected,fact)
  } yield {
    val addresses=Join(selected,lookup,Inner,Some(lk),JoinHint.NONE)
    if(mode=="measure") addresses.setTagValue(measure,true)
    val eligible=Join(addresses,outer.right,Inner,Some(geo),JoinHint.NONE)
    Project(outer.output,Join(eligible,fact,Inner,Some(fk),JoinHint.NONE))
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"off")
    if(p.isStreaming || !Set("order","measure").contains(mode)) p
    else p.transformUp {case j @ Join(_,_,Inner,_,JoinHint.NONE)=>rewrite(j,mode).getOrElse(j)}
  }
}
