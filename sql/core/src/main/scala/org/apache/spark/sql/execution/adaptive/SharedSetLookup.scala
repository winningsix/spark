package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression,BitOrAgg}
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{IntegralType,LongType,StringType}

class SharedSetLookupExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit=ext.injectPreCBORule(_=>SharedSetLookup)
}

private[adaptive] object SharedSetLookup extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.shareSetLookup"
  private case class Arm(fact:LogicalPlan,dim:LogicalPlan,foreign:Attribute,pk:Attribute,
      names:Seq[Int],factOutputs:Seq[Attribute],flag:NamedExpression)

  private def arm(p:LogicalPlan):Option[Arm]=p match {
    case Project(cols,Join(f,d,Inner,Some(EqualTo(x:Attribute,y:Attribute)),JoinHint.NONE))
        if cols.lastOption.exists {
          case Alias(l:Literal,_)=>l.dataType==LongType && l.value!=null
          case _=>false
        } && d.deterministic && f.deterministic && cols.dropRight(1).forall(_.isInstanceOf[Attribute])=>
      val plain=cols.dropRight(1).map(_.toAttribute)
      for {
        (fk,pk)<-Seq(x->y,y->x).find {case(a,b)=>f.outputSet.contains(a) && d.outputSet.contains(b)}
        if fk.dataType.isInstanceOf[IntegralType] && plain.forall(a=>d.outputSet.contains(a) || f.outputSet.contains(a))
        names=plain.map(a=>d.output.indexWhere(_.semanticEquals(a)))
        if names.exists(_>=0) && names.exists(_<0) && plain.zip(names).forall {
          case (a,n)=>n<0 || a.dataType==StringType }
        other=plain.filter(f.outputSet.contains) if !other.contains(fk)
      } yield Arm(f,d,fk,pk,names,other,cols.last)
    case _=>None
  }

  private def factor(a:Aggregate,u:Union,mode:String):Option[LogicalPlan]={
    val arms=u.children.flatMap(arm)
    if(arms.size<3 || arms.size!=u.children.size || u.byName || u.allowMissingCol) return None
    val head=arms.head
    if(!arms.forall(b=>b.names==head.names && b.dim.sameResult(head.dim) &&
        b.dim.output.indexOf(b.pk)==head.dim.output.indexOf(head.pk) &&
        b.foreign.dataType==head.foreign.dataType &&
        b.factOutputs.map(_.dataType)==head.factOutputs.map(_.dataType))) return None
    val keys=u.output.dropRight(1);val source=u.output.last
    val metrics=a.aggregateExpressions.flatMap(_.collect { case e:AggregateExpression=>e })
    if(a.groupingExpressions!=keys || metrics.isEmpty || !metrics.forall { e=>e.aggregateFunction match {
      case BitOrAgg(c) => c.semanticEquals(source) && e.filter.isEmpty && !e.isDistinct
      case _=>false
    }}) return None
    val facts=Union(arms.map(b=>Project((b.foreign+:b.factOutputs):+b.flag,b.fact)))
    val narrow=if(mode=="early") {
      val group=facts.output.dropRight(1)
      Aggregate(group,group:+Alias(BitOrAgg(facts.output.last).toAggregateExpression(),"partial_set_membership")(),facts)
    } else facts
    val joined=Join(narrow,head.dim,Inner,Some(EqualTo(narrow.output.head,head.pk)),JoinHint.NONE)
    val nonDim=narrow.output.drop(1).dropRight(1).iterator
    val attrs=head.names.map(n=>if(n>=0) head.dim.output(n) else nonDim.next()):+narrow.output.last
    val projection=attrs.zip(u.output).map { case (v,old)=>
      if(v.exprId==old.exprId) v else Alias(v,old.name)(exprId=old.exprId,qualifier=old.qualifier,
        explicitMetadata=Some(old.metadata))
    }
    Some(a.copy(child=Project(projection,joined)))
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"off")
    if(p.isStreaming || !Set("join","early").contains(mode)) p
    else p.transformUp {case a @ Aggregate(_,_,u:Union,_)=>factor(a,u,mode).getOrElse(a)}
  }
}
