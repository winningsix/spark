package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{Max,Min}
import org.apache.spark.sql.catalyst.plans.{Inner,LeftAnti,LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation,LogicalRelation}
import org.apache.spark.sql.types.IntegralType

class UnequalWitnessExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit=ext.injectPreCBORule(_=>UnequalWitness)
}

private[adaptive] object UnequalWitness extends Rule[LogicalPlan] with PredicateHelper {
  val setting="spark.sql.optimizer.aggregateUnequalWitnesses"
  private case class Keys(l:Attribute,r:Attribute,x:Attribute,y:Attribute)
  private def oriented(a:Expression,b:Expression,j:Join):Option[(Attribute,Attribute)]=
    Seq(a->b,b->a).collectFirst {case (l:Attribute,r:Attribute) if j.left.outputSet.contains(l) &&
      j.right.outputSet.contains(r) && l.dataType==r.dataType && l.dataType.isInstanceOf[IntegralType]=>l->r}
  private def keys(j:Join):Option[Keys]=for {
    cond<-j.condition
    ps=splitConjunctivePredicates(cond) if ps.size==2
    (a,b)<-ps.collectFirst {case EqualTo(a,b)=>(a,b)}
    (l,r)<-oriented(a,b,j)
    (c,d)<-ps.collectFirst {case Not(EqualTo(c,d))=>(c,d)}
    (x,y)<-oriented(c,d,j) if x.exprId!=l.exprId
  } yield Keys(l,r,x,y)

  private def scan(p:LogicalPlan):Boolean=p match {
    case Project(cols,c) if cols.forall {case _:Attribute=>true;case a:Alias=>a.child.foldable && a.deterministic;case _=>false}=>scan(c)
    case Filter(cond,c) if cond.deterministic && !SubqueryExpression.hasSubquery(cond)=>scan(c)
    case l:LogicalRelation=>l.relation.isInstanceOf[HadoopFsRelation] && !l.isStreaming
    case _=>false
  }

  private def bounds(p:LogicalPlan,k:Attribute,v:Attribute):(Aggregate,Attribute,Attribute)={
    val lo=Alias(Min(v).toAggregateExpression(),"witness_min")()
    val hi=Alias(Max(v).toAggregateExpression(),"witness_max")()
    (Aggregate(Seq(k),Seq(k,lo,hi),p),lo.toAttribute,hi.toAttribute)
  }

  // This subtree is only used to decide existence. Duplicates of projected keys are immaterial.
  private def pairSet(pr:Project,j:Join):Option[LogicalPlan]=for {
    k<-keys(j) if scan(j.left) && scan(j.right) && pr.projectList.nonEmpty
    if pr.projectList.forall { case a:Attribute => a.semanticEquals(k.l) || a.semanticEquals(k.r)
      case a:Alias => a.child.foldable && a.deterministic
      case _ => false }
    if Project(Seq(k.l,k.x),j.left).sameResult(Project(Seq(k.r,k.y),j.right))
  } yield {
    val (agg,lo,hi)=bounds(j.left,k.l,k.x)
    val output=pr.projectList.map {
      case key:Attribute if key.exprId==k.r.exprId=>Alias(k.l,key.name)(exprId=key.exprId,qualifier=key.qualifier,explicitMetadata=Some(key.metadata))
      case other=>other
    }
    Project(output,Filter(And(IsNotNull(k.l),LessThan(lo,hi)),agg))
  }

  private def existenceInput(p:LogicalPlan):LogicalPlan=p match {
    case pr @ Project(_,j @ Join(_,_,Inner,_,JoinHint.NONE)) if pr.deterministic=>
      pairSet(pr,j).getOrElse(pr.copy(child=existenceInput(j)))
    case pr:Project if pr.deterministic=>pr.copy(child=existenceInput(pr.child))
    case f:Filter if f.condition.deterministic=>f.copy(child=existenceInput(f.child))
    case j @ Join(l,r,Inner,c,JoinHint.NONE) if c.forall(_.deterministic)=>
      j.copy(left=existenceInput(l),right=existenceInput(r))
    case _=>p
  }

  // Positive IN conjuncts only: if both X IN K and X IN (B join K) hold, the
  // second test can use B alone. Only TRUE passes this filter, including for nullable keys.
  private def factorDomain(f:Filter):LogicalPlan={
    val conditions=splitConjunctivePredicates(f.condition)
    val memberships=conditions.collect {case InSubquery(Seq(v:Attribute),q)
        if q.outerAttrs.isEmpty && q.joinCond.isEmpty && q.hint.isEmpty && q.numCols==1 &&
          q.plan.deterministic && q.plan.output.size==1=>v->q}
    if(memberships.size<2) return f
    val reduced=conditions.map {
      case in @ InSubquery(Seq(v:Attribute),q) if memberships.exists(_._2 eq q)=>
        val alternative=for {
          Project(Seq(result:Attribute),Join(l,r,Inner,Some(EqualTo(a:Attribute,b:Attribute)),JoinHint.NONE))<-Some(q.plan)
          (lookup,domain,resultKey,domainKey)<-Seq((l,r,a,b),(r,l,b,a),(l,r,b,a),(r,l,a,b)).find {
            case (side,other,x,y)=>result.semanticEquals(x) && side.outputSet.contains(x) &&
              other.output.size==1 && other.output.head.semanticEquals(y) &&
              memberships.exists {case (w,k)=>w.semanticEquals(v) && (k ne q) && k.plan.sameResult(other)}
          }
        } yield InSubquery(Seq(v),q.withNewPlan(Project(Seq(resultKey),lookup)))
        alternative.getOrElse(in)
      case other=>other
    }
    if(reduced==conditions) f else f.copy(condition=reduced.reduceLeft(And))
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"off")
    if(p.isStreaming || !Set("pairs","summary","factor").contains(mode)) return p
    val subqueries=p.transformUp { case f:Filter=>f.transformExpressionsUp {
      case q:ListQuery if q.hint.isEmpty && q.plan.deterministic => q.withNewPlan(existenceInput(q.plan))
      case q:Exists if q.hint.isEmpty && q.plan.deterministic =>
        val right=existenceInput(q.plan)
        val condition=q.joinCond.reduceOption(And)
        val outer=AttributeSet(q.joinCond.flatMap(_.references)) -- right.outputSet
        val pair=Join(LocalRelation(outer.toSeq),right,LeftSemi,condition,JoinHint.NONE)
        (if(mode!="pairs" && scan(right)) keys(pair) else None).map { k=>
          val (agg,lo,hi)=bounds(right,k.r,k.y)
          q.copy(plan=agg,joinCond=Seq(EqualTo(k.l,k.r),Or(Not(EqualTo(k.x,lo)),Not(EqualTo(k.x,hi)))))
        }.getOrElse(q.withNewPlan(right))
    }}
    val factored=if(mode=="factor") subqueries.transformUp {case f:Filter=>factorDomain(f)} else subqueries
    factored.transformUp {case j @ Join(_,right,LeftSemi | LeftAnti,_,JoinHint.NONE)=>
      val changed=if(right.deterministic) existenceInput(right) else right
      (if(mode!="pairs" && scan(right)) keys(j) else None).map { k=>
        val (agg,lo,hi)=bounds(right,k.r,k.y)
        j.copy(right=agg,condition=Some(And(EqualTo(k.l,k.r),Or(Not(EqualTo(k.x,lo)),Not(EqualTo(k.x,hi))))))
      }.getOrElse(j.copy(right=changed))
    }
  }
}
