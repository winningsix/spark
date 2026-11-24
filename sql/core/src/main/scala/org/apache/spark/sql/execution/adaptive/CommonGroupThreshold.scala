package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression,Average}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule

class CommonGroupThresholdExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit=ext.injectPostHocResolutionRule(_=>CommonGroupThreshold)
}

/** Share grouped rows between a selective grouped consumer and its unfiltered scalar threshold. */
private[sql] object CommonGroupThreshold extends Rule[LogicalPlan] {
  private[sql] val sharedOutput = org.apache.spark.sql.catalyst.trees.TreeNodeTag[Boolean](
    "org.apache.spark.sql.sharedGroupedThresholdOutput")
  val setting="spark.sql.optimizer.shareGroupedThresholdCTE"

  private def bare(plan:LogicalPlan):LogicalPlan=plan match {
    case SubqueryAlias(_,c)=>bare(c)
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>bare(c)
    case _=>plan
  }

  private def keys(f:Filter,cte:CTERelationDef):Option[Seq[Attribute]]=for {
    outer<-Option(bare(f.child)).collect {case a:Aggregate=>a}
    if outer.groupingExpressions.nonEmpty && outer.groupingExpressions.forall(_.isInstanceOf[Attribute])
    keep<-Option(bare(outer.child)).collect {case f:Filter if f.condition.deterministic=>f}
    used<-Option(bare(keep.child)).collect {case r:CTERelationRef if r.cteId==cte.id=>r}
    if keep.condition.references.subsetOf(used.outputSet)
    queries=f.condition.collect {case s:ScalarSubquery=>s} if queries.size==1
    s=queries.head if !s.isCorrelated && s.hint.isEmpty
    threshold<-Option(bare(s.plan)).collect {case a:Aggregate if a.groupingExpressions.isEmpty=>a}
    if threshold.aggregateExpressions.exists(_.exists {
      case a:AggregateExpression=>a.aggregateFunction.isInstanceOf[Average] && !a.isDistinct && a.filter.isEmpty
      case _=>false
    })
    other<-Option(bare(threshold.child)).collect {case r:CTERelationRef if r.cteId==cte.id=>r}
    if used.output.size==cte.output.size && other.output.size==cte.output.size
    indices=outer.groupingExpressions.map(e=>used.output.indexWhere(_.semanticEquals(e))) if indices.forall(_>=0)
  } yield indices.map(cte.output)

  private def rewrite(w:WithCTE,mode:String):LogicalPlan={
    val defs=w.cteDefs.map { d=>
      val refs=w.plan.collectWithSubqueries {case r:CTERelationRef if r.cteId==d.id=>r}
      val grouped=bare(d.child) match {
        case a:Aggregate=>a.groupingExpressions.nonEmpty && a.child.exists(_.isInstanceOf[Join])
        case _=>false
      }
      if(refs.size!=2 || !grouped || !d.child.deterministic || d.materialized.nonEmpty ||
          d.underSubquery || d.hasSelfReferenceAsCTERef || d.forceSkipInline) d
      else w.plan.collect {case f:Filter=>keys(f,d)}.flatten.headOption.map { partition =>
        val child=if(mode=="keyed") {
          val output = RepartitionByExpression(partition,d.child,None)
          output.setTagValue(sharedOutput,true)
          output
        } else d.child
        // The keyed exchange is already the shared output, even if column pruning
        // later places a Project above it. Skip Spark's second round-robin exchange.
        d.copy(child=child,materialized=Some(true),underSubquery=(mode=="keyed"))
      }.getOrElse(d)
    }
    if(defs==w.cteDefs) w else w.copy(cteDefs=defs)
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"keyed")
    if(!p.resolved || p.isStreaming || !conf.exchangeReuseEnabled || !Set("shared","keyed").contains(mode)) p
    else p match {case w:WithCTE=>rewrite(w,mode);case _=>p}
  }
}
