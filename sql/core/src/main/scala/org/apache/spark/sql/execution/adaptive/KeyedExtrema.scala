package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.{DecimalType, IntegralType, StringType}

class KeyedExtremaExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectPreCBORule(_ => KeyedExtrema)
}

private[adaptive] object KeyedExtrema extends Rule[LogicalPlan] {
  val setting = "spark.sql.optimizer.groupExtremaBeforeWideDimension"

  private def throughProjection(p: LogicalPlan): LogicalPlan = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => child
    case other => other
  }

  private def fileInput(p: LogicalPlan): Boolean = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => fileInput(child)
    case Filter(cond, child) if cond.deterministic && !SubqueryExpression.hasSubquery(cond) => fileInput(child)
    case l: LogicalRelation => !l.isStreaming && l.relation.isInstanceOf[HadoopFsRelation]
    case _ => false
  }

  private def keys(eq: EqualTo, left: LogicalPlan, right: LogicalPlan): Option[(Attribute, Attribute)] =
    Seq(eq.left -> eq.right, eq.right -> eq.left).collectFirst {
      case (a: Attribute, b: Attribute) if left.outputSet.contains(a) && right.outputSet.contains(b) => a -> b
    }

  private def exactExtremum(e: AggregateExpression, facts: LogicalPlan): Boolean = {
    val f = e.aggregateFunction
    val exact = f.dataType.isInstanceOf[IntegralType] || f.dataType.isInstanceOf[DecimalType]
    (f.isInstanceOf[Min] || f.isInstanceOf[Max]) && exact && e.mode == Complete &&
      !e.isDistinct && e.filter.isEmpty && f.children.head.isInstanceOf[Attribute] &&
      f.references.subsetOf(facts.outputSet)
  }

  private def rewrite(a: Aggregate): Option[LogicalPlan] = for {
    outer @ Join(inner, calendar, Inner, Some(dateEq: EqualTo), JoinHint.NONE) <-
      Some(throughProjection(a.child))
    if fileInput(calendar)
    Join(dim, fact, Inner, Some(dimEq: EqualTo), JoinHint.NONE) <- Some(throughProjection(inner))
    if fileInput(dim) && fileInput(fact)
    (_, fk) <- keys(dimEq, dim, fact)
    (_, _) <- keys(dateEq, fact, calendar)
    if a.groupingExpressions.nonEmpty && a.groupingExpressions.forall {
      case col: Attribute => dim.outputSet.contains(col) || calendar.outputSet.contains(col)
      case _ => false
    } && a.groupingExpressions.count(e => e.dataType == StringType && e.references.subsetOf(dim.outputSet)) >= 2
    metrics = a.aggregateExpressions.collect { case x @ Alias(e: AggregateExpression, _) => x -> e }
    if metrics.nonEmpty && metrics.forall { case (_, e) => exactExtremum(e, fact) }
    if a.aggregateExpressions.forall {
      case Alias(_: AggregateExpression, _) => true
      case n => n.deterministic && n.references.subsetOf(dim.outputSet ++ calendar.outputSet)
    }
  } yield {
    val filtered = outer.copy(left = fact)
    val partials = metrics.map { case (out, e) =>
      Alias(e.copy(resultId = NamedExpression.newExprId), "partial_" + out.name)()
    }
    val period = a.groupingExpressions.collect { case c: Attribute if calendar.outputSet.contains(c) => c }
    val keys = (fk +: period).distinct
    val partial = Aggregate(keys, keys ++ partials, filtered)
    val byOutput = metrics.map(_._1.exprId).zip(partials.map(_.toAttribute)).toMap
    val outputs = a.aggregateExpressions.map {
      case n @ Alias(e: AggregateExpression, _) =>
        val v = byOutput(n.exprId)
        val f = if (e.aggregateFunction.isInstanceOf[Min]) Min(v) else Max(v)
        n.withNewChildren(Seq(e.copy(aggregateFunction = f))).asInstanceOf[NamedExpression]
      case n => n
    }
    a.copy(aggregateExpressions = outputs, child = Join(dim, partial, Inner, Some(dimEq), JoinHint.NONE))
  }

  override def apply(p: LogicalPlan): LogicalPlan =
    if (p.isStreaming || !conf.getConfString(setting, "false").toBoolean) p
    else p.transformUp { case a: Aggregate => rewrite(a).getOrElse(a) }
}
