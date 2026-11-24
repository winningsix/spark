package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.{DecimalType, IntegralType, StringType}

class KeyedCompactSumExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectOptimizerRule { session =>
    val ex=session.experimental
    ex.synchronized {
      if (!ex.extraOptimizations.contains(KeyedCompactSum)) ex.extraOptimizations = ex.extraOptimizations :+ KeyedCompactSum
    }
    new Rule[LogicalPlan] { override def apply(p:LogicalPlan):LogicalPlan=p }
  }
}

private[adaptive] object KeyedCompactSum extends Rule[LogicalPlan] {
  val setting = "spark.sql.optimizer.groupCompactSumBeforeWideDimension"

  private def throughProjection(p: LogicalPlan): LogicalPlan = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => child
    case other => other
  }

  private def fileInput(p: LogicalPlan): Boolean = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => fileInput(child)
    case Filter(cond, child) if cond.deterministic => fileInput(child)
    case l: LogicalRelation => !l.isStreaming && l.relation.isInstanceOf[HadoopFsRelation]
    case _ => false
  }

  private def keys(eq: EqualTo, left: LogicalPlan, right: LogicalPlan): Option[(Attribute, Attribute)] =
    Seq(eq.left -> eq.right, eq.right -> eq.left).collectFirst {
      case (a: Attribute, b: Attribute) if left.outputSet.contains(a) && right.outputSet.contains(b) => a -> b
    }

  private def compact(e:Expression):Boolean=e.dataType match {
    case d:DecimalType=>d.precision<=18
    case _=>false
  }

  private def safeInput(e:Expression):Boolean=e match {
    case a:Attribute=>compact(a)
    case x:Subtract if compact(x)=> x.left.isInstanceOf[Attribute] && x.right.isInstanceOf[Attribute] &&
      compact(x.left) && compact(x.right)
    case _=>false
  }

  // Spark's legacy long addition wraps. Integer addition modulo 2^64 is associative,
  // including on overflow. Keep MakeDecimal outside both sums for the original final check.
  private def integralSum(e:AggregateExpression,facts:LogicalPlan):Boolean=e.aggregateFunction match {
    case s:Sum if e.mode==Complete && !e.isDistinct && e.filter.isEmpty && s==Sum(s.child) =>
      s.child match {
        case UnscaledValue(inner)=>safeInput(inner) && inner.references.subsetOf(facts.outputSet)
        case _=>false
      }
    case _=>false
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
    metrics = a.aggregateExpressions.collect { case n @ Alias(m:MakeDecimal,_) if
        m.child.isInstanceOf[AggregateExpression] => n -> m.child.asInstanceOf[AggregateExpression] }
    if metrics.nonEmpty && metrics.forall {case (_,e)=>integralSum(e,fact)}
    if a.aggregateExpressions.forall {
      case n if metrics.exists(_._1.exprId==n.exprId)=>true
      case n=>n.deterministic && n.references.subsetOf(dim.outputSet ++ calendar.outputSet) &&
        !n.exists(_.isInstanceOf[AggregateExpression])
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
      case n @ Alias(m:MakeDecimal,_) if byOutput.contains(n.exprId) =>
        val old=m.child.asInstanceOf[AggregateExpression]
        val sum=old.aggregateFunction.asInstanceOf[Sum].copy(child=byOutput(n.exprId))
        n.withNewChildren(Seq(m.copy(child=old.copy(aggregateFunction=sum)))).asInstanceOf[NamedExpression]
      case n => n
    }
    a.copy(aggregateExpressions = outputs, child = Join(dim, partial, Inner, Some(dimEq), JoinHint.NONE))
  }

  override def apply(p: LogicalPlan): LogicalPlan =
    if (p.isStreaming || conf.ansiEnabled || !conf.getConfString(setting, "false").toBoolean) p
    else p.transformUp { case a: Aggregate => rewrite(a).getOrElse(a) }
}
