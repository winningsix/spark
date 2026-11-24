package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Complete, Count}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule

class FactorGroupedJoinCountExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectOptimizerRule { session =>
      val experimental = session.experimental
      experimental.synchronized {
        if (!experimental.extraOptimizations.contains(FactorGroupedJoinCount)) {
          experimental.extraOptimizations = experimental.extraOptimizations :+ FactorGroupedJoinCount
        }
      }
      FactorGroupedJoinCount
    }
}

/** Factor the multiplicity of a grouped inner equijoin on the build side of a semi join. */
private[adaptive] object FactorGroupedJoinCount extends Rule[LogicalPlan] {
  private def underlying(e: NamedExpression): Expression = e match {
    case a: Alias => a.child
    case a => a
  }

  // Each side may evaluate its grouping key even when the opposite side has no match.
  private def safeGroup(e: Expression): Boolean = e match {
    case _: Attribute => true
    case Substring(_: Attribute, _: Literal, _: Literal) => true
    case _ => false
  }

  private def rewrite(build: LogicalPlan): Option[LogicalPlan] = build match {
    case p @ Project(Seq(selected: Attribute),
        filter @ Filter(GreaterThan(cnt: Attribute, _: Literal), agg: Aggregate)) =>
      val (join, fields) = agg.child match {
        case Project(cols, j: Join) => (j, cols)
        case j: Join => (j, j.output)
        case _ => return None
      }
      val (lk, rk) = join match {
        case Join(left, right, Inner, Some(EqualTo(a: Attribute, b: Attribute)), JoinHint.NONE)
            if left.outputSet.contains(a) && right.outputSet.contains(b) => (a, b)
        case Join(left, right, Inner, Some(EqualTo(b: Attribute, a: Attribute)), JoinHint.NONE)
            if left.outputSet.contains(a) && right.outputSet.contains(b) => (a, b)
        case _ => return None
      }
      val replacements = AttributeMap(fields.map(x => x.toAttribute -> underlying(x)))
      def expand(e: Expression): Expression = e.transformUp {
        case a: Attribute if replacements.contains(a) => replacements(a)
      }
      val groups = agg.groupingExpressions.map(expand)
      if (!groups.forall(safeGroup)) return None
      val leftGroups = groups.filter(_.references.subsetOf(join.left.outputSet))
      val rightGroups = groups.filter(_.references.subsetOf(join.right.outputSet))
      if (leftGroups.size + rightGroups.size != groups.size ||
          !leftGroups.exists(e => !e.semanticEquals(lk)) ||
          !rightGroups.exists(e => !e.semanticEquals(rk))) return None
      val key = agg.aggregateExpressions.find(_.exprId == selected.exprId)
      val count = agg.aggregateExpressions.find(_.exprId == cnt.exprId)
      if (agg.aggregateExpressions.size != 2 || key.isEmpty || count.isEmpty) return None
      val keyExpr = expand(underlying(key.get))
      if (!(keyExpr.semanticEquals(lk) || keyExpr.semanticEquals(rk)) ||
          !groups.exists(_.semanticEquals(keyExpr))) return None
      underlying(count.get) match {
        case AggregateExpression(Count(Seq(l: Literal)), Complete, false, None, _)
            if l.value != null =>
        case _ => return None
      }
      def grouped(child: LogicalPlan, joinKey: Attribute, exprs: Seq[Expression]) = {
        val sideCount = Alias(Count(Literal(1)).toAggregateExpression(), "group_count")()
        val groupKeys = joinKey +: exprs.filterNot(_.semanticEquals(joinKey))
        (Aggregate(groupKeys, Seq(joinKey, sideCount), child), sideCount.toAttribute)
      }
      val (left, leftCount) = grouped(join.left, lk, leftGroups)
      val (right, rightCount) = grouped(join.right, rk, rightGroups)
      // Preserve the count output identity for the original HAVING predicate.
      val jointCount = Alias(Multiply(leftCount, rightCount), cnt.name)(
        exprId = cnt.exprId, qualifier = cnt.qualifier)
      val resultKey = Alias(keyExpr, selected.name)(exprId = selected.exprId,
        qualifier = selected.qualifier, explicitMetadata = Some(selected.metadata))
      val project = Project(Seq(resultKey, jointCount), join.copy(left = left, right = right))
      Some(p.copy(child = filter.copy(child = project)))
    case _ => None
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || !conf.getConfString(
        "spark.sql.optimizer.factorGroupedJoinCount.enabled", "false").toBoolean) return plan
    plan.transformUp {
      case j @ Join(_, build, LeftSemi, Some(_: EqualTo), _) =>
        rewrite(build).map(r => j.copy(right = r)).getOrElse(j)
    }
  }
}
