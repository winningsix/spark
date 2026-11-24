package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.{Inner, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.DecimalType

/** Reuse an existing decimal group sum when the same fact rows are joined back on its group key. */
private[adaptive] object ReuseQualifiedSum extends Rule[LogicalPlan] with PredicateHelper {
  private case class Qualified(keys: Project, rows: Filter, key: Attribute,
      subtotal: Attribute, value: Attribute, sum: Sum, source: LogicalPlan)

  private def qualified(plan: LogicalPlan): Option[Qualified] = plan match {
    case p @ Project(Seq(k: Attribute), f @ Filter(cond, a: Aggregate))
        if a.groupingExpressions.size == 1 && a.groupingExpressions.head.semanticEquals(k) &&
          a.aggregateExpressions.size == 2 && cond.deterministic =>
      a.aggregateExpressions.collectFirst {
        case named @ Alias(AggregateExpression(s @ Sum(v: Attribute, _), Complete, false, None, _), _)
            if v.dataType.isInstanceOf[DecimalType] && splitConjunctivePredicates(cond).exists {
              case IsNotNull(x) => x.semanticEquals(named.toAttribute)
              case g: BinaryComparison if !g.isInstanceOf[EqualNullSafe] =>
                g.children.exists(_.semanticEquals(named.toAttribute))
              case _ => false
            } => Qualified(p, f, k, named.toAttribute, v, s, a.child)
      }
    case _ => None
  }

  // Only identical unmodified file columns qualify. Equality joins discard null keys on both sides.
  private def source(p: LogicalPlan, key: Attribute, value: Attribute):
      Option[(HadoopFsRelation, Int, Int)] = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) &&
        p.outputSet.contains(key) && p.outputSet.contains(value) => source(child, key, value)
    case Filter(IsNotNull(k), child) if k.semanticEquals(key) => source(child, key, value)
    case r: LogicalRelation if !r.isStreaming && r.relation.isInstanceOf[HadoopFsRelation] =>
      val ki = r.output.indexWhere(_.semanticEquals(key))
      val vi = r.output.indexWhere(_.semanticEquals(value))
      Option.when(ki >= 0 && vi >= 0)((r.relation.asInstanceOf[HadoopFsRelation], ki, vi))
    case _ => None
  }

  private def matches(eq: Expression, a: Attribute, b: Attribute): Boolean = eq match {
    case EqualTo(l, r) => (l.semanticEquals(a) && r.semanticEquals(b)) ||
      (r.semanticEquals(a) && l.semanticEquals(b))
    case _ => false
  }

  private def measureAtJoin(child: LogicalPlan, condition: Option[Expression]): LogicalPlan = {
    val key = condition.collect { case EqualTo(a: Attribute, b: Attribute) =>
      Seq(a, b).filter(child.outputSet.contains)
    }
    key match {
      case Some(Seq(k)) if conf.adaptiveExecutionEnabled =>
        QualifiedStageBuild.mark(RebalancePartitions(Seq(k), child, Some(conf.numShufflePartitions)))
      case _ => child
    }
  }

  // A semi join with this unique grouped build already selects precisely these dimension rows.
  private def carry(p: LogicalPlan, key: Attribute, q: Qualified): Option[LogicalPlan] = p match {
    case j @ Join(_, build, LeftSemi, Some(eq), _) if build.output.size == 1 &&
        matches(eq, key, build.output.head) && build.sameResult(q.keys) =>
      val build = if (conf.adaptiveExecutionEnabled) {
        val decimals = new org.apache.spark.sql.execution.FactorDecimalSums(
          org.apache.spark.sql.SparkSession.active)
        val agg = decimals.useBoundedLong(q.rows.child.asInstanceOf[Aggregate], q.value)
        val raw = RepartitionByExpression(Seq(q.key), agg.child, None)
        raw.setTagValue(org.apache.spark.sql.execution.exchange.EnablePipelinedShuffle.flexibleGroupedInput, true)
        val qualifiedRows = q.rows.copy(child = agg.copy(child = raw))
        QualifiedStageBuild.mark(RebalancePartitions(Seq(q.key), qualifiedRows, Some(conf.numShufflePartitions)))
      } else q.rows
      Some(Project(j.output :+ q.subtotal, j.copy(right = build, joinType = Inner,
        condition = Some(EqualTo(key, q.key)))))
    case p @ Project(cols, child) if cols.exists(_.semanticEquals(key)) =>
      carry(child, key, q).map(c => p.copy(projectList = cols :+ q.subtotal, child = c))
    case f: Filter if f.condition.deterministic => carry(f.child, key, q).map(c => f.copy(child = c))
    case j @ Join(l, r, Inner, _, _) if l.outputSet.contains(key) =>
      carry(l, key, q).map(c => j.copy(left = measureAtJoin(c, j.condition)))
    case j @ Join(l, r, Inner, _, _) if r.outputSet.contains(key) =>
      carry(r, key, q).map(c => j.copy(right = measureAtJoin(c, j.condition)))
    case _ => None
  }

  private def rewrite(a: Aggregate): Option[LogicalPlan] = {
    val base = a.child match {
      case Project(cols, j: Join) if cols.forall(_.isInstanceOf[Attribute]) => Some(j)
      case j: Join => Some(j)
      case _ => None
    }
    for {
      j <- base if j.joinType == Inner && j.hint == JoinHint.NONE
      pair <- Seq((j.left,j.right),(j.right,j.left)).collectFirst {
        case (dim, semi: Join) if semi.joinType == LeftSemi && semi.hint == JoinHint.NONE => (dim,semi)
      }
      (dim, semi) = pair
      q <- qualified(semi.right)
      factKey <- semi.left.output.find(k => semi.condition.exists(matches(_, k, q.key)))
      dimKey <- dim.output.find(k => j.condition.exists(matches(_, k, factKey)))
      if a.groupingExpressions.exists(_.semanticEquals(dimKey)) &&
        a.groupingExpressions.forall(e => e.deterministic && e.references.subsetOf(dim.outputSet))
      outputs = a.aggregateExpressions.collect {
        case named @ Alias(expr @ AggregateExpression(s @ Sum(v: Attribute, _), Complete, false, None, _), _) =>
          (named, expr, s, v)
      }
      if outputs.size == 1
      (named, expr, original, v) = outputs.head
      if a.aggregateExpressions.forall(n => n.eq(named) || (n.isInstanceOf[Attribute] &&
        dim.outputSet.contains(n.toAttribute))) && original.evalContext == q.sum.evalContext &&
        original.dataType == q.subtotal.dataType && v.dataType == q.value.dataType
      raw <- source(semi.left, factKey, v)
      grouped <- source(q.source, q.key, q.value) if raw == grouped && dim.deterministic
      enriched <- carry(dim, dimKey, q)
    } yield {
      // A group may contain duplicate dimension rows. Sum one subtotal per surviving row;
      // retain the outer SUM's original decimal scale, overflow mode, name and expression ID.
      val merged = expr.copy(aggregateFunction = original.copy(child = q.subtotal))
      val checked = CheckOverflowInSum(merged, original.dataType.asInstanceOf[DecimalType],
        original.evalContext.evalMode != EvalMode.ANSI, original.getContextOrNull())
      val replacement = named.withNewChildren(Seq(checked)).asInstanceOf[NamedExpression]
      a.copy(aggregateExpressions = a.aggregateExpressions.map(n => if (n.eq(named)) replacement else n),
        child = enriched)
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan.transformUp {
    case a: Aggregate if !a.isStreaming => rewrite(a).getOrElse(a)
  }
}
