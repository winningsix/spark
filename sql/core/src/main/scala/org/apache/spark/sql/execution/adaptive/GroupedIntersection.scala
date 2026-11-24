package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, BitOrAgg}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{IntegerType, LongType}

class GroupedIntersectionExtension extends SparkSessionExtensionsProvider {
  override def apply(extensions: SparkSessionExtensions): Unit = {
    extensions.injectPostHocResolutionRule(_ => GroupedIntersection)
    extensions.injectOptimizerRule(_ => IntersectionKeyDomains)
  }
}

/** An integer tuple belongs to the DISTINCT intersection if every input contributes a row. */
private[adaptive] object GroupedIntersection extends Rule[LogicalPlan] {
  private def inputs(plan: LogicalPlan): Seq[LogicalPlan] = plan match {
    case i: Intersect if !i.isAll => inputs(i.left) ++ inputs(i.right)
    case other => Seq(other)
  }

  private def grouped(i: Intersect): LogicalPlan = {
    val arms = inputs(i)
    // Two-way intersections retain the existing join selection. Only group identical, narrow
    // key schemas so the ordinary set-operation coercion and output attributes are preserved.
    val keys = i.output
    if (arms.size < 3 || arms.size > 63 || keys.isEmpty ||
        !keys.forall(a => a.dataType == IntegerType || a.dataType == LongType) ||
        !arms.forall(_.output.map(k => (k.dataType, k.nullable)) ==
          keys.map(k => (k.dataType, k.nullable)))) return i

    val branches = arms.zipWithIndex.map { case (arm, index) =>
      Project(arm.output :+ Alias(Literal(1L << index), "intersection_source")(), arm)
    }
    val union = Union(branches)
    val grouping = union.output.dropRight(1)
    val membership = Alias(BitOrAgg(union.output.last).toAggregateExpression(), "intersection_sources")()
    val aggregate = Aggregate(grouping, grouping :+ membership, union)
    val allSources = -1L >>> (64 - arms.size)
    val matched = Filter(EqualTo(membership.toAttribute, Literal(allSources)), aggregate)
    Project(keys, matched)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.groupedIntersection.enabled", "false").toBoolean ||
        !plan.resolved || plan.isStreaming) return plan
    plan.resolveOperatorsDown {
      case i: Intersect if !i.isAll => grouped(i)
    }
  }
}

/** A set-membership aggregate observes presence. In a dimension-only branch the two inner
 * joins can be planned as an existence check on the filtered fact's distinct foreign keys.
 */
private[adaptive] object IntersectionKeyDomains extends Rule[LogicalPlan] {
  private def stable(plan: LogicalPlan): Boolean =
    !plan.exists(node => node.expressions.exists(e => !e.deterministic))

  private def rewrite(branch: LogicalPlan): LogicalPlan = branch match {
    case p @ Project(columns, Join(Project(mid, Join(fact, dimension, Inner,
        Some(item: EqualTo), innerHint)), dates, Inner, Some(date: EqualTo), outerHint))
        if innerHint == JoinHint.NONE && outerHint == JoinHint.NONE &&
          mid.forall(_.isInstanceOf[Attribute]) && stable(branch) &&
          p.references.nonEmpty && p.references.subsetOf(dimension.outputSet) =>
      def attributeOn(e: EqualTo, allowed: AttributeSet): Option[Attribute] =
        Seq(e.left, e.right).collectFirst { case a: Attribute if allowed.contains(a) => a }
      val keys = for {
        fk <- attributeOn(item, fact.outputSet)
        _ <- attributeOn(item, dimension.outputSet)
        _ <- attributeOn(date, fact.outputSet)
        _ <- attributeOn(date, dates.outputSet)
      } yield fk
      keys.map { fk =>
        val filtered = Join(fact, dates, LeftSemi, Some(date), JoinHint.NONE)
        val domain = Aggregate(Seq(fk), Seq(fk), filtered)
        Project(columns, Join(dimension, domain, LeftSemi, Some(item), JoinHint.NONE))
      }.getOrElse(branch)
    case _ => branch
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming ||
        !conf.getConfString("spark.sql.optimizer.intersectionKeyDomains.enabled", "false").toBoolean)
      return plan
    plan.transformUp {
      case a @ Aggregate(keys, outputs, u: Union, _) if keys == u.output.dropRight(1) &&
          outputs.dropRight(1) == keys && outputs.lastOption.exists {
            case Alias(e: AggregateExpression, _) => e.filter.isEmpty &&
              e.aggregateFunction.isInstanceOf[BitOrAgg] &&
              e.aggregateFunction.children == Seq(u.output.last)
            case _ => false
          } =>
        a.copy(child = u.copy(children = u.children.map(rewrite)))
    }
  }
}
