package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.types.StringType

class FilterWidePayloadExtension extends SparkSessionExtensionsProvider {
  override def apply(extensions: SparkSessionExtensions): Unit =
    extensions.injectPreCBORule(_ => FilterWidePayload)
}

private[adaptive] object FilterWidePayload extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.filterWidePayloadBeforeShuffle"

  private def scan(plan: LogicalPlan): Boolean = plan match {
    case _: LogicalRelation => true
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => scan(child)
    case Filter(condition, child) if condition.deterministic => scan(child)
    case _ => false
  }

  private def literalFilter(plan: LogicalPlan): Boolean = plan.exists {
    case Filter(condition, _) => splitConjunctivePredicates(condition).exists {
      case EqualTo(_: Attribute, Literal(value, _)) if value != null => true
      case EqualTo(Literal(value, _), _: Attribute) if value != null => true
      case _ => false
    }
    case _ => false
  }

  private def connects(eq: EqualTo, left: LogicalPlan, right: LogicalPlan): Boolean =
    (eq.left, eq.right) match {
      case (a: Attribute, b: Attribute) =>
        (left.outputSet.contains(a) && right.outputSet.contains(b)) ||
          (left.outputSet.contains(b) && right.outputSet.contains(a))
      case _ => false
    }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || !conf.getConfString(setting, "false").toBoolean) return plan
    plan.transformUp {
      case outer @ Join(Project(cols, Join(grouped, wide, Inner, Some(key: EqualTo), JoinHint.NONE)),
          lookup, Inner, Some(foreignKey: EqualTo), JoinHint.NONE)
          if cols.forall(_.isInstanceOf[Attribute]) && scan(wide) && scan(lookup) &&
            lookup.output.size == 1 && literalFilter(lookup) &&
            wide.output.count(_.dataType == StringType) >= 2 &&
            grouped.exists(_.isInstanceOf[Aggregate]) &&
            connects(key, grouped, wide) && connects(foreignKey, wide, lookup) =>
        val filtered = Join(wide, lookup, Inner, Some(foreignKey), JoinHint.NONE)
        Project(outer.output, Join(grouped, filtered, Inner, Some(key), JoinHint.NONE))
    }
  }
}
