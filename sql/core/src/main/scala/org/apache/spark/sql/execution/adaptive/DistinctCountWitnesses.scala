package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Count}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule

/** Factorized grouped counts can emit a membership key once per qualifying group pair. */
private[adaptive] object DistinctCountWitnesses extends Rule[LogicalPlan] with PredicateHelper {
  private def hasHiddenGroups(input: LogicalPlan, key: Attribute): Boolean = input match {
    case a: Aggregate =>
      a.groupingExpressions.size > 1 && a.output.size == 2 && a.outputSet.contains(key) &&
        a.groupingExpressions.exists(_.semanticEquals(key)) && a.aggregateExpressions.exists {
          case Alias(e: AggregateExpression, _) => e.aggregateFunction.isInstanceOf[Count]
          case _ => false
        }
    case _ => false
  }

  private def repeatsKey(input: LogicalPlan): Boolean = input match {
    case p: Project => repeatsKey(p.child)
    case f: Filter => repeatsKey(f.child)
    case Join(left, right, Inner, Some(condition), _) =>
      splitConjunctivePredicates(condition).exists {
        case EqualTo(a: Attribute, b: Attribute) =>
          (hasHiddenGroups(left, a) && hasHiddenGroups(right, b)) ||
            (hasHiddenGroups(left, b) && hasHiddenGroups(right, a))
        case _ => false
      }
    case _ => false
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    plan.transformUp {
    case s @ Join(_, right, LeftSemi, _, _) if right.output.size == 1 &&
        s.condition.forall(_.deterministic) && right.deterministic && !right.isStreaming && repeatsKey(right) =>
      val keys = Aggregate(right.output, right.output, right)
      val build = if (conf.adaptiveExecutionEnabled && conf.exchangeReuseEnabled &&
          (keys.output.head.dataType == org.apache.spark.sql.types.IntegerType ||
            keys.output.head.dataType == org.apache.spark.sql.types.LongType)) {
        RebalancePartitions(keys.output, keys, Some(conf.numShufflePartitions))
      } else keys
      s.copy(right = build)
    }
  }
}
