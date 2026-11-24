package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.DecimalType

/** Evaluate an invariant decimal product once per input row of a grouping-sets expansion. */
private[adaptive] object ProjectInvariantSum extends Rule[LogicalPlan] {
  private def rewrite(a: Aggregate, expand: Expand): LogicalPlan = {
    val calls = a.aggregateExpressions.collect {
      case Alias(call @ AggregateExpression(s: Sum, Complete, false, None, _), _)
          if s.child.deterministic && s.child.dataType.isInstanceOf[DecimalType] &&
            s.child.exists(_.isInstanceOf[Multiply]) => (call, s)
    }
    if (calls.size != 1 || expand.projections.size < 2) return a
    val (call, sum) = calls.head
    val argument = sum.child
    val invariant = AttributeMap(expand.output.zipWithIndex.flatMap { case (out, index) =>
      expand.projections.head(index) match {
        case in: Attribute if expand.child.outputSet.contains(in) &&
            expand.projections.forall(_(index).semanticEquals(in)) => Some(out -> in)
        case _ => None
      }
    })
    if (argument.references.isEmpty || !argument.references.forall(invariant.contains)) return a
    val input = argument.transform { case v: Attribute => invariant(v) }
    val computed = Alias(input, "grouping_set_sum_input")()
    val output = computed.toAttribute.newInstance()
    val next = expand.copy(projections = expand.projections.map(_ :+ computed.toAttribute),
      output = expand.output :+ output, child = Project(expand.child.output :+ computed, expand.child))
    val results = a.aggregateExpressions.map { named =>
      named.transform { case expr: AggregateExpression if expr.eq(call) =>
        expr.copy(aggregateFunction = sum.copy(child = output))
      }.asInstanceOf[NamedExpression]
    }
    a.copy(aggregateExpressions = results, child = next)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan.transformUp {
    case a @ Aggregate(_, _, e: Expand, _) if !a.isStreaming => rewrite(a, e)
  }
}
