package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Complete, Count, Sum}
import org.apache.spark.sql.catalyst.plans.LeftOuter
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation

/** A grouped count on the nullable side needs the matched keys and their multiplicity. */
object NarrowOuterCount extends Rule[LogicalPlan] {
  private def scan(p: LogicalPlan): Boolean = p match {
    case Project(cols, child) => cols.forall(_.isInstanceOf[Attribute]) && scan(child)
    case Filter(cond, child) => cond.deterministic && scan(child)
    case _: LogicalRelation => true
    case _ => false
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val mode = conf.getConfString("spark.sql.optimizer.outerJoinCount.mode", "off")
    if (mode != "narrow" && mode != "grouped" || plan.isStreaming) return plan
    plan.transformUp {
      case agg @ Aggregate(Seq(group: Attribute), result, Project(cols,
          j @ Join(l, r, LeftOuter, Some(EqualTo(a: Attribute, b: Attribute)), _)), _)
          if l.outputSet.contains(group) && cols.forall(_.isInstanceOf[Attribute]) && scan(r) =>
        val keys = Seq((a, b), (b, a)).find { case (lk, rk) =>
          lk.semanticEquals(group) && r.outputSet.contains(rk)
        }
        val counts = result.collect {
          case alias @ Alias(ae @ AggregateExpression(Count(Seq(x: Attribute)),
                  Complete, false, None, _), _) if r.outputSet.contains(x) => (alias, ae, x)
        }
        (keys, counts) match {
          case (Some((_, key)), Seq((alias, ae, payload))) if !payload.semanticEquals(key) &&
              result.forall(c => c.semanticEquals(group) || c.exprId == alias.exprId) =>
            val validKeys = Project(Seq(key), Filter(IsNotNull(payload), r))
            val compress = mode == "grouped" && !conf.ansiEnabled
            val count = Alias(Count(Seq(Literal(1))).toAggregateExpression(), "matching_rows")()
            val input = if (compress) Aggregate(Seq(key), Seq(key, count), validKeys) else validKeys
            val join = j.copy(right = input)
            val needed = if (compress) count.toAttribute else key
            val nullable = join.output.find(_.exprId == needed.exprId).get
            val expr = if (compress) {
              Coalesce(Seq(Sum(nullable).toAggregateExpression(), Literal(0L)))
            } else ae.copy(aggregateFunction = Count(Seq(nullable)))
            val rewritten = result.map {
              case c: Alias if c.exprId == alias.exprId => c.withNewChildren(Seq(expr)).asInstanceOf[NamedExpression]
              case c => c
            }
            agg.copy(aggregateExpressions = rewritten, child = Project(Seq(group, nullable), join))
          case _ => agg
        }
    }
  }
}
