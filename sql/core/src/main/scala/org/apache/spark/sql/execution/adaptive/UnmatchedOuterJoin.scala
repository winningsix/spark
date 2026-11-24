package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.{LeftAnti, LeftOuter, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule

class UnmatchedOuterJoinExtension extends SparkSessionExtensionsProvider {
  override def apply(extensions: SparkSessionExtensions): Unit =
    extensions.injectOptimizerRule(_ => UnmatchedOuterJoin)
}

/** A matched row cannot have a null marker referenced by a mandatory ordinary equality. */
private[adaptive] object UnmatchedOuterJoin extends Rule[LogicalPlan] with PredicateHelper {
  private def rewrite(f: Filter, join: Join, kept: LogicalPlan, other: LogicalPlan,
      condition: Expression): LogicalPlan = {
    val markers = AttributeSet(splitConjunctivePredicates(condition).flatMap {
      case EqualTo(a: Attribute, b: Attribute) if kept.outputSet.contains(a) &&
          other.outputSet.contains(b) => Some(b)
      case EqualTo(a: Attribute, b: Attribute) if kept.outputSet.contains(b) &&
          other.outputSet.contains(a) => Some(a)
      case _ => None
    })
    val (matched, residual) = splitConjunctivePredicates(f.condition).partition {
      case IsNull(a: Attribute) => markers.contains(a)
      case _ => false
    }
    if (matched.isEmpty) return f
    val anti = Join(kept, other, LeftAnti, Some(condition), JoinHint.NONE)
    val columns = join.output.map { a =>
      if (other.outputSet.contains(a)) {
        Alias(Literal.create(null, a.dataType), a.name)(
          exprId = a.exprId, qualifier = a.qualifier, explicitMetadata = Some(a.metadata))
      } else a
    }
    val output = Project(columns, anti)
    residual.reduceOption(And).map(Filter(_, output)).getOrElse(output)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.unmatchedOuterAsAnti.enabled",
        "false").toBoolean || plan.isStreaming) return plan
    plan.transformUp {
      case f @ Filter(predicate, j @ Join(l, r, LeftOuter, Some(c), JoinHint.NONE))
          if predicate.deterministic && c.deterministic => rewrite(f, j, l, r, c)
      case f @ Filter(predicate, j @ Join(l, r, RightOuter, Some(c), JoinHint.NONE))
          if predicate.deterministic && c.deterministic => rewrite(f, j, r, l, c)
    }
  }
}
