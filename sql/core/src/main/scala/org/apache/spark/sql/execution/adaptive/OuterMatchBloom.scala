package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.{LeftOuter, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation

class OuterMatchBloomExtension extends SparkSessionExtensionsProvider {
  override def apply(extensions: SparkSessionExtensions): Unit =
    extensions.injectOptimizerRule { session =>
      val methods = session.experimental
      methods.synchronized {
        if (!methods.extraOptimizations.contains(OuterMatchBloom)) {
          methods.extraOptimizations = methods.extraOptimizations :+ OuterMatchBloom
        }
      }
      new Rule[LogicalPlan] { override def apply(plan: LogicalPlan): LogicalPlan = plan }
    }
}

/** Rows on the nullable input can match only keys that survived the preserved input's filter. */
private[adaptive] object OuterMatchBloom extends Rule[LogicalPlan] with PredicateHelper {
  private def scan(plan: LogicalPlan): Boolean = plan match {
    case p: Project if p.projectList.forall(_.isInstanceOf[Attribute]) => scan(p.child)
    case Filter(c, child) if c.deterministic => scan(child)
    case r: LogicalRelation => !r.isStreaming
    case _ => false
  }

  private def tests(plan: LogicalPlan): Seq[Expression] = plan match {
    case p: Project => tests(p.child)
    case Filter(c, child) => splitConjunctivePredicates(c) ++ tests(child)
    case _ => Nil
  }

  private def restrict(source: LogicalPlan, target: LogicalPlan, condition: Expression): LogicalPlan = {
    if (!scan(source) || !scan(target)) return target
    val filters = tests(source)
    val existing = tests(target)
    val derived = splitConjunctivePredicates(condition).flatMap {
      case EqualTo(a: Attribute, b: Attribute) if a.dataType == b.dataType &&
          (a.dataType == org.apache.spark.sql.types.IntegerType ||
           a.dataType == org.apache.spark.sql.types.LongType) =>
        val keys = Seq((a, b), (b, a)).find { case (l, r) =>
          source.outputSet.contains(l) && target.outputSet.contains(r)
        }
        keys.toSeq.flatMap { case (leftKey, rightKey) =>
          filters.collect {
            case BloomFilterMightContain(s: ScalarSubquery, XxHash64(Seq(k: Attribute), seed))
                if k.semanticEquals(leftKey) && !s.isCorrelated && s.plan.deterministic =>
              BloomFilterMightContain(s, XxHash64(Seq(rightKey), seed))
          }
        }
      case _ => Nil
    }
    val fresh = ExpressionSet(derived).filterNot(p => existing.exists(_.semanticEquals(p)))
    fresh.toSeq.reduceOption(And).map(Filter(_, target)).getOrElse(target)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.runtime.bloomFilter.reuseOnOuterMatch.enabled",
        "false").toBoolean || !conf.subqueryReuseEnabled || plan.isStreaming) return plan
    plan.transformUp {
      case j @ Join(l, r, LeftOuter, Some(c), _) if c.deterministic =>
        val right = restrict(l, r, c)
        if (right eq r) j else j.copy(right = right)
      case j @ Join(l, r, RightOuter, Some(c), _) if c.deterministic =>
        val left = restrict(r, l, c)
        if (left eq l) j else j.copy(left = left)
    }
  }
}
