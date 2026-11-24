package org.apache.spark.sql.execution.adaptive

import org.apache.gluten.extension.columnar.DimensionStringGroupingIds

import org.apache.spark.sql.{SparkSession, SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.LeftOuter
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule

class RankedDimensionLookupExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectOptimizerRule { session =>
    val experimental = session.experimental
    experimental.synchronized {
      if (!experimental.extraOptimizations.exists(_.isInstanceOf[RankedDimensionLookup])) {
        experimental.extraOptimizations = new RankedDimensionLookup(session) +:
          experimental.extraOptimizations
      }
    }
    new Rule[LogicalPlan] { override def apply(plan: LogicalPlan): LogicalPlan = plan }
  }
}

/** Apply the window cutoff before decoding dimension strings unused by ranking. */
private[adaptive] class RankedDimensionLookup(session: SparkSession) extends Rule[LogicalPlan] {
  private val encode = DimensionStringGroupingIds(session)

  private def optimize(f: Filter, w: Window, limit: WindowGroupLimit, a: Aggregate,
      defer: Boolean): LogicalPlan = {
    val encoded = encode(a)
    if (encoded.fastEquals(a)) return f
    def ranked(child: LogicalPlan, window: Window, group: WindowGroupLimit, cond: Expression) =
      Filter(cond, window.copy(child = group.copy(child = child)))

    // Only cross restoring joins that this invocation of the encoder constructed above the
    // aggregate. Each restoring relation contains one row per injective dictionary ID.
    def push(plan: LogicalPlan, window: Window, group: WindowGroupLimit,
        cond: Expression): LogicalPlan = plan match {
      case p @ Project(cols, child) if cols.forall {
          case _: Attribute | Alias(_: Attribute, _) => true
          case _ => false
        } =>
        val aliases = AttributeMap(cols.map {
          case c @ Alias(source: Attribute, _) => c.toAttribute -> source
          case c => c.toAttribute -> c.toAttribute
        })
        def subst(e: Expression): Expression = e.transform {
          case v: Attribute if aliases.contains(v) => aliases(v)
        }
        val newWindow = window.mapExpressions(subst).asInstanceOf[Window]
        val newGroup = group.mapExpressions(subst).asInstanceOf[WindowGroupLimit]
        Project(cols ++ window.windowExpressions.map(_.toAttribute),
          push(child, newWindow, newGroup, subst(cond)))
      case j @ Join(left, _, LeftOuter, Some(_: EqualTo), _) if
          (window.references ++ group.references ++
            (cond.references -- AttributeSet(window.windowExpressions.map(_.toAttribute))))
            .subsetOf(left.outputSet) =>
        j.copy(left = push(left, window, group, cond))
      case _ => ranked(plan, window, group, cond)
    }

    val next = if (defer) push(encoded, w, limit, f.condition)
      else ranked(encoded, w, limit, f.condition)
    Project(f.output, next)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val mode = conf.getConfString("spark.sql.optimizer.rankedDimensionLookup", "off")
    if (plan.isStreaming || !(mode == "early" || mode == "late")) return plan
    plan.transformUp {
      case f @ Filter(cond, w: Window) if cond.deterministic =>
        w.child match {
          case g: WindowGroupLimit if w.windowExpressions.size == 1 &&
              w.partitionSpec.nonEmpty && w.deterministic =>
            g.child match {
              case a: Aggregate if a.child.isInstanceOf[Expand] => optimize(f, w, g, a, mode == "late")
              case _ => f
            }
          case _ => f
        }
    }
  }
}
