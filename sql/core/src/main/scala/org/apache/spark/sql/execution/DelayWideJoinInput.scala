package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.optimizer.JoinSelectionHelper
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.logical.statsEstimation.EstimationUtils
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{BinaryType,StringType}

/** Delay carrying variable-width payloads through a second repartitioning equi-join. */
object DelayWideJoinInput extends Rule[LogicalPlan] with JoinSelectionHelper with PredicateHelper {
  private def filters(p: LogicalPlan): Option[Seq[Expression]] = p match {
    case Project(xs, child) if xs.forall(_.isInstanceOf[Attribute]) => filters(child)
    case Filter(cond, child) if cond.deterministic && !SubqueryExpression.hasSubquery(cond) =>
      filters(child).map(_ ++ splitConjunctivePredicates(cond))
    case r: LogicalRelation if r.stats.sizeInBytes < conf.defaultSizeInBytes &&
        r.stats.sizeInBytes > conf.autoBroadcastJoinThreshold.max(0) => Some(Nil)
    case _ => None
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.delayWideJoinInput.enabled", "false").toBoolean ||
        plan.isStreaming || plan.isInstanceOf[Subquery]) return plan
    val estimate = conf.clone()
    estimate.setConf(SQLConf.HASH_JOIN_EQUI_JOIN_SIZE_ESTIMATE, true)
    def volume(p: LogicalPlan): BigInt =
      pipelinedPolicyRowEstimate(p, estimate) * EstimationUtils.getSizePerRow(p.output)
    plan.transformUp {
      case result @ Project(keep, Join(first @ Project(mid, Join(dim, bridge, Inner,
          Some(cond1 @ EqualTo(x: Attribute, y: Attribute)), JoinHint.NONE)), probe, Inner,
          Some(cond2 @ EqualTo(z: Attribute, w: Attribute)), JoinHint.NONE))
          if keep.forall(_.isInstanceOf[Attribute]) && mid.forall(_.isInstanceOf[Attribute]) =>
        val wanted=AttributeSet(keep.map(_.toAttribute))
        val wide = dim.output.exists(a => wanted.contains(a) && (a.dataType.isInstanceOf[StringType] ||
          a.dataType == BinaryType))
        val different = cond1.references.intersect(bridge.outputSet) !=
          cond2.references.intersect(bridge.outputSet)
        if (!wide || !different || cond1.references.intersect(dim.outputSet).isEmpty ||
            cond1.references.intersect(bridge.outputSet).isEmpty || cond2.references.intersect(bridge.outputSet).isEmpty ||
            cond2.references.intersect(probe.outputSet).isEmpty ||
            !filters(dim).exists(_.forall(_.isInstanceOf[IsNotNull])) ||
            !Seq(bridge,probe).forall(p => filters(p).exists(_.exists(e => !e.isInstanceOf[IsNotNull])))) result
        else {
          val paired=Join(bridge,probe,Inner,Some(cond2),JoinHint.NONE)
          val retained=wanted ++ cond1.references
          val compact=Project(paired.output.filter(retained.contains),paired)
          if (volume(compact) < volume(first))
            result.copy(child=Join(dim,compact,Inner,Some(cond1),JoinHint.NONE))
          else result
        }
    }
  }
}
