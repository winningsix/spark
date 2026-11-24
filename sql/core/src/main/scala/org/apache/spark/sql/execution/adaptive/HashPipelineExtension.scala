package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.expressions.Alias
import org.apache.spark.sql.execution.{ProjectExec, SparkPlan}
import org.apache.spark.sql.execution.exchange.{BroadcastExchangeExec, EnablePipelinedShuffle, Exchange, ReusedExchangeExec}
import org.apache.spark.sql.internal.SQLConf

/** Place after the application's query-stage rewrites, before AQE creates shuffle stages. */
class HashPipelineExtension extends SparkSessionExtensionsProvider {
  override def apply(extensions: SparkSessionExtensions): Unit = {
    extensions.injectPostHocResolutionRule(_ => CommonGroupThreshold)
    extensions.injectOptimizerRule { session =>
      val experimental = session.experimental
      val rules = Seq(DistinctCountWitnesses, ShareRestrictedGroupSum, ProjectInvariantSum, CompactGroupingKeys, ReuseQualifiedSum)
      experimental.synchronized {
        val previous = experimental.extraOptimizations
        experimental.extraOptimizations = previous ++ rules.filterNot(previous.contains)
      }
      DistinctCountWitnesses
    }
    extensions.injectPlannerStrategy(_ => FuseWitnesses)
    extensions.injectQueryPostPlannerStrategyRule(_ => AlignJoinedRunningSums)
    extensions.injectQueryPostPlannerStrategyRule(_ => PreferPipelineHashJoins)
    extensions.injectQueryStagePrepRule(_ => HashPipelinePlanning)
  }
}

// Reuse turns the shared exchange into a leaf. Choose its join algorithm while
// the shared subtree is still visible to ordinary physical-plan transformations.
private[adaptive] object PreferPipelineHashJoins extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    val mergeHint = plan.exists(_.logicalLink.exists {
      case j: org.apache.spark.sql.catalyst.plans.logical.Join =>
        val merge = org.apache.spark.sql.catalyst.plans.logical.SHUFFLE_MERGE
        Seq(j.hint.leftHint, j.hint.rightHint).flatten.exists(_.strategy.contains(merge))
      case _ => false
    })
    if (mergeHint || plan.exists(_.logicalLink.exists(_.isStreaming))) plan
    else BroadcastRowInputs(PipelinedHashJoinConversion(plan))
  }
}

private[adaptive] object HashPipelinePlanning extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    BroadcastRowInputs(EnablePipelinedShuffle.restoreMaterializedWidths(EnablePipelinedShuffle.planHashPipelines(plan)))
  }
}

private[adaptive] object BroadcastRowInputs extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    val visited = new java.util.IdentityHashMap[SparkPlan, SparkPlan]()
    def rewrite(node: SparkPlan): SparkPlan = {
      val cached = visited.get(node)
      if (cached != null) return cached
      val prepared = node match {
        case reuse @ ReusedExchangeExec(_, owner) =>
          val next = rewrite(owner).asInstanceOf[Exchange]
          if (next eq owner) reuse else {
            val updated = reuse.copy(child = next)
            updated.copyTagsFrom(reuse)
            updated
          }
        case other => other.mapChildren(rewrite)
      }
      val result = prepared match {
        // A broadcast exchange collects rows. Requirements can add another one
        // if the required mode changes (including a key's bound nullability).
        // The outer mode belongs to the join and must be built from the original rows.
        case outer @ BroadcastExchangeExec(mode, stage: BroadcastQueryStageExec) =>
        val inner = stage.plan match {
          case b: BroadcastExchangeExec => Some(b)
          case ReusedExchangeExec(_, b: BroadcastExchangeExec) => Some(b)
          case _ => None
        }
        inner match {
          case Some(b) if mode.canonicalized == b.mode.canonicalized => stage
          // AQE can keep its current valid plan. An incompatible published relation
          // cannot supply rows to a second broadcast or replay consumed pipelined input.
          case Some(_) => throw InvalidAQEPlanException(
            "Cannot collect an already planned broadcast with a different broadcast mode", outer)
          case _ => outer
        }
      case outer @ BroadcastExchangeExec(_, inner: BroadcastExchangeExec) =>
          outer.withNewChildren(Seq(inner.child))
        case outer @ BroadcastExchangeExec(_, ReusedExchangeExec(output, inner: BroadcastExchangeExec))
            if output.size == inner.child.output.size &&
              output.zip(inner.child.output).forall { case (a, b) => a.dataType == b.dataType } =>
          val aliases = output.zip(inner.child.output).map { case (expected, source) =>
            Alias(source, expected.name)(exprId = expected.exprId, qualifier = expected.qualifier,
              explicitMetadata = Some(expected.metadata))
          }
          outer.withNewChildren(Seq(ProjectExec(aliases, inner.child)))
        case other => other
      }
      visited.put(node, result)
      result
    }
    rewrite(plan)
  }
}
