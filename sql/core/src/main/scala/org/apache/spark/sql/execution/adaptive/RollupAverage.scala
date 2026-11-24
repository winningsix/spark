package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types._

class RollupAverageExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = {
    ext.injectOptimizerRule { session =>
      val options = session.experimental
      options.synchronized {
        if (!options.extraOptimizations.contains(RollupAverage)) {
          options.extraOptimizations = RollupAverage +: options.extraOptimizations
        }
      }
      new Rule[LogicalPlan] { override def apply(plan: LogicalPlan): LogicalPlan = plan }
    }
    ext.injectQueryStagePrepRule(_ => RouteRollupAverage)
  }
}

private[adaptive] object RollupAverage extends Rule[LogicalPlan] {
  val setting = "spark.sql.optimizer.preaggregateRollupAverage"
  val marker = "spark.rtm.preaggregateRollupAverage"
  private def rewrite(agg: Aggregate, expand: Expand, join: Join, fk: Attribute,
      measure: Attribute, original: AggregateExpression): Option[LogicalPlan] = {
    if (!join.left.outputSet.contains(fk) || !join.left.outputSet.contains(measure) ||
        !join.left.exists(_.isInstanceOf[Join]) || !join.deterministic) return None
    val index = expand.output.indexWhere(_.semanticEquals(measure))
    if (index < 0 || expand.projections.size < 2 ||
        !expand.projections.forall { row =>
          row(index).semanticEquals(measure) && row.zipWithIndex.forall {
            case (_, i) if i == index => true
            case (a: Attribute, _) => join.right.outputSet.contains(a)
            case (_: Literal, _) => true
            case _ => false
          }
        } || !agg.groupingExpressions.forall {
          case k: Attribute => !k.semanticEquals(measure) && expand.outputSet.contains(k)
          case _ => false
        }) return None
    val tag = new MetadataBuilder().putBoolean(marker, true).build()
    // Spark's integral AVG uses a double sum and a long count of non-null inputs.
    val sum = Alias(Sum(Cast(measure, DoubleType)).toAggregateExpression(), "rollup_item_sum")(
      explicitMetadata = Some(tag))
    val count = Alias(Count(Seq(measure)).toAggregateExpression(), "rollup_item_count")()
    val grouped = Aggregate(Seq(fk), Seq(fk, sum, count), join.left)
    val sumAttr = sum.toAttribute
    val countAttr = count.toAttribute
    val projections = expand.projections.map(_.patch(index, Seq(sumAttr, countAttr), 1))
    val rolled = expand.copy(projections = projections,
      output = expand.output.patch(index, Seq(sumAttr, countAttr), 1),
      child = join.copy(left = grouped))
    val total = Sum(sumAttr).toAggregateExpression()
    val number = Sum(countAttr).toAggregateExpression()
    val average = If(EqualTo(number, Literal(0L)), Literal.create(null, DoubleType),
      Divide(total, Cast(number, DoubleType)))
    val outputs = agg.aggregateExpressions.map(_.transform {
      case e: AggregateExpression if e == original => average
    }.asInstanceOf[NamedExpression])
    val result = agg.copy(aggregateExpressions = outputs, child = rolled)
    Option.when(result.resolved && result.missingInput.isEmpty)(result)
  }
  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || !Set("early","block","live").contains(conf.getConfString(setting, "off"))) return plan
    plan.transformUp {
      case agg @ Aggregate(_, outputs, expand @ Expand(_, _, Project(cols,
          join @ Join(left, right, Inner, Some(EqualTo(a: Attribute, b: Attribute)), _))), _)
          if cols.forall(_.isInstanceOf[Attribute]) =>
        val avgs = outputs.flatMap(_.collect { case e: AggregateExpression => e })
        val key = Seq((a,b),(b,a)).find { case (l,r) =>
          left.outputSet.contains(l) && right.outputSet.contains(r)
        }.map(_._1)
        (avgs,key) match {
          case (Seq(e @ AggregateExpression(Average(m: Attribute, _), Complete, false, None, _)),
              Some(k)) if Set[DataType](ByteType, ShortType, IntegerType, LongType).contains(m.dataType) &&
                outputs.forall {
                  case alias: Alias => alias.child == e
                  case a: Attribute => agg.groupingExpressions.exists(_.semanticEquals(a))
                  case _ => false
                } => rewrite(agg, expand, join, k, m, e).getOrElse(agg)
          case _ => agg
        }
    }
  }
}

private[adaptive] object RouteRollupAverage extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    val mode = conf.getConfString(RollupAverage.setting, "off")
    if (!Set("block","live").contains(mode) || !PipelinedShuffleEligibility.enabled(plan, conf)) return plan
    val all = plan.collectWithSubqueries { case e: ShuffleExchangeExec => e }
    if (all.exists(_.pipelined)) return plan
    val edges = plan.collect { case a: HashAggregateExec if
        a.resultExpressions.exists(_.metadata.contains(RollupAverage.marker)) => a.child
    }.collect { case e: ShuffleExchangeExec if e.shuffleOrigin == ENSURE_REQUIREMENTS &&
        e.outputPartitioning.isInstanceOf[HashPartitioning] => e }
    if (edges.size != 1 || all.count(_.canonicalized == edges.head.canonicalized) != 1) return plan
    val sc = plan.session.sparkContext
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val fraction = conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val reserved = sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow", 1)
    if (!sc.getConf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled", false) ||
        !sc.getConf.getBoolean("spark.shuffle.streaming.readyQuota.enabled", false)) return plan
    val budget = (if (fraction > 0) (fraction * slots).toInt else slots).min(slots - reserved)
    if (budget <= 0) return plan
    val edge = edges.head
    val p = edge.outputPartitioning.asInstanceOf[HashPartitioning]
    val width = p.numPartitions.min(budget)
    val replacement = edge.copy(outputPartitioning = p.copy(numPartitions = width),
      pipelined = mode == "live", shuffleOrigin = REPARTITION_BY_NUM)
    replacement.copyTagsFrom(edge)
    edge.logicalLink.foreach(replacement.setLogicalLink)
    val result = plan.transformUp { case e: ShuffleExchangeExec if e eq edge => replacement }
    if (ValidateRequirements.validate(result)) result else plan
  }
}
