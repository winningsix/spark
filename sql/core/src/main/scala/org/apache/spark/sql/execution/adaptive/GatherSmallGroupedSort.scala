/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions.{Alias, Attribute, NamedExpression, UnsafeRow}
import org.apache.spark.sql.catalyst.expressions.aggregate.{Average, Count, Final, Max, Min, Sum}
import org.apache.spark.sql.catalyst.plans.physical.{RangePartitioning, SinglePartition}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{SortExec, SparkPlan}
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.exchange.{ENSURE_REQUIREMENTS, ShuffleExchangeExec}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.DecimalType

/**
 * Once a grouped aggregate's partial shuffle is materialized, its record count bounds the
 * number of final groups. For a small terminal ORDER BY, gather the final groups directly.
 * This keeps the parallel final aggregation and sort comparator while avoiding the separate
 * range-sampling job over that same aggregate.
 */
object GatherSmallGroupedSort extends Rule[SparkPlan] {
  private def boundedOutput(expr: NamedExpression): Boolean = {
    val value = expr match {
      case a: Alias => a.child
      case other => other
    }
    // A projected string or array can expand a few input rows into an arbitrarily
    // large sort. Pass-through group/aggregate values already occur in the input.
    value.deterministic && (value.isInstanceOf[Attribute] || UnsafeRow.isFixedLength(value.dataType) ||
      value.dataType.isInstanceOf[DecimalType])
  }

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConfString("spark.sql.adaptive.gatherSmallGroupedSort.enabled", "false").toBoolean) {
      return plan
    }
    plan match {
      case sort @ SortExec(_, true, exchange: ShuffleExchangeExec, _)
          if exchange.shuffleOrigin == ENSURE_REQUIREMENTS && !exchange.pipelined =>
        (exchange.outputPartitioning, exchange.child) match {
          case (range: RangePartitioning, agg: BaseAggregateExec) if range.numPartitions > 1 &&
              agg.groupingExpressions.nonEmpty && agg.aggregateExpressions.nonEmpty &&
              agg.resultExpressions.forall(boundedOutput) &&
              agg.aggregateExpressions.forall(a => a.mode == Final && (a.aggregateFunction match {
                case _: Sum | _: Count | _: Min | _: Max | _: Average => true
                case _ => false
              })) =>
            agg.child match {
              case stage: ShuffleQueryStageExec if stage.isMaterialized =>
                val stats = stage.getRuntimeStatistics
                val budget = math.min(1000000L, range.numPartitions.toLong *
                  conf.getConf(SQLConf.RANGE_EXCHANGE_SAMPLE_SIZE_PER_PARTITION))
                if (stats.rowCount.exists(n => n > 0 && n <= budget) &&
                    stats.sizeInBytes > 0 &&
                    stats.sizeInBytes <= conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)) {
                  sort.copy(child = exchange.copy(outputPartitioning = SinglePartition))
                } else sort
              case _ => sort
            }
          case _ => sort
        }
      case _ => plan
    }
  }
}
