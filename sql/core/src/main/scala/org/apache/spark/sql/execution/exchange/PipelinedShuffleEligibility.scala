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

package org.apache.spark.sql.execution.exchange

import java.util.concurrent.atomic.AtomicBoolean

import org.apache.spark.SparkEnv
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config
import org.apache.spark.shuffle.local.pipelined.PipelinedChannelShuffleManager
import org.apache.spark.sql.execution.{CoalesceExec, CollectLimitExec, CollectTailExec, DeserializeToObjectExec, ExternalRDDScanExec, RDDScanExec, SparkPlan, TakeOrderedAndProjectExec}
import org.apache.spark.sql.execution.adaptive.QueryStageExec
import org.apache.spark.sql.execution.columnar.InMemoryTableScanExec
import org.apache.spark.sql.execution.joins.CartesianProductExec
import org.apache.spark.sql.internal.SQLConf

/** Shared deployment and consumer checks for batch pipelined-shuffle planning rules. */
private[sql] object PipelinedShuffleEligibility extends Logging {

  // The flag/manager mismatch is a start-up misconfiguration, so warn once per JVM rather than on
  // every query planned in the session.
  private val mismatchWarned = new AtomicBoolean(false)

  /** Limits require a transport that supports their hidden materialized shuffle boundary. */
  def isUnsupportedConsumer(
      plan: SparkPlan,
      supportsUnmaterializedRegularBoundary: Boolean = false): Boolean = plan match {
    case _: CoalesceExec | _: CartesianProductExec | _: DeserializeToObjectExec => true
    case _: CollectLimitExec | _: CollectTailExec | _: TakeOrderedAndProjectExec =>
      !supportsUnmaterializedRegularBoundary
    case _ => false
  }

  /**
   * Estimate the complete group's task demand without executing or materializing the plan.
   * Each exchange contributes its producer width; the root contributes the consumer width.
   * Unknown widths conservatively retain regular execution. The scheduler still checks actual
   * RDD widths and free slots at submission, including contention from other jobs.
   */
  def fitsLocalCapacity(plan: SparkPlan, candidates: Set[Int]): Boolean = {
    val exchanges = plan.collect {
      case s: ShuffleExchangeExec if s.pipelined || candidates.contains(s.id) => s
    }.groupBy(_.id).values.map(_.head).toSeq
    val widths = plan.outputPartitioning.numPartitions +:
      exchanges.map(_.child.outputPartitioning.numPartitions)
    val sc = plan.session.sparkContext
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val demand = widths.map(_.toLong).sum
    val fits = widths.forall(_ > 0) && demand <= slots
    if (!fits) {
      logDebug(s"Pipelined shuffle: estimated stage widths ${widths.mkString(",")} cannot " +
        s"fit $slots local task slots; retaining regular shuffles.")
    }
    fits
  }

  /**
   * Whether the configured pipelined transport may be used for `plan` at all, independent of plan
   * shape. The manager declares whether it requires a single executor; distributed transports can
   * therefore run in cluster mode without weakening the in-process channel's safety check.
   */
  def enabled(plan: SparkPlan, conf: SQLConf): Boolean = {
    val distributedEnabled = conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED)
    if (!conf.localPipelinedShuffleEnabled && !distributedEnabled) {
      return false
    }
    val manager = SparkEnv.get.pipelinedShuffleManager
    if (manager == null) {
      logDebug("Pipelined shuffle is enabled but no incremental shuffle manager is configured; " +
        "leaving the plan regular.")
      return false
    }
    if (manager.isInstanceOf[PipelinedChannelShuffleManager]) {
      if (!conf.localPipelinedShuffleEnabled || plan.session == null ||
          !plan.session.sparkContext.isLocal) {
        return false
      }
    } else if (!distributedEnabled || manager.requiresSingleExecutor) {
      if (conf.localPipelinedShuffleEnabled && mismatchWarned.compareAndSet(false, true)) {
        logWarning(s"${SQLConf.LOCAL_PIPELINED_SHUFFLE_ENABLED.key} requires the in-process " +
          s"channel manager in ${config.SHUFFLE_MANAGER_INCREMENTAL.key}. Distributed batch " +
          s"execution requires ${SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key}.")
      }
      return false
    }
    // RDD exports, scans, and cached inputs can introduce readers outside this SQL plan.
    def hasUnsupportedBoundary(p: SparkPlan): Boolean = p match {
      case _: DeserializeToObjectExec | _: InMemoryTableScanExec |
          _: RDDScanExec | _: ExternalRDDScanExec[_] => true
      case q: QueryStageExec => hasUnsupportedBoundary(q.plan)
      case other => other.children.exists(hasUnsupportedBoundary)
    }
    if (hasUnsupportedBoundary(plan)) return false
    // Streaming execution selects its own exchanges, including materialized static inputs.
    if (plan.exists(_.logicalLink.exists(_.isStreaming))) {
      logDebug("Pipelined shuffle: the plan is a streaming plan; leaving it to the streaming " +
        "engine's own pipelined-shuffle marking.")
      return false
    }
    if (manager.requiresSingleExecutor &&
        (plan.session == null || !plan.session.sparkContext.isLocal)) {
      logDebug("The configured pipelined shuffle manager requires a single executor; leaving " +
        "the cluster-mode plan regular.")
      return false
    }
    true
  }
}
