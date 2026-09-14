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
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.internal.SQLConf

/**
 * Shared environment gate for the two pipelined-shuffle enabling rules
 * ([[EnablePipelinedShuffle]] non-AQE and `AQEEnablePipelinedShuffle` under AQE). This is a
 * CORRECTNESS gate, not cosmetics: flipping an exchange to pipelined while the incremental manager
 * is incompatible with the deployment would hang readers waiting on producers they cannot reach.
 * Both rules must apply the identical gate, so it lives here rather than being copy-pasted into
 * each `apply` (where the two could drift and split AQE vs non-AQE behavior). Each rule keeps only
 * its own plan-shape logic.
 */
private[sql] object PipelinedShuffleEligibility extends Logging {

  // The flag/manager mismatch is a start-up misconfiguration, so warn once per JVM rather than on
  // every query planned in the session.
  private val mismatchWarned = new AtomicBoolean(false)

  /**
   * Whether the configured pipelined transport may be used for `plan` at all, independent of plan
   * shape. The manager declares whether it requires a single executor; distributed transports can
   * therefore run in cluster mode without weakening the in-process channel's safety check.
   */
  def enabled(plan: SparkPlan, conf: SQLConf): Boolean = {
    if (!conf.localPipelinedShuffleEnabled) {
      return false
    }
    val manager = SparkEnv.get.pipelinedShuffleManager
    if (manager == null) {
      logDebug("Pipelined shuffle is enabled but no incremental shuffle manager is configured; " +
        "leaving the plan regular.")
      return false
    }
    // Batch only. `IncrementalExecution.preparations` inherits QueryExecution's list, so without
    // this gate a streaming plan would be rewritten here: every micro-batch exchange (the
    // state-store shuffles, the static side of a stream-static join) would be flipped to pipelined
    // BEFORE `MarkPipelinedShuffleForRealTimeMode` runs. That contradicts what the Real-Time Mode
    // rule deliberately does -- it leaves the static side regular, because pulling it into the gang
    // would demand slots for stages that must instead finish first, failing admission. Streaming
    // marks its own pipelined boundaries; this opt-in batch path must not pre-empt that decision.
    // (`logicalLink.exists(_.isStreaming)` is the same signal InsertAdaptiveSparkPlan uses to keep
    // AQE off streaming plans.)
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
