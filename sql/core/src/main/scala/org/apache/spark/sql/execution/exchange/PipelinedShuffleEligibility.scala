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

  def supportsMemoryRetainingConsumer: Boolean = {
    val manager = SparkEnv.get.pipelinedShuffleManager
    manager != null && manager.supportsMemoryRetainingConsumer
  }

  private def enabled(conf: SQLConf, isLocal: Boolean): Boolean = {
    if (!conf.localPipelinedShuffleEnabled) {
      return false
    }
    val manager = SparkEnv.get.pipelinedShuffleManager
    if (manager == null) {
      logDebug("Pipelined shuffle is enabled but no incremental shuffle manager is configured; " +
        "leaving the plan regular.")
      return false
    }
    if (manager.requiresSingleExecutor && !isLocal) {
      logDebug("The configured pipelined shuffle manager requires a single executor; leaving " +
        "the cluster-mode plan regular.")
      return false
    }
    true
  }

  /**
   * Whether the configured pipelined transport may be used for `plan` at all, independent of plan
   * shape. The manager declares whether it requires a single executor; distributed transports can
   * therefore run in cluster mode without weakening the in-process channel's safety check.
   */
  def enabled(plan: SparkPlan, conf: SQLConf): Boolean = {
    enabled(conf, plan.session != null && plan.session.sparkContext.isLocal)
  }

  /**
   * Whether a shuffle dependency created inside an operator's `doExecute` may use the pipelined
   * transport. Such a dependency is invisible to the physical-plan rules. Restrict this to the
   * prepared-receive transport: it can admit the hidden producer/consumer boundary elastically,
   * while the local channel still relies on conservative whole-plan shape checks.
   */
  def hiddenShuffleEnabled(conf: SQLConf, isLocal: Boolean): Boolean = {
    enabled(conf, isLocal) &&
      SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary
  }
}
