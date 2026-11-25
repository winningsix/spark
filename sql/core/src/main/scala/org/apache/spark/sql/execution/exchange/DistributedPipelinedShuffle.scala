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

import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.{SparkPlan, SQLExecution}
import org.apache.spark.sql.internal.SQLConf

/** Execute a job-owned copy of the planned shuffle and release its initialized dependencies. */
private[sql] object DistributedPipelinedShuffle {
  val ownsShuffles = TreeNodeTag[Unit]("ownsDistributedPipelinedShuffles")

  def resultPlan(plan: SparkPlan, iterator: Boolean = false): SparkPlan = {
    val template = plan.getTagValue(SelectBatchPipelinedShuffle.fullResult) match {
      case Some(result) if !iterator || result.supportsIterator => result.plan
      case _ => return plan
    }
    // The session can opt out between actions on an already prepared Dataset.
    val conf = plan.conf
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) ||
        conf.adaptiveExecutionEnabled || conf.localPipelinedShuffleEnabled) return plan
    val id = plan.session.sparkContext.getLocalProperty(SQLExecution.EXECUTION_ID_KEY)
    if (id == null) return plan
    val qe = SQLExecution.getQueryExecution(id.toLong)
    // A prefix or broadcast job can run under the outer execution ID.
    if (qe == null || !(qe.executedPlan eq plan)) return plan
    val selected = template.clone()
    selected.setTagValue(ownsShuffles, ())
    SQLExecution.updatePhysicalPlan(id.toLong, qe.withExecutedPlan(selected))
    selected
  }

  def cleanup(plan: SparkPlan): Unit = {
    plan.session.sparkContext.cleaner.foreach { cleaner =>
      plan.foreach {
        case s: ShuffleExchangeExec =>
          s.initializedShuffleId.foreach(cleaner.doCleanupShuffle(_, blocking = true))
        case _ =>
      }
    }
  }
}
