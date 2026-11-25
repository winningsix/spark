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

import scala.concurrent.duration.Duration

import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.command.DataWritingCommandExec
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.util.ThreadUtils

/** A job owns its cloned exchanges, including the ordinary inputs to the group. */
private[sql] class DistributedBatchShuffle(val plan: SparkPlan) {
  def materializeInputs(): Unit = {
    def prepare(node: SparkPlan): Unit = node match {
      case s: ShuffleExchangeExec if !s.pipelined =>
        ThreadUtils.awaitResult(s.submitShuffleJob(), Duration.Inf)
      case b: BroadcastExchangeExec => b.executeBroadcast[Any]()
      case other => other.children.foreach(prepare)
    }
    prepare(plan)
  }

  def cleanup(): Unit = {
    plan.session.sparkContext.cleaner.foreach { cleaner =>
      plan.foreach {
        case s: ShuffleExchangeExec =>
          s.initializedShuffleId.foreach(cleaner.doCleanupShuffle(_, blocking = true))
        case _ =>
      }
    }
  }
}

private[sql] object DistributedBatchShuffle {
  /**
   * Scope a one-shot shuffle to a synchronous physical job that consumes every partition.
   * Partial reads and RDDs handed to an unknown consumer keep their materialized exchanges.
   */
  def withFullInput[T](
      plan: SparkPlan,
      collectTopK: Boolean = false)(run: SparkPlan => T): T = {
    val conf = plan.conf
    if (plan.session == null || !conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) ||
        conf.adaptiveExecutionEnabled || conf.localPipelinedShuffleEnabled) {
      return run(plan)
    }
    val sc = plan.session.sparkContext
    val execution = Option(sc.getLocalProperty(SQLExecution.EXECUTION_ID_KEY))
      .map(_.toLong).flatMap(id => Option(SQLExecution.getQueryExecution(id)).map(id -> _))
    execution match {
      case Some((id, qe)) if qe.transactionOpt.isEmpty =>
        SelectBatchPipelinedShuffle.forFullInput(plan, collectTopK) match {
          case Some(selected) =>
            val group = new DistributedBatchShuffle(selected.clone())
            // Prefix and broadcast jobs may execute other physical plans under the same ID.
            // Only activate the root or the file writer's input in this execution.
            val reportedPlan = qe.executedPlan match {
              case p if p eq plan => group.plan
              case w: DataWritingCommandExec if w.child eq plan =>
                w.withNewChildren(Seq(group.plan))
              case _ => return run(plan)
            }
            try {
              SQLExecution.updatePhysicalPlan(id, qe.withExecutedPlan(reportedPlan))
              group.materializeInputs()
              run(group.plan)
            } finally {
              group.cleanup()
            }
          case None => run(plan)
        }
      case _ => run(plan)
    }
  }
}
