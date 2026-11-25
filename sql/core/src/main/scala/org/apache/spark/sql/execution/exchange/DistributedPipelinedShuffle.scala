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

import java.util.concurrent.ConcurrentHashMap

import scala.concurrent.duration.Duration

import org.apache.spark.rdd.RDD
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions.{Attribute, SortOrder}
import org.apache.spark.sql.catalyst.plans.physical.Partitioning
import org.apache.spark.sql.execution._
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.util.ThreadUtils

/** Materialize the regular inputs only when the file writer actually requests its input RDD. */
private[sql] case class MaterializeShuffleInputsExec(child: SparkPlan) extends UnaryExecNode {
  override def output: Seq[Attribute] = child.output
  override def outputOrdering: Seq[SortOrder] = child.outputOrdering
  override def outputPartitioning: Partitioning = child.outputPartitioning

  override protected def doExecute(): RDD[InternalRow] = {
    DistributedPipelinedShuffle.materializeInputs(child)
    child.execute()
  }

  override protected def withNewChildInternal(newChild: SparkPlan): MaterializeShuffleInputsExec =
    copy(child = newChild)
}

/** Execute the plan chosen by the physical rule and release the job's initialized shuffles. */
private[sql] object DistributedPipelinedShuffle {
  private val active = new ConcurrentHashMap[Long, List[SparkPlan]]()

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
    SQLExecution.updatePhysicalPlan(id.toLong, qe.withExecutedPlan(selected))
    materializeInputs(selected)
    selected
  }

  def materializeInputs(plan: SparkPlan): Unit = {
    val id = plan.session.sparkContext.getLocalProperty(SQLExecution.EXECUTION_ID_KEY)
    if (id != null) {
      active.merge(id.toLong, List(plan), (previous, added) => added ::: previous)
    }
    def prepare(node: SparkPlan): Unit = node match {
      case s: ShuffleExchangeExec if !s.pipelined =>
        ThreadUtils.awaitResult(s.submitShuffleJob(), Duration.Inf)
      case b: BroadcastExchangeExec => b.executeBroadcast[Any]()
      case other => other.children.foreach(prepare)
    }
    prepare(plan)
  }

  def cleanup(id: Long): Unit = Option(active.remove(id)).iterator.flatten.foreach { plan =>
    plan.session.sparkContext.cleaner.foreach { cleaner =>
      plan.foreach {
        case s: ShuffleExchangeExec =>
          s.initializedShuffleId.foreach(cleaner.doCleanupShuffle(_, blocking = true))
        case _ =>
      }
    }
  }
}
