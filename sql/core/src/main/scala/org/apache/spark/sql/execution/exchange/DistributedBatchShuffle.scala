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

import org.apache.spark.SparkEnv
import org.apache.spark.internal.config
import org.apache.spark.shuffle.streaming.StreamingShuffleManager
import org.apache.spark.sql.catalyst.expressions.SortOrder
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter, RightOuter}
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.command.DataWritingCommandExec
import org.apache.spark.sql.execution.datasources.WriteFilesExec
import org.apache.spark.sql.execution.joins.{BroadcastHashJoinExec, ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.execution.window.WindowExec
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
  // These unary operators preserve the task-to-partition mapping and consuming all output drains
  // their inputs. In particular a local sort reads its entire input before yielding a row.
  private def boundary(plan: SparkPlan): SparkPlan = plan match {
    case _: ProjectExec | _: FilterExec | _: WholeStageCodegenExec | _: HashAggregateExec |
        _: WindowExec | _: SortExec | _: ExpandExec | _: InputAdapter | _: ColumnarToRowExec =>
      boundary(plan.children.head)
    case other => other
  }

  // Get the producer task count without executing the joins (which could start broadcast jobs).
  // Ordinary exchanges cut the stage. A shuffled join zips two equally partitioned RDDs.
  private def stageWidth(plan: SparkPlan): Option[Int] = boundary(plan) match {
    case s: ShuffleExchangeExec => Some(s.outputPartitioning.numPartitions)
    case r: RangeExec => Some(r.execute().getNumPartitions)
    case f: FileSourceScanExec => Some(f.inputRDD.getNumPartitions)
    case j: BroadcastHashJoinExec =>
      val (streamed, build) = if (j.buildSide == BuildLeft) (j.right, j.left) else (j.left, j.right)
      boundary(build) match {
        case _: BroadcastExchangeExec => stageWidth(streamed)
        case _ => None
      }
    case j @ (_: SortMergeJoinExec | _: ShuffledHashJoinExec) =>
      stageWidth(j.children.head).filter(n => stageWidth(j.children.last).contains(n))
    case _ => None
  }

  private def candidate(plan: SparkPlan): Option[ShuffleExchangeExec] = boundary(plan) match {
    case s: ShuffleExchangeExec
        if s.getTagValue(SelectBatchPipelinedShuffle.candidate).isDefined =>
      Some(s)
    case _ => None
  }

  private def sortedInput(plan: SparkPlan): Option[ShuffleExchangeExec] = plan match {
    case s: SortExec if !s.global => candidate(s.child)
    case _: WholeStageCodegenExec | _: InputAdapter => sortedInput(plan.children.head)
    case _ => None
  }

  private def probe(plan: SparkPlan): Option[ShuffleExchangeExec] = boundary(plan) match {
    case j: ShuffledHashJoinExec =>
      (j.joinType, j.buildSide) match {
        case (LeftOuter, BuildRight) if boundary(j.right).isInstanceOf[ShuffleExchangeExec] =>
          candidate(j.left)
        case (RightOuter, BuildLeft) if boundary(j.left).isInstanceOf[ShuffleExchangeExec] =>
          candidate(j.right)
        case _ => None
      }
    case j: SortMergeJoinExec if j.joinType == Inner && stageWidth(j.right).isDefined =>
      // Inner merge joins request the streamed (left) input even for an empty right
      // partition. Its local sort drains the reader before the join can stop early.
      sortedInput(j.left)
    case other => candidate(other)
  }

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
        forFullInput(plan, collectTopK) match {
          case Some(group) =>
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

  private[exchange] def forFullInput(
      plan: SparkPlan,
      collectTopK: Boolean): Option[DistributedBatchShuffle] = {
    val sc = plan.session.sparkContext
    if (sc.isLocal || sc.cleaner.isEmpty || sc.conf.get(config.SPECULATION_ENABLED) ||
        sc.conf.get(config.DYN_ALLOCATION_ENABLED) ||
        !sc.conf.get(config.PIPELINED_GROUP_SLOT_CHECK_ENABLED) ||
        !SparkEnv.get.pipelinedShuffleManager.isInstanceOf[StreamingShuffleManager] ||
        plan.exists(p => p.subqueries.nonEmpty || p.isInstanceOf[ReusedExchangeExec])) {
      return None
    }

    val selected = plan match {
      // Only the root uses TakeOrderedAndProjectExec.executeCollect. With ordered input it
      // takes at most K rows per partition, and nested Top-K can introduce another shuffle.
      case k: TakeOrderedAndProjectExec if collectTopK && k.limit > 0 &&
          !SortOrder.orderingSatisfies(k.child.outputOrdering, k.sortOrder) => probe(k.child)
      case w: WriteFilesExec => probe(w.child)
      case other => probe(other)
    }
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    selected.filter { exchange =>
      val readers = exchange.outputPartitioning.numPartitions
      stageWidth(exchange.child).exists(maps => maps > 0 && readers > 0 &&
        maps.toLong + readers <= slots)
    }.map { exchange =>
      // Only this edge belongs to the admitted group. Candidates inside regular prefix jobs
      // and on sibling inputs must remain ordinary shuffles.
      val rewritten = plan.transformUp {
        case s: ShuffleExchangeExec if s eq exchange => s.copy(pipelined = true)
      }
      new DistributedBatchShuffle(rewritten.clone())
    }
  }
}
