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
import org.apache.spark.internal.config
import org.apache.spark.internal.LogKeys.{CONFIG, CONFIG2}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager
import org.apache.spark.sql.catalyst.expressions.SortOrder
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical.Command
import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, RangePartitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.{BaseAggregateExec, HashAggregateExec}
import org.apache.spark.sql.execution.command.DataWritingCommandExec
import org.apache.spark.sql.execution.datasources.{InsertIntoHadoopFsRelationCommand, WriteFilesExec}
import org.apache.spark.sql.execution.joins.{BroadcastHashJoinExec, HashJoin, ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.execution.window.{WindowExec, WindowGroupLimitExec}
import org.apache.spark.sql.internal.SQLConf

/**
 * Plan one distributed pipelined exchange for a full-input batch job after exchange reuse.
 * A V1 file insertion has a known consumer, so its child carries the chosen shuffle type.
 * Result queries also support partial reads. Keep their regular plan and prepare a separate
 * full-result plan with the chosen exchange; the scheduler admits the group at submission.
 */
private[sql] object SelectBatchPipelinedShuffle extends Rule[SparkPlan] {
  val candidate = TreeNodeTag[Unit]("batchPipelinedShuffleCandidate")

  // The cached result plan also serves partial/RDD consumers. Plan the full-result variant here
  // and give each full action a fresh copy. The template is only used on the driver.
  private[exchange] final class FullResult(
      @transient val plan: SparkPlan,
      val supportsIterator: Boolean) extends Serializable
  private[exchange] val fullResult = TreeNodeTag[FullResult]("batchPipelinedFullResult")

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED)) return plan
    val input = plan match {
      case DataWritingCommandExec(_: InsertIntoHadoopFsRelationCommand, child) => child
      case other => other
    }
    if (input.exists(_.logicalLink.exists(p => p.isStreaming || p.isInstanceOf[Command]))) {
      return plan
    }

    if (conf.adaptiveExecutionEnabled) {
      logWarning(log"Skipping distributed pipelined shuffle for this batch query. " +
        log"${MDC(CONFIG, SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key)} is enabled, " +
        log"but it requires ${MDC(CONFIG2, SQLConf.ADAPTIVE_EXECUTION_ENABLED.key)}=false.")
      return plan
    }
    if (conf.localPipelinedShuffleEnabled) {
      return plan
    }

    // Count owners and references before selecting. An unvisited build side or subquery can
    // share the same shuffle as the main query. ReusedExchangeExec is a leaf in the plan tree.
    val readers = plan.collectWithSubqueries {
      case s: ShuffleExchangeExec =>
        s.unsetTagValue(candidate)
        s.id
      case ReusedExchangeExec(_, s: ShuffleExchangeExec) => s.id
    }.groupMapReduce(identity)(_ => 1)(_ + _)

    def mark(s: ShuffleExchangeExec): Unit = {
      if (readers(s.id) == 1 && !s.pipelined &&
          s.outputPartitioning.isInstanceOf[HashPartitioning]) {
        s.setTagValue(candidate, ())
      }
    }

    def visit(node: SparkPlan, singleReader: Boolean): Unit = node match {
      case s: ShuffleExchangeExec =>
        if (singleReader) mark(s)
        // A shuffle starts a new producer stage. RangePartitioner samples that stage's input
        // before the map pass, so the first exchange below it can be read more than once.
        visit(s.child, !s.outputPartitioning.isInstanceOf[RangePartitioning])
      case j: HashJoin =>
        visit(if (j.buildSide == BuildLeft) j.right else j.left, singleReader)
      case _: WriteFilesExec | _: ProjectExec | _: FilterExec | _: BaseAggregateExec | _: SortExec |
          _: InputAdapter | _: WholeStageCodegenExec | _: ColumnarToRowExec |
          _: ExpandExec | _: GenerateExec | _: WindowExec | _: WindowGroupLimitExec |
          _: SortMergeJoinExec | _: TakeOrderedAndProjectExec =>
        // Top-K consumes each child partition once. An ordered child can stop after K rows;
        // handling early completion is an execution requirement for the transport.
        node.children.foreach(visit(_, singleReader))
      case other =>
        // An unknown consumer may merge, skip, or reread partitions. Its restriction reaches
        // the first shuffle on each branch. Stages feeding that shuffle have their own readers.
        other.children.foreach(visit(_, singleReader = false))
    }

    if (input eq plan) {
      plan.unsetTagValue(fullResult)
      visit(input, singleReader = true)
      forFullInput(plan, collectTopK = true).foreach { selected =>
        plan.setTagValue(fullResult, new FullResult(selected,
          supportsIterator = !plan.isInstanceOf[TakeOrderedAndProjectExec]))
      }
      plan
    } else {
      // A file insertion drains its input in one job. Only its final-stage edge is selectable.
      probe(consumerInput(input, collectTopK = false)).foreach(mark)
      forFullInput(input, collectTopK = false).map { selected =>
        val writeInput = selected.clone() match {
          case w: WriteFilesExec => w.withNewChildren(Seq(MaterializeShuffleInputsExec(w.child)))
          case rows => MaterializeShuffleInputsExec(rows)
        }
        plan.withNewChildren(Seq(writeInput))
      }.getOrElse(plan)
    }
  }

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
    case r: RangeExec => Some(r.outputPartitioning.numPartitions)
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

  private def exchange(plan: SparkPlan): Option[ShuffleExchangeExec] = boundary(plan) match {
    case s: ShuffleExchangeExec => Some(s)
    case _ => None
  }

  private def sortedInput(plan: SparkPlan): Option[ShuffleExchangeExec] = plan match {
    case s: SortExec if !s.global => exchange(s.child)
    case _: WholeStageCodegenExec | _: InputAdapter => sortedInput(plan.children.head)
    case _ => None
  }

  private def probe(input: SparkPlan): Option[ShuffleExchangeExec] = boundary(input) match {
    case j: ShuffledHashJoinExec =>
      (j.joinType, j.buildSide) match {
        case (LeftOuter, BuildRight) if boundary(j.right).isInstanceOf[ShuffleExchangeExec] =>
          exchange(j.left)
        case (RightOuter, BuildLeft) if boundary(j.left).isInstanceOf[ShuffleExchangeExec] =>
          exchange(j.right)
        case _ => None
      }
    case j: SortMergeJoinExec if j.joinType == Inner =>
      // Inner merge joins request the streamed (left) input even for an empty right
      // partition. Its local sort drains the reader before the join can stop early.
      sortedInput(j.left)
    case other => exchange(other)
  }

  private def consumerInput(plan: SparkPlan, collectTopK: Boolean): SparkPlan = plan match {
    // Only the root uses TakeOrderedAndProjectExec.executeCollect. With ordered input it
    // takes at most K rows per partition, and nested Top-K can introduce another shuffle.
    case k: TakeOrderedAndProjectExec if collectTopK && k.limit > 0 &&
        !SortOrder.orderingSatisfies(k.child.outputOrdering, k.sortOrder) => k.child
    case w: WriteFilesExec => w.child
    case other => other
  }

  /** Select the shuffle mode for this full-input job before creating shuffle IDs. */
  private def forFullInput(
      plan: SparkPlan,
      collectTopK: Boolean): Option[SparkPlan] = {
    val sc = plan.session.sparkContext
    if (sc.isLocal || sc.cleaner.isEmpty || sc.conf.get(config.SPECULATION_ENABLED) ||
        sc.conf.get(config.DYN_ALLOCATION_ENABLED) ||
        !sc.conf.get(config.PIPELINED_GROUP_SLOT_CHECK_ENABLED) ||
        !SparkEnv.get.pipelinedShuffleManager.isInstanceOf[StreamingShuffleManager] ||
        plan.exists(p => p.subqueries.nonEmpty || p.isInstanceOf[ReusedExchangeExec])) {
      return None
    }

    val input = consumerInput(plan, collectTopK)
    boundary(input) match {
      case j: SortMergeJoinExec if stageWidth(j.right).isEmpty => return None
      case _ =>
    }
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    probe(input).filter(_.getTagValue(candidate).isDefined).filter { exchange =>
      val readers = exchange.outputPartitioning.numPartitions
      stageWidth(exchange.child).exists(maps => maps > 0 && readers > 0 &&
        maps.toLong + readers <= slots)
    }.map { exchange =>
      // Only this edge belongs to the admitted group. Candidates inside regular prefix jobs
      // and on sibling inputs must remain ordinary shuffles.
      plan.transformUp {
        case s: ShuffleExchangeExec if s eq exchange => s.copy(pipelined = true)
      }
    }
  }
}
