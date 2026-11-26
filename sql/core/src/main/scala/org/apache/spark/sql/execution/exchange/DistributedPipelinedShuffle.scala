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

import scala.annotation.tailrec

import org.apache.spark.SparkEnv
import org.apache.spark.internal.config
import org.apache.spark.internal.LogKeys.{CONFIG, CONFIG2}
import org.apache.spark.rdd.RDD
import org.apache.spark.shuffle.streaming.StreamingShuffleManager
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions.{Attribute, SortOrder}
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical.Command
import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, Partitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.command.DataWritingCommandExec
import org.apache.spark.sql.execution.datasources.InsertIntoHadoopFsRelationCommand
import org.apache.spark.sql.execution.datasources.WriteFilesExec
import org.apache.spark.sql.execution.joins.{BaseJoinExec, BroadcastHashJoinExec}
import org.apache.spark.sql.execution.joins.{ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.execution.window.WindowExec
import org.apache.spark.sql.internal.SQLConf

/** Plan a single-source pipeline or a join with one pipelined probe after exchange reuse. */
private[sql] object DistributedPipelinedShuffle extends Rule[SparkPlan] {
  val candidate = TreeNodeTag[Int]("batchPipelinedShuffleCandidate")

  val ownsShuffles = TreeNodeTag[Unit]("ownsDistributedPipelinedShuffles")

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED)) return plan
    val input = plan match {
      // A V1 file write drains its child when it writes. Inspect the child for exchanges and
      // keep the command as the execution root. Other DataWritingCommands decide how much of
      // their input to consume, so leave them behind the command guard below.
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
    if (conf.localPipelinedShuffleEnabled && plan.session.sparkContext.isLocal) return plan

    if (input.exists(p => p.subqueries.nonEmpty || p.isInstanceOf[ReusedExchangeExec])) return plan
    val isResult = input eq plan
    val consumer = consumerInput(input, collectTopK = isResult)
    val group = if (input.exists(_.isInstanceOf[BaseJoinExec])) {
      // An exchange can also be referenced twice without a reuse wrapper.
      val ids = input.collect { case s: ShuffleExchangeExec => s.id }
      probe(consumer).filter(s => !s.pipelined &&
        s.outputPartitioning.isInstanceOf[HashPartitioning] && ids.count(_ == s.id) == 1).toList
    } else {
      singleSourceGroup(consumer)
    }
    if (group.isEmpty) return plan
    group.foreach(s => s.setTagValue(candidate, s.id))
    val sc = plan.session.sparkContext
    if (sc.isLocal || sc.cleaner.isEmpty || sc.conf.get(config.SPECULATION_ENABLED) ||
        sc.conf.get(config.DYN_ALLOCATION_ENABLED) ||
        !sc.conf.get(config.PIPELINED_GROUP_SLOT_CHECK_ENABLED) ||
        !SparkEnv.get.pipelinedShuffleManager.isInstanceOf[StreamingShuffleManager]) return plan
    val readers = group.map(_.outputPartitioning.numPartitions)
    val fits = stageWidth(group.head.child).exists { source =>
      PipelinedShuffleEligibility.fitsCapacity(plan, source +: readers)
    }
    if (!fits) return plan
    val ids = group.iterator.map(_.id).toSet
    if (isResult) {
      PipelinedShuffleResultExec(input, ids)
    } else {
      val write = plan.withNewChildren(Seq(pipeline(input, ids).clone()))
      write.setTagValue(ownsShuffles, ())
      write
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
    case j: SortMergeJoinExec if j.joinType == Inner && stageWidth(j.right).isDefined =>
      // Inner merge joins request the streamed (left) input even for an empty right
      // partition. Its local sort drains the reader before the join can stop early.
      sortedInput(j.left)
    case other => exchange(other)
  }

  // Walk from the final reader to the scan. One unsupported edge disqualifies the whole chain.
  @tailrec
  private def singleSourceGroup(
      plan: SparkPlan,
      downstream: List[ShuffleExchangeExec] = Nil): List[ShuffleExchangeExec] = {
    boundary(plan) match {
      case s: ShuffleExchangeExec if !s.pipelined &&
          s.outputPartitioning.isInstanceOf[HashPartitioning] =>
        singleSourceGroup(s.child, s :: downstream)
      case _: RangeExec | _: FileSourceScanExec => downstream
      case _ => Nil
    }
  }

  private def consumerInput(plan: SparkPlan, collectTopK: Boolean): SparkPlan = plan match {
    // Only the root uses TakeOrderedAndProjectExec.executeCollect. With ordered input it
    // takes at most K rows per partition, and nested Top-K can introduce another shuffle.
    case k: TakeOrderedAndProjectExec if collectTopK && k.limit > 0 &&
        !SortOrder.orderingSatisfies(k.child.outputOrdering, k.sortOrder) => k.child
    case w: WriteFilesExec => w.child
    case other => other
  }

  private[exchange] def pipeline(plan: SparkPlan, ids: Set[Int]): SparkPlan =
    PipelinedShuffleEligibility.markExchanges(plan)(_.getTagValue(candidate).exists(ids.contains))

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

/** Partial reads use ordinary shuffle because unread partitions can block pipelined writers. */
private[sql] case class PipelinedShuffleResultExec(child: SparkPlan, exchangeIds: Set[Int])
  extends UnaryExecNode {
  override def output: Seq[Attribute] = child.output
  override def outputOrdering: Seq[SortOrder] = child.outputOrdering
  override def outputPartitioning: Partitioning = child.outputPartitioning

  @transient private val fullInput = DistributedPipelinedShuffle.pipeline(child, exchangeIds)

  private def collectPlan(): SparkPlan = {
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) ||
        conf.adaptiveExecutionEnabled) return child
    val id = sparkContext.getLocalProperty(SQLExecution.EXECUTION_ID_KEY)
    if (id == null) return child
    val qe = SQLExecution.getQueryExecution(id.toLong)
    if (qe == null || !(qe.executedPlan eq this)) return child
    // Exchanges cache their shuffle dependencies. Clone the plan so each SQL execution gets fresh
    // shuffle IDs even when a previous action on the same Dataset has cleaned up its shuffles.
    val selected = fullInput.clone()
    selected.setTagValue(DistributedPipelinedShuffle.ownsShuffles, ())
    SQLExecution.updatePhysicalPlan(id.toLong, qe.withExecutedPlan(selected))
    selected
  }

  override def executeCollect(): Array[InternalRow] = collectPlan().executeCollect()
  override private[spark] def executeCollectIterator(): (Long, Iterator[InternalRow]) = {
    val plan = if (child.isInstanceOf[TakeOrderedAndProjectExec]) child else collectPlan()
    plan.executeCollectIterator()
  }
  override protected def doExecute(): RDD[InternalRow] = child.execute()
  override protected def withNewChildInternal(newChild: SparkPlan): SparkPlan =
    copy(child = newChild)
}
