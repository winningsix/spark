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
import org.apache.spark.sql.catalyst.plans.logical.Command
import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, Partitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.command.DataWritingCommandExec
import org.apache.spark.sql.execution.datasources.InsertIntoHadoopFsRelationCommand
import org.apache.spark.sql.execution.datasources.WriteFilesExec
import org.apache.spark.sql.execution.window.WindowExec
import org.apache.spark.sql.internal.SQLConf

/**
 * Plan an all-pipelined group for a single-source, full-input batch job after exchange reuse.
 * A V1 file insertion has a known consumer, so its child carries the chosen shuffle type.
 * Result queries also support partial reads. Keep their regular plan and prepare a separate
 * full-result plan with the chosen exchanges; the scheduler admits the group at submission.
 */
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

    // Subqueries and reused exchanges can introduce another reader outside the unary chain.
    if (input.exists(p => p.subqueries.nonEmpty || p.isInstanceOf[ReusedExchangeExec])) return plan

    val isResult = input eq plan
    val consumer = consumerInput(input, collectTopK = isResult)
    val group = singleSourceGroup(consumer)
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

  private def stageWidth(plan: SparkPlan): Option[Int] = boundary(plan) match {
    case r: RangeExec => Some(r.outputPartitioning.numPartitions)
    case f: FileSourceScanExec => Some(f.inputRDD.getNumPartitions)
    case _ => None
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

/** Collect a job-owned copy of the planned pipeline. Partial readers use the ordinary child. */
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
