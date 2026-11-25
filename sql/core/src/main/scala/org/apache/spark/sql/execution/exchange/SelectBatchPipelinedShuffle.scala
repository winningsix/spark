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

import org.apache.spark.internal.LogKeys.{CONFIG, CONFIG2}
import org.apache.spark.sql.catalyst.optimizer.BuildLeft
import org.apache.spark.sql.catalyst.plans.logical.Command
import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, RangePartitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.joins.{HashJoin, SortMergeJoinExec}
import org.apache.spark.sql.execution.window.{WindowExec, WindowGroupLimitExec}
import org.apache.spark.sql.internal.SQLConf

/**
 * Select single-reader hash shuffle edges in a prepared batch plan. Run on the main query
 * after exchange reuse, when each physical reader is visible. A candidate describes the
 * topology only. Execution still needs to materialize build inputs and admit the group
 * before it can activate the distributed transport.
 */
private[sql] object SelectBatchPipelinedShuffle extends Rule[SparkPlan] {
  val candidate = TreeNodeTag[Unit]("batchPipelinedShuffleCandidate")

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) ||
        plan.exists(_.logicalLink.exists(p => p.isStreaming || p.isInstanceOf[Command]))) {
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

    def visit(node: SparkPlan, singleReader: Boolean): Unit = node match {
      case s: ShuffleExchangeExec =>
        if (singleReader && readers(s.id) == 1 && !s.pipelined &&
            s.outputPartitioning.isInstanceOf[HashPartitioning]) {
          s.setTagValue(candidate, ())
        }
        // A shuffle starts a new producer stage. RangePartitioner samples that stage's input
        // before the map pass, so the first exchange below it can be read more than once.
        visit(s.child, !s.outputPartitioning.isInstanceOf[RangePartitioning])
      case j: HashJoin =>
        visit(if (j.buildSide == BuildLeft) j.right else j.left, singleReader)
      case _: ProjectExec | _: FilterExec | _: BaseAggregateExec | _: SortExec |
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

    visit(plan, singleReader = true)
    plan
  }
}
