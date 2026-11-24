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

import scala.collection.mutable

import org.apache.spark.sql.catalyst.optimizer.BuildLeft
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.datasources.v2.BatchScanExec
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
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
    if (!conf.getConf(SQLConf.BATCH_PIPELINED_SHUFFLE_SELECTION_ENABLED) ||
        conf.adaptiveExecutionEnabled || conf.localPipelinedShuffleEnabled) {
      return plan
    }

    val seen = mutable.Set.empty[Int]
    val selected = mutable.ArrayBuffer.empty[ShuffleExchangeExec]

    // Validate both join inputs. A build subtree can contain a second reference to an
    // exchange on the probe side, even though its own exchanges must stay materialized.
    def visit(node: SparkPlan, materialized: Boolean): Boolean = {
      if (node.subqueries.nonEmpty || node.logicalLink.exists(_.isStreaming)) return false
      node match {
        case s: ShuffleExchangeExec =>
          if (s.pipelined || !seen.add(s.id)) return false
          if (!materialized) {
            if (!s.outputPartitioning.isInstanceOf[HashPartitioning]) return false
            selected += s
          }
          visit(s.child, materialized)
        case j: ShuffledHashJoinExec =>
          val buildLeft = j.buildSide == BuildLeft
          visit(j.left, materialized || buildLeft) && visit(j.right, materialized || !buildLeft)
        case _: ProjectExec | _: FilterExec | _: BaseAggregateExec | _: SortExec |
            _: InputAdapter | _: WholeStageCodegenExec | _: ColumnarToRowExec =>
          visit(node.children.head, materialized)
        case _: FileSourceScanExec | _: BatchScanExec | _: LocalTableScanExec | _: RangeExec =>
          true
        // Other operators can merge partitions, open a partition repeatedly, hide shuffle
        // dependencies or stop reading early. A reused exchange also fails this check.
        case _ => false
      }
    }

    if (visit(plan, materialized = false)) {
      selected.foreach(_.setTagValue(candidate, ()))
    }
    plan
  }
}
