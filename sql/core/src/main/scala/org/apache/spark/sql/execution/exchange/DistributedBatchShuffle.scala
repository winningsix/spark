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
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight}
import org.apache.spark.sql.catalyst.plans.{LeftOuter, RightOuter}
import org.apache.spark.sql.execution._
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.util.ThreadUtils

/** One action owns both exchanges. Concurrent collects use independent shuffle IDs. */
private[sql] class DistributedBatchShuffle(
    val plan: SparkPlan,
    probe: ShuffleExchangeExec,
    build: Option[ShuffleExchangeExec]) {
  def materializeBuild(): Unit = {
    build.foreach(s => ThreadUtils.awaitResult(s.submitShuffleJob(), Duration.Inf))
  }

  def cleanup(): Unit = {
    plan.session.sparkContext.cleaner.foreach { cleaner =>
      (build.toList :+ probe).foreach(s => cleaner.doCleanupShuffle(s.shuffleId, blocking = true))
    }
  }
}

private[sql] object DistributedBatchShuffle {
  // Project and filter consume their entire input during collect. Operators such as limit
  // may leave partitions unread, even if their input exchange has exactly one reader.
  private def boundary(plan: SparkPlan): SparkPlan = plan match {
    case _: ProjectExec | _: FilterExec | _: WholeStageCodegenExec |
        _: InputAdapter | _: ColumnarToRowExec => boundary(plan.children.head)
    case other => other
  }

  private def scan(exchange: ShuffleExchangeExec): Boolean = boundary(exchange.child) match {
    case _: RangeExec | _: FileSourceScanExec => true
    case _ => false
  }

  def forCollect(plan: SparkPlan): Option[DistributedBatchShuffle] = {
    val sc = plan.session.sparkContext
    if (sc.isLocal || sc.cleaner.isEmpty || sc.conf.get(config.SPECULATION_ENABLED) ||
        sc.conf.get(config.DYN_ALLOCATION_ENABLED) ||
        !sc.conf.get(config.PIPELINED_GROUP_SLOT_CHECK_ENABLED) ||
        !SparkEnv.get.pipelinedShuffleManager.isInstanceOf[StreamingShuffleManager] ||
        plan.exists(_.subqueries.nonEmpty)) {
      return None
    }

    def activate(probePlan: SparkPlan): Option[DistributedBatchShuffle] = {
      boundary(probePlan) match {
        case s: ShuffleExchangeExec if s.getTagValue(SelectBatchPipelinedShuffle.candidate)
            .isDefined && scan(s) =>
          val maps = s.inputRDD.getNumPartitions
          val reducers = s.outputPartitioning.numPartitions
          val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
          if (maps <= 0 || reducers <= 0 || maps.toLong + reducers > slots) return None
          val rewritten = plan.clone().transformUp {
            case exchange: ShuffleExchangeExec
                if exchange.getTagValue(SelectBatchPipelinedShuffle.candidate).isDefined =>
              exchange.copy(pipelined = true)
          }
          val exchanges = rewritten.collect { case e: ShuffleExchangeExec => e }
          Some(new DistributedBatchShuffle(rewritten, exchanges.find(_.pipelined).get,
            exchanges.find(!_.pipelined)))
        case _ => None
      }
    }

    boundary(plan) match {
      case s: ShuffleExchangeExec => activate(s)
      case j: ShuffledHashJoinExec =>
        val sides = (j.joinType, j.buildSide) match {
          case (LeftOuter, BuildRight) => Some((j.left, j.right))
          case (RightOuter, BuildLeft) => Some((j.right, j.left))
          case _ => None
        }
        sides.flatMap { case (probe, build) =>
          boundary(build) match {
            case s: ShuffleExchangeExec if !s.pipelined && scan(s) => activate(probe)
            case _ => None
          }
        }
      case _ => None
    }
  }
}
