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

package org.apache.spark.shuffle.streaming

import java.util.concurrent.{ScheduledExecutorService, TimeUnit}
import java.util.concurrent.atomic.AtomicBoolean

import scala.collection.mutable.{ArrayBuffer, HashMap, HashSet}

import org.apache.spark.{SparkConf, SparkEnv, StreamingShuffleOutputTrackerMaster}
import org.apache.spark.internal.config._
import org.apache.spark.scheduler.TaskSetManager

/**
 * Shuffle-owned placement and launch policy. The scheduler supplies eligible executors and live
 * task-set state while holding its own monitor; this policy never acquires the scheduler lock.
 * RPC completion only enqueues a revive on the scheduler-owned timer.
 */
private[spark] class StreamingShuffleSchedulingPolicy(
    conf: SparkConf,
    abortTimer: ScheduledExecutorService,
    reviveOffers: () => Unit) {
  private val offerReadyPreTaskReaderIndices =
    new HashMap[(Int, Int, String), HashSet[Int]]
  private val executorReceiveServiceEnabled =
    conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED)
  private val elasticProducerMaxTasksPerStage =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE)
  private val elasticProducerSoleStageMaxTasks =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_SOLE_STAGE_MAX_TASKS)
  private val preparedReaderDiagonalAssignment =
    conf.get(STREAMING_SHUFFLE_PREPARED_READER_DIAGONAL_ASSIGNMENT_ENABLED)
  private val inboxReadyRevivePending = new AtomicBoolean(false)

  private lazy val shuffleReadiness: Option[StreamingShuffleReadinessCoordinator] = {
    if (executorReceiveServiceEnabled) {
      SparkEnv.get.streamingShuffleOutputTracker.collect {
        case tracker: StreamingShuffleOutputTrackerMaster => tracker.receiveCoordinator
      }
    } else {
      None
    }
  }

  private def requestInboxReadyRevive(): Unit = {
    if (inboxReadyRevivePending.compareAndSet(false, true)) {
      abortTimer.schedule(
        new Runnable {
          override def run(): Unit = {
            inboxReadyRevivePending.set(false)
            reviveOffers()
          }
        },
        10L,
        TimeUnit.MILLISECONDS)
    }
  }

  private def preparePipelinedReaders(
      taskSets: Iterable[TaskSetManager],
      executorHosts: => Map[String, String]): Unit = {
    shuffleReadiness.foreach { coordinator =>
      val activeExecutorHosts = executorHosts
      val receiveExecutors = coordinator.executorIds.filter(activeExecutorHosts.contains).sorted
      val existing = coordinator.snapshot
      val pending = new ArrayBuffer[StreamingShuffleReaderPreparation]
      taskSets.iterator.filter { taskSet =>
        taskSet.isActiveForScheduling && taskSet.taskSet.isPipelinedShuffleReader &&
          taskSet.taskSet.pipelinedReaderShuffleIds.nonEmpty
      }.foreach { taskSet =>
        taskSet.tasks.indices.foreach { taskIndex =>
          val key = StreamingShuffleReaderKey(
            taskSet.stageId, taskSet.taskSet.stageAttemptId, taskIndex)
          if (taskSet.isActiveForScheduling && taskSet.isTaskPendingForOffer(taskIndex)) {
            val eligibleExecutors = receiveExecutors.filter { executorId =>
              taskSet.canPrepareReaderOnExecutor(
                taskIndex, executorId, activeExecutorHosts(executorId))
            }
            existing.get(key) match {
              case Some(state) if state.failure.isDefined =>
                taskSet.abort(state.failure.get)
              case Some(state) if !eligibleExecutors.contains(state.executorId) =>
                // A prepared input may own the only copy of an acknowledged stream.
                taskSet.abort(s"Prepared streaming shuffle reader lost its schedulable " +
                  s"executor ${state.executorId}; resubmit the pipelined job")
              case Some(_) =>
              case None if eligibleExecutors.nonEmpty =>
                val executorId = eligibleExecutors(
                  StreamingShuffleSchedulingPolicy.preparedReaderExecutorIndex(
                  taskIndex, eligibleExecutors.size, preparedReaderDiagonalAssignment))
                pending += StreamingShuffleReaderPreparation(key, executorId,
                  taskSet.tasks(taskIndex).partitionId, taskSet.taskSet.pipelinedReaderShuffleIds)
              case _ =>
            }
          }
        }
      }
      // An abort above may retire an entire task set. Do not prepare its earlier placements.
      coordinator.prepare(pending.filter { request =>
        taskSets.exists { manager =>
          manager.isActiveForScheduling && manager.stageId == request.key.stageId &&
            manager.taskSet.stageAttemptId == request.key.stageAttemptId
        }
      }.toSeq)
    }
  }

  private def rebuildOfferReadyPreTaskReaderIndices(
      taskSets: Iterable[TaskSetManager]): Unit = {
    offerReadyPreTaskReaderIndices.clear()
    if (!executorReceiveServiceEnabled) return
    val managersByStage = taskSets.iterator.map { manager =>
      (manager.stageId, manager.taskSet.stageAttemptId) -> manager
    }.toMap
    shuffleReadiness.foreach { coordinator =>
      coordinator.snapshot.foreach { case (key, state) =>
        managersByStage.get((key.stageId, key.stageAttemptId)).foreach { manager =>
          if (manager.isActiveForScheduling && manager.isTaskPendingForOffer(key.taskIndex) &&
              state.ready) {
            offerReadyPreTaskReaderIndices.getOrElseUpdate(
              (key.stageId, key.stageAttemptId, state.executorId), new HashSet[Int]) +=
              key.taskIndex
          }
        }
      }
    }
  }

  def preTaskReaderIndexAllowed(
      taskSet: TaskSetManager,
      executorId: String,
      taskIndex: Int): Boolean = {
    if (!executorReceiveServiceEnabled || !taskSet.taskSet.isPipelinedShuffleReader) {
      true
    } else {
      offerReadyPreTaskReaderIndices.get(
        (taskSet.stageId, taskSet.taskSet.stageAttemptId, executorId))
        .exists(_.contains(taskIndex))
    }
  }

  def preTaskReaderTaskSetReady(taskSet: TaskSetManager): Boolean = {
    if (!executorReceiveServiceEnabled || !taskSet.taskSet.isPipelinedShuffleReader) {
      true
    } else {
      offerReadyPreTaskReaderIndices.keysIterator.exists { case (stageId, attemptId, _) =>
        stageId == taskSet.stageId && attemptId == taskSet.taskSet.stageAttemptId
      }
    }
  }

  private def isOfferReadyPipelinedReader(taskSet: TaskSetManager): Boolean = {
    taskSet.taskSet.isPipelinedShuffleReader && preTaskReaderTaskSetReady(taskSet)
  }

  private def isActivePurePipelinedProducer(taskSet: TaskSetManager): Boolean = {
    taskSet.isActiveForScheduling && taskSet.numCompletedTasks < taskSet.numTasks &&
      taskSet.taskSet.isPipelinedShuffleProducer &&
      !taskSet.taskSet.isPipelinedShuffleReader
  }

  private def readerFrontierStartedForProducer(
      producer: TaskSetManager,
      taskSets: Iterable[TaskSetManager]): Boolean = {
    producer.taskSet.shuffleId.exists { shuffleId =>
      val directReaders = taskSets.iterator.filter { taskSet =>
        taskSet.isActiveForScheduling && taskSet.taskSet.isPipelinedShuffleReader &&
          taskSet.taskSet.pipelinedReaderShuffleIds.contains(shuffleId)
      }.toSeq
      // submitTasks(producer) can trigger a resource offer before DAGScheduler has submitted the
      // direct consumer. Treat that transient absence as NOT started; otherwise this race lets the
      // producer consume the entire sole-stage window and recreates a producer-then-consumer
      // boundary. Ready readers are ordered first in the same offer pass, so the condition becomes
      // true immediately after every submitted direct reader launches.
      directReaders.nonEmpty && directReaders.forall { reader =>
        reader.runningTasks > 0 || reader.numCompletedTasks > 0
      }
    }
  }

  def elasticProducerLaunchAllowed(
      taskSet: TaskSetManager,
      soleActivePureProducer: Boolean): Boolean = {
    val pureProducer = taskSet.taskSet.isPipelinedShuffleProducer &&
      !taskSet.taskSet.isPipelinedShuffleReader
    val taskLimit = if (soleActivePureProducer) {
      elasticProducerSoleStageMaxTasks.orElse(elasticProducerMaxTasksPerStage)
    } else {
      elasticProducerMaxTasksPerStage
    }
    !executorReceiveServiceEnabled || !pureProducer ||
      taskLimit.forall(taskSet.runningTasks < _)
  }

  def initialize(): Unit = {
    shuffleReadiness.foreach(_.setOnUpdate(() => requestInboxReadyRevive()))
  }

  def prepareOffers(
      taskSets: Seq[TaskSetManager],
      executorHosts: => Map[String, String]): StreamingShuffleOfferPlan = {
    val pureProducers = taskSets.filter(isActivePurePipelinedProducer)
    val solePureProducer = if (pureProducers.size == 1) pureProducers.headOption else None
    preparePipelinedReaders(taskSets, executorHosts)
    rebuildOfferReadyPreTaskReaderIndices(taskSets)
    // Ready readers drain before producers; preserve the pool order within each category.
    val ordered = taskSets.zipWithIndex.sortBy { case (taskSet, index) =>
      (if (isOfferReadyPipelinedReader(taskSet)) 0 else 1, index)
    }.map(_._1)
    // Task-set references belong to this offer pass, not to the long-lived shuffle policy.
    StreamingShuffleOfferPlan(ordered, taskSet =>
      solePureProducer.contains(taskSet) && readerFrontierStartedForProducer(taskSet, taskSets))
  }

  def readerTaskLaunched(taskSet: TaskSetManager, executorId: String, index: Int): Unit = {
    offerReadyPreTaskReaderIndices.get(
      (taskSet.stageId, taskSet.taskSet.stageAttemptId, executorId)).foreach(_ -= index)
  }

  def releaseStage(stageId: Int, stageAttemptId: Int): Unit = {
    shuffleReadiness.foreach(_.releaseStage(stageId, stageAttemptId))
  }

  def removeExecutor(executorId: String): Unit = {
    shuffleReadiness.foreach(_.removeExecutor(executorId))
  }

  def close(): Unit = {
    shuffleReadiness.foreach(_.close())
    offerReadyPreTaskReaderIndices.clear()
  }
}

private[spark] case class StreamingShuffleOfferPlan(
    taskSets: Seq[TaskSetManager],
    useSoleProducerWindow: TaskSetManager => Boolean)

private[spark] object StreamingShuffleSchedulingPolicy {
  def preparedReaderExecutorIndex(
      taskIndex: Int,
      executorCount: Int,
      diagonalAssignment: Boolean): Int = {
    require(taskIndex >= 0, s"taskIndex must be non-negative: $taskIndex")
    require(executorCount > 0, s"executorCount must be positive: $executorCount")
    val column = taskIndex % executorCount
    if (diagonalAssignment) {
      (column + taskIndex / executorCount) % executorCount
    } else {
      column
    }
  }

}
