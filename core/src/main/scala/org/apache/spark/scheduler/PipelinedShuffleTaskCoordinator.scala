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

package org.apache.spark.scheduler

import java.util.concurrent.{ScheduledExecutorService, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicLong}

import scala.collection.mutable.{ArrayBuffer, HashMap, HashSet}

import org.apache.spark.{SparkConf, SparkContext, SparkEnv, StreamingShuffleOutputTrackerMaster}
import org.apache.spark.internal.config._
import org.apache.spark.shuffle.streaming.StreamingShuffleReceiveInboxId

/**
 * Driver-side admission and placement state for executor-owned pipelined-shuffle inboxes and
 * memory-retaining consumers.
 *
 * The ordinary scheduler remains responsible for locality, resource profiles, exclusions, and
 * task serialization. This coordinator prepares and prioritizes transport inboxes, bounds pure
 * producers until their direct reader frontier can make progress, and enforces the same sampled
 * execution-memory admission for memory-retaining consumers after a regular-shuffle fallback.
 */
private[scheduler] final class PipelinedShuffleTaskCoordinator(
    conf: SparkConf,
    timer: ScheduledExecutorService,
    reviveOffers: () => Unit) {

  private case class ReaderKey(stageId: Int, stageAttemptId: Int, taskIndex: Int)
  private case class ReaderAssignment(
      executorId: String,
      inboxes: Seq[StreamingShuffleReceiveInboxId])

  private val assignments = new HashMap[ReaderKey, ReaderAssignment]
  private val readyTaskIndices = new HashMap[(Int, Int, String), HashSet[Int]]
  private val enabled = conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED)
  private val producerMaxTasks =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE)
  private val soleProducerMaxTasks =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_SOLE_STAGE_MAX_TASKS)
  private val expandedProducerMaxTasks =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_EXPANDED_MAX_TASKS_PER_STAGE)
  private val expandedProducerMinActiveStages =
    conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_EXPANDED_MIN_ACTIVE_STAGES)
  require(
    (expandedProducerMinActiveStages == 0) == expandedProducerMaxTasks.isEmpty,
    "expanded producer task limit and active-stage threshold must be configured together")
  require(
    expandedProducerMaxTasks.forall(expanded => producerMaxTasks.exists(expanded >= _)),
    "expanded producer task limit must be at least the base producer task limit")
  private val readerTaskCpus = conf.get(STREAMING_SHUFFLE_READER_TASK_CPUS)
  private val readerProducerTaskCpus = conf.get(STREAMING_SHUFFLE_READER_PRODUCER_TASK_CPUS)
  private val maxTotalReaderTasksPerExecutor =
    conf.get(STREAMING_SHUFFLE_MAX_TOTAL_READER_TASKS_PER_EXECUTOR)
  private val expandedMaxTotalReaderTasksPerExecutor =
    conf.get(STREAMING_SHUFFLE_EXPANDED_MAX_TOTAL_READER_TASKS_PER_EXECUTOR)
  private val maxRetainedReaderExecutionMemory =
    conf.get(STREAMING_SHUFFLE_PREPARED_READER_MAX_RETAINED_EXECUTION_MEMORY)
  require(
    expandedMaxTotalReaderTasksPerExecutor == 0 ||
      (maxTotalReaderTasksPerExecutor > 0 &&
        expandedMaxTotalReaderTasksPerExecutor >= maxTotalReaderTasksPerExecutor),
    "expanded prepared reader cap requires a positive, no-larger initial total cap")
  private val revivePending = new AtomicBoolean(false)
  // A prepared inbox is reusable only until its attached task completes. Give every replacement a
  // distinct negative token so a delayed ready ACK from the previous lease cannot satisfy the new
  // assignment (the task attempt id itself is not known until the scheduler launches the task).
  private val nextPreparedInboxGeneration = new AtomicLong(-1L)

  private lazy val trackerMaster: Option[StreamingShuffleOutputTrackerMaster] = {
    SparkEnv.get.streamingShuffleOutputTracker.collect {
      case tracker: StreamingShuffleOutputTrackerMaster => tracker
    }
  }

  def initialize(): Unit = {
    if (enabled) {
      trackerMaster.foreach(_.setInboxReadyCallback(() => requestReviveOffers()))
    }
  }

  private def requestReviveOffers(): Unit = {
    if (revivePending.compareAndSet(false, true)) {
      timer.schedule(
        new Runnable {
          override def run(): Unit = {
            revivePending.set(false)
            reviveOffers()
          }
        },
        PipelinedShuffleTaskCoordinator.INBOX_READY_REVIVE_COALESCE_MS,
        TimeUnit.MILLISECONDS)
    }
  }

  /** Prepare missing reader inboxes, then rebuild the ready-task view for this offer pass. */
  def prepareForOffers(
      taskSets: Iterable[TaskSetManager],
      activeExecutors: Set[String],
      placementCandidates: (TaskSetManager, Int) => Seq[String]): Unit = {
    if (!enabled) return
    trackerMaster.foreach { tracker =>
      val receiveExecutors = tracker.receiveExecutorIds.filter(activeExecutors.contains).sorted
      if (activeExecutors.nonEmpty && receiveExecutors.size == activeExecutors.size) {
        val pending = new ArrayBuffer[(ReaderKey, ReaderAssignment)]
        taskSets.iterator.filter { taskSet =>
          !taskSet.isZombie && taskSet.taskSet.isPipelinedShuffleReader &&
            taskSet.taskSet.pipelinedReaderShuffleIds.nonEmpty
        }.foreach { taskSet =>
          taskSet.tasks.indices.foreach { taskIndex =>
            val key = ReaderKey(taskSet.stageId, taskSet.taskSet.stageAttemptId, taskIndex)
            if (taskSet.isTaskPendingForOffer(taskIndex)) {
              val candidates = placementCandidates(taskSet, taskIndex)
                .filter(receiveExecutors.contains).distinct.sorted
              assignments.get(key).filterNot(a => candidates.contains(a.executorId)).foreach {
                stale =>
                  assignments.remove(key)
                  readyTaskIndices.get((key.stageId, key.stageAttemptId, stale.executorId))
                    .foreach(_ -= taskIndex)
                  stale.inboxes.foreach(tracker.releaseReceiveInbox(stale.executorId, _))
              }
              if (!assignments.contains(key) && candidates.nonEmpty) {
                val executorId = candidates(taskIndex % candidates.size)
                val partitionId = taskSet.tasks(taskIndex).partitionId
                // With a regular SHJ build input, reader memory can stabilize independently of
                // probe completion. Keep credit outstanding on unattached probe routes so the
                // producer stops instead of converting the receive service into a disk sink.
                val stageBeforeConsumerAttach =
                  !taskSet.taskSet.retainsExecutionMemory ||
                    taskSet.taskSet.pipelinedReaderStartupShuffleIds.nonEmpty
                val nextOrdinalByShuffle = new HashMap[Int, Int]
                val inboxes = taskSet.taskSet.pipelinedReaderShuffleIds.map { shuffleId =>
                  val readerOrdinal = nextOrdinalByShuffle.getOrElse(shuffleId, 0)
                  nextOrdinalByShuffle.update(shuffleId, readerOrdinal + 1)
                  StreamingShuffleReceiveInboxId(
                    shuffleId,
                    taskSet.stageId,
                    taskSet.taskSet.stageAttemptId,
                    partitionId,
                    nextPreparedInboxGeneration.getAndDecrement(),
                    readerOrdinal,
                    stageBeforeConsumerAttach)
                }
                pending += key -> ReaderAssignment(executorId, inboxes)
              }
            }
          }
        }

        // One prepare batch per executor avoids an RPC round trip per reduce partition.
        val assignmentsByExecutor = pending.groupBy(_._2.executorId)
        val preparedExecutors = tracker.prepareReceiveInboxesByExecutor(
          assignmentsByExecutor.map { case (executorId, executorAssignments) =>
            executorId -> executorAssignments.flatMap(_._2.inboxes).toSeq
          })
        assignmentsByExecutor.foreach { case (executorId, executorAssignments) =>
          if (preparedExecutors.contains(executorId)) {
            executorAssignments.foreach { case (key, assignment) =>
              assignments.put(key, assignment)
            }
          }
        }
      }
    }
    rebuildReadyTaskIndices(taskSets)
  }

  private def rebuildReadyTaskIndices(taskSets: Iterable[TaskSetManager]): Unit = {
    readyTaskIndices.clear()
    val managersByStage = taskSets.iterator.map { manager =>
      (manager.stageId, manager.taskSet.stageAttemptId) -> manager
    }.toMap
    trackerMaster.foreach { tracker =>
      assignments.foreach { case (key, assignment) =>
        managersByStage.get((key.stageId, key.stageAttemptId)).foreach { manager =>
          val required = requiredReaderInboxes(manager.taskSet, assignment.inboxes)
          if (manager.isTaskPendingForOffer(key.taskIndex) && required.forall {
              tracker.isReceiveInboxDrainReady(assignment.executorId, _)
            }) {
            readyTaskIndices.getOrElseUpdate(
              (key.stageId, key.stageAttemptId, assignment.executorId), new HashSet[Int]) +=
              key.taskIndex
          }
        }
      }
    }
  }

  def requiredReaderInboxes(
      taskSet: TaskSet,
      inboxes: Seq[StreamingShuffleReceiveInboxId]): Seq[StreamingShuffleReceiveInboxId] = {
    val startupInboxes = inboxes.filter { inbox =>
      taskSet.pipelinedReaderStartupShuffleIds.contains(inbox.shuffleId)
    }
    // If the declared startup ids do not resolve to this task, retain the conservative all-input
    // gate. This also preserves the default for non-SQL RDD consumers.
    if (startupInboxes.nonEmpty) startupInboxes else inboxes
  }

  def taskIndexAllowed(
      taskSet: TaskSetManager,
      executorId: String,
      taskIndex: Int): Boolean = {
    if (!enabled || !taskSet.taskSet.isPipelinedShuffleReader) {
      true
    } else {
      readyTaskIndices.get((taskSet.stageId, taskSet.taskSet.stageAttemptId, executorId))
        .exists(_.contains(taskIndex))
    }
  }

  /**
   * Admit reader compute independently from executor-owned inbox preparation.
   *
   * A fully streaming query can have several downstream hash joins alive at once. Preparing all
   * inboxes is required to keep producer routes non-blocking, but attaching all of their compute
   * tasks to the same executor can overcommit execution memory. The per-stage sampled cap protects
   * the first heavy tasks; the executor-wide cap bounds overlapping reader stages.
   */
  def readerLaunchAllowed(
      taskSet: TaskSetManager,
      executorId: String,
      activeTaskSets: Iterable[TaskSetManager],
      upstreamReaderProducers: Seq[TaskSetManager]): Boolean = {
    def admissionParticipant(manager: TaskSetManager): Boolean = {
      manager.taskSet.isPipelinedShuffleReader || manager.taskSet.retainsExecutionMemory
    }

    if (!admissionParticipant(taskSet)) {
      true
    } else {
      val stageCap = taskSet.preparedReaderMaxTasksPerExecutor
      val belowStageCap = stageCap <= 0 || taskSet.runningTasksOnExecutor(executorId) < stageCap
      val effectiveTotalReaderCap =
        if (expandedMaxTotalReaderTasksPerExecutor > 0 && taskSet.preparedReaderCanExpand) {
          expandedMaxTotalReaderTasksPerExecutor
        } else {
          maxTotalReaderTasksPerExecutor
        }
      val totalReaders = if (effectiveTotalReaderCap > 0) {
        activeTaskSets.iterator
          .filter(manager => !manager.isZombie && admissionParticipant(manager))
          .map(_.runningTasksOnExecutor(executorId))
          .sum
      } else {
        0
      }
      val withinRetainedMemoryBudget = if (maxRetainedReaderExecutionMemory > 0L) {
        val runningRetainedBytes = activeTaskSets.iterator
          .filter(manager => !manager.isZombie && admissionParticipant(manager))
          .foldLeft(0L) { (total, manager) =>
            val perTaskBytes = manager.preparedReaderEstimatedPeakExecutionMemory
              .getOrElse(maxRetainedReaderExecutionMemory)
            val runningTasks = manager.runningTasksOnExecutor(executorId).toLong
            val stageBytes = if (runningTasks > 0L &&
                perTaskBytes > Long.MaxValue / runningTasks) {
              Long.MaxValue
            } else {
              perTaskBytes * runningTasks
            }
            if (Long.MaxValue - total < stageBytes) Long.MaxValue else total + stageBytes
          }
        val candidateBytes = taskSet.preparedReaderEstimatedPeakExecutionMemory
          .getOrElse(maxRetainedReaderExecutionMemory)
        runningRetainedBytes <= maxRetainedReaderExecutionMemory - candidateBytes
      } else {
        true
      }
      val upstreamAttachmentAvailable = !taskSet.taskSet.isPipelinedShuffleReader ||
        !upstreamReaderAttachmentReserved(executorId, upstreamReaderProducers)
      belowStageCap && upstreamAttachmentAvailable &&
        (effectiveTotalReaderCap <= 0 || totalReaders < effectiveTotalReaderCap) &&
        withinRetainedMemoryBudget
    }
  }

  /**
   * Return the direct reader-producers that feed a reader.
   *
   * Inbox readiness is input-local: a downstream shuffled hash join can become ready from its
   * build input while a streamed input is still produced by an upstream join. If that downstream
   * stage attaches first, it can fill the executor-wide reader cap and strand that upstream join.
   */
  def upstreamReaderProducers(
      reader: TaskSetManager,
      taskSets: Iterable[TaskSetManager]): Seq[TaskSetManager] = {
    if (!enabled || !reader.taskSet.isPipelinedShuffleReader) {
      Seq.empty
    } else {
      val inputShuffleIds = reader.taskSet.pipelinedReaderShuffleIds.toSet
      taskSets.iterator.filter { producer =>
        !producer.isZombie && producer.taskSet.isPipelinedShuffleReader &&
          producer.taskSet.shuffleId.exists(inputShuffleIds.contains)
      }.toSeq
    }
  }

  /**
   * Reserve only the executor slots needed by pending tasks of a direct reader-producer.
   *
   * Once an upstream task attaches (or completes), its reservation disappears immediately. This
   * lets independent executors and later stages overlap while preventing a readiness race from
   * leaving a few critical upstream partitions queued behind their own consumers.
   */
  private def upstreamReaderAttachmentReserved(
      executorId: String,
      upstreamReaderProducers: Seq[TaskSetManager]): Boolean = {
    upstreamReaderProducers.exists { producer =>
      producer.tasks.indices.exists { taskIndex =>
        producer.isTaskPendingForOffer(taskIndex) && {
          val key = ReaderKey(producer.stageId, producer.taskSet.stageAttemptId, taskIndex)
          // Missing preparation is conservatively reserved on every executor until a placement
          // exists; prepareForOffers normally resolves it before this admission check.
          assignments.get(key).forall(_.executorId == executorId)
        }
      }
    }
  }

  def taskLaunched(taskSet: TaskSetManager, executorId: String, taskIndex: Int): Unit = {
    if (taskIndex >= 0) {
      readyTaskIndices.get((taskSet.stageId, taskSet.taskSet.stageAttemptId, executorId))
        .foreach(_ -= taskIndex)
    }
  }

  /**
   * Forget the consumed inbox assignment for a reader task that must be retried.
   *
   * An executor-owned inbox is a single-attempt lease: task completion closes it after the
   * attached iterator either drains or fails. Keeping the driver assignment after a failed task
   * would therefore let the retry pass the stale drain-ready gate and fall back to a task-owned
   * route. Remove both sides of the old preparation here so the next offer pass prepares a fresh
   * inbox and waits for a new ready acknowledgement before launching the retry.
   */
  def taskFailed(taskSet: TaskSetManager, taskIndex: Int): Unit = {
    if (!enabled || !taskSet.taskSet.isPipelinedShuffleReader || taskIndex < 0) return
    val key = ReaderKey(taskSet.stageId, taskSet.taskSet.stageAttemptId, taskIndex)
    assignments.remove(key).foreach { assignment =>
      readyTaskIndices.get((key.stageId, key.stageAttemptId, assignment.executorId))
        .foreach(_ -= taskIndex)
      trackerMaster.foreach { tracker =>
        assignment.inboxes.foreach(tracker.releaseReceiveInbox(assignment.executorId, _))
      }
    }
  }

  def taskSetReady(taskSet: TaskSetManager): Boolean = {
    if (!enabled || !taskSet.taskSet.isPipelinedShuffleReader) {
      true
    } else {
      readyTaskIndices.keysIterator.exists { case (stageId, attemptId, _) =>
        stageId == taskSet.stageId && attemptId == taskSet.taskSet.stageAttemptId
      }
    }
  }

  def isReadyReader(taskSet: TaskSetManager): Boolean = {
    taskSet.taskSet.isPipelinedShuffleReader && taskSetReady(taskSet)
  }

  def isActivePureProducer(taskSet: TaskSetManager): Boolean = {
    !taskSet.isZombie && taskSet.tasksSuccessful < taskSet.numTasks &&
      taskSet.taskSet.isPipelinedShuffleProducer &&
      !taskSet.taskSet.isPipelinedShuffleReader
  }

  /**
   * Reserve enough CPU on each executor to attach one prepared reader in every active run epoch.
   *
   * Pure producers normally consume whole CPUs while prepared readers use a fractional charge.
   * If producers take the final whole CPU before an inbox becomes drain-ready, bounded transport
   * backpressure can stop every producer while the reader that would return credit has no
   * schedulable CPU. The old heap wire fallback hid that cycle by letting producers allocate past
   * the transport budget. Keep the small reservation only until a reader in that epoch is already
   * running on the executor; its own CPU charge then preserves the progress path.
   */
  def readerCpuReservations(
      taskSets: Iterable[TaskSetManager]): Map[(Option[String], String), BigDecimal] = {
    if (!enabled) return Map.empty

    def runEpoch(taskSet: TaskSetManager): Option[String] = {
      Option(taskSet.taskSet.properties).flatMap { properties =>
        Option(properties.getProperty(SparkContext.SPARK_PIPELINED_RUN_EPOCH))
      }
    }

    val activeReaders = taskSets.iterator.filter { taskSet =>
      !taskSet.isZombie && taskSet.taskSet.isPipelinedShuffleReader
    }.toSeq
    val readersByAttempt = activeReaders.map { taskSet =>
      (taskSet.stageId, taskSet.taskSet.stageAttemptId) -> taskSet
    }.toMap
    val result = new HashMap[(Option[String], String), BigDecimal]

    assignments.foreach { case (key, assignment) =>
      readersByAttempt.get((key.stageId, key.stageAttemptId)).foreach { reader =>
        val reservationKey = runEpoch(reader) -> assignment.executorId
        val hasRunningReader = activeReaders.exists { candidate =>
          runEpoch(candidate) == reservationKey._1 &&
            candidate.runningTasksOnExecutor(assignment.executorId) > 0
        }
        if (!hasRunningReader && reader.isTaskPendingForOffer(key.taskIndex)) {
          val configuredCpus = if (reader.taskSet.isPipelinedShuffleProducer) {
            readerProducerTaskCpus
          } else {
            readerTaskCpus
          }
          // Without an explicit fractional charge there is no CPU amount that can let a reader
          // overlap a whole-CPU producer (notably on a one-core executor). Preserve ordinary
          // scheduling in that case; the reservation is specifically the progress guarantee for
          // fractional prepared-reader execution.
          configuredCpus.filter(_ < 1).foreach { cpus =>
            result.updateWith(reservationKey) {
              case Some(current) => Some(current.max(cpus))
              case None => Some(cpus)
            }
          }
        }
      }
    }
    result.toMap
  }

  /** Topological reader depth inside one pipelined run epoch. */
  def readerDepths(taskSets: Iterable[TaskSetManager]): Map[TaskSetManager, Int] = {
    val active = taskSets.iterator.filter { taskSet =>
      !taskSet.isZombie && taskSet.taskSet.isPipelined
    }.toSeq
    val producerByShuffleId = active.flatMap { taskSet =>
      taskSet.taskSet.shuffleId.map(_ -> taskSet)
    }.toMap
    val depths = new HashMap[TaskSetManager, Int]
    val visiting = new HashSet[TaskSetManager]

    def depth(taskSet: TaskSetManager): Int = {
      depths.getOrElseUpdate(taskSet, {
        // Pipelined task graphs are acyclic. Keep this guard defensive so malformed metadata
        // cannot recurse forever in the task scheduler's resource-offer path.
        if (!visiting.add(taskSet)) {
          0
        } else {
          val parents = taskSet.taskSet.pipelinedReaderShuffleIds.distinct.flatMap(
            producerByShuffleId.get)
          val result = if (parents.isEmpty) 0 else 1 + parents.map(depth).max
          visiting -= taskSet
          result
        }
      })
    }

    active.foreach(depth)
    depths.toMap
  }

  def readerFrontierStarted(
      producer: TaskSetManager,
      taskSets: Iterable[TaskSetManager]): Boolean = {
    producer.taskSet.shuffleId.exists { shuffleId =>
      val directReaders = taskSets.iterator.filter { taskSet =>
        !taskSet.isZombie && taskSet.taskSet.isPipelinedShuffleReader &&
          taskSet.taskSet.pipelinedReaderShuffleIds.contains(shuffleId)
      }.toSeq
      // The producer TaskSet can be submitted before its direct consumer. Do not open the wider
      // sole-producer window until every submitted direct reader has actually started.
      directReaders.nonEmpty && directReaders.forall { reader =>
        reader.runningTasks > 0 || reader.tasksSuccessful > 0
      }
    }
  }

  /**
   * Whether every partition of a producer's submitted direct-reader frontier has a prepared
   * executor-owned inbox.
   *
   * A reader task may intentionally defer its compute attachment while another join input is
   * still being built. That must not hold an otherwise wide producer frontier at its conservative
   * startup window: executor-owned inbox preparation makes the producer route safe independently
   * of when reader compute attaches. The drain-ready signal intentionally controls only compute
   * attachment; waiting for it here makes a small shuffle hold producers at their conservative
   * window until every writer finishes. Tasks that have already launched or completed have a
   * route by construction. A pending retry or executor loss removes its assignment and makes the
   * frontier non-routable again until a fresh inbox is prepared.
   */
  def readerFrontierRoutable(
      producer: TaskSetManager,
      taskSets: Iterable[TaskSetManager]): Boolean = {
    producer.taskSet.shuffleId.exists { shuffleId =>
      val directReaders = taskSets.iterator.filter { taskSet =>
        !taskSet.isZombie && taskSet.taskSet.isPipelinedShuffleReader &&
          taskSet.taskSet.pipelinedReaderShuffleIds.contains(shuffleId)
      }.toSeq
      directReaders.nonEmpty && trackerMaster.isDefined && directReaders.forall { reader =>
        reader.tasks.indices.forall { taskIndex =>
          if (!reader.isTaskPendingForOffer(taskIndex)) {
            true
          } else {
            val key = ReaderKey(reader.stageId, reader.taskSet.stageAttemptId, taskIndex)
            assignments.get(key).exists { assignment =>
              val directInboxes = assignment.inboxes.filter(_.shuffleId == shuffleId)
              directInboxes.nonEmpty
            }
          }
        }
      }
    }
  }

  def producerLaunchAllowed(
      taskSet: TaskSetManager,
      activePureProducerStages: Int,
      readerFrontierRoutable: Boolean,
      readerFrontierStarted: Boolean,
      fairTaskLimit: Option[Int]): Boolean = {
    val pureProducer = taskSet.taskSet.isPipelinedShuffleProducer &&
      !taskSet.taskSet.isPipelinedShuffleReader
    val configuredTaskLimit = if (activePureProducerStages == 1 &&
        (readerFrontierRoutable || readerFrontierStarted)) {
      soleProducerMaxTasks.orElse(producerMaxTasks)
    } else if (readerFrontierRoutable && readerFrontierStarted &&
        expandedProducerMinActiveStages > 0 &&
        activePureProducerStages >= expandedProducerMinActiveStages) {
      expandedProducerMaxTasks.orElse(producerMaxTasks)
    } else {
      producerMaxTasks
    }
    val taskLimit = fairTaskLimit match {
      case Some(fairLimit) => Some(configuredTaskLimit.fold(fairLimit)(math.min(_, fairLimit)))
      case None => configuredTaskLimit
    }
    !enabled || !pureProducer || taskLimit.forall(taskSet.runningTasks < _)
  }

  def taskCpus(taskSet: TaskSet, profileTaskCpus: BigDecimal): BigDecimal = {
    if (taskSet.isPipelinedShuffleReader && taskSet.isPipelinedShuffleProducer) {
      readerProducerTaskCpus.getOrElse(profileTaskCpus)
    } else if (taskSet.isPipelinedShuffleReader) {
      readerTaskCpus.getOrElse(profileTaskCpus)
    } else {
      profileTaskCpus
    }
  }

  def removeTaskSet(taskSet: TaskSetManager): Unit = {
    assignments.keysIterator.filter { key =>
      key.stageId == taskSet.taskSet.stageId &&
        key.stageAttemptId == taskSet.taskSet.stageAttemptId
    }.toSeq.foreach { key =>
      assignments.remove(key).foreach { assignment =>
        trackerMaster.foreach { tracker =>
          assignment.inboxes.foreach(tracker.releaseReceiveInbox(assignment.executorId, _))
        }
      }
    }
  }

  def removeExecutor(executorId: String): Unit = {
    assignments.filterInPlace { case (_, assignment) => assignment.executorId != executorId }
    trackerMaster.foreach(_.removeReceiveExecutor(executorId))
  }
}

private object PipelinedShuffleTaskCoordinator {
  val INBOX_READY_REVIVE_COALESCE_MS = 10L
}
