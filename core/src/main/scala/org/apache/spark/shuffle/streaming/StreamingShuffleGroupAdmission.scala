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

import scala.collection.mutable

import org.apache.spark.SparkConf
import org.apache.spark.internal.config._
import org.apache.spark.scheduler.{Pool, TaskSetManager, WorkerOffer}

private[spark] case class PipelinedStageAdmission(
    stageId: Int,
    stageAttemptId: Int,
    numTasks: Int,
    reader: Boolean,
    producer: Boolean)

private[spark] case class PipelinedGroupAdmission(
    jobId: Int,
    stages: Seq[PipelinedStageAdmission])

/**
 * CPU-only reservations for finite pipelined groups. Called only under the task scheduler lock.
 * Registration precedes every member's submission. A complete group reserves reader placements
 * and a minimum rolling window for each pure producer. Producers may also use unreserved CPUs
 * in the scheduler's task-set order. Reserved but idle slots are charged to the owning pool,
 * and cannot be lent to non-preemptible tasks. No RPC waits occur here.
 */
private[spark] class StreamingShuffleGroupAdmission(
    conf: SparkConf,
    taskCpus: TaskSetManager => BigDecimal,
    runningOn: (TaskSetManager, String) => Int) {
  val enabled: Boolean = conf.get(STREAMING_SHUFFLE_GROUP_ADMISSION_ENABLED)
  private val minimumProducers = conf.get(STREAMING_SHUFFLE_GROUP_PRODUCER_WINDOW)
  private val maxGroups = conf.get(STREAMING_SHUFFLE_GROUP_MAX_CONCURRENT)
  private val agingMs = conf.get(STREAMING_SHUFFLE_GROUP_RESERVATION_DELAY)
  private val timeoutMs = conf.get(STREAMING_SHUFFLE_GROUP_ADMISSION_TIMEOUT)

  private case class Slot(stageId: Int, index: Int, executorId: String)
  private class Group(val descriptor: PipelinedGroupAdmission) {
    private val stagesById = descriptor.stages.iterator.map(stage => stage.stageId -> stage).toMap
    private val readerStages = descriptor.stages.filter(_.reader)
    val managers = mutable.HashMap.empty[Int, TaskSetManager]
    val finished = mutable.HashSet.empty[Int]
    val slots = mutable.ArrayBuffer.empty[Slot]
    var admitted = false
    var failed = false
    var readyAt: Option[Long] = None
    var pool: Option[Pool] = None
    var charged = 0
    def allTaskSetsSubmitted: Boolean = descriptor.stages.forall { s =>
      s.numTasks == 0 || managers.contains(s.stageId)
    }
    def allStagesFinished: Boolean =
      descriptor.stages.forall(s => s.numTasks == 0 || finished(s.stageId))
    def allReadersLaunched: Boolean = readerStages.forall { s =>
      finished(s.stageId) || s.numTasks == 0 || managers.get(s.stageId).exists { m =>
        // A finished task leaves runningTasks before its result is processed asynchronously.
        // Startup is monotonic; pending results must not rearm the timeout or stop producers.
        m.taskAttempts.forall(_.nonEmpty)
      }
    }
    def stage(id: Int): PipelinedStageAdmission = stagesById(id)
  }
  private val groups = mutable.ArrayBuffer.empty[Group]
  private val byStage = mutable.HashMap.empty[Int, Group]
  private var receiveExecutors = Set.empty[String]

  def register(descriptors: Seq[PipelinedGroupAdmission]): Unit = {
    require(enabled, "Pipelined group admission is disabled")
    val stages = descriptors.flatMap(_.stages)
    require(stages.map(_.stageId).distinct.size == stages.size,
      "A stage cannot belong to multiple pipelined groups")
    require(stages.forall(s => !byStage.contains(s.stageId)),
      "Concurrent jobs cannot share a live reserved pipelined stage")
    descriptors.foreach { d =>
      val group = new Group(d)
      groups += group
      d.stages.foreach(s => byStage(s.stageId) = group)
    }
  }

  def submitted(manager: TaskSetManager): Unit = {
    if (manager.taskSet.pipelinedGroupAdmissionRequired && !contains(manager.stageId)) {
      manager.abort("Pipelined task set submitted without a registered group")
    }
    byStage.get(manager.stageId).foreach { g =>
      val s = g.stage(manager.stageId)
      if (s.stageAttemptId != manager.taskSet.stageAttemptId || s.numTasks != manager.numTasks ||
          s.reader != manager.taskSet.isPipelinedShuffleReader ||
          s.producer != manager.taskSet.isPipelinedShuffleProducer ||
          manager.taskSet.tasks.exists(_.isBarrier)) {
        fail(g, "Pipelined group task set does not match its registered descriptor")
        manager.abort("Pipelined group task set does not match its registered descriptor")
      } else if (g.failed) {
        manager.abort("Pipelined group admission already failed")
      } else {
        g.managers(manager.stageId) = manager
        g.pool match {
          case Some(pool) if pool ne manager.parent =>
            fail(g, "A reserved pipelined group must belong to a single scheduling pool")
          case _ => g.pool = Some(manager.parent)
        }
      }
    }
  }

  def contains(stageId: Int): Boolean = byStage.contains(stageId)
  def admitted(stageId: Int): Boolean =
    byStage.get(stageId).exists(g => g.admitted && !g.failed)

  def readerPlacement(stageId: Int, index: Int): Option[String] =
    byStage.get(stageId).filter(g => g.admitted && !g.failed).flatMap { g =>
      g.slots.find(s => s.stageId == stageId && s.index == index).map(_.executorId)
    }

  private def liveSlots(g: Group): Seq[Slot] = g.slots.filter { s =>
    !g.finished(s.stageId) && (!g.stage(s.stageId).reader ||
      !g.managers(s.stageId).successful(s.index))
  }.toSeq

  private def idleSlots(g: Group, executorId: String, stageId: Int): Int = {
    val allocated = liveSlots(g).count(s => s.executorId == executorId && s.stageId == stageId)
    math.max(0, allocated - g.managers.get(stageId).map(runningOn(_, executorId)).getOrElse(0))
  }

  private def idleCpus(g: Group, executorId: String): BigDecimal = {
    g.managers.iterator.map { case (stageId, manager) =>
      taskCpus(manager) * idleSlots(g, executorId, stageId)
    }.sum
  }

  private def allIdleCpus(executorId: String): BigDecimal =
    groups.iterator.filterNot(_.failed).map(idleCpus(_, executorId)).sum

  /** Charge reservations as well as running tasks, without double-counting launched tasks. */
  def syncPoolAccounting(): Unit = groups.foreach { g =>
    val desired = if (g.failed) 0 else liveSlots(g).groupBy(_.executorId).iterator.map {
      case (executorId, _) =>
        g.managers.keysIterator.map(idleSlots(g, executorId, _)).sum
    }.sum
    g.pool.foreach { pool =>
      pool.addReservedTasks(desired - g.charged)
    }
    g.charged = desired
  }

  private def fail(g: Group, reason: String): Unit = {
    if (g.failed) return
    g.failed = true
    g.slots.clear()
    syncPoolAccounting()
    g.managers.values.toSeq.filter(_.isActiveForScheduling).foreach(_.abort(reason))
  }

  def expire(now: Long): Unit = groups.toSeq.filter { g =>
    !g.failed && (!g.admitted || !g.allReadersLaunched) &&
      g.readyAt.exists(t => now - t >= timeoutMs)
  }.foreach(g => fail(g, "Timed out waiting for pipelined group admission or reader startup"))

  /**
   * Select new reservation targets in the pool's task-set order. A partially reserved target
   * continues accumulating free CPUs; BSP may use only the unreserved remainder. Reservations
   * start only after all task sets are submitted, so materialized prerequisites hold no slots.
   */
  def prepare(
      ordered: Seq[TaskSetManager],
      offers: IndexedSeq[WorkerOffer],
      availableCpus: Array[BigDecimal],
      receiveExecutors: Set[String],
      now: Long): Unit = {
    this.receiveExecutors = receiveExecutors
    groups.toSeq.filter(g => !g.failed && g.managers.values.exists { m =>
      !m.isActiveForScheduling && m.numCompletedTasks != m.numTasks
    }).foreach(g => fail(g, "A reserved pipelined task set was aborted"))
    groups.filter(g => g.allTaskSetsSubmitted && !g.failed && g.readyAt.isEmpty)
      .foreach(_.readyAt = Some(now))
    expire(now)
    val candidates = ordered.flatMap(m => byStage.get(m.stageId)).distinct
      .filter(g => g.allTaskSetsSubmitted && !g.failed && !g.admitted && !g.allStagesFinished)
      .filter { g =>
        g.slots.nonEmpty || ordered.headOption.exists(m => g.managers.contains(m.stageId)) ||
          g.readyAt.exists(t => now - t >= agingMs)
      }
    val active = groups.count(g => !g.failed && !g.allStagesFinished &&
      (g.admitted || g.slots.nonEmpty))
    // Accumulate one reservation at a time. The next offer re-evaluates pool entitlement
    // after this reservation is charged, rather than selecting several groups from one pool.
    val partial = candidates.filter(_.slots.nonEmpty)
    val targets = if (partial.nonEmpty) partial.take(1) else {
      candidates.filter(_.slots.isEmpty).take(math.min(1, math.max(0, maxGroups - active)))
    }
    targets.foreach(reserve(_, offers, availableCpus))
    syncPoolAccounting()
  }

  /** Reserve reader placements and each producer's minimum without borrowing other slots. */
  private def reserve(
      group: Group,
      offers: IndexedSeq[WorkerOffer],
      availableCpus: Array[BigDecimal]): Unit = {
    val demand = group.descriptor.stages.sortBy(s => (!s.reader, s.stageId)).flatMap { s =>
      val count = if (s.reader) s.numTasks else math.min(minimumProducers, s.numTasks)
      (0 until count).map(i => (s, i))
    }
    demand.foreach { case (stage, index) =>
      if (!group.slots.exists(s => s.stageId == stage.stageId && s.index == index)) {
        val manager = group.managers(stage.stageId)
        val cpus = taskCpus(manager)
        val compatible = offers.indices.filter { i =>
          val o = offers(i)
          receiveExecutors(o.executorId) &&
            o.resourceProfileId == manager.taskSet.resourceProfileId &&
            availableCpus(i) - allIdleCpus(o.executorId) >= cpus &&
            (if (stage.reader) {
              manager.canPrepareReaderOnExecutor(index, o.executorId, o.host)
            } else {
              (0 until manager.numTasks).forall { taskIndex =>
                manager.canPrepareReaderOnExecutor(taskIndex, o.executorId, o.host)
              }
            })
        }
        compatible.sortBy(i => group.slots.count(_.executorId == offers(i).executorId))
          .headOption.foreach { i =>
            group.slots += Slot(stage.stageId, index, offers(i).executorId)
          }
      }
    }
    group.admitted = group.slots.size == demand.size
  }

  def launchAllowed(manager: TaskSetManager, executorId: String, freeCpus: BigDecimal): Boolean = {
    if (!enabled) return true
    val cpus = taskCpus(manager)
    byStage.get(manager.stageId) match {
      case Some(g) =>
        val reader = g.stage(manager.stageId).reader
        val ownIdle = idleSlots(g, executorId, manager.stageId)
        // The minimum is a liveness reservation, not a throughput cap. Extra producers
        // consume only unreserved offers, never another branch's or group's idle slots.
        // Their normal running-task accounting disappears when they finish; no extra
        // reservation is retained, so subsequent offers can serve other pools or BSP.
        g.admitted && !g.failed &&
          (reader || g.allReadersLaunched) &&
          (ownIdle > 0 || (!reader && receiveExecutors(executorId))) &&
          freeCpus - allIdleCpus(executorId) + cpus * ownIdle >= cpus
      case None => !manager.taskSet.pipelinedGroupAdmissionRequired &&
        freeCpus - allIdleCpus(executorId) >= cpus
    }
  }

  def orderWithinGroups(taskSets: Seq[TaskSetManager]): Seq[TaskSetManager] = {
    val queues = taskSets.filter(m => contains(m.stageId))
      .groupBy(m => byStage(m.stageId)).map { case (g, members) =>
        g -> mutable.Queue.from(members.sortBy(m => !m.taskSet.isPipelinedShuffleReader))
      }
    taskSets.map(m => byStage.get(m.stageId).map(queues(_).dequeue()).getOrElse(m))
  }

  def finishStage(manager: TaskSetManager): Unit = byStage.get(manager.stageId).foreach { g =>
    if (manager.numCompletedTasks != manager.numTasks) {
      fail(g, "A member of the reserved pipelined group did not complete successfully")
    } else {
      g.finished += manager.stageId
      syncPoolAccounting()
    }
  }

  def cancelStage(stageId: Int): Unit = byStage.get(stageId).foreach { g =>
    fail(g, "A member of the reserved pipelined group was cancelled")
  }

  def removeExecutor(executorId: String): Unit = groups.toSeq.filter { g =>
    !g.failed && (g.slots.exists(_.executorId == executorId) ||
      // Completed producers can still own shuffle state needed by live readers or replay.
      g.managers.values.exists(_.taskAttempts.iterator.flatten.exists(_.executorId == executorId)))
  }.foreach(g => fail(g, s"Pipelined group lost participating executor $executorId"))

  def releaseJob(jobId: Int): Unit = {
    groups.filter(_.descriptor.jobId == jobId).toSeq.foreach { g =>
      g.pool.foreach(_.addReservedTasks(-g.charged))
      g.descriptor.stages.foreach(s => byStage.remove(s.stageId))
      groups -= g
    }
  }

  def close(): Unit = groups.map(_.descriptor.jobId).toSeq.distinct.foreach(releaseJob)
  private[spark] def reservedSlots: Int = groups.iterator.map(liveSlots(_).size).sum
}
