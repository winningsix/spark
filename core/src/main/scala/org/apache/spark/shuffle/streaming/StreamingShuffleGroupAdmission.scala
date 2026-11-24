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
import org.apache.spark.internal.Logging
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
    runningOn: (TaskSetManager, String) => Int) extends Logging {
  val enabled: Boolean = conf.get(STREAMING_SHUFFLE_GROUP_ADMISSION_ENABLED)
  private val minimumProducers = conf.get(STREAMING_SHUFFLE_GROUP_PRODUCER_WINDOW)
  private val maxGroups = conf.get(STREAMING_SHUFFLE_GROUP_MAX_CONCURRENT)
  // The explicit group limit always applies. In capacity-driven mode an additional group
  // can use the residual CPU only if every one of its placements fits in the current offer.
  private val capacityAdmission =
    conf.getBoolean("spark.shuffle.streaming.groupAdmission.capacitySharing.enabled", false)
  private val groupLimit =
    if (capacityAdmission && !conf.contains(STREAMING_SHUFFLE_GROUP_MAX_CONCURRENT.key)) {
      Int.MaxValue
    } else maxGroups
  private val agingMs = conf.get(STREAMING_SHUFFLE_GROUP_RESERVATION_DELAY)
  private val timeoutMs = conf.get(STREAMING_SHUFFLE_GROUP_ADMISSION_TIMEOUT)
  private val readyStartEnabled =
    conf.getBoolean("spark.shuffle.streaming.groupAdmission.readyStart.enabled", false) &&
      conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED) &&
      conf.get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES) == 0L
  private val balanceReaders =
    conf.getBoolean("spark.shuffle.streaming.groupAdmission.balanceReaders", true)

  private case class Slot(stageId: Int, index: Int, executorId: String)
  private class Group(val descriptor: PipelinedGroupAdmission) {
    private val stagesById = descriptor.stages.iterator.map(stage => stage.stageId -> stage).toMap
    private val readerStages = descriptor.stages.filter(_.reader)
    val managers = mutable.HashMap.empty[Int, TaskSetManager]
    val finished = mutable.HashSet.empty[Int]
    val slots = mutable.ArrayBuffer.empty[Slot]
    var admitted = false
    var failed = false
    var useReadyStart = false
    var receivePrepared = false
    def producerMayStart: Boolean = if (useReadyStart) receivePrepared else allReadersLaunched
    var readyAt: Option[Long] = None
    var pool: Option[Pool] = None
    var charged = 0
    // Live-slot table cache. Live slots change only when slots are added or cleared, a stage
    // finishes, or a reader task succeeds; the key captures all three. Recomputing the table on
    // every call made each status update and launch O(slots) per (executor, stage) pair, which
    // serialized ~1000-task groups on the driver's scheduler thread for tens of seconds.
    var liveKey: (Int, Int, Int) = (-1, -1, -1)
    var liveCache: Seq[Slot] = Nil
    var liveCount: Map[(String, Int), Int] = Map.empty
    var liveExecutors: Set[String] = Set.empty
    var placementKey = -1
    var placement: Map[(Int, Int), String] = Map.empty
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

  def loanStages(stageId: Int): Set[Int] = byStage.get(stageId) match {
    case Some(g) if g.admitted && !g.failed => g.descriptor.stages.iterator.map(_.stageId).toSet
    case Some(_) => Set.empty
    case None => Set(stageId)
  }

  def contains(stageId: Int): Boolean = byStage.contains(stageId)
  def admitted(stageId: Int): Boolean =
    byStage.get(stageId).exists(g => g.admitted && !g.failed)

  def waitsForData(stageId: Int): Boolean =
    byStage.get(stageId).exists(g => g.admitted && g.useReadyStart && !g.failed)

  /** Preparation acknowledges a bounded inbox on its pinned executor for every reader. */
  def updatePreparedReaders(preparedCounts: collection.Map[(Int, Int), Int]): Unit = {
    groups.foreach { g =>
      if (g.admitted && g.useReadyStart && !g.receivePrepared && !g.failed) {
        val readers = g.descriptor.stages.filter(_.reader)
        if (readers.forall { reader =>
            preparedCounts.getOrElse((reader.stageId, reader.stageAttemptId), 0) == reader.numTasks
          }) {
          g.receivePrepared = true
          logInfo(s"Ready-start shuffle group job=${g.descriptor.jobId} " +
            s"preparedReaderStages=${readers.size}")
        }
      }
    }
  }

  def readerPlacement(stageId: Int, index: Int): Option[String] =
    byStage.get(stageId).filter(g => g.admitted && !g.failed).flatMap { g =>
      if (g.placementKey != g.slots.size) {
        g.placement = g.slots.iterator.map(s => (s.stageId, s.index) -> s.executorId).toMap
        g.placementKey = g.slots.size
      }
      g.placement.get((stageId, index))
    }

  private def refreshLive(g: Group): Unit = {
    val key = (g.slots.size, g.finished.size, g.managers.valuesIterator.map(_.numCompletedTasks).sum)
    if (key != g.liveKey) {
      g.liveCache = g.slots.filter { s =>
        !g.finished(s.stageId) && (!g.stage(s.stageId).reader ||
          !g.managers(s.stageId).successful(s.index))
      }.toSeq
      g.liveCount = g.liveCache.groupBy(s => (s.executorId, s.stageId)).view
        .mapValues(_.size).toMap
      g.liveExecutors = g.liveCache.iterator.map(_.executorId).toSet
      g.liveKey = key
    }
  }

  private def liveSlots(g: Group): Seq[Slot] = { refreshLive(g); g.liveCache }

  private def idleSlots(g: Group, executorId: String, stageId: Int): Int = {
    refreshLive(g)
    val allocated = g.liveCount.getOrElse((executorId, stageId), 0)
    if (allocated == 0) 0
    else math.max(0, allocated - g.managers.get(stageId).map(runningOn(_, executorId)).getOrElse(0))
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
    val desired = if (g.failed) 0 else {
      refreshLive(g)
      g.liveCount.keysIterator.map { case (executorId, stageId) =>
        idleSlots(g, executorId, stageId)
      }.sum
    }
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
    !g.failed && (!g.admitted || !g.producerMayStart) &&
      g.readyAt.exists(t => now - t >= timeoutMs)
  }.foreach(g => fail(g, "Timed out waiting for pipelined group admission or reader startup"))

  private def minimumReservationCpus(g: Group): BigDecimal =
    g.descriptor.stages.iterator.filter(_.numTasks > 0).map { stage =>
      val n = if (stage.reader) stage.numTasks else math.min(minimumProducers, stage.numTasks)
      taskCpus(g.managers(stage.stageId)) * n
    }.sum

  // Before the reservation delay expires, an admitted sibling already owns its minimum.
  // Another group in the same SQL execution and pool may use the residual offer atomically.
  // Keep the normal queue order for other pools, queries, and runnable block-shuffle stages.
  private def followsAdmittedSibling(g: Group, ordered: Seq[TaskSetManager]): Boolean = {
    if (!capacityAdmission || g.slots.nonEmpty) return false
    val ahead = ordered.takeWhile(m => !g.managers.contains(m.stageId))
    if (!ahead.exists(m => admitted(m.stageId))) return false
    def execution(m: TaskSetManager): Option[String] =
      Option(m.taskSet.properties).flatMap(p => Option(p.getProperty("spark.sql.execution.id")))
    val sql = g.managers.valuesIterator.flatMap(execution).nextOption()
    sql.isDefined && g.managers.valuesIterator.forall(m => execution(m) == sql) &&
      ahead.forall { m =>
        g.pool.contains(m.parent) && execution(m) == sql && (admitted(m.stageId) ||
          (!conf.getBoolean("spark.speculation", false) &&
            m.runningTasks + m.numCompletedTasks >= m.numTasks &&
            !m.tasks.exists(_.isBarrier) && !m.tasks.indices.exists(m.isTaskPendingForOffer)))
      }
  }

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
    lazy val offeredCpus = availableCpus.sum
    val candidates = ordered.flatMap(m => byStage.get(m.stageId)).distinct
      .filter(g => g.allTaskSetsSubmitted && !g.failed && !g.admitted && !g.allStagesFinished)
      .filter { g =>
        g.slots.nonEmpty || ordered.headOption.exists(m => g.managers.contains(m.stageId)) ||
          g.readyAt.exists(t => now - t >= agingMs) ||
          (capacityAdmission && offeredCpus >= minimumReservationCpus(g) &&
            followsAdmittedSibling(g, ordered))
      }
    val active = groups.count(g => !g.failed && !g.allStagesFinished &&
      (g.admitted || g.slots.nonEmpty))
    // Accumulate one reservation at a time. The next offer re-evaluates pool entitlement
    // after this reservation is charged, rather than selecting several groups from one pool.
    val partial = candidates.filter(_.slots.nonEmpty)
    val targets = if (partial.nonEmpty) partial.take(1) else {
      candidates.filter(_.slots.isEmpty).take(math.min(1, math.max(0, groupLimit - active)))
    }
    targets.foreach { g =>
      val requireComplete = capacityAdmission && active > 0 && g.slots.isEmpty
      // Most offers contain just one executor. Skip the placement walk when the aggregate
      // cannot possibly accommodate the group, then let the current group use that CPU.
      val enough = !requireComplete || {
        val free = offers.indices.iterator.filter(i => receiveExecutors(offers(i).executorId))
          .map(i => (availableCpus(i) - allIdleCpus(offers(i).executorId)).max(BigDecimal(0))).sum
        free >= minimumReservationCpus(g)
      }
      if (enough) {
        reserve(g, offers, availableCpus, relaxBalance = g.readyAt.exists(t => now - t >= agingMs))
        if (requireComplete && g.admitted && !ordered.headOption.exists(m =>
            g.managers.contains(m.stageId)) && g.readyAt.exists(t => now - t < agingMs)) {
          logInfo(s"Admitted sibling shuffle group job=${g.descriptor.jobId} " +
            s"before reservation delay with ${g.slots.size} available placements")
        }
        if (requireComplete && !g.admitted) {
          // Resource profile or locality constraints prevented an atomic reservation.
          g.slots.clear()
          g.liveKey = (-1, -1, -1)
          g.placementKey = -1
        }
      }
    }
    syncPoolAccounting()
  }

  /** Reserve reader placements and each producer's minimum without borrowing other slots. */
  private def reserve(
      group: Group,
      offers: IndexedSeq[WorkerOffer],
      availableCpus: Array[BigDecimal],
      relaxBalance: Boolean): Unit = {
    val demand = group.descriptor.stages.sortBy(s => (!s.reader, s.stageId)).flatMap { s =>
      val count = if (s.reader) s.numTasks else math.min(minimumProducers, s.numTasks)
      (0 until count).map(i => (s, i))
    }
    // Running tallies so each demanded slot costs O(offers), not O(offers * all slots).
    val placed = mutable.HashSet.empty[(Int, Int)] ++= group.slots.map(s => (s.stageId, s.index))
    val idleByExecutor = mutable.HashMap.empty[String, BigDecimal]
    def idleOn(executorId: String): BigDecimal =
      idleByExecutor.getOrElseUpdate(executorId, allIdleCpus(executorId))
    val slotsOnExecutor = mutable.HashMap.empty[String, Int] ++=
      group.slots.groupBy(_.executorId).view.mapValues(_.size)
    val producerOk = mutable.HashMap.empty[(Int, String), Boolean]
    // Spread each reader stage evenly. With fractional reader CPUs one executor can host many
    // readers, and reserving greedily on whichever executors happen to be free piles a stage
    // onto a few of them; those readers then share a few cores and become the stage's tail.
    // Keep unplaced readers pending instead, so the reservation accumulates as executors free.
    val receivers = math.max(1, offers.count(o => receiveExecutors(o.executorId)))
    val stageOnExecutor = mutable.HashMap.empty[(Int, String), Int] ++=
      group.slots.groupBy(s => (s.stageId, s.executorId)).view.mapValues(_.size)
    def readerCap(stage: PipelinedStageAdmission): Int =
      // The cap is a preference: once the group has waited past the aging delay, place
      // greedily again so a busy cluster cannot keep it from ever being admitted.
      if (balanceReaders && !relaxBalance) {
        math.max(1, math.ceil(stage.numTasks.toDouble / receivers).toInt)
      } else {
        Int.MaxValue
      }
    demand.foreach { case (stage, index) =>
      if (!placed.contains((stage.stageId, index))) {
        val manager = group.managers(stage.stageId)
        val cpus = taskCpus(manager)
        val cap = if (stage.reader) readerCap(stage) else Int.MaxValue
        val compatible = offers.indices.iterator.filter { i =>
          val o = offers(i)
          receiveExecutors(o.executorId) &&
            stageOnExecutor.getOrElse((stage.stageId, o.executorId), 0) < cap &&
            o.resourceProfileId == manager.taskSet.resourceProfileId &&
            availableCpus(i) - idleOn(o.executorId) >= cpus &&
            (if (stage.reader) {
              manager.canPrepareReaderOnExecutor(index, o.executorId, o.host)
            } else {
              producerOk.getOrElseUpdate((stage.stageId, o.executorId),
                (0 until manager.numTasks).forall { taskIndex =>
                  manager.canPrepareReaderOnExecutor(taskIndex, o.executorId, o.host)
                })
            })
        }
        compatible.minByOption(i => slotsOnExecutor.getOrElse(offers(i).executorId, 0))
          .foreach { i =>
            val executorId = offers(i).executorId
            group.slots += Slot(stage.stageId, index, executorId)
            placed += ((stage.stageId, index))
            slotsOnExecutor(executorId) = slotsOnExecutor.getOrElse(executorId, 0) + 1
            stageOnExecutor((stage.stageId, executorId)) =
              stageOnExecutor.getOrElse((stage.stageId, executorId), 0) + 1
            // A new reservation is idle until its task launches.
            idleByExecutor(executorId) = idleOn(executorId) + cpus
          }
      }
    }
    group.admitted = group.slots.size == demand.size
    if (group.admitted && readyStartEnabled) {
      val stages = group.descriptor.stages
      val readers = stages.filter(s => s.reader && !s.producer)
      val producers = stages.filter(s => s.producer && !s.reader)
      if (stages.forall(_.numTasks > 0)) {
        val single = readers.size == 1 && producers.size == 1 && stages.size == 2 &&
          group.managers(readers.head.stageId).taskSet.pipelinedReaderShuffleIds.size == 1
        val tree = stages.size > 2 && HashShuffleTree.enabled(conf) &&
          HashShuffleTree.supports(stages.map { s =>
            val tasks = group.managers(s.stageId).taskSet
            (s.stageId, tasks.pipelinedReaderShuffleIds, if (s.producer) tasks.shuffleId else None)
          })
        group.useReadyStart = single || tree
      }
    }
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
          (reader || g.producerMayStart) &&
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


private[spark] object HashShuffleTree {
  // One terminal stage, one consumer per live shuffle, and every stage reachable
  // from that terminal. Reject shared input, disconnected components and cycles.
  def supports(stages: Seq[(Int, Seq[Int], Option[Int])]): Boolean = {
    if (stages.size < 2) return false
    val byId = stages.iterator.map(x => x._1 -> x._2).toMap
    val outputs = stages.flatMap { case (id, _, out) => out.map(_ -> id) }.toMap
    val sinks = stages.collect { case (id, _, None) => id }
    if (byId.size != stages.size || sinks.size != 1 || outputs.size != stages.size - 1) {
      return false
    }
    val seen = mutable.HashSet.empty[Int]
    val pending = mutable.ArrayDeque(sinks.head)
    while (pending.nonEmpty) {
      val id = pending.removeLast()
      if (!seen.add(id)) return false
      val inputs = byId(id)
      if (!inputs.forall(outputs.contains)) return false
      inputs.foreach(shuffle => pending.append(outputs(shuffle)))
    }
    seen.size == stages.size
  }

  def enabled(conf: org.apache.spark.SparkConf): Boolean =
    conf.getBoolean("spark.shuffle.streaming.groupAdmission.enabled", false) &&
      conf.getBoolean("spark.shuffle.streaming.groupAdmission.readyStart.enabled", false) &&
      conf.getBoolean("spark.shuffle.streaming.groupAdmission.executorReady.enabled", false) &&
      conf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled", false) &&
      conf.getBoolean("spark.shuffle.streaming.readyQuota.enabled", false) &&
      conf.getBoolean("spark.shuffle.streaming.rawBufferPressureSpill.enabled", false) &&
      conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED) &&
      conf.get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES) == 0L
}
