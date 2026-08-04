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

import scala.collection.mutable.{HashMap, HashSet, ListBuffer}

import org.apache.spark.{PipelinedShuffleDependency, SparkConf, SparkException}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.LogKeys.{CONFIG, GROUP_ID, REASON, SHUFFLE_IDS, STAGE_ATTEMPT_ID, STAGE_ID}
import org.apache.spark.internal.config
import org.apache.spark.rdd.RDD
import org.apache.spark.shuffle.{FullGroupResidency, PipelinedGroupSchedulingRequirements,
  PipelinedShuffleControlPlane, PipelinedShuffleGroupMetadata, PipelinedShuffleManager,
  PipelinedShuffleSchedulingProvider, PipelinedShuffleStageMetadata,
  ReaderResidencyWithElasticProducers}

private[scheduler] sealed trait PipelinedGroupAdmissionDecision

private[scheduler] case object PipelinedGroupReady extends PipelinedGroupAdmissionDecision

private[scheduler] case class WaitForPipelinedGroup(reason: String)
  extends PipelinedGroupAdmissionDecision

private[scheduler] case class RejectPipelinedGroup(reason: String)
  extends PipelinedGroupAdmissionDecision

private[scheduler] case class PipelinedTaskSetInfo(
    isMember: Boolean = false,
    groupStageCount: Int = 0,
    groupAttemptId: Option[String] = None,
    schedulingRequirements: PipelinedGroupSchedulingRequirements =
      PipelinedGroupSchedulingRequirements(),
    isReader: Boolean = false,
    isProducer: Boolean = false,
    producerShuffleIds: Seq[Int] = Seq.empty,
    readerShuffleIds: Seq[Int] = Seq.empty)

/**
 * Owns the topology, admission, publication, and lifecycle state of pipelined stage groups.
 *
 * DAGScheduler remains the authority for stage and job transitions. This component derives group
 * state from that authoritative stage graph and returns decisions to DAGScheduler; it never submits
 * or completes a stage on its own.
 */
private[scheduler] final class PipelinedStageGroupScheduler(
    conf: SparkConf,
    shuffleManager: () => PipelinedShuffleManager,
    allStages: () => Iterable[Stage],
    stageById: Int => Option[Stage],
    isStageActive: Stage => Boolean,
    readsPipelinedShuffle: RDD[_] => Boolean,
    maxConcurrentTasks: Int => Int,
    outstandingTasksForOtherWork: (Int, Set[Int]) => Int,
    submitTaskSets: (Seq[TaskSet], PipelinedGroupSchedulingRequirements) => Unit)
  extends Logging {

  private val groupStageIds = new HashMap[String, Set[Int]]
  private val stageIdToGroupId = new HashMap[Int, String]
  private val groupAttemptIds = new HashMap[String, String]
  private val registeredGroups = new HashSet[String]
  private val admittedGroups = new HashSet[String]
  private val requirementsByGroupAttempt =
    new HashMap[String, PipelinedGroupSchedulingRequirements]
  private val pendingTaskSetsByGroup = new HashMap[String, ListBuffer[TaskSet]]

  private var submitScopeDepth = 0
  private var warnedSlotCheckDisabled = false

  def isEmpty: Boolean = {
    groupStageIds.isEmpty &&
      stageIdToGroupId.isEmpty &&
      groupAttemptIds.isEmpty &&
      registeredGroups.isEmpty &&
      admittedGroups.isEmpty &&
      requirementsByGroupAttempt.isEmpty &&
      pendingTaskSetsByGroup.isEmpty
  }

  def isProducer(stage: Stage): Boolean = stage match {
    case mapStage: ShuffleMapStage =>
      mapStage.shuffleDep.isInstanceOf[PipelinedShuffleDependency[_, _, _]]
    case _ => false
  }

  def isMember(stage: Stage): Boolean = {
    isProducer(stage) || readsPipelinedShuffle(stage.rdd)
  }

  def beginSubmitScope(): Boolean = {
    val outermost = submitScopeDepth == 0
    submitScopeDepth += 1
    outermost
  }

  def endSubmitScope(outermost: Boolean): Unit = {
    submitScopeDepth -= 1
    if (outermost) {
      publishReadyTaskSetGroups()
    }
  }

  def queueTaskSetIfNeeded(taskSet: TaskSet): Boolean = {
    if (submitScopeDepth == 0 || !taskSet.isPipelined) {
      return false
    }

    val groupId = taskSet.pipelinedGroupId.getOrElse {
      throw SparkException.internalError(
        s"Pipelined TaskSet ${taskSet.id} is missing its attempt-scoped group id")
    }
    val pending = pendingTaskSetsByGroup.getOrElseUpdate(groupId, new ListBuffer[TaskSet])
    pending.indexWhere(existing =>
      existing.stageId == taskSet.stageId &&
        existing.stageAttemptId == taskSet.stageAttemptId) match {
      case -1 => pending += taskSet
      case index => pending(index) = taskSet
    }
    true
  }

  def taskSetInfo(stage: Stage): PipelinedTaskSetInfo = {
    if (!isMember(stage)) {
      return PipelinedTaskSetInfo()
    }

    val group = groupOf(stage)
    PipelinedTaskSetInfo(
      isMember = true,
      groupStageCount = group.size,
      groupAttemptId = Some(groupAttemptId(group)),
      schedulingRequirements = schedulingRequirements(group),
      isReader = stage.parents.exists(isProducer),
      isProducer = isProducer(stage),
      producerShuffleIds = producerShuffleIds(stage),
      readerShuffleIds = parentShuffleIds(stage))
  }

  def admissionDecision(stage: Stage): PipelinedGroupAdmissionDecision = {
    if (!slotCheckEnabled) {
      return PipelinedGroupReady
    }

    val group = groupOf(stage)
    val totalSlots = maxConcurrentTasks(stage.resourceProfileId)
    val occupiedByOthers =
      outstandingTasksForOtherWork(stage.resourceProfileId, group.map(_.id))
    val freeSlots = math.max(0, totalSlots - occupiedByOthers)

    schedulingRequirements(group).residencyPolicy match {
      case FullGroupResidency =>
        val demand = group.toSeq.map(_.numTasks).sum
        if (demand > freeSlots) {
          RejectPipelinedGroup(
            s"Cannot co-schedule pipelined stage group: needs $demand concurrent task slots " +
              s"but only $freeSlots are currently free.")
        } else {
          PipelinedGroupReady
        }

      case policy: ReaderResidencyWithElasticProducers =>
        readerResidencyDecision(
          group, policy, totalSlots, occupiedByOthers, freeSlots)
    }
  }

  def register(stage: Stage): Option[String] = {
    if (!isMember(stage)) {
      return None
    }

    val group = groupOf(stage)
    val id = groupId(group)
    val metadata = groupMetadata(group)
    val firstRegistration = registeredGroups.add(id)
    groupStageIds(id) = group.map(_.id).toSet
    groupAttemptIds(id) = metadata.groupAttemptId
    group.foreach(groupStage => stageIdToGroupId(groupStage.id) = id)
    controlPlane.foreach(_.registerPipelinedShuffleGroup(metadata))
    if (firstRegistration) {
      logInfo(log"Registered pipelined shuffle group ${MDC(GROUP_ID, id)} attempt " +
        log"${MDC(STAGE_ATTEMPT_ID, metadata.groupAttemptId)} with stages " +
        log"${MDC(STAGE_ID, metadata.stages.map(_.stageId))} and shuffles " +
        log"${MDC(SHUFFLE_IDS, metadata.stages.flatMap(_.shuffleId))}")
    }
    Some(id)
  }

  def admit(stage: Stage): Unit = {
    register(stage).foreach { id =>
      if (admittedGroups.add(id)) {
        val attemptId = groupAttemptIds(id)
        controlPlane.foreach(_.admitPipelinedShuffleGroup(attemptId))
        logInfo(log"Admitted pipelined shuffle group ${MDC(GROUP_ID, id)} attempt " +
          log"${MDC(STAGE_ATTEMPT_ID, attemptId)}")
      }
    }
  }

  def completeIfReady(stage: Stage): Boolean = {
    stageIdToGroupId.get(stage.id).exists { id =>
      val stillActive = groupStageIds.getOrElse(id, Set.empty).exists { stageId =>
        stageById(stageId).exists(isStageActive)
      }
      if (!stillActive && registeredGroups.contains(id)) {
        val attemptId = groupAttemptIds(id)
        controlPlane.foreach(_.completePipelinedShuffleGroup(attemptId))
        logInfo(log"Completed pipelined shuffle group ${MDC(GROUP_ID, id)} attempt " +
          log"${MDC(STAGE_ATTEMPT_ID, attemptId)}")
        removeGroup(id)
        true
      } else {
        false
      }
    }
  }

  def abort(stage: Stage, reason: String): Boolean = {
    val id = stageIdToGroupId.get(stage.id).orElse {
      if (isMember(stage)) Some(groupId(groupOf(stage))) else None
    }
    id.exists { groupId =>
      val attemptId = groupAttemptIds.getOrElse(groupId, groupId)
      val known = registeredGroups.contains(groupId) ||
        admittedGroups.contains(groupId) ||
        groupStageIds.contains(groupId) ||
        pendingTaskSetsByGroup.contains(attemptId)
      if (known) {
        controlPlane.foreach(_.abortPipelinedShuffleGroup(attemptId, reason))
        logWarning(log"Aborted pipelined shuffle group ${MDC(GROUP_ID, groupId)} attempt " +
          log"${MDC(STAGE_ATTEMPT_ID, attemptId)}: ${MDC(REASON, reason)}")
        removeGroup(groupId)
        true
      } else {
        false
      }
    }
  }

  def removeStage(stageId: Int): Unit = {
    stageIdToGroupId.get(stageId).foreach { id =>
      stageIdToGroupId -= stageId
      val remaining = groupStageIds.getOrElse(id, Set.empty) - stageId
      if (remaining.isEmpty) {
        if (registeredGroups.contains(id)) {
          val attemptId = groupAttemptIds.getOrElse(id, id)
          controlPlane.foreach(_.completePipelinedShuffleGroup(attemptId))
          logInfo(log"Completed pipelined shuffle group ${MDC(GROUP_ID, id)} attempt " +
            log"${MDC(STAGE_ATTEMPT_ID, attemptId)} during cleanup")
        }
        removeGroup(id)
      } else {
        groupStageIds(id) = remaining
      }
    }
  }

  private def publishReadyTaskSetGroups(): Unit = {
    val readyGroupIds = pendingTaskSetsByGroup.iterator.collect {
      case (id, taskSets) if taskSets.nonEmpty &&
          taskSets.map(_.pipelinedGroupStageCount).distinct == Seq(taskSets.size) =>
        id
    }.toSeq.sorted

    readyGroupIds.foreach { id =>
      val taskSets = pendingTaskSetsByGroup.remove(id).get.toSeq
      val requirements = taskSets.map(_.pipelinedGroupSchedulingRequirements).distinct
      if (requirements.size != 1) {
        throw SparkException.internalError(
          s"Pipelined group $id has inconsistent scheduling requirements: " +
            requirements.mkString("[", ", ", "]"))
      }
      submitTaskSets(taskSets, requirements.head)
    }
  }

  private def slotCheckEnabled: Boolean = {
    val enabled = conf.get(config.PIPELINED_GROUP_SLOT_CHECK_ENABLED)
    if (!enabled && !warnedSlotCheckDisabled) {
      warnedSlotCheckDisabled = true
      logWarning(log"${MDC(CONFIG, config.PIPELINED_GROUP_SLOT_CHECK_ENABLED.key)}=false: " +
        log"pipelined-group admission is not checking free slots. This is safe only if " +
        log"capacity is reserved out-of-band; otherwise a group that cannot co-fit may deadlock.")
    }
    enabled
  }

  private def readerResidencyDecision(
      group: Set[Stage],
      policy: ReaderResidencyWithElasticProducers,
      totalSlots: Int,
      occupiedByOthers: Int,
      freeSlots: Int): PipelinedGroupAdmissionDecision = {
    val metadata = groupMetadata(group)
    val demand = readerResidencyDemand(group, policy)
    val readerSlots = demand.readerSlots
    val producerSlots = demand.producerSlots
    val requiredSlots = demand.totalSlots
    val managerName = shuffleManager().getClass.getName

    if (requiredSlots > totalSlots) {
      RejectPipelinedGroup(
        s"Cannot admit pipelined shuffle group ${metadata.groupId}: incremental shuffle manager " +
          s"$managerName requires all $readerSlots reader task(s) in the largest transitive " +
          s"reader frontier to be resident and at least $producerSlots producer task slot(s) " +
          s"to remain available, but this resource profile has only $totalSlots task slot(s). " +
          s"Increase Spark task-slot capacity for this resource profile, reduce resident reader " +
          s"stages, or lower the pipelined shuffle partition count; otherwise push-based shuffle " +
          s"readers can occupy every slot while producers never launch.")
    } else if (requiredSlots > freeSlots) {
      WaitForPipelinedGroup(
        s"Deferring pipelined shuffle group ${metadata.groupId}: incremental shuffle manager " +
          s"$managerName requires all $readerSlots reader task(s) in the largest transitive " +
          s"reader frontier to be resident and at least $producerSlots producer task slot(s) " +
          s"to remain available; this resource profile has $totalSlots task slot(s), but only " +
          s"$freeSlots are currently free because $occupiedByOthers task(s) are running for " +
          s"other work. The group will be reconsidered when running stages finish.")
    } else {
      PipelinedGroupReady
    }
  }

  private case class ReaderResidencyDemand(readerSlots: Int, producerSlots: Int) {
    def totalSlots: Int = readerSlots + producerSlots
  }

  private def readerResidencyDemand(
      group: Set[Stage],
      policy: ReaderResidencyWithElasticProducers): ReaderResidencyDemand = {
    val demands = readerResidencyFrontiers(group).map { case (readers, producers) =>
      ReaderResidencyDemand(
        readers.toSeq.map(_.numTasks).sum,
        producerSlots(producers, policy.minProducerTasksPerStage))
    }
    if (demands.isEmpty) ReaderResidencyDemand(0, 0) else demands.maxBy(_.totalSlots)
  }

  private def readerResidencyFrontiers(
      group: Set[Stage]): Seq[(Set[Stage], Seq[Stage])] = {
    val producers = group.toSeq.filter(stage => isProducer(stage) && stage.numTasks > 0)
    producers
      .groupBy(producer => transitiveReaders(producer, group).map(_.id).toSeq.sorted)
      .collect {
        case (readerIds, frontierProducers) if readerIds.nonEmpty =>
          val readerIdSet = readerIds.toSet
          (group.filter(stage => readerIdSet.contains(stage.id)), frontierProducers)
      }
      .toSeq
  }

  private def producerSlots(producers: Seq[Stage], target: Int): Int = {
    if (target <= 1) {
      producers.size
    } else if (producers.isEmpty) {
      0
    } else {
      producers.map(producer => math.min(producer.numTasks, target)).max
    }
  }

  private def groupOf(stage: Stage): Set[Stage] = {
    val group = new HashSet[Stage]
    val toVisit = new ListBuffer[Stage]
    toVisit += stage
    while (toVisit.nonEmpty) {
      val current = toVisit.remove(0)
      if (group.add(current)) {
        current.parents.collect { case producer if isProducer(producer) => producer }
          .foreach(toVisit += _)
        allStages().iterator.foreach { candidate =>
          if (!group.contains(candidate) && candidate.parents.contains(current) &&
              isProducer(current)) {
            toVisit += candidate
          }
        }
      }
    }
    group.toSet
  }

  private def transitiveReaders(producer: Stage, group: Set[Stage]): Set[Stage] = {
    val readers = new HashSet[Stage]
    val toVisit = new ListBuffer[Stage]
    toVisit ++= directReaders(producer, group)
    while (toVisit.nonEmpty) {
      val reader = toVisit.remove(0)
      if (readers.add(reader) && isProducer(reader)) {
        toVisit ++= directReaders(reader, group)
      }
    }
    readers.toSet
  }

  private def directReaders(producer: Stage, group: Set[Stage]): Set[Stage] = {
    val shuffleIds = producerShuffleIds(producer).toSet
    if (shuffleIds.isEmpty) {
      Set.empty
    } else {
      group.filter(stage => parentShuffleIds(stage).exists(shuffleIds.contains))
    }
  }

  private def producerShuffleIds(stage: Stage): Seq[Int] = stage match {
    case mapStage: ShuffleMapStage if isProducer(mapStage) => Seq(mapStage.shuffleDep.shuffleId)
    case _ => Seq.empty
  }

  private def parentShuffleIds(stage: Stage): Seq[Int] = {
    stage.parents.collect {
      case mapStage: ShuffleMapStage if isProducer(mapStage) => mapStage.shuffleDep.shuffleId
    }.toSeq
  }

  private def schedulingRequirements(
      group: Set[Stage]): PipelinedGroupSchedulingRequirements = {
    val metadata = groupMetadata(group)
    requirementsByGroupAttempt.getOrElseUpdate(metadata.groupAttemptId, {
      val configuredPerExecutorLimit =
        Option(conf.get(config.SCHEDULER_PIPELINED_GROUP_MAX_RUNNING_TASKS_PER_EXECUTOR))
          .filter(_ > 0)
      val declared = schedulingProvider
        .map(_.schedulingRequirements(metadata))
        .getOrElse(PipelinedGroupSchedulingRequirements())
      declared.copy(
        maxRunningTasksPerExecutor =
          declared.maxRunningTasksPerExecutor.orElse(configuredPerExecutorLimit))
    })
  }

  private def groupMetadata(group: Set[Stage]): PipelinedShuffleGroupMetadata = {
    PipelinedShuffleGroupMetadata(
      groupId = groupId(group),
      groupAttemptId = groupAttemptId(group),
      stages = group.toSeq.sortBy(_.id).map(stageMetadata))
  }

  private def stageMetadata(stage: Stage): PipelinedShuffleStageMetadata = {
    PipelinedShuffleStageMetadata(
      stageId = stage.id,
      attemptId = stage.latestInfo.attemptNumber(),
      numTasks = stage.numTasks,
      shuffleId = producerShuffleIds(stage).headOption,
      pipelinedParentShuffleIds = parentShuffleIds(stage))
  }

  private def groupId(group: Set[Stage]): String = {
    group.toSeq.map(_.id).sorted.mkString("stages-", "-", "")
  }

  private def groupAttemptId(group: Set[Stage]): String = {
    val id = groupId(group)
    groupAttemptIds.getOrElseUpdate(id, {
      group.toSeq
        .sortBy(_.id)
        .map(stage => s"${stage.id}.${stage.latestInfo.attemptNumber()}")
        .mkString("stages-", "-", "")
    })
  }

  private def removeGroup(id: String): Unit = {
    groupAttemptIds.get(id).foreach { attemptId =>
      pendingTaskSetsByGroup -= attemptId
      requirementsByGroupAttempt -= attemptId
    }
    groupStageIds.remove(id).getOrElse(Set.empty).foreach { stageId =>
      if (stageIdToGroupId.get(stageId).contains(id)) {
        stageIdToGroupId -= stageId
      }
    }
    registeredGroups -= id
    admittedGroups -= id
    groupAttemptIds -= id
  }

  private def controlPlane: Option[PipelinedShuffleControlPlane] = shuffleManager() match {
    case value: PipelinedShuffleControlPlane => Some(value)
    case _ => None
  }

  private def schedulingProvider: Option[PipelinedShuffleSchedulingProvider] =
    shuffleManager() match {
      case value: PipelinedShuffleSchedulingProvider => Some(value)
      case _ => None
    }
}
