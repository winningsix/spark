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

import scala.collection.mutable.{ArrayBuffer, HashMap, HashSet}

import org.apache.spark.shuffle.ReaderResidencyWithElasticProducers

private[scheduler] case class PipelinedTaskLaunchLimit(maxTasks: Int, reason: String)

/**
 * Low-level TaskSet scheduling policy for pipelined stage groups.
 *
 * TaskSchedulerImpl owns resource accounting and task launch. This class owns only the pipelined
 * group registry and the ordering/admission decisions layered on top of a normal resource offer.
 * Every method is called while holding TaskSchedulerImpl's monitor; this class adds no locking.
 */
private[scheduler] class PipelinedTaskSetScheduler(
    executorIds: () => Iterable[String],
    executorRunningTaskCount: String => Int) {

  private val taskSetsByGroup = new HashMap[String, HashSet[TaskSetManager]]

  def register(taskSet: TaskSetManager): Unit = {
    taskSet.taskSet.pipelinedGroupId.foreach { groupId =>
      taskSetsByGroup.getOrElseUpdate(groupId, new HashSet[TaskSetManager]) += taskSet
    }
  }

  def unregister(taskSet: TaskSetManager): Unit = {
    taskSet.taskSet.pipelinedGroupId.foreach { groupId =>
      taskSetsByGroup.get(groupId).foreach { taskSets =>
        taskSets -= taskSet
        if (taskSets.isEmpty) {
          taskSetsByGroup -= groupId
        }
      }
    }
  }

  def usesRoundRobin(taskSet: TaskSetManager): Boolean = {
    taskSet.taskSet.isPipelined && !taskSet.isBarrier
  }

  def offerIndices(
      taskSet: TaskSetManager,
      shuffledOffers: Seq[WorkerOffer]): IndexedSeq[Int] = {
    val indices = shuffledOffers.indices
    if (!usesRoundRobin(taskSet)) {
      indices
    } else {
      indices.sortBy { i =>
        val execId = shuffledOffers(i).executorId
        (taskSet.runningTasksOnExecutor(execId), executorRunningTaskCount(execId), i)
      }
    }
  }

  def canLaunchOnExecutor(
      taskSet: TaskSetManager,
      execId: String,
      eligibleExecutors: Set[String]): Boolean = {
    val readerResidencyTarget = readerResidencyTargetPerExecutor(taskSet)
    val maxRunningTasksPerExecutor =
      taskSet.taskSet.pipelinedGroupSchedulingRequirements.maxRunningTasksPerExecutor
        .getOrElse(0)
    val effectiveTaskSetCap =
      if (maxRunningTasksPerExecutor > 0 && readerResidencyTarget > 0) {
        math.max(maxRunningTasksPerExecutor, readerResidencyTarget)
      } else {
        maxRunningTasksPerExecutor
      }
    val belowTaskSetCap =
      !usesRoundRobin(taskSet) ||
        effectiveTaskSetCap <= 0 ||
        taskSet.runningTasksOnExecutor(execId) < effectiveTaskSetCap
    belowTaskSetCap && producerExecutorFairnessAllows(taskSet, execId, eligibleExecutors)
  }

  def launchLimit(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): PipelinedTaskLaunchLimit = {
    activeReaderResidencyGroupBlockReason(taskSet, activeTaskSets) match {
      case Some(reason) =>
        PipelinedTaskLaunchLimit(0, reason)
      case None =>
        pipelinedLaunchLimit(taskSet, activeTaskSets)
    }
  }

  def offerOrder(
      sortedTaskSets: Iterable[TaskSetManager]): Iterable[TaskSetManager] = {
    val offerOrder = new ArrayBuffer[TaskSetManager]
    val pipelinedBlock = new ArrayBuffer[TaskSetManager]

    def flushPipelinedBlock(): Unit = {
      if (pipelinedBlock.nonEmpty) {
        // A later TaskSet can make an earlier one runnable in the same offer. Revisit the block
        // after its normal task-count passes so reader residency can unblock its producer.
        val passes = pipelinedBlock.map(_.numTasks).max + 1
        for (_ <- 0 until passes) {
          offerOrder ++= pipelinedBlock
        }
        pipelinedBlock.clear()
      }
    }

    sortedTaskSets.foreach { taskSet =>
      if (usesRoundRobin(taskSet)) {
        pipelinedBlock += taskSet
      } else {
        flushPipelinedBlock()
        offerOrder += taskSet
      }
    }
    flushPipelinedBlock()
    offerOrder
  }

  def hasPendingWork(taskSet: TaskSetManager): Boolean = {
    taskSet.runningTasks + taskSet.tasksSuccessful < taskSet.numTasks
  }

  def describeTaskSet(taskSet: TaskSetManager): String = {
    val taskSetInfo = taskSet.taskSet
    val pendingCount = taskSet.pendingTasks.all.size + taskSet.pendingSpeculatableTasks.all.size
    s"stage=${taskSet.stageId}.${taskSetInfo.stageAttemptId}" +
      s" group=${taskSetInfo.pipelinedGroupId.getOrElse("-")}" +
      s" reader=${taskSetInfo.isPipelinedShuffleReader}" +
      s" producer=${taskSetInfo.isPipelinedShuffleProducer}" +
      s" residencyPolicy=${taskSetInfo.pipelinedGroupSchedulingRequirements.residencyPolicy}" +
      s" producerShuffleIds=${taskSetInfo.pipelinedProducerShuffleIds.mkString("[", ",", "]")}" +
      s" readerShuffleIds=${taskSetInfo.pipelinedReaderShuffleIds.mkString("[", ",", "]")}" +
      s" running=${taskSet.runningTasks}" +
      s" success=${taskSet.tasksSuccessful}/${taskSet.numTasks}" +
      s" pending=$pendingCount" +
      s" zombie=${taskSet.isZombie}"
  }

  def describeGroup(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): String = {
    taskSet.taskSet.pipelinedGroupId match {
      case Some(_) =>
        groupTaskSets(taskSet, activeTaskSets)
          .sortBy(taskSet => (taskSet.stageId, taskSet.taskSet.stageAttemptId))
          .map(describeTaskSet)
          .mkString("[", " | ", "]")
      case None =>
        describeTaskSet(taskSet)
    }
  }

  def describeOffers(
      shuffledOffers: Seq[WorkerOffer],
      availableCpus: Array[BigDecimal]): String = {
    shuffledOffers.indices.map { i =>
      val offer = shuffledOffers(i)
      s"${offer.executorId}@${offer.host}:freeCpus=${availableCpus(i)} " +
        s"running=${executorRunningTaskCount(offer.executorId)}"
    }.mkString("[", ", ", "]")
  }

  private def readerResidencyTargetPerExecutor(taskSet: TaskSetManager): Int = {
    val taskSetInfo = taskSet.taskSet
    val executorCount = executorIds().size
    if (executorCount > 0 &&
        usesElasticProducers(taskSetInfo) &&
        taskSetInfo.isPipelinedShuffleReader &&
        taskSetInfo.isPipelinedShuffleProducer) {
      ((taskSet.numTasks.toLong + executorCount - 1) / executorCount).toInt
    } else {
      0
    }
  }

  /** Keep producer work balanced while long-lived reader tasks occupy executor slots. */
  private def producerExecutorFairnessAllows(
      taskSet: TaskSetManager,
      execId: String,
      eligibleExecutors: Set[String]): Boolean = {
    val taskSetInfo = taskSet.taskSet
    if (!usesRoundRobin(taskSet) ||
        !usesElasticProducers(taskSetInfo) ||
        !taskSetInfo.isPipelinedShuffleProducer) {
      return true
    }

    if (taskSetInfo.isPipelinedShuffleReader) {
      val balancedPerExecutorTarget = readerResidencyTargetPerExecutor(taskSet)
      if (balancedPerExecutorTarget <= 0) {
        return true
      }

      val residencySkewLimit = balancedPerExecutorTarget + 1
      if (taskSet.runningTasksOnExecutor(execId) >= residencySkewLimit) {
        return false
      }

      val runningByEligibleExecutor = eligibleExecutors.iterator.map { executorId =>
        executorId -> taskSet.runningTasksOnExecutor(executorId)
      }.toMap
      return runningByEligibleExecutor.isEmpty ||
        taskSet.runningTasksOnExecutor(execId) <= runningByEligibleExecutor.values.min
    }

    taskSetInfo.pipelinedGroupId.forall { _ =>
      val pureProducers = pendingPureProducerTaskSets(groupTaskSets(taskSet, Seq.empty))
      val executors = executorIds().toSeq
      if (pureProducers.isEmpty || executors.isEmpty) {
        true
      } else {
        val runningByExecutor = executors.iterator.map { executorId =>
          executorId -> pureProducers.iterator.map(_.runningTasksOnExecutor(executorId)).sum
        }.toMap
        runningByExecutor.getOrElse(execId, 0) <= runningByExecutor.values.min
      }
    }
  }

  private def elasticProducerPolicy(
      taskSet: TaskSet): Option[ReaderResidencyWithElasticProducers] = {
    taskSet.pipelinedGroupSchedulingRequirements.residencyPolicy match {
      case policy: ReaderResidencyWithElasticProducers => Some(policy)
      case _ => None
    }
  }

  private def usesElasticProducers(taskSet: TaskSet): Boolean = {
    elasticProducerPolicy(taskSet).isDefined
  }

  private def producerMinRunningTasksPerStage(taskSet: TaskSet): Int = {
    elasticProducerPolicy(taskSet).map(_.minProducerTasksPerStage).getOrElse(1)
  }

  private def groupTaskSets(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Seq[TaskSetManager] = {
    taskSet.taskSet.pipelinedGroupId match {
      case Some(groupId) =>
        val registeredTaskSets = taskSetsByGroup
          .get(groupId)
          .map(_.toSeq)
          .getOrElse(Seq.empty)
        (registeredTaskSets ++ activeTaskSets.filter(_.taskSet.pipelinedGroupId.contains(groupId)))
          .distinct
      case None =>
        Seq(taskSet)
    }
  }

  private def pipelinedLaunchLimit(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): PipelinedTaskLaunchLimit = {
    if (!usesRoundRobin(taskSet)) {
      PipelinedTaskLaunchLimit(Int.MaxValue, "not-pipelined")
    } else if (readerResidencyBlocksProducer(taskSet, activeTaskSets)) {
      PipelinedTaskLaunchLimit(0, "waiting-for-reader-residency")
    } else if (readerFrontierBlocksTaskSet(taskSet, activeTaskSets)) {
      PipelinedTaskLaunchLimit(0, "reader-frontier-reservation")
    } else if (producerFairnessBlocksProducer(taskSet, activeTaskSets)) {
      PipelinedTaskLaunchLimit(0, "producer-sibling-fairness")
    } else {
      val runningTasksCap = producerMaxRunningTasksFor(taskSet.taskSet)
      if (runningTasksCap <= 0) {
        PipelinedTaskLaunchLimit(1, "allowed-no-stage-cap")
      } else {
        val remaining = runningTasksCap - taskSet.runningTasks
        if (remaining <= 0) {
          PipelinedTaskLaunchLimit(0, s"stage-running-cap($runningTasksCap)")
        } else {
          PipelinedTaskLaunchLimit(math.min(1, remaining), s"allowed-stage-cap($runningTasksCap)")
        }
      }
    }
  }

  private def activeReaderResidencyGroupBlockReason(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Option[String] = {
    activeReaderResidencyGroup(activeTaskSets).flatMap { case (activeGroupId, taskSets) =>
      if (taskSet.taskSet.pipelinedGroupId.contains(activeGroupId)) {
        None
      } else if (taskSets.exists(taskSet => taskSet.isZombie && taskSet.runningTasks > 0)) {
        Some(s"pipelined-group-draining($activeGroupId)")
      } else {
        Some(s"active-pipelined-group($activeGroupId)")
      }
    }
  }

  private def activeReaderResidencyGroup(
      activeTaskSets: Iterable[TaskSetManager]): Option[(String, Seq[TaskSetManager])] = {
    val groups = readerResidencyGroups(activeTaskSets)
    val runningGroups = groups.filter { case (_, taskSets) =>
      taskSets.exists(_.runningTasks > 0)
    }
    val candidates = if (runningGroups.nonEmpty) runningGroups else groups
    candidates.sortBy { case (groupId, taskSets) =>
      val firstStageId = taskSets.map(_.stageId).min
      val hasRunningTasks = taskSets.exists(_.runningTasks > 0)
      (if (hasRunningTasks) 0 else 1, firstStageId, groupId)
    }.headOption
  }

  private def readerResidencyGroups(
      activeTaskSets: Iterable[TaskSetManager]): Seq[(String, Seq[TaskSetManager])] = {
    val grouped = new HashMap[String, ArrayBuffer[TaskSetManager]]
    registeredAndActiveTaskSets(activeTaskSets).foreach { taskSet =>
      val taskSetInfo = taskSet.taskSet
      taskSetInfo.pipelinedGroupId.foreach { groupId =>
        if (usesElasticProducers(taskSetInfo) &&
            (taskSetInfo.isPipelinedShuffleReader || taskSetInfo.isPipelinedShuffleProducer) &&
            hasActiveWork(taskSet)) {
          grouped.getOrElseUpdate(groupId, new ArrayBuffer[TaskSetManager]) += taskSet
        }
      }
    }
    grouped.iterator.map { case (groupId, taskSets) =>
      groupId -> taskSets.toSeq
    }.toSeq
  }

  private def registeredAndActiveTaskSets(
      activeTaskSets: Iterable[TaskSetManager]): Seq[TaskSetManager] = {
    (activeTaskSets.iterator ++ taskSetsByGroup.valuesIterator.flatten).toSeq.distinct
  }

  private def readerFrontierBlocksTaskSet(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Boolean = {
    val taskSetInfo = taskSet.taskSet
    if (!usesElasticProducers(taskSetInfo)) {
      return false
    }

    taskSetInfo.pipelinedGroupId.exists { _ =>
      val group = groupTaskSets(taskSet, activeTaskSets)
      val pendingPureProducers = group.iterator.filter { producer =>
        val producerInfo = producer.taskSet
        !producer.isZombie &&
          usesElasticProducers(producerInfo) &&
          producerInfo.isPipelinedShuffleProducer &&
          !producerInfo.isPipelinedShuffleReader &&
          hasPendingWork(producer)
      }.toSeq

      val producersMissingReaders = pendingPureProducers.filter { producer =>
        val readers = residentReaderTaskSetsForProducer(producer, group)
        readers.nonEmpty && readers.exists { reader =>
          reader.runningTasks + reader.tasksSuccessful < reader.numTasks
        }
      }

      if (producersMissingReaders.nonEmpty) {
        val missingDirectReaders = producersMissingReaders.flatMap { producer =>
          residentReaderTaskSetsForProducer(producer, group).filter { reader =>
            reader.runningTasks + reader.tasksSuccessful < reader.numTasks
          }
        }.toSet
        !missingDirectReaders.contains(taskSet) && !producersMissingReaders.contains(taskSet)
      } else if (producerMinRunningTasksPerStage(taskSetInfo) > 1) {
        pureProducerFrontierTargetTaskSet(group).exists(_ != taskSet)
      } else {
        val readyStarvedProducers = pendingPureProducers.filter { producer =>
          val readers = residentReaderTaskSetsForProducer(producer, group)
          producer.runningTasks == 0 &&
            readers.nonEmpty &&
            readers.forall { reader =>
              reader.runningTasks + reader.tasksSuccessful >= reader.numTasks
            }
        }
        readyStarvedProducers.nonEmpty && !readyStarvedProducers.contains(taskSet)
      }
    }
  }

  private def producerFairnessBlocksProducer(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Boolean = {
    val taskSetInfo = taskSet.taskSet
    if (!usesElasticProducers(taskSetInfo) ||
        !taskSetInfo.isPipelinedShuffleProducer ||
        taskSetInfo.isPipelinedShuffleReader ||
        taskSet.runningTasks <= 0) {
      return false
    }

    taskSetInfo.pipelinedGroupId.exists { _ =>
      val group = groupTaskSets(taskSet, activeTaskSets)
      if (producerMinRunningTasksPerStage(taskSetInfo) > 1 &&
          pureProducerFrontierTargetTaskSet(group).contains(taskSet)) {
        false
      } else {
        val pendingPureProducers = group.iterator.filter { candidate =>
          val candidateInfo = candidate.taskSet
          !candidate.isZombie &&
            usesElasticProducers(candidateInfo) &&
            candidateInfo.isPipelinedShuffleProducer &&
            !candidateInfo.isPipelinedShuffleReader &&
            hasPendingWork(candidate)
        }.toSeq
        pendingPureProducers.size > 1 &&
          taskSet.runningTasks > pendingPureProducers.map(_.runningTasks).min
      }
    }
  }

  private def pureProducerFrontierTargetTaskSet(
      groupTaskSets: Seq[TaskSetManager]): Option[TaskSetManager] = {
    val underTargetProducers = groupTaskSets.iterator.filter { producer =>
      val producerInfo = producer.taskSet
      !producer.isZombie &&
        usesElasticProducers(producerInfo) &&
        producerInfo.isPipelinedShuffleProducer &&
        !producerInfo.isPipelinedShuffleReader &&
        hasPendingWork(producer) &&
        pureProducerFrontierDeficit(producer, groupTaskSets) > 0
    }.toSeq
    underTargetProducers.sortBy { producer =>
      (producer.stageId, producer.taskSet.stageAttemptId)
    }.headOption
  }

  private def pureProducerFrontierDeficit(
      producer: TaskSetManager,
      groupTaskSets: Seq[TaskSetManager]): Int = {
    val target = pureProducerFrontierTarget(producer)
    if (target <= 0) {
      return 0
    }
    val readers = residentReaderTaskSetsForProducer(producer, groupTaskSets)
    if (readers.isEmpty || readers.exists { reader =>
        reader.runningTasks + reader.tasksSuccessful < reader.numTasks
      }) {
      0
    } else {
      math.max(0, target - producer.runningTasks - producer.tasksSuccessful)
    }
  }

  private def pureProducerFrontierTarget(taskSet: TaskSetManager): Int = {
    val taskSetInfo = taskSet.taskSet
    if (usesElasticProducers(taskSetInfo) &&
        taskSetInfo.isPipelinedShuffleProducer &&
        !taskSetInfo.isPipelinedShuffleReader) {
      math.min(taskSet.numTasks, producerMinRunningTasksPerStage(taskSetInfo))
    } else {
      0
    }
  }

  private def hasActiveWork(taskSet: TaskSetManager): Boolean = {
    taskSet.runningTasks > 0 || (!taskSet.isZombie && hasPendingWork(taskSet))
  }

  private def residentReaderTaskSetsForProducer(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Seq[TaskSetManager] = {
    val group = groupTaskSets(taskSet, activeTaskSets)
    val readers = new ArrayBuffer[TaskSetManager]
    val seenReaders = new HashSet[TaskSetManager]
    val toVisit = new ArrayBuffer[TaskSetManager]
    toVisit ++= directResidentReaderTaskSetsForProducer(taskSet, group)
    while (toVisit.nonEmpty) {
      val reader = toVisit.remove(0)
      if (seenReaders.add(reader)) {
        readers += reader
        if (reader.taskSet.isPipelinedShuffleProducer) {
          toVisit ++= directResidentReaderTaskSetsForProducer(reader, group)
        }
      }
    }
    readers.toSeq
  }

  private def directResidentReaderTaskSetsForProducer(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Seq[TaskSetManager] = {
    val taskSetInfo = taskSet.taskSet
    val readers = groupTaskSets(taskSet, activeTaskSets).iterator.filter { candidate =>
      val candidateInfo = candidate.taskSet
      !candidate.isZombie &&
        usesElasticProducers(candidateInfo) &&
        candidateInfo.isPipelinedShuffleReader
    }.toSeq
    val producerShuffleIds = taskSetInfo.pipelinedProducerShuffleIds.toSet
    if (producerShuffleIds.isEmpty || readers.forall(_.taskSet.pipelinedReaderShuffleIds.isEmpty)) {
      readers
    } else {
      readers.filter { reader =>
        reader.taskSet.pipelinedReaderShuffleIds.exists(producerShuffleIds.contains)
      }
    }
  }

  private def readerResidencyBlocksProducer(
      taskSet: TaskSetManager,
      activeTaskSets: Iterable[TaskSetManager]): Boolean = {
    val taskSetInfo = taskSet.taskSet
    if (!usesElasticProducers(taskSetInfo) ||
        !taskSetInfo.isPipelinedShuffleProducer ||
        taskSetInfo.isPipelinedShuffleReader) {
      return false
    }

    taskSetInfo.pipelinedGroupId.exists { _ =>
      val group = groupTaskSets(taskSet, activeTaskSets)
      val readers = residentReaderTaskSetsForProducer(taskSet, activeTaskSets)
      if (readers.isEmpty) {
        true
      } else if (readers.forall { reader =>
          reader.runningTasks + reader.tasksSuccessful >= reader.numTasks
        }) {
        false
      } else {
        val pureProducers = pendingPureProducerTaskSets(group)
        val reservationTarget = pureProducerReservationTarget(pureProducers)
        pureProducers.iterator.map(_.runningTasks).sum >= reservationTarget
      }
    }
  }

  private def pendingPureProducerTaskSets(
      groupTaskSets: Seq[TaskSetManager]): Seq[TaskSetManager] = {
    groupTaskSets.filter { producer =>
      val producerInfo = producer.taskSet
      !producer.isZombie &&
        usesElasticProducers(producerInfo) &&
        producerInfo.isPipelinedShuffleProducer &&
        !producerInfo.isPipelinedShuffleReader &&
        hasPendingWork(producer)
    }
  }

  private def pureProducerReservationTarget(
      pureProducers: Seq[TaskSetManager]): Int = {
    pureProducers.iterator
      .map(producer => math.min(producer.numTasks,
        producerMinRunningTasksPerStage(producer.taskSet)))
      .sum
  }

  private def producerMaxRunningTasksFor(taskSet: TaskSet): Int = {
    if (taskSet.isPipelinedShuffleProducer && !taskSet.isPipelinedShuffleReader) {
      elasticProducerPolicy(taskSet).flatMap(_.maxProducerTasksPerStage).getOrElse(0)
    } else {
      0
    }
  }
}
