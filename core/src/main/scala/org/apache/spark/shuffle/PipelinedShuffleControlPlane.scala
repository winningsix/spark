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

package org.apache.spark.shuffle

/**
 * Driver-side metadata for one Spark stage participating in a pipelined shuffle group.
 */
private[spark] case class PipelinedShuffleStageMetadata(
    stageId: Int,
    attemptId: Int,
    numTasks: Int,
    shuffleId: Option[Int],
    pipelinedParentShuffleIds: Seq[Int] = Seq.empty)

/**
 * Driver-side metadata for a connected component of stages joined by pipelined shuffle edges.
 */
private[spark] case class PipelinedShuffleGroupMetadata(
    groupId: String,
    groupAttemptId: String,
    stages: Seq[PipelinedShuffleStageMetadata])

/**
 * Minimum task residency required before a pipelined shuffle group can make progress safely.
 */
private[spark] sealed trait PipelinedGroupResidencyPolicy

/**
 * Conservatively require every task in every member stage to fit concurrently.
 *
 * This is the default for incremental shuffle managers that do not declare a more specific
 * requirement, and for long-running CPU real-time tasks that cannot rotate source partitions.
 */
private[spark] case object FullGroupResidency extends PipelinedGroupResidencyPolicy

/**
 * Keep all pipelined readers resident while allowing finite pure-producer tasks to rotate.
 *
 * The producer limits are data-plane policy, interpreted and enforced only by Spark.
 */
private[spark] case class ReaderResidencyWithElasticProducers(
    minProducerTasksPerStage: Int = 1,
    maxProducerTasksPerStage: Option[Int] = None)
  extends PipelinedGroupResidencyPolicy {
  require(minProducerTasksPerStage >= 1, "minimum producer residency must be positive")
  require(maxProducerTasksPerStage.forall(_ >= minProducerTasksPerStage),
    "maximum producer residency must not be lower than its minimum")
}

/**
 * Spark-internal scheduling requirements resolved before a pipelined group is published.
 */
private[spark] case class PipelinedGroupSchedulingRequirements(
    residencyPolicy: PipelinedGroupResidencyPolicy = FullGroupResidency,
    maxRunningTasksPerExecutor: Option[Int] = None) {
  require(maxRunningTasksPerExecutor.forall(_ >= 1),
    "per-executor task limit must be positive when set")
}

/**
 * Optional, declarative scheduling hook for incremental shuffle managers.
 *
 * A provider selects only from the residency policies defined and implemented by Spark. The
 * returned requirements are resolved once per group attempt and remain immutable until that
 * attempt completes or aborts. Providers must not perform admission, choose tasks, or refill
 * producer stages; those decisions remain entirely in Spark's schedulers.
 */
private[spark] trait PipelinedShuffleSchedulingProvider {

  def schedulingRequirements(
      group: PipelinedShuffleGroupMetadata): PipelinedGroupSchedulingRequirements =
    PipelinedGroupSchedulingRequirements()
}

/**
 * Optional runtime-lifecycle listener for incremental shuffle managers.
 *
 * DAGScheduler owns the Spark stage graph and is the authority for group registration, admission,
 * completion, and abort. An incremental shuffle manager treats these callbacks as commands or
 * notifications. It must not maintain an independent scheduler outcome that can override Spark's
 * group outcome.
 */
private[spark] trait PipelinedShuffleControlPlane {

  def registerPipelinedShuffleGroup(group: PipelinedShuffleGroupMetadata): Unit = {}

  def admitPipelinedShuffleGroup(groupAttemptId: String): Unit = {}

  def completePipelinedShuffleGroup(groupAttemptId: String): Unit = {}

  def abortPipelinedShuffleGroup(groupAttemptId: String, reason: String): Unit = {}
}
