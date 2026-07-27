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
 * Optional scheduling-requirement and runtime-lifecycle hook for incremental shuffle managers.
 *
 * DAGScheduler owns the Spark stage graph and is the authority for group registration, admission,
 * completion, and abort. An incremental shuffle manager reports data-plane requirements and treats
 * lifecycle callbacks as commands or notifications. It must not maintain an independent scheduler
 * outcome that can override Spark's group outcome.
 */
private[spark] trait PipelinedShuffleControlPlane {

  /**
   * Whether every reduce partition reader for each pipelined shuffle in this group must be resident
   * before the group can make progress safely.
   *
   * Pull-oriented implementations can leave this at false. Push-oriented implementations with
   * bounded native output queues should return true so the scheduler rejects configurations that
   * cap a reader stage below its partition count; otherwise producers can block forever on output
   * partitions whose reader tasks were never launched.
   */
  def requiresAllPipelinedShuffleReadersResident(group: PipelinedShuffleGroupMetadata): Boolean =
    false

  def registerPipelinedShuffleGroup(group: PipelinedShuffleGroupMetadata): Unit = {}

  def admitPipelinedShuffleGroup(groupAttemptId: String): Unit = {}

  def completePipelinedShuffleGroup(groupAttemptId: String): Unit = {}

  def abortPipelinedShuffleGroup(groupAttemptId: String, reason: String): Unit = {}
}

private[spark] trait RequiresAllPipelinedShuffleReadersResident
  extends PipelinedShuffleControlPlane {
  final override def requiresAllPipelinedShuffleReadersResident(
      group: PipelinedShuffleGroupMetadata): Boolean = true
}
