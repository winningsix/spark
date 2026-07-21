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
    shuffleId: Option[Int])

/**
 * Driver-side metadata for a connected component of stages joined by pipelined shuffle edges.
 */
private[spark] case class PipelinedShuffleGroupMetadata(
    groupId: String,
    jobId: Int,
    queryExecutionId: Option[Long],
    stages: Seq[PipelinedShuffleStageMetadata])

/**
 * Optional lifecycle hook for incremental shuffle managers that need query/stage-group state.
 *
 * DAGScheduler owns the Spark stage graph and therefore announces group registration, admission,
 * completion, and abort. The concrete incremental shuffle manager owns the shuffle implementation
 * and can use these callbacks to maintain a query-level control plane.
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

  def registerPipelinedShuffleGroup(group: PipelinedShuffleGroupMetadata): Unit

  def admitPipelinedShuffleGroup(groupId: String): Unit

  def completePipelinedShuffleGroup(groupId: String): Unit

  def abortPipelinedShuffleGroup(groupId: String, reason: String): Unit
}
