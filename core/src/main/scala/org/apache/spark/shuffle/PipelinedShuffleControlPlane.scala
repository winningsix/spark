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

  /**
   * Maximum number of pure producer tasks that Spark may keep running for this group.
   *
   * This admission happens before a Spark task is launched. It lets a query-level control plane
   * bound native producers without occupying executor task slots with writers that are only
   * waiting for credit. Reader-producer tasks are excluded because they form the resident drain
   * path for push-oriented shuffle data.
   *
   * None means unlimited. Zero temporarily pauses producer expansion; already-running tasks are
   * never preempted. Spark may exceed this cap by the configured per-stage minimum when a pending
   * pure producer stage has no running task. This liveness lane prevents a query-level pause from
   * fencing a sibling producer stage that is needed to drain the current frontier.
   */
  def maxConcurrentPipelinedShuffleProducers(groupId: String): Option[Int] = None

  def registerPipelinedShuffleGroup(group: PipelinedShuffleGroupMetadata): Unit

  def admitPipelinedShuffleGroup(groupId: String): Unit

  def completePipelinedShuffleGroup(groupId: String): Unit

  def abortPipelinedShuffleGroup(groupId: String, reason: String): Unit

  /**
   * Mark the SQL execution that owns one or more pipelined shuffle groups as successful.
   *
   * Group completion only means that the currently known Spark stage component has stopped. A
   * query-level control plane must retain exchange state until this callback so later jobs in the
   * same SQL execution join the same coordinator instance.
   */
  def completePipelinedQuery(queryExecutionId: Long): Unit = {}

  /**
   * Abort every pipelined shuffle group owned by the failed SQL execution.
   */
  def abortPipelinedQuery(queryExecutionId: Long, reason: String): Unit = {}
}
