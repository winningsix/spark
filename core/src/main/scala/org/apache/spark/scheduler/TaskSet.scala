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

import java.util.Properties

import org.apache.spark.internal.LogKeys.{STAGE_ATTEMPT_ID, STAGE_ID}
import org.apache.spark.internal.MessageWithContext

/**
 * A set of tasks submitted together to the low-level TaskScheduler, usually representing
 * missing partitions of a particular stage.
 */
private[spark] class TaskSet(
    val tasks: Array[Task[_]],
    val stageId: Int,
    val stageAttemptId: Int,
    val priority: Int,
    val properties: Properties,
    val resourceProfileId: Int,
    val shuffleId: Option[Int],
    // True if this stage is a member of a pipelined group (connected to another stage by a
    // PipelinedShuffleDependency). Such a stage's transient shuffle output cannot be re-read in
    // isolation, so any task failure must fail the whole group rather than be retried per-task;
    // the TaskSetManager uses this to fail fast (maxTaskFailures = 1) and to count every failure,
    // including otherwise-uncounted ones like executor loss. Defaults to false.
    val isPipelined: Boolean = false,
    // Number of scheduler stages in the connected pipelined group. Zero for non-pipelined task
    // sets or when the creator does not provide group metadata.
    val pipelinedGroupStageCount: Int = 0,
    // Stable identifier for the connected pipelined group this task set belongs to. Used by the
    // task scheduler to coordinate admission across the active TaskSetManagers in the group.
    val pipelinedGroupId: Option[String] = None,
    // True when the selected incremental shuffle manager needs every pipelined shuffle reader
    // partition in the group to be launched before pure producer stages can freely consume slots.
    val requiresAllPipelinedShuffleReadersResident: Boolean = false,
    // True if this pipelined stage consumes an upstream PipelinedShuffleDependency. UCX-style
    // push shuffles need every reader partition to stay resident, so the task scheduler can cap
    // readers differently from source-side pure producers.
    val isPipelinedShuffleReader: Boolean = false,
    // True if this stage writes a PipelinedShuffleDependency. A stage can be both producer and
    // reader in a multi-hop pipelined chain.
    val isPipelinedShuffleProducer: Boolean = false,
    // Pipelined shuffle ids produced by this stage. Used by UCX-style push shuffles to gate a
    // producer only on the reader task sets that directly consume its output.
    val pipelinedProducerShuffleIds: Seq[Int] = Seq.empty,
    // Pipelined shuffle ids consumed by this stage.
    val pipelinedReaderShuffleIds: Seq[Int] = Seq.empty) {

  def this(
      tasks: Array[Task[_]],
      stageId: Int,
      stageAttemptId: Int,
      priority: Int,
      properties: Properties,
      resourceProfileId: Int,
      shuffleId: Option[Int],
      isPipelined: Boolean) = {
    this(tasks, stageId, stageAttemptId, priority, properties, resourceProfileId, shuffleId,
      isPipelined, 0)
  }

  val id: String = s"$stageId.$stageAttemptId"

  override def toString: String = "TaskSet " + id

  // Identifier used in the structured logging framework.
  lazy val logId: MessageWithContext = {
    val hashMap = new java.util.HashMap[String, String]()
    hashMap.put(STAGE_ID.name, stageId.toString)
    hashMap.put(STAGE_ATTEMPT_ID.name, stageAttemptId.toString)
    MessageWithContext(id, hashMap)
  }
}
