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
    // True when this stage directly reads one or more pipelined shuffle dependencies. Distributed
    // transports use this metadata to prepare and place executor-owned receive inboxes.
    val isPipelinedShuffleReader: Boolean = false,
    val pipelinedReaderShuffleIds: Seq[Int] = Seq.empty,
    // True when this stage writes a pipelined shuffle. A reader that also writes one is a combined
    // stage; only a pure producer is governed by the elastic producer launch window.
    val isPipelinedShuffleProducer: Boolean = false,
    // Shuffle inputs that must be ready before this stage can make useful progress. Empty means
    // all reader inputs are required, preserving the conservative default for operators such as
    // SortMergeJoin. ShuffledHashJoin identifies only its build-side shuffle(s).
    val pipelinedReaderStartupShuffleIds: Set[Int] = Set.empty) {
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
