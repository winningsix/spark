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

import scala.collection.mutable
import scala.collection.mutable.{HashMap, HashSet}

import org.apache.spark.PipelinedShuffleDependency
import org.apache.spark.shuffle.streaming.{PipelinedGroupAdmission, PipelinedStageAdmission, StreamingShuffleStagePlanning}

/** Builds admission descriptors from the active stage graph without submitting tasks. */
private[scheduler] object PipelinedStageGroup {

  def isPipelinedProducer(stage: Stage): Boolean = stage match {
    case map: ShuffleMapStage =>
      map.shuffleDep.isInstanceOf[PipelinedShuffleDependency[_, _, _]]
    case _ => false
  }

  /** Partition active stages into components connected by pipelined shuffle dependencies. */
  def admissionGroups(jobId: Int, finalStage: Stage): Seq[PipelinedGroupAdmission] = {
    // Completed shuffle output (including a leased replay) needs no producer task set.
    // Stop at that boundary: its ancestors are not part of this job's execution demand.
    val stages = new mutable.ArrayBuffer[Stage]
    val visited = new HashSet[Int]
    val pendingStages = new mutable.Stack[Stage]
    pendingStages.push(finalStage)
    while (pendingStages.nonEmpty) {
      val stage = pendingStages.pop()
      val available = stage match {
        case map: ShuffleMapStage => map.isAvailable
        case _ => false
      }
      if (visited.add(stage.id) && !available) {
        stages += stage
        stage.parents.foreach(pendingStages.push(_))
      }
    }
    val stagesById = stages.iterator.map(stage => stage.id -> stage).toMap
    val activeStageIds = stagesById.keySet
    val adjacent = new HashMap[Int, HashSet[Int]]
    stages.foreach { child =>
      child.parents.filter(isPipelinedProducer).foreach { parent =>
        // A replay-only consumer still needs its reader slots reserved.
        val parents = adjacent.getOrElseUpdate(child.id, new HashSet[Int])
        if (activeStageIds(parent.id)) {
          parents += parent.id
          adjacent.getOrElseUpdate(parent.id, new HashSet[Int]) += child.id
        }
      }
    }
    val remaining = new HashSet[Int] ++ adjacent.keys
    val groups = new mutable.ArrayBuffer[PipelinedGroupAdmission]
    while (remaining.nonEmpty) {
      val members = new HashSet[Int]
      val pending = new mutable.Stack[Int]
      pending.push(remaining.head)
      while (pending.nonEmpty) {
        val id = pending.pop()
        if (members.add(id)) {
          remaining -= id
          adjacent(id).foreach(next => pending.push(next))
        }
      }
      require(members.forall { id =>
        stagesById(id).parents.forall(p => isPipelinedProducer(p) || !members(p.id))
      }, "A materialized dependency cannot be internal to a reserved pipelined group")
      val descriptors = members.toSeq.sorted.map { id =>
        val stage = stagesById(id)
        PipelinedStageAdmission(id, stage.getNextAttemptId, stage.numTasks,
          reader = StreamingShuffleStagePlanning.shuffleIdsReadByStage(stage.rdd).nonEmpty,
          producer = isPipelinedProducer(stage))
      }
      groups += PipelinedGroupAdmission(jobId, descriptors)
    }
    groups.toSeq
  }
}
