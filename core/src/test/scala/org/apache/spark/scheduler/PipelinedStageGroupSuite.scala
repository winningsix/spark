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

import org.mockito.Mockito.{doReturn, when}
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark.{Dependency, PipelinedShuffleDependency, ShuffleDependency, SparkFunSuite}
import org.apache.spark.rdd.RDD

class PipelinedStageGroupSuite extends SparkFunSuite with MockitoSugar {

  private def stage(
      id: Int,
      numTasks: Int,
      parents: List[ShuffleMapStage] = Nil,
      pipelined: Boolean = true,
      available: Boolean = false): ShuffleMapStage = {
    val result = mock[ShuffleMapStage]
    val rdd = mock[RDD[Int]]
    val dependency = if (pipelined) {
      mock[PipelinedShuffleDependency[Int, Int, Int]]
    } else {
      mock[ShuffleDependency[Int, Int, Int]]
    }
    val dependencies = parents.map(_.shuffleDep: Dependency[_])
    when(rdd.dependencies).thenReturn(dependencies)
    when(result.id).thenReturn(id)
    when(result.numTasks).thenReturn(numTasks)
    when(result.parents).thenReturn(parents)
    doReturn(rdd).when(result).rdd
    doReturn(dependency).when(result).shuffleDep
    when(result.isAvailable).thenReturn(available)
    when(result.getNextAttemptId).thenReturn(2)
    result
  }

  test("a connected chain records readers, producers, task counts, and attempts") {
    val source = stage(0, 100)
    val join = stage(1, 8, List(source))
    val aggregate = stage(2, 8, List(join), pipelined = false)
    val groups = PipelinedStageGroup.admissionGroups(7, aggregate)
    assert(groups.size === 1)
    assert(groups.head.jobId === 7)
    assert(groups.head.stages.map(s => (s.stageId, s.numTasks, s.reader, s.producer)) ===
      Seq((0, 100, false, true), (1, 8, true, true), (2, 8, true, false)))
    assert(groups.head.stages.forall(_.stageAttemptId == 2))
  }

  test("fan-out counts a shared producer once") {
    val source = stage(0, 100)
    val left = stage(1, 8, List(source))
    val right = stage(2, 8, List(source))
    val result = stage(3, 8, List(left, right), pipelined = false)
    val groups = PipelinedStageGroup.admissionGroups(7, result)
    assert(groups.size === 1)
    assert(groups.head.stages.map(_.stageId) === Seq(0, 1, 2, 3))
    assert(groups.head.stages.map(_.numTasks).sum === 124)
  }

  test("materialized boundaries separate admission groups") {
    val source = stage(0, 100)
    val materialized = stage(1, 8, List(source), pipelined = false)
    val probe = stage(2, 8, List(materialized))
    val result = stage(3, 8, List(probe), pipelined = false)
    val groups = PipelinedStageGroup.admissionGroups(7, result)
    assert(groups.map(_.stages.map(_.stageId).toSet).toSet ===
      Set(Set(0, 1), Set(2, 3)))
  }

  test("completed replay stops execution demand at the available producer") {
    val source = stage(0, 100)
    val completed = stage(1, 8, List(source), available = true)
    val result = stage(2, 8, List(completed), pipelined = false)
    val groups = PipelinedStageGroup.admissionGroups(7, result)
    assert(groups.size === 1)
    assert(groups.head.stages.map(s => (s.stageId, s.reader, s.producer)) ===
      Seq((2, true, false)))
  }

  test("a materialized dependency inside a pipelined component is rejected") {
    val source = stage(0, 100)
    val materialized = stage(1, 8, List(source), pipelined = false)
    val result = stage(2, 8, List(source, materialized), pipelined = false)
    val error = intercept[IllegalArgumentException] {
      PipelinedStageGroup.admissionGroups(7, result)
    }
    assert(error.getMessage.contains("A materialized dependency cannot be internal"))
  }
}
