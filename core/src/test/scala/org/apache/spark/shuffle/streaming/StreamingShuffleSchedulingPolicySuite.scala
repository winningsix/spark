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

package org.apache.spark.shuffle.streaming

import org.mockito.Mockito.when
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark.{SparkConf, SparkFunSuite}
import org.apache.spark.internal.config.STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED
import org.apache.spark.scheduler.{Task, TaskSet, TaskSetManager}
import org.apache.spark.shuffle.PipelinedShuffleManager
import org.apache.spark.util.ThreadUtils

class StreamingShuffleSchedulingPolicySuite extends SparkFunSuite with MockitoSugar {

  test("disabled receive preparation does not inspect executor placement") {
    val conf = new SparkConf(false)
      .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, false)
    val timer = ThreadUtils.newDaemonSingleThreadScheduledExecutor("shuffle-policy-test")
    val policy = new StreamingShuffleSchedulingPolicy(
      conf, timer, () => fail("Disabled preparation must not revive offers"))
    try {
      policy.initialize()
      val offers = policy.prepareOffers(Seq.empty,
        fail("Disabled preparation must not inspect executors or SparkEnv"))
      assert(offers.taskSets.isEmpty)
    } finally {
      policy.close()
      ThreadUtils.shutdown(timer)
    }
  }

  test("reader placement rejects invalid task and executor counts") {
    intercept[IllegalArgumentException] {
      StreamingShuffleSchedulingPolicy.preparedReaderExecutorIndex(-1, 1, false)
    }
    intercept[IllegalArgumentException] {
      StreamingShuffleSchedulingPolicy.preparedReaderExecutorIndex(0, 0, false)
    }
  }

  test("offer plans isolate producer membership but observe readers launched in the same pass") {
    val conf = new SparkConf(false)
      .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, false)
    val timer = ThreadUtils.newDaemonSingleThreadScheduledExecutor("shuffle-offer-plan-test")
    val policy = new StreamingShuffleSchedulingPolicy(conf, timer, () => ())
    def manager(stageId: Int, producer: Boolean): TaskSetManager = {
      val result = mock[TaskSetManager]
      when(result.taskSet).thenReturn(new TaskSet(
        Array.empty[Task[_]], stageId, 0, 0, null, 0,
        if (producer) Some(7) else None, isPipelined = true,
        isPipelinedShuffleReader = !producer,
        pipelinedReaderShuffleIds = if (producer) Seq.empty else Seq(7),
        isPipelinedShuffleProducer = producer))
      when(result.isActiveForScheduling).thenReturn(true)
      when(result.numTasks).thenReturn(1)
      result
    }
    val producer = manager(1, producer = true)
    val reader = manager(2, producer = false)
    try {
      val first = policy.prepareOffers(Seq(producer, reader), Map.empty)
      assert(!first.useSoleProducerWindow(producer))
      when(reader.runningTasks).thenReturn(1)
      assert(first.useSoleProducerWindow(producer))
      val next = policy.prepareOffers(Seq.empty, Map.empty)
      assert(next.taskSets.isEmpty)
      assert(first.useSoleProducerWindow(producer),
        "a later offer pass must not overwrite an earlier pass's producer membership")
    } finally {
      policy.close()
      ThreadUtils.shutdown(timer)
    }
  }

  test("mixed shuffle eligibility preserves transport capability and admission guards") {
    val manager = mock[PipelinedShuffleManager]
    for (supportsBoundary <- Seq(false, true); wholeGroup <- Seq(false, true)) {
      when(manager.supportsUnmaterializedRegularBoundary).thenReturn(supportsBoundary)
      when(manager.requiresWholeGroupSlotAdmission).thenReturn(wholeGroup)
      assert(StreamingShuffleStagePlanning.supportsMixedShape(
        manager, hasPipelined = false, hasPipelinedBelowRegular = true,
        hasUnmaterializedRegularBoundary = true) === supportsBoundary)
      assert(StreamingShuffleStagePlanning.supportsMixedShape(
        manager, hasPipelined = true, hasPipelinedBelowRegular = false,
        hasUnmaterializedRegularBoundary = true) === supportsBoundary)
      assert(StreamingShuffleStagePlanning.supportsMixedShape(
        manager, hasPipelined = true, hasPipelinedBelowRegular = true,
        hasUnmaterializedRegularBoundary = true) === (supportsBoundary && !wholeGroup))
    }
  }
}
