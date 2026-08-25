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

import io.netty.buffer.Unpooled
import org.mockito.Mockito.when
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark._
import org.apache.spark.LocalSparkContext.withSpark
import org.apache.spark.internal.config.{SHUFFLE_MANAGER, SHUFFLE_MANAGER_INCREMENTAL,
  STREAMING_SHUFFLE_ELASTIC_PRODUCERS_ENABLED, STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED}
import org.apache.spark.network.shuffle.streaming.{DataMessage, TerminationAckMessage, TerminationControlMessage}
import org.apache.spark.shuffle.{FullGroupResidency, PipelinedShuffleGroupMetadata,
  PipelinedShuffleSchedulingProvider, ReaderResidencyWithElasticProducers}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager.{getQueryId, getWriterId, QUERY_ID_PROPERTY_KEY}

class StreamingShuffleManagerSuite
  extends SparkFunSuite
  with LocalSparkContext
  with Matchers
  with MockitoSugar {

  private val SQL_EXECUTION_ID_KEY = "spark.sql.execution.id"

  // ---- getWriterId ----

  test("getWriterId returns the writer id for a data message") {
    val msg = new DataMessage(7, 3, 0, Unpooled.EMPTY_BUFFER, 0L)
    getWriterId(msg) should be(7)
  }

  test("getWriterId returns the writer id for a termination control message") {
    getWriterId(new TerminationControlMessage(5, 2)) should be(5)
  }

  test("getWriterId throws on an unexpected message type") {
    val e = intercept[SparkRuntimeException] {
      getWriterId(new TerminationAckMessage(1, 1))
    }
    checkError(
      e,
      condition = "STREAMING_SHUFFLE_UNEXPECTED_MESSAGE_TYPE",
      parameters = Map("messageType" -> "TERMINATION_ACK_MESSAGE"))
  }

  // ---- getQueryId ----

  test("getQueryId returns the streaming query id when set") {
    val context = mock[TaskContext]
    when(context.getLocalProperty(QUERY_ID_PROPERTY_KEY)).thenReturn("query-123")
    getQueryId(context) should be("query-123")
  }

  test("getQueryId falls back to the SQL execution id for batch queries") {
    val context = mock[TaskContext]
    when(context.getLocalProperty(SQL_EXECUTION_ID_KEY)).thenReturn("42")
    getQueryId(context) should be("42")
  }

  test("getQueryId throws when no query id property is set") {
    val context = mock[TaskContext]
    val e = intercept[SparkException] {
      getQueryId(context)
    }
    checkError(
      e,
      condition = "INTERNAL_ERROR",
      parameters = Map("message" ->
        "Streaming shuffle requires the query id or SQL execution id local property to be set"))
  }

  // ---- registerShuffle ----

  test("registerShuffle returns a StreamingShuffleHandle") {
    withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", new SparkConf())) { sc =>
      val rdd = sc.parallelize(1 to 4).map(x => (x, x))
      val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(2))
      val handle = new StreamingShuffleManager().registerShuffle(0, dep)
      assert(handle.isInstanceOf[StreamingShuffleHandle[_, _, _]])
    }
  }

  test("streaming shuffle manager selects configured producer residency policy") {
    val metadata = PipelinedShuffleGroupMetadata("group", "attempt", Seq.empty)
    val conf = new SparkConf()
      .set(SHUFFLE_MANAGER_INCREMENTAL, classOf[StreamingShuffleManager].getName)
    withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", conf)) { _ =>
      val manager = new StreamingShuffleManager()
      assert(manager.isInstanceOf[PipelinedShuffleSchedulingProvider])
      manager.schedulingRequirements(metadata).residencyPolicy should be(FullGroupResidency)

      SparkEnv.get.conf.set(STREAMING_SHUFFLE_ELASTIC_PRODUCERS_ENABLED, true)
      manager.schedulingRequirements(metadata).residencyPolicy shouldBe
        ReaderResidencyWithElasticProducers()
    }

    val multiManager = new MultiShuffleManager(new SparkConf(loadDefaults = false))
    try {
      assert(!multiManager.isInstanceOf[PipelinedShuffleSchedulingProvider])
    } finally {
      multiManager.stop()
    }
  }

  test("streaming shuffle writers can share one executor server across shuffles") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, true)
    withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", conf)) { sc =>
      val rdd = sc.parallelize(1 to 2).map(x => (x, x))
      val dependency = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
      val manager = new StreamingShuffleManager()
      val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
        .asInstanceOf[StreamingShuffleOutputTrackerMaster]
      tracker.registerShuffle(10, 1, 1, 0)
      tracker.registerShuffle(11, 1, 1, 0)

      val writer1 = manager.getWriter[Int, Int](
        manager.registerShuffle(10, dependency), 100, TaskContext.empty(), null)
        .asInstanceOf[StreamingShuffleWriter[Int, Int]]
      val writer2 = manager.getWriter[Int, Int](
        manager.registerShuffle(11, dependency), 100, TaskContext.empty(), null)
        .asInstanceOf[StreamingShuffleWriter[Int, Int]]
      try {
        writer1.shuffleWriterId should be(100)
        writer2.shuffleWriterId should be(100)
        writer1.server.getPort should be(writer2.server.getPort)
      } finally {
        writer1.cleanupResources()
        writer2.cleanupResources()
        manager.stop()
      }
    }
  }

  // ---- SparkEnv tracker initialization gating ----

  private def assertTrackerInitialized(
      defaultManager: Option[String] = None,
      incrementalManager: Option[String] = None,
      expectPresent: Boolean): Unit = {
    val conf = new SparkConf()
    // The default slot must be a BlockingShuffleManager; the incremental slot holds a
    // PipelinedShuffleManager and defaults to the streaming manager. Each is set only when the test
    // provides it, so leaving the incremental slot unset exercises the streaming default. The
    // tracker is initialized when either slot requires it.
    defaultManager.foreach(conf.set(SHUFFLE_MANAGER, _))
    incrementalManager.foreach(conf.set(SHUFFLE_MANAGER_INCREMENTAL, _))
    withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", conf)) { _ =>
      val tracker = SparkEnv.get.streamingShuffleOutputTracker
      assert(tracker.isDefined == expectPresent)
      // On the driver a present tracker is always the master.
      if (expectPresent) {
        assert(tracker.get.isInstanceOf[StreamingShuffleOutputTrackerMaster])
      }
    }
  }

  test("SparkEnv initializes the streaming shuffle tracker by default (streaming incremental " +
      "manager)") {
    // The incremental slot defaults to the streaming manager, so the tracker is present with no
    // explicit configuration.
    assertTrackerInitialized(expectPresent = true)
  }

  test("SparkEnv initializes the streaming shuffle tracker for an explicit incremental " +
      "StreamingShuffleManager") {
    assertTrackerInitialized(
      incrementalManager = Some(classOf[StreamingShuffleManager].getName), expectPresent = true)
  }

  test("SparkEnv initializes the streaming shuffle tracker for a MultiShuffleManager default") {
    assertTrackerInitialized(
      defaultManager = Some(classOf[MultiShuffleManager].getName), expectPresent = true)
  }
}
