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

import java.nio.ByteBuffer
import java.util.concurrent.{CountDownLatch, LinkedBlockingQueue, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger}

import io.netty.buffer.Unpooled
import org.mockito.ArgumentMatchers.{any, eq => eqTo}
import org.mockito.Mockito.{verify, when}
import org.scalatest.concurrent.Eventually.eventually
import org.scalatest.concurrent.PatienceConfiguration.Timeout
import org.scalatest.matchers.should.Matchers
import org.scalatest.time.SpanSugar._
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark._
import org.apache.spark.LocalSparkContext.withSpark
import org.apache.spark.internal.config.{SHUFFLE_MANAGER, SHUFFLE_MANAGER_INCREMENTAL,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS,
  STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED,
  STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL,
  STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED, STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
  STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED}
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.{DataMessage, StreamingShuffleMessage,
  TerminationAckMessage, TerminationControlMessage}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager.{getQueryId, getWriterId, QUERY_ID_PROPERTY_KEY}
import org.apache.spark.util.{ErrorNotifier, ThreadUtils}

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

  test("executor receive service owns and releases task-attempt inboxes") {
    withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", new SparkConf())) { _ =>
      val service = new StreamingShuffleReceiveService(SparkEnv.get.conf)
      val first = service.acquire(10, TaskContext.empty())
      service.activeInboxCount shouldBe 1

      val duplicate = service.acquire(10, TaskContext.empty())
      service.activeInboxCount shouldBe 2
      first.id.readerOrdinal shouldBe 0
      duplicate.id.readerOrdinal shouldBe 1

      service.unregisterShuffle(11)
      service.activeInboxCount shouldBe 2

      first.close() shouldBe StreamingShuffleReceiveInboxStats(0L, 0L)
      duplicate.close() shouldBe StreamingShuffleReceiveInboxStats(0L, 0L)
      service.activeInboxCount shouldBe 0
      first.close() shouldBe StreamingShuffleReceiveInboxStats(0L, 0L)

      val second = service.acquire(12, TaskContext.empty())
      service.activeInboxCount shouldBe 1
      service.unregisterShuffle(12)
      service.activeInboxCount shouldBe 0
      second.close() shouldBe StreamingShuffleReceiveInboxStats(0L, 0L)
    }
  }

  test("prepared receive service enables elastic group admission") {
    Seq(false -> true, true -> false).foreach { case (receiveServiceEnabled, requiresWholeGroup) =>
      val conf = new SparkConf()
        .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, receiveServiceEnabled)
        .set(STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED, receiveServiceEnabled)
        .set(STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
          if (receiveServiceEnabled) 1024L else 0L)
        .set(STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, receiveServiceEnabled)
        .set(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, receiveServiceEnabled)
      withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", conf)) { _ =>
        SparkEnv.get.pipelinedShuffleManager.requiresWholeGroupSlotAdmission shouldBe
          requiresWholeGroup
        SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary shouldBe
          receiveServiceEnabled
        SparkEnv.get.pipelinedShuffleManager.supportsFanOut shouldBe true
      }
    }
  }

  test("multiplexed routes coalesce cumulative credit updates by physical lane") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS, 100L)
    withSpark(new SparkContext("local", "cumulative-credit-batch", conf)) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val queues = (0 until 8).map { writerId =>
        writerId -> new LinkedBlockingQueue[StreamingShuffleMessage]()
      }.toMap
      val readerHandlers = queues.toSeq.sortBy(_._1).map { case (writerId, queue) =>
        writerId -> new StreamingShuffleClientHandler(
          writerId, 0, queue, 7, 40L, null, new ErrorNotifier())
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => (), 7, 1, TaskContext.empty(), new ErrorNotifier())
      }
      val writerHandlersById = writerHandlers.toMap
      val queued = new scala.collection.mutable.ArrayBuffer[StreamingShuffleMessage]()
      try {
        val routeClients = client.registerBatch(
          7, 0, "127.0.0.1", server.port, readerHandlers)
        eventually(Timeout(10.seconds)) {
          server.pendingCreditRouteCount shouldBe readerHandlers.size
        }
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        server.pendingCreditRouteCount shouldBe 0
        eventually(Timeout(10.seconds)) {
          writerHandlers.foreach { case (_, handler) =>
            handler.clientsFor(0).size shouldBe 1
          }
        }

        readerHandlers.foreach { case (writerId, handler) =>
          val writerHandler = writerHandlersById(writerId)
          writerHandler.consumeDataCredit(0, writerHandler.clientsFor(0).head, 40L)
          val encoded = ByteBuffer.allocate(40)
          encoded.putInt(1).putLong(0L).putInt(7).putInt(writerId).putInt(0)
            .putInt(0).putInt(0).putLong(0L).flip()
          handler.receive(routeClients(writerId), encoded, null)
          queued += queues(writerId).poll(10, TimeUnit.SECONDS)
        }
        queued.foreach(_.release())
        queued.clear()

        eventually(Timeout(10.seconds)) {
          client.cumulativeCreditBatchStats shouldBe (8L, 1L, 8L, 0L)
          writerHandlers.foreach { case (_, handler) =>
            handler.availableDataCredit(0, handler.clientsFor(0).head) shouldBe 40L
          }
        }
      } finally {
        queued.filter(_ != null).foreach(_.release())
        writerHandlers.foreach { case (writerId, handler) => server.unregister(7, writerId, handler) }
        readerHandlers.foreach { case (writerId, handler) => client.unregister(7, writerId, 0, handler) }
        client.close()
        server.close()
      }
    }
  }

  test("prepared inboxes for one shuffle share one executor location snapshot") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val polls = new AtomicInteger(0)
    val ready = new AtomicInteger(0)
    val publishSnapshot = new AtomicBoolean(false)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf,
      _ => {
        if (publishSnapshot.get()) {
          polls.incrementAndGet()
          Some(ShuffleLocationResponse(Map.empty, 0))
        } else {
          None
        }
      })
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(2, "prepared-discovery-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val sessions = (0 until 8).map { partitionId =>
      val inbox = new StreamingShuffleReceiveInbox(
        StreamingShuffleReceiveInboxId(7, 9, 0, partitionId, -1L),
        new LinkedBlockingQueue[StreamingShuffleMessage]())
      new StreamingShufflePreparedReceiveSession(
        inbox,
        sharedClient,
        conf,
        discovery,
        clientCreationExecutor,
        () => ready.incrementAndGet())
    }
    try {
      sessions.foreach(_.start())
      publishSnapshot.set(true)
      eventually(Timeout(10.seconds)) {
        ready.get() shouldBe sessions.size
      }
      polls.get() shouldBe 1
      sessions.foreach(_.totalNumShuffleWriters.get() shouldBe 0)
      val (active, peak, _, deliveries) = discovery.stats
      active shouldBe 0
      peak shouldBe sessions.size
      deliveries shouldBe sessions.size.toLong
    } finally {
      sessions.foreach(_.close())
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared session unregisters a route that completes after inbox close") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => None)
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(1, "prepared-close-race-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val transportClient = mock[TransportClient]
    val registerEntered = new CountDownLatch(1)
    val finishRegister = new CountDownLatch(1)
    when(sharedClient.registerBatch(
      eqTo(7),
      eqTo(0),
      eqTo("writer-host"),
      eqTo(7337),
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenAnswer { _ =>
        registerEntered.countDown()
        finishRegister.await(10, TimeUnit.SECONDS)
        Map(3 -> transportClient)
      }
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L),
      new LinkedBlockingQueue[StreamingShuffleMessage]())
    val session = new StreamingShufflePreparedReceiveSession(
      inbox,
      sharedClient,
      conf,
      discovery,
      clientCreationExecutor,
      () => ())
    try {
      session.start()
      session.onWriterSnapshot(ShuffleLocationResponse(
        Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)),
        1))
      registerEntered.await(10, TimeUnit.SECONDS) shouldBe true
      session.close()
      finishRegister.countDown()
      eventually(Timeout(10.seconds)) {
        verify(sharedClient).unregister(
          eqTo(7), eqTo(3), eqTo(0), any[StreamingShuffleClientHandler])
      }
    } finally {
      finishRegister.countDown()
      session.close()
      discovery.close()
      clientCreationExecutor.shutdownNow()
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
