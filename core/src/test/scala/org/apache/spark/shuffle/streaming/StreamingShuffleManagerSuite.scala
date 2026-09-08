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
import java.util.concurrent.{CompletableFuture, ConcurrentHashMap, CountDownLatch,
  LinkedBlockingQueue, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicReference}

import scala.collection.mutable

import io.netty.buffer.Unpooled
import io.netty.channel.ChannelOption
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
  STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE,
  STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED,
  STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL,
  STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES,
  STREAMING_SHUFFLE_PREPARED_INBOX_READY_IDLE_TIMEOUT,
  STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT,
  STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED, STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
  STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED}
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.{DataMessage, StreamingShuffleMessage,
  StreamingShuffleMessageType, TerminationAckMessage, TerminationControlMessage}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager.{getQueryId, getWriterId, QUERY_ID_PROPERTY_KEY}
import org.apache.spark.util.{ErrorNotifier, ThreadUtils}

class StreamingShuffleManagerSuite
  extends SparkFunSuite
  with LocalSparkContext
  with Matchers
  with MockitoSugar {

  private val SQL_EXECUTION_ID_KEY = "spark.sql.execution.id"

  test("prepared inbox defers compute attachment by default") {
    new SparkConf().get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES) shouldBe (1L << 20)
    new SparkConf().get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_IDLE_TIMEOUT) shouldBe 100L
  }

  test("executor direct wire budget is exact and work conserving") {
    val budget = new StreamingShuffleDirectBufferBudget(1024L)
    budget.tryAcquire(768) shouldBe true
    budget.tryAcquire(300) shouldBe false
    budget.recordRawFallback(300)
    budget.stats shouldBe (768L, 768L, 1024L, 1L, 300L)

    budget.release(768)
    budget.tryAcquire(1024) shouldBe true
    budget.stats shouldBe (1024L, 1024L, 1024L, 1L, 300L)
    budget.release(1024)
    budget.close()
    budget.tryAcquire(1) shouldBe false
  }

  test("executor wire budget uses a bounded heap fallback at the JVM direct limit") {
    val directOomConstructor =
      classOf[_root_.io.netty.util.internal.OutOfDirectMemoryError]
        .getDeclaredConstructor(classOf[String])
    directOomConstructor.setAccessible(true)
    val budget = new StreamingShuffleDirectBufferBudget(
      1024L,
      _ => throw directOomConstructor.newInstance("test direct limit"))

    val buffer = budget.tryAllocate(512)
    buffer should not be null
    buffer.isDirect shouldBe false
    budget.stats shouldBe (512L, 512L, 1024L, 0L, 0L)
    budget.heapFallbackStats shouldBe (1L, 512L)
    buffer.release()
    budget.release(512)
  }

  test("executor wire budget wakes a waiter after a payload completes") {
    val budget = new StreamingShuffleDirectBufferBudget(1024L)
    val first = budget.tryAllocate(1024)
    first should not be null

    val waiting = CompletableFuture.supplyAsync(() => budget.awaitAllocate(1024, 10000L))
    Thread.sleep(50L)
    waiting.isDone shouldBe false
    first.release()
    budget.release(1024)

    val second = waiting.get(10L, TimeUnit.SECONDS)
    second should not be null
    second.release()
    budget.release(1024)
  }

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

  test("prepared receive mode never falls back to a task-owned inbox") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, true)
    val service = new StreamingShuffleReceiveService(conf)
    val error = intercept[IllegalStateException] {
      service.acquire(10, TaskContext.empty())
    }
    error.getMessage should include("must not fall back to a task-owned route")
    service.activeInboxCount shouldBe 0
  }

  test("task attachment resolves the current prepared inbox generation") {
    withSpark(new SparkContext("local", "prepared-inbox-generation", new SparkConf())) { _ =>
      val conf = SparkEnv.get.conf.clone()
        .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, true)
      val service = new StreamingShuffleReceiveService(
        conf, () => Some(mock[StreamingShuffleExecutorClient]))
      val context = mock[TaskContext]
      when(context.stageId()).thenReturn(9)
      when(context.stageAttemptNumber()).thenReturn(0)
      when(context.partitionId()).thenReturn(3)
      when(context.taskAttemptId()).thenReturn(41L)
      val generatedId = StreamingShuffleReceiveInboxId(7, 9, 0, 3, -17L)
      try {
        service.prepare(generatedId) shouldBe true
        val lease = service.acquire(7, context)
        lease.id shouldBe generatedId
        lease.close() shouldBe StreamingShuffleReceiveInboxStats(0L, 0L)
      } finally {
        service.close()
      }
    }
  }

  test("failed prepared inbox batch rolls back the executor-side prefix") {
    withSpark(new SparkContext("local", "prepared-inbox-batch-rollback", new SparkConf())) { _ =>
      val conf = SparkEnv.get.conf.clone()
        .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, true)
      val first = StreamingShuffleReceiveInboxId(7, 9, 0, 3, -17L)
      val second = StreamingShuffleReceiveInboxId(7, 9, 0, 4, -18L)
      val service = new StreamingShuffleReceiveService(
        conf, () => Some(mock[StreamingShuffleExecutorClient])) {
        override def prepare(id: StreamingShuffleReceiveInboxId): Boolean = {
          if (id == second) throw new IllegalStateException("injected prepare failure")
          super.prepare(id)
        }
      }
      try {
        val error = intercept[IllegalStateException] {
          service.prepareAll(Seq(first, second))
        }
        error.getMessage should include("injected prepare failure")
        service.activeInboxCount shouldBe 0

        // The failed batch must not leave the logical partition owned by its old generation.
        val replacement = first.copy(taskAttemptId = -19L)
        service.prepare(replacement) shouldBe true
        service.activeInboxCount shouldBe 1
      } finally {
        service.close()
      }
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
        // Prepared receive can stage inactive partitions, but doing so merely moves the whole
        // memory-retaining boundary to disk. It must not advertise the no-spill contract needed
        // to pipeline a shuffled hash join with only a subset of reducers attached.
        SparkEnv.get.pipelinedShuffleManager.supportsMemoryRetainingConsumer shouldBe false
        SparkEnv.get.pipelinedShuffleManager.supportsFanOut shouldBe true
      }
    }
  }

  test("prepared inboxes share one executor location snapshot across active shuffles") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val polls = new AtomicInteger(0)
    val ready = new AtomicInteger(0)
    val publishSnapshot = new AtomicBoolean(false)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf,
      shuffleIds => {
        if (publishSnapshot.get()) {
          polls.incrementAndGet()
          shuffleIds.map(_ -> ShuffleLocationResponse(Map.empty, 0)).toMap
        } else {
          Map.empty
        }
      })
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(2, "prepared-discovery-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val sessions = (0 until 8).map { partitionId =>
      val inbox = new StreamingShuffleReceiveInbox(
        StreamingShuffleReceiveInboxId(7 + partitionId % 2, 9, 0, partitionId, -1L),
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

  test("prepared session registration wakes discovery before the periodic refresh") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 60000L)
    val ready = new CountDownLatch(1)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf,
      shuffleIds => shuffleIds.map(_ -> ShuffleLocationResponse(Map.empty, 0)).toMap)
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(1, "prepared-discovery-wakeup-test-client")
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L),
      new LinkedBlockingQueue[StreamingShuffleMessage]())
    val session = new StreamingShufflePreparedReceiveSession(
      inbox,
      mock[StreamingShuffleExecutorClient],
      conf,
      discovery,
      clientCreationExecutor,
      () => ready.countDown())
    try {
      session.start()

      ready.await(10, TimeUnit.SECONDS) shouldBe true
      discovery.stats._3 shouldBe 1L
    } finally {
      session.close()
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared inbox becomes drain-ready when its receive window fills below threshold") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 60000L)
      .set(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES, 32L << 20)
      .set(STREAMING_SHUFFLE_PREPARED_INBOX_READY_IDLE_TIMEOUT, 200L)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => Map.empty)
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(1, "prepared-window-ready-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val transportClient = mock[TransportClient]
    val routeHandler = new AtomicReference[StreamingShuffleClientHandler]()
    val drainReady = new CountDownLatch(1)
    when(sharedClient.registerBatch(
      eqTo(7),
      eqTo(0),
      eqTo("writer-host"),
      eqTo(7337),
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenAnswer { invocation =>
        val handlers = invocation.getArgument[Seq[(Int, StreamingShuffleClientHandler)]](4)
        routeHandler.set(handlers.head._2)
        Map(3 -> transportClient)
      }
    val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L), queue)
    val session = new StreamingShufflePreparedReceiveSession(
      inbox,
      sharedClient,
      conf,
      discovery,
      clientCreationExecutor,
      () => drainReady.countDown())
    val queued = new java.util.ArrayList[StreamingShuffleMessage]()

    def encodedData(sequenceNumber: Long, payloadBytes: Int): ByteBuffer = {
      val encoded = ByteBuffer.allocate(40 + payloadBytes)
      encoded.putInt(StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW.id())
      encoded.putLong(sequenceNumber)
      encoded.putInt(7)
      encoded.putInt(3)
      encoded.putInt(0)
      encoded.putInt(payloadBytes)
      encoded.putInt(payloadBytes)
      encoded.putLong(0L)
      while (encoded.hasRemaining) encoded.put(0.toByte)
      encoded.flip()
      encoded
    }

    try {
      session.start()
      // Four hundred lifetime writers share the 32 MiB reader window, but only a bounded wave is
      // scheduled at once. The old code waited for the full 32 MiB threshold even after an active
      // route had exhausted its approximately 82 KiB credit and could publish neither data nor
      // its terminal frame.
      session.onWriterSnapshot(ShuffleLocationResponse(
        Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)),
        400))
      eventually(Timeout(10.seconds)) {
        routeHandler.get() should not be null
      }
      val handler = routeHandler.get()
      handler.useMultiplexedChannel()
      val routeWindow = StreamingShuffleReceiveService.routeByteLimit(32L << 20, 400).toInt

      handler.receive(null, encodedData(0L, routeWindow / 2), null)
      drainReady.await(100, TimeUnit.MILLISECONDS) shouldBe false

      handler.receive(null, encodedData(1L, routeWindow / 2), null)
      drainReady.await(100, TimeUnit.MILLISECONDS) shouldBe false
      drainReady.await(10, TimeUnit.SECONDS) shouldBe true
      queue.size() shouldBe 2
    } finally {
      queue.drainTo(queued)
      queued.forEach(_.release())
      session.close()
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("writer-location notification wakes discovery before the periodic refresh") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 60000L)
    val initialPoll = new CountDownLatch(1)
    val ready = new CountDownLatch(1)
    val publishSnapshot = new AtomicBoolean(false)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf,
      shuffleIds => {
        initialPoll.countDown()
        if (publishSnapshot.get()) {
          shuffleIds.map(_ -> ShuffleLocationResponse(Map.empty, 0)).toMap
        } else {
          Map.empty
        }
      })
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(1, "prepared-discovery-push-test-client")
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L),
      new LinkedBlockingQueue[StreamingShuffleMessage]())
    val session = new StreamingShufflePreparedReceiveSession(
      inbox,
      mock[StreamingShuffleExecutorClient],
      conf,
      discovery,
      clientCreationExecutor,
      () => ready.countDown())
    try {
      session.start()
      initialPoll.await(10, TimeUnit.SECONDS) shouldBe true
      publishSnapshot.set(true)

      discovery.writerLocationsAvailable()

      ready.await(10, TimeUnit.SECONDS) shouldBe true
      discovery.stats._3 shouldBe 2L
    } finally {
      session.close()
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared session unregisters a route that completes after inbox close") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => Map.empty)
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
      // A published location is not a completed route. Keep discovery alive while the physical
      // lane is still being created so a stuck registration cannot silently become an eternal
      // reader wait.
      discovery.stats._1 shouldBe 1
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

  test("prepared session fails a blocked route registration within a bounded timeout") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
      .set(STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT, 50L)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => Map.empty)
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(1, "prepared-route-timeout-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val transportClient = mock[TransportClient]
    val registerEntered = new CountDownLatch(1)
    val finishRegister = new CountDownLatch(1)
    val drainReady = new CountDownLatch(1)
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
      () => drainReady.countDown())
    try {
      session.start()
      session.onWriterSnapshot(ShuffleLocationResponse(
        Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)),
        1))
      registerEntered.await(10, TimeUnit.SECONDS) shouldBe true

      eventually(Timeout(10.seconds)) {
        session.errorNotifier.getError().map(_.getMessage) shouldBe
          Some("Prepared shuffle route registration timed out for " +
            "StreamingShuffleReceiveInboxId(7,9,0,0,-1,0,true): " +
            "completed=0, advertised=1, expected=1")
        discovery.stats._1 shouldBe 0
      }
      drainReady.await(10, TimeUnit.SECONDS) shouldBe true
    } finally {
      finishRegister.countDown()
      session.close()
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared discovery batches inbox route registration tasks by endpoint") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val snapshot = ShuffleLocationResponse(
      Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)),
      1)
    val publishSnapshot = new AtomicBoolean(false)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf, shuffleIds => {
        if (publishSnapshot.get()) shuffleIds.map(_ -> snapshot).toMap else Map.empty
      })
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(2, "prepared-route-batch-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val transportClient = mock[TransportClient]
    val registrations = new AtomicInteger(0)
    when(sharedClient.registerBatch(
      eqTo(7),
      any[Int],
      eqTo("writer-host"),
      eqTo(7337),
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenAnswer { _ =>
        registrations.incrementAndGet()
        Map(3 -> transportClient)
      }
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
        () => ())
    }
    try {
      sessions.foreach(_.start())
      publishSnapshot.set(true)
      eventually(Timeout(10.seconds)) {
        registrations.get() shouldBe sessions.size
      }
      discovery.routeRegistrationStats shouldBe (sessions.size.toLong, 1L)
    } finally {
      sessions.foreach(_.close())
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared discovery stays active across an executor-sized blocked lane frontier") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 60000L)
    val writerExecutors = 26
    val reducerInboxes = 52
    val snapshot = ShuffleLocationResponse(
      (0 until writerExecutors).map { writerId =>
        writerId.toLong -> StreamingShuffleTaskLocation(
          s"executor-$writerId", s"writer-host-$writerId", 7300 + writerId, writerId)
      }.toMap,
      writerExecutors)
    val publishSnapshot = new AtomicBoolean(false)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(
      conf, shuffleIds => {
        if (publishSnapshot.get()) shuffleIds.map(_ -> snapshot).toMap else Map.empty
      })
    // Match a 15-core executor: the first wave can occupy every synchronous lane-creation worker
    // while the remaining endpoint groups stay queued.
    val clientCreationExecutor =
      ThreadUtils.newDaemonFixedThreadPool(15, "prepared-executor-frontier-test-client")
    val sharedClient = mock[StreamingShuffleExecutorClient]
    val transportClient = mock[TransportClient]
    val blockedEndpoints = ConcurrentHashMap.newKeySet[String]()
    val blockedEntrances = new CountDownLatch(15)
    val releaseBlockedEndpoints = new CountDownLatch(1)
    val registrations = new AtomicInteger(0)
    when(sharedClient.registerBatch(
      eqTo(7),
      any[Int],
      any[String],
      any[Int],
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenAnswer { invocation =>
        val host = invocation.getArgument[String](2)
        val hostIndex = host.stripPrefix("writer-host-").toInt
        if (hostIndex < 15 && blockedEndpoints.add(host)) {
          blockedEntrances.countDown()
          releaseBlockedEndpoints.await(10, TimeUnit.SECONDS)
        }
        registrations.incrementAndGet()
        invocation.getArgument[Seq[(Int, StreamingShuffleClientHandler)]](4)
          .map { case (writerId, _) => writerId -> transportClient }.toMap
      }
    val sessions = (0 until reducerInboxes).map { partitionId =>
      val inbox = new StreamingShuffleReceiveInbox(
        StreamingShuffleReceiveInboxId(7, 9, 0, partitionId, -1L),
        new LinkedBlockingQueue[StreamingShuffleMessage]())
      new StreamingShufflePreparedReceiveSession(
        inbox,
        sharedClient,
        conf,
        discovery,
        clientCreationExecutor,
        () => ())
    }
    try {
      sessions.foreach(_.start())
      publishSnapshot.set(true)
      discovery.writerLocationsAvailable()

      blockedEntrances.await(10, TimeUnit.SECONDS) shouldBe true
      discovery.stats._1 shouldBe reducerInboxes

      releaseBlockedEndpoints.countDown()
      eventually(Timeout(10.seconds)) {
        registrations.get() shouldBe writerExecutors * reducerInboxes
        discovery.stats._1 shouldBe 0
      }
      discovery.routeRegistrationStats shouldBe
        (writerExecutors.toLong * reducerInboxes, writerExecutors.toLong)
    } finally {
      releaseBlockedEndpoints.countDown()
      sessions.foreach(_.close())
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }

  test("prepared routes coalesce initial credits across inboxes on one physical lane") {
    withSpark(new SparkContext("local", "prepared-initial-credit-batch", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val handlers = (0 until 9).map { readerId =>
        readerId -> new StreamingShuffleClientHandler(
          3,
          readerId,
          new LinkedBlockingQueue[StreamingShuffleMessage](),
          7,
          1L << 20,
          null,
          new ErrorNotifier())
      }
      val failedRequest = new Object()
      val successfulRequests = handlers.map { case (readerId, handler) =>
        val request = new Object()
        request -> (() => {
          client.registerBatch(
            7, readerId, "127.0.0.1", server.port, Seq(3 -> handler))
          // Model an inbox that closes after route installation but before this worker flushes
          // the shared initial-credit body. Its pending frame must be canceled.
          if (readerId == 8) client.unregister(7, 3, readerId, handler)
          ()
        })
      }
      try {
        val expectedFailure = new RuntimeException("isolated route failure")
        val failures = StreamingShuffleExecutorClient.runBatchedRouteRegistrations(
          successfulRequests :+ (failedRequest -> (() => throw expectedFailure)))

        failures shouldBe Map(failedRequest -> expectedFailure)
        client.initialCreditBatchStats shouldBe (handlers.size.toLong, 1L)
        eventually(Timeout(10.seconds)) {
          server.controlBodyStats shouldBe (1L, handlers.size.toLong - 1L)
        }
      } finally {
        handlers.foreach { case (readerId, handler) =>
          client.unregister(7, 3, readerId, handler)
        }
        client.close()
        server.close()
      }
    }
  }

  test("prepared routes discover at zero window until executor credit is available") {
    withSpark(new SparkContext("local", "prepared-global-credit-budget", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val budget = new StreamingShuffleReceiveCreditBudget(64L)
      val readerHandlers = (3 to 4).map { writerId =>
        val handler = new StreamingShuffleClientHandler(
          writerId,
          0,
          new LinkedBlockingQueue[StreamingShuffleMessage](),
          7,
          64L,
          null,
          new ErrorNotifier())
        handler.useExecutorReceiveCreditBudget(budget, 64L)
        writerId -> handler
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => (),
          shuffleId = 7,
          numReaders = 1,
          context = mock[TaskContext],
          errorNotifier = new ErrorNotifier())
      }
      try {
        client.registerBatch(7, 0, "127.0.0.1", server.port, readerHandlers)
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        eventually(Timeout(10.seconds)) {
          budget.usedBytesCount shouldBe 64L
          budget.pendingLeaseCount shouldBe 1
          writerHandlers.head._2.availableDataCredit(
            0, writerHandlers.head._2.clientsFor(0).head) shouldBe 64L
          writerHandlers(1)._2.availableDataCredit(
            0, writerHandlers(1)._2.clientsFor(0).head) shouldBe 0L
          readerHandlers(1)._2.prepareMultiplexedCreditRepair() shouldBe empty
        }

        // Retiring the active route transfers the executor lease to the already-discovered route.
        readerHandlers.head._2.closeReceiveCreditLease()
        eventually(Timeout(10.seconds)) {
          writerHandlers(1)._2.availableDataCredit(
            0, writerHandlers(1)._2.clientsFor(0).head) shouldBe 64L
          budget.usedBytesCount shouldBe 64L
          budget.pendingLeaseCount shouldBe 0
        }
      } finally {
        writerHandlers.foreach { case (writerId, handler) =>
          server.unregister(7, writerId, handler)
        }
        readerHandlers.foreach { case (writerId, handler) =>
          client.unregister(7, writerId, 0, handler)
        }
        client.close()
        server.close()
      }
      budget.usedBytesCount shouldBe 0L
    }
  }

  test("consumed route window rotates without starving a sibling input") {
    withSpark(new SparkContext("local", "prepared-cross-input-credit", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val budget = new StreamingShuffleReceiveCreditBudget(64L)
      budget.registerOwners(Seq("left-input", "right-input"))
      val queues = (3 to 5).map { writerId =>
        writerId -> new LinkedBlockingQueue[StreamingShuffleMessage]()
      }.toMap
      val readerHandlers = Seq(
        3 -> new StreamingShuffleClientHandler(
          3, 0, queues(3), 7, 64L, null, new ErrorNotifier()),
        4 -> new StreamingShuffleClientHandler(
          4, 0, queues(4), 7, 64L, null, new ErrorNotifier()),
        5 -> new StreamingShuffleClientHandler(
          5, 0, queues(5), 7, 64L, null, new ErrorNotifier()))
      readerHandlers.take(2).foreach { case (_, handler) =>
        handler.useExecutorReceiveCreditBudget(budget, 64L, "left-input")
      }
      readerHandlers.drop(2).foreach { case (_, handler) =>
        handler.useExecutorReceiveCreditBudget(budget, 64L, "right-input")
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => (), 7, 1, mock[TaskContext], new ErrorNotifier())
      }.toMap
      var queuedData: StreamingShuffleMessage = null
      try {
        val routeClients = client.registerBatch(
          7, 0, "127.0.0.1", server.port, readerHandlers)
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        eventually(Timeout(10.seconds)) {
          writerHandlers(3).availableDataCredit(
            0, writerHandlers(3).clientsFor(0).head) shouldBe 32L
          writerHandlers(4).availableDataCredit(
            0, writerHandlers(4).clientsFor(0).head) shouldBe 0L
          writerHandlers(5).availableDataCredit(
            0, writerHandlers(5).clientsFor(0).head) shouldBe 32L
        }

        val firstWriterClient = writerHandlers(3).clientsFor(0).head
        writerHandlers(3).consumeDataCredit(0, firstWriterClient, 40L)
        val encoded = ByteBuffer.allocate(40)
        encoded.putInt(StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW.id())
        encoded.putLong(0L)
        encoded.putInt(7)
        encoded.putInt(3)
        encoded.putInt(0)
        encoded.putInt(0)
        encoded.putInt(0)
        encoded.putLong(0L)
        encoded.flip()
        readerHandlers.head._2.receive(routeClients(3), encoded, null)
        queuedData = queues(3).poll(10, TimeUnit.SECONDS)
        queuedData should not be null
        queuedData.release()
        queuedData = null

        eventually(Timeout(10.seconds)) {
          writerHandlers(4).availableDataCredit(
            0, writerHandlers(4).clientsFor(0).head) shouldBe 32L
          writerHandlers(3).availableDataCredit(0, firstWriterClient) shouldBe 0L
        }
      } finally {
        if (queuedData != null) queuedData.release()
        writerHandlers.foreach { case (writerId, handler) =>
          server.unregister(7, writerId, handler)
        }
        readerHandlers.foreach { case (writerId, handler) =>
          client.unregister(7, writerId, 0, handler)
        }
        client.close()
        server.close()
      }
      budget.usedBytesCount shouldBe 0L
    }
  }

  test("successive consumer generations pool routes on replay-isolated lanes") {
    withSpark(new SparkContext("local", "prepared-consumer-generation-lanes", new SparkConf())) {
      _ =>
        val server = new StreamingShuffleExecutorServer()
        val client = new StreamingShuffleExecutorClient()
        def handlers(): Seq[(Int, StreamingShuffleClientHandler)] = (3 to 11).map { writerId =>
          writerId -> new StreamingShuffleClientHandler(
            writerId,
            0,
            new LinkedBlockingQueue[StreamingShuffleMessage](),
            7,
            1L << 20,
            null,
            new ErrorNotifier())
        }
        val firstHandlers = handlers()
        val secondHandlers = handlers()
        try {
          val first = client.registerBatch(
            7, 0, "127.0.0.1", server.port, firstHandlers)
          first.values.toSet.size shouldBe 1
          firstHandlers.foreach { case (writerId, handler) =>
            client.unregister(7, writerId, 0, handler)
          }

          val second = client.registerBatch(
            7, 0, "127.0.0.1", server.port, secondHandlers)
          second.values.toSet.size shouldBe 1
          (second.values.head eq first.values.head) shouldBe false
        } finally {
          firstHandlers.foreach { case (writerId, handler) =>
            client.unregister(7, writerId, 0, handler)
          }
          secondHandlers.foreach { case (writerId, handler) =>
            client.unregister(7, writerId, 0, handler)
          }
          client.close()
          server.close()
        }
    }
  }

  test("prepared routes coalesce idle credit repairs on one physical lane") {
    val socketBufferSize = 128 << 10
    val conf = new SparkConf().set(STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE, socketBufferSize)
    withSpark(new SparkContext("local", "prepared-credit-repair-batch", conf)) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val readerHandlers = (0 until 9).map { writerId =>
        writerId -> new StreamingShuffleClientHandler(
          writerId,
          0,
          new LinkedBlockingQueue[StreamingShuffleMessage](),
          7,
          1L << 20,
          null,
          new ErrorNotifier())
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => (),
          shuffleId = 7,
          numReaders = 1,
          context = mock[TaskContext],
          errorNotifier = new ErrorNotifier())
      }
      try {
        val routeClients = client.registerBatch(
          7, 0, "127.0.0.1", server.port, readerHandlers)
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        eventually(Timeout(10.seconds)) {
          server.controlBodyStats shouldBe (1L, readerHandlers.size.toLong)
          writerHandlers.foreach { case (_, handler) =>
            handler.clientsFor(0).size shouldBe 1
          }
        }
        val sharedLane = writerHandlers.head._2.clientsFor(0).head
        // Linux commonly reports twice the requested value after applying its socket accounting.
        sharedLane.getChannel.config.getOption(ChannelOption.SO_RCVBUF).intValue() should be >=
          socketBufferSize

        client.repairCreditWindows(readerHandlers.map { case (writerId, handler) =>
          routeClients(writerId) -> handler
        })
        eventually(Timeout(10.seconds)) {
          server.controlBodyStats shouldBe (2L, readerHandlers.size.toLong * 2L)
        }
        client.creditRepairBatchWriteCount shouldBe 1L
      } finally {
        writerHandlers.foreach { case (writerId, handler) =>
          server.unregister(7, writerId, handler)
        }
        readerHandlers.foreach { case (writerId, handler) =>
          client.unregister(7, writerId, 0, handler)
        }
        client.close()
        server.close()
      }
    }
  }

  test("prepared routes coalesce hot cumulative credits on one physical lane") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS, 100L)
    withSpark(new SparkContext("local", "prepared-cumulative-credit-batch", conf)) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val queues = (0 until 9).map { writerId =>
        writerId -> new LinkedBlockingQueue[StreamingShuffleMessage]()
      }.toMap
      val readerHandlers = queues.toSeq.sortBy(_._1).map { case (writerId, queue) =>
        writerId -> new StreamingShuffleClientHandler(
          writerId, 0, queue, 7, 1L << 20, null, new ErrorNotifier())
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => (), 7, 1, mock[TaskContext], new ErrorNotifier())
      }
      val queued = new mutable.ArrayBuffer[StreamingShuffleMessage]()
      try {
        val routeClients = client.registerBatch(
          7, 0, "127.0.0.1", server.port, readerHandlers)
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        eventually(Timeout(10.seconds)) {
          server.controlBodyStats shouldBe (1L, readerHandlers.size.toLong)
        }

        readerHandlers.foreach { case (writerId, handler) =>
          val encoded = ByteBuffer.allocate(40)
          encoded.putInt(StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW.id())
          encoded.putLong(0L)
          encoded.putInt(7)
          encoded.putInt(writerId)
          encoded.putInt(0)
          encoded.putInt(0)
          encoded.putInt(0)
          encoded.putLong(0L)
          encoded.flip()
          handler.receive(routeClients(writerId), encoded, null)
          queued += queues(writerId).poll(10, TimeUnit.SECONDS)
        }
        queued.foreach(_.release())
        queued.clear()

        eventually(Timeout(10.seconds)) {
          client.cumulativeCreditBatchStats shouldBe
            (readerHandlers.size.toLong, 1L, readerHandlers.size.toLong)
          server.controlBodyStats shouldBe
            (2L, readerHandlers.size.toLong * 2L)
        }
      } finally {
        queued.filter(_ != null).foreach(_.release())
        writerHandlers.foreach { case (writerId, handler) =>
          server.unregister(7, writerId, handler)
        }
        readerHandlers.foreach { case (writerId, handler) =>
          client.unregister(7, writerId, 0, handler)
        }
        client.close()
        server.close()
      }
    }
  }

  test("prepared routes return one terminal ACK body for one multiplexed terminal body") {
    val conf = new SparkConf()
      .set(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS, 100L)
    withSpark(new SparkContext("local", "prepared-terminal-ack-batch", conf)) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val writerCount = 9
      val queues = Array.fill(writerCount)(new LinkedBlockingQueue[StreamingShuffleMessage]())
      val clientAckCompletions = new AtomicInteger(0)
      val terminalSendCompletions = new AtomicInteger(0)
      val writerAcks = ConcurrentHashMap.newKeySet[Int]()
      val readerHandlers = (0 until writerCount).map { writerId =>
        val handler = new StreamingShuffleClientHandler(
          writerId, 0, queues(writerId), 7, 1L << 20, null, new ErrorNotifier())
        handler.setOnTermAckResponseHandler(_ => clientAckCompletions.incrementAndGet())
        writerId -> handler
      }
      val writerHandlers = readerHandlers.map { case (writerId, _) =>
        writerId -> new StreamingShuffleServerHandler(
          (_, _) => { writerAcks.add(writerId); () },
          shuffleId = 7,
          numReaders = 1,
          context = mock[TaskContext],
          errorNotifier = new ErrorNotifier())
      }
      val queued = new mutable.ArrayBuffer[StreamingShuffleMessage]()
      try {
        client.registerBatch(7, 0, "127.0.0.1", server.port, readerHandlers)
        writerHandlers.foreach { case (writerId, handler) =>
          server.register(7, writerId, handler)
        }
        eventually(Timeout(10.seconds)) {
          server.controlBodyStats shouldBe (1L, writerCount.toLong)
          writerHandlers.foreach { case (_, handler) =>
            handler.clientsFor(0).size shouldBe 1
          }
        }
        val writerClients = writerHandlers.flatMap(_._2.clientsFor(0)).distinct
        writerClients.size shouldBe 1

        val terminalOwner = new Object()
        val terminalErrors = new ErrorNotifier()
        (0 until writerCount).foreach { writerId =>
          val body = Unpooled.compositeBuffer().capacity(24)
          val terminal = new TerminationControlMessage(7, writerId, 0)
          terminal.setSeqNum(0L)
          terminal.encode(body)
          server.crossRouteBatcher.submit(
            writerClients.head,
            body,
            () => terminalSendCompletions.incrementAndGet(),
            terminalOwner,
            terminalErrors)
        }
        // Model the bounded timer firing after all concurrently completing writers reached the
        // shared executor batcher. Their individually encoded terminals become one wire body.
        server.crossRouteBatcher.flush(writerClients.head)

        (0 until writerCount).foreach { writerId =>
          val message = queues(writerId).poll(10, TimeUnit.SECONDS)
          message should not be null
          queued += message
        }
        eventually(Timeout(10.seconds)) {
          writerAcks.size shouldBe writerCount
          terminalSendCompletions.get() shouldBe writerCount
          clientAckCompletions.get() shouldBe writerCount
          client.terminationAckBatchStats shouldBe (1L, writerCount.toLong)
          server.controlBodyStats shouldBe (2L, writerCount.toLong * 2L)
          server.crossRouteBatcher.transportBatchStats shouldBe
            (writerCount.toLong, 1L, writerCount.toLong, writerCount.toLong)
        }
      } finally {
        queued.foreach(_.release())
        writerHandlers.foreach { case (writerId, handler) =>
          server.unregister(7, writerId, handler)
        }
        readerHandlers.foreach { case (writerId, handler) =>
          client.unregister(7, writerId, 0, handler)
        }
        client.close()
        server.close()
      }
    }
  }

  test("shared writer endpoint replays prepared credit that arrives before writer registration") {
    withSpark(new SparkContext("local", "prepared-credit-before-writer", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val readerHandler = new StreamingShuffleClientHandler(
        3,
        0,
        new LinkedBlockingQueue[StreamingShuffleMessage](),
        7,
        1L << 20,
        null,
        new ErrorNotifier())
      val writerContext = mock[TaskContext]
      val writerHandler = new StreamingShuffleServerHandler(
        (_, _) => (),
        shuffleId = 7,
        numReaders = 1,
        context = writerContext,
        errorNotifier = new ErrorNotifier())
      try {
        val routeClient = client.registerBatch(
          shuffleId = 7,
          readerId = 0,
          remoteHost = "127.0.0.1",
          remotePort = server.port,
          handlersByWriter = Seq(3 -> readerHandler))(3)
        eventually(Timeout(10.seconds)) {
          server.pendingCreditCount shouldBe 1
        }

        server.register(7, 3, writerHandler)
        eventually(Timeout(10.seconds)) {
          server.pendingCreditCount shouldBe 0
          writerHandler.clientsFor(0).size shouldBe 1
        }

        server.unregister(7, 3, writerHandler)
        readerHandler.repairCreditWindow(routeClient)
        eventually(Timeout(10.seconds)) {
          server.pendingCreditCount shouldBe 0
        }
      } finally {
        server.unregister(7, 3, writerHandler)
        client.unregister(7, 3, 0, readerHandler)
        client.close()
        server.close()
      }
    }
  }

  test("prepared route repairs a lost cumulative credit ack after receiving data") {
    withSpark(new SparkContext("local", "prepared-credit-after-data", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
      val byteLimit = 40L
      val suppressedAck = new AtomicBoolean(false)
      val readerHandler = new StreamingShuffleClientHandler(
          3, 0, queue, 7, byteLimit, null, new ErrorNotifier()) {
        override protected def sendCumulativeCreditAck(
            routeClient: TransportClient,
            releasedBytes: Long): Unit = {
          if (!suppressedAck.compareAndSet(false, true)) {
            super.sendCumulativeCreditAck(routeClient, releasedBytes)
          }
        }
      }
      val writerHandler = new StreamingShuffleServerHandler(
        (_, _) => (),
        shuffleId = 7,
        numReaders = 1,
        context = mock[TaskContext],
        errorNotifier = new ErrorNotifier())
      var queuedData: StreamingShuffleMessage = null
      try {
        val routeClient = client.registerBatch(
          shuffleId = 7,
          readerId = 0,
          remoteHost = "127.0.0.1",
          remotePort = server.port,
          handlersByWriter = Seq(3 -> readerHandler))(3)
        server.register(7, 3, writerHandler)
        eventually(Timeout(10.seconds)) {
          writerHandler.clientsFor(0).size shouldBe 1
          writerHandler.availableDataCredit(0, writerHandler.clientsFor(0).head) shouldBe byteLimit
        }

        // Advance the reader sequence so this is no longer an initial-discovery repair. The empty
        // encoded data frame is exactly 40 bytes on the wire and consumes the complete route
        // window. Suppress its first cumulative release ACK to model a delayed/lost final wake-up.
        val encoded = ByteBuffer.allocate(40)
        encoded.putInt(StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW.id())
        encoded.putLong(0L)
        encoded.putInt(7)
        encoded.putInt(3)
        encoded.putInt(0)
        encoded.putInt(0)
        encoded.putInt(0)
        encoded.putLong(0L)
        encoded.flip()
        readerHandler.receive(routeClient, encoded, null)
        queuedData = queue.poll(10, TimeUnit.SECONDS)
        queuedData should not be null

        val writerRouteClient = writerHandler.clientsFor(0).head
        writerHandler.consumeDataCredit(0, writerRouteClient, byteLimit)
        writerHandler.availableDataCredit(0, writerRouteClient) shouldBe 0L
        queuedData.release()
        queuedData = null
        suppressedAck.get() shouldBe true
        writerHandler.availableDataCredit(0, writerRouteClient) shouldBe 0L

        client.repairCreditWindows(Seq(routeClient -> readerHandler))
        eventually(Timeout(10.seconds)) {
          writerHandler.availableDataCredit(0, writerRouteClient) shouldBe byteLimit
        }
        client.creditRepairBatchWriteCount shouldBe 1L
      } finally {
        if (queuedData != null) queuedData.release()
        server.unregister(7, 3, writerHandler)
        client.unregister(7, 3, 0, readerHandler)
        client.close()
        server.close()
      }
    }
  }

  test("shared writer endpoint atomically hands concurrent prepared credits to registration") {
    withSpark(new SparkContext("local", "concurrent-prepared-credit-handoff", new SparkConf())) {
      _ =>
        val server = new StreamingShuffleExecutorServer()
        val client = new StreamingShuffleExecutorClient()
        val readers = 16
        val readerHandlers = Array.tabulate(readers) { readerId =>
          new StreamingShuffleClientHandler(
            9,
            readerId,
            new LinkedBlockingQueue[StreamingShuffleMessage](),
            11,
            1L << 20,
            null,
            new ErrorNotifier())
        }
        val writerHandler = new StreamingShuffleServerHandler(
          (_, _) => (),
          shuffleId = 11,
          numReaders = readers,
          context = mock[TaskContext],
          errorNotifier = new ErrorNotifier())
        val start = new CountDownLatch(1)
        val writerRegistered = new AtomicBoolean(false)
        val pool = ThreadUtils.newDaemonFixedThreadPool(
          readers + 1, "concurrent-prepared-credit-handoff")
        try {
          val writer = CompletableFuture.runAsync(
            () => {
              start.await()
              server.register(11, 9, writerHandler)
              writerRegistered.set(true)
            },
            pool)
          val credits = readerHandlers.zipWithIndex.map { case (handler, readerId) =>
            CompletableFuture.runAsync(
              () => {
                start.await()
                client.register(11, 9, readerId, "127.0.0.1", server.port, handler)
                ()
              },
              pool)
          }
          start.countDown()
          CompletableFuture.allOf((credits :+ writer): _*).get(10, TimeUnit.SECONDS)

          eventually(Timeout(10.seconds)) {
            server.pendingCreditCount shouldBe 0
            (0 until readers).foreach { readerId =>
              writerHandler.clientsFor(readerId).size shouldBe 1
            }
          }
        } finally {
          if (writerRegistered.get()) server.unregister(11, 9, writerHandler)
          readerHandlers.zipWithIndex.foreach { case (handler, readerId) =>
            client.unregister(11, 9, readerId, handler)
          }
          pool.shutdownNow()
          client.close()
          server.close()
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
