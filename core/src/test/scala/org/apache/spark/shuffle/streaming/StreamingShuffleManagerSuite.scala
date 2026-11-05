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
import java.util.concurrent.{Callable, CountDownLatch, LinkedBlockingQueue, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger}

import io.netty.buffer.Unpooled
import io.netty.handler.timeout.IdleStateEvent
import org.mockito.ArgumentMatchers.{any, eq => eqTo}
import org.mockito.Mockito.{atLeastOnce, inOrder => inMockitoOrder, never, verify, when}
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
  STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
  STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED,
  STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS}
import org.apache.spark.network.client.{TransportClient, TransportClientFactory}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, DataMessage, StreamingShuffleMessage,
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

  Seq("reader", "writer", "receive endpoint").foreach { operation =>
    test(s"a stopped shuffle manager rejects a late $operation") {
      val manager = new StreamingShuffleManager()
      manager.stop()
      try {
        val error = intercept[IllegalStateException] {
          operation match {
            case "reader" => manager.getReader[Int, Int](null, 0, 1, 0, 1, null, null)
            case "writer" => manager.getWriter[Int, Int](null, 0L, null, null)
            case _ => manager.initializeReceiveServiceEndpoint()
          }
        }
        error.getMessage should include("Streaming shuffle manager is stopped")
      } finally {
        manager.stop()
      }
    }
  }

  Seq("receive service", "shared client", "reader factory", "writer server").foreach { resource =>
    test(s"shuffle manager stop fences pending $resource initialization") {
      val conf = new SparkConf()
        .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, resource == "receive service")
        .set(STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY, 1024L)
        .set(STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, resource != "reader factory")
        .set(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, true)
      withSpark(new SparkContext("local", "shuffle-stop-race", conf)) { _ =>
        val manager = new StreamingShuffleManager()
        val failures = new LinkedBlockingQueue[Throwable]()
        val worker = new Thread(() => {
          try {
            if (resource == "writer server") {
              manager.getWriter[Int, Int](null, 0L, null, null)
            } else {
              manager.getReader[Int, Int](null, 0, 1, 0, 1, null, null)
            }
          } catch {
            case error: Throwable => failures.add(error)
          }
          ()
        }, "shuffle-manager-stop-race")
        worker.setDaemon(true)
        try {
          manager.synchronized {
            worker.start()
            // The task has passed its entry check but cannot initialize the lazy resource yet.
            eventually(Timeout(5.seconds)) {
              worker.getState shouldBe Thread.State.BLOCKED
            }
            manager.stop()
          }
          val error = failures.poll(5, TimeUnit.SECONDS)
          error shouldBe a[IllegalStateException]
          error.getMessage should include("Streaming shuffle manager is stopped")
          worker.join(5000L)
          assert(!worker.isAlive)
        } finally {
          manager.stop()
          worker.interrupt()
          worker.join(5000L)
        }
      }
    }
  }

  test("shuffle manager cleanup is outside its monitor and continues after a close failure") {
    val manager = new StreamingShuffleManager()
    val closedUnderManagerLock = new AtomicBoolean(true)
    val service = new StreamingShuffleReceiveService(new SparkConf(false)) {
      override def close(): Unit = {
        closedUnderManagerLock.set(Thread.holdsLock(manager))
        super.close()
        throw new IllegalStateException("injected receive service close failure")
      }
    }
    val factory = mock[TransportClientFactory]
    val client = mock[StreamingShuffleExecutorClient]
    val server = mock[StreamingShuffleExecutorServer]
    // Inject owned resources without starting network threads, including a failed close.
    Seq("readerClientFactory" -> factory, "receiveService" -> service,
      "sharedExecutorClient" -> client, "sharedWriterServer" -> server).foreach {
      case (name, resource) =>
        val field = classOf[StreamingShuffleManager].getDeclaredField(name)
        field.setAccessible(true)
        field.set(manager, resource)
    }
    manager.stop()
    manager.stop()
    assert(!closedUnderManagerLock.get())
    val order = inMockitoOrder(factory, client, server)
    order.verify(factory).close()
    order.verify(client).close()
    order.verify(server).close()
    order.verifyNoMoreInteractions()
  }

  Seq(false, true).foreach { throwOnFailure =>
    test(s"prepare rollback preserves existing inboxes and shared client: throw=$throwOnFailure") {
      withSpark(new SparkContext("local", "prepare-rollback", new SparkConf())) { _ =>
        val client = mock[StreamingShuffleExecutorClient]
        val service = new StreamingShuffleReceiveService(SparkEnv.get.conf, () => Some(client)) {
          override def prepare(id: StreamingShuffleReceiveInboxId): Boolean = {
            if (id.partitionId == 2) {
              if (throwOnFailure) throw new IllegalStateException("prepare failed")
              false
            } else {
              super.prepare(id)
            }
          }
        }
        val existing = StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L)
        val created = existing.copy(partitionId = 1)
        val failed = existing.copy(partitionId = 2)
        try {
          service.prepare(existing) shouldBe true
          if (throwOnFailure) {
            intercept[IllegalStateException] {
              service.prepareAll(Seq(existing, created, failed))
            }
          } else {
            service.prepareAll(Seq(existing, created, failed)) shouldBe false
          }
          service.activeInboxCount shouldBe 1
          service.releasePrepared(created) shouldBe false
          service.releasePrepared(existing) shouldBe true
          service.releasePrepared(existing) shouldBe false
          verify(client, never()).close()
        } finally {
          service.close()
        }
      }
    }
  }

  test("a closed receive service cannot be resurrected by a late prepare") {
    val service = new StreamingShuffleReceiveService(new SparkConf(false))
    service.close()
    service.close()
    intercept[IllegalArgumentException] {
      service.prepare(StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L))
    }
    service.activeInboxCount shouldBe 0
  }

  test("prepared receive service enables elastic group admission") {
    for (receiveServiceEnabled <- Seq(false, true); waitForAcks <- Seq(false, true)) {
      val requiresWholeGroup = !receiveServiceEnabled || waitForAcks
      val conf = new SparkConf()
        .set(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, waitForAcks)
        .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, receiveServiceEnabled)
        .set(STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
          if (receiveServiceEnabled) 1024L else 0L)
        .set(STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, receiveServiceEnabled)
        .set(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, receiveServiceEnabled)
      withSpark(new SparkContext("local", "StreamingShuffleManagerSuite", conf)) { _ =>
        SparkEnv.get.pipelinedShuffleManager.requiresWholeGroupSlotAdmission shouldBe
          requiresWholeGroup
        SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary shouldBe
          !requiresWholeGroup
        SparkEnv.get.pipelinedShuffleManager.supportsFanOut shouldBe true
      }
    }
  }

  test("a prepared route failure before the first frame wakes its reader with the error") {
    val conf = new SparkConf()
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => None)
    val executor = ThreadUtils.newDaemonFixedThreadPool(1, "prepared-error-test")
    val client = mock[StreamingShuffleExecutorClient]
    val transport = mock[TransportClient]
    val ready = new AtomicInteger()
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L),
      new LinkedBlockingQueue[StreamingShuffleMessage]())
    val session = new StreamingShufflePreparedReceiveSession(
      inbox, client, conf, discovery, executor, () => { ready.incrementAndGet(); () })
    when(client.registerBatch(
      eqTo(7), eqTo(0), eqTo("writer-host"), eqTo(7337),
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenAnswer { invocation =>
        val handler = invocation.getArgument[Seq[(Int, StreamingShuffleClientHandler)]](4).head._2
        handler.channelInactive(transport)
        assert(session.receiveSession.errorNotifier.getError().isDefined)
        assert(ready.get() == 1)
        Map(3 -> transport)
      }
    try {
      session.onWriterSnapshot(ShuffleLocationResponse(
        Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)), 1))
      eventually(Timeout(10.seconds)) {
        ready.get() shouldBe 1
        session.receiveSession.errorNotifier.getError().get.getMessage should
          include("closed before termination")
      }
      inbox.queue shouldBe empty
    } finally {
      session.close()
      discovery.close()
      executor.shutdownNow()
    }
  }

  test("prepared discovery repairs an idle route before its reader task can launch") {
    val conf = new SparkConf().set(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL, 10L)
    val discovery = new StreamingShufflePreparedReceiveDiscovery(conf, _ => Some(
      ShuffleLocationResponse(
        Map(3L -> StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, 0)), 1)))
    val executor = ThreadUtils.newDaemonFixedThreadPool(1, "prepared-repair-test")
    val client = mock[StreamingShuffleExecutorClient]
    val transport = mock[TransportClient]
    val ready = new AtomicInteger()
    val inbox = new StreamingShuffleReceiveInbox(
      StreamingShuffleReceiveInboxId(7, 9, 0, 0, -1L),
      new LinkedBlockingQueue[StreamingShuffleMessage]())
    val session = new StreamingShufflePreparedReceiveSession(
      inbox, client, conf, discovery, executor, () => { ready.incrementAndGet(); () })
    when(client.registerBatch(
      eqTo(7), eqTo(0), eqTo("writer-host"), eqTo(7337),
      any[Seq[(Int, StreamingShuffleClientHandler)]]))
      .thenReturn(Map(3 -> transport))
    try {
      session.start()
      eventually(Timeout(10.seconds)) {
        session.receiveSession.routes.size shouldBe 1
        verify(client, atLeastOnce()).repairCreditWindows(session.receiveSession.routes)
      }
      ready.get() shouldBe 0
      inbox.queue shouldBe empty
    } finally {
      session.close()
      discovery.close()
      executor.shutdownNow()
    }
  }

  test("idle repairs before writer registration preserve route discovery") {
    withSpark(new SparkContext("local", "pending-discovery", new SparkConf())) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = mock[TransportClient]
      val handler = new StreamingShuffleServerHandler(
        (_, _) => (), 7, 1, TaskContext.empty(), new ErrorNotifier())
      def deliver(credit: Int): Unit = {
        val message = new CreditControlMessage(7, 3, 0, credit)
        message.setSeqNum(-1L)
        val buf = Unpooled.compositeBuffer()
        buf.addComponent(Unpooled.buffer(message.headerLength()))
        try {
          message.encode(buf)
          server.handleControlBody(client, buf)
        } finally {
          buf.release()
        }
      }
      try {
        deliver(-40)
        deliver(0)
        deliver(Int.MinValue)
        server.pendingCreditRouteCount shouldBe 1
        server.register(7, 3, handler)
        handler.futureClients(0).isDone shouldBe true
        handler.clientsFor(0) should contain only client
        handler.availableDataCredit(0, client) shouldBe 40L
        server.pendingCreditRouteCount shouldBe 0
      } finally {
        server.unregister(7, 3, handler)
        server.close()
      }
    }
  }

  test("an idle shuffle lane stays open until shuffle cleanup") {
    val module = "spark.streaming-shuffle-reader-multiplexed.io"
    val conf = new SparkConf()
      // Inject an overdue idle event without sleeping or racing a real idle timer.
      .set(s"$module.connectionTimeout", "0s")
      .set(s"$module.connectionCreationTimeout", "10s")
    withSpark(new SparkContext("local", "idle-shuffle-lane", conf)) { _ =>
      val server = new StreamingShuffleExecutorServer()
      val client = new StreamingShuffleExecutorClient()
      val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
      val reader = new StreamingShuffleClientHandler(
        3, 0, queue, 7, 40L, null, new ErrorNotifier())
      val writer = new StreamingShuffleServerHandler(
        (_, _) => (), 7, 1, TaskContext.empty(), new ErrorNotifier())
      try {
        server.register(7, 3, writer)
        val route = client.register(7, 3, 0, "127.0.0.1", server.port, reader)
        eventually(Timeout(10.seconds)) {
          writer.clientsFor(0).size shouldBe 1
        }
        val channel = route.getChannel
        val activeAfterIdle = channel.eventLoop().submit(new Callable[Boolean] {
          override def call(): Boolean = {
            channel.pipeline().fireUserEventTriggered(IdleStateEvent.ALL_IDLE_STATE_EVENT)
            channel.isActive
          }
        }).get(10, TimeUnit.SECONDS)
        activeAfterIdle shouldBe true

        StreamingShuffleUtils.sendControlMessages(
          writer.clientsFor(0).head, Seq(new TerminationControlMessage(7, 3, 0)))
        val terminal = queue.poll(10, TimeUnit.SECONDS)
        terminal shouldBe a[TerminationControlMessage]
        terminal.release()

        client.unregisterShuffle(7)
        eventually(Timeout(10.seconds)) {
          channel.isActive shouldBe false
        }
      } finally {
        client.close()
        server.unregister(7, 3, writer)
        server.close()
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
      sessions.foreach(_.receiveSession.totalNumShuffleWriters.get() shouldBe 0)
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
