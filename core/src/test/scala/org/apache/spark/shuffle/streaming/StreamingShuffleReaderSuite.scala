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

import java.util.Properties
import java.util.concurrent.{Callable, CompletableFuture, CompletionException, CountDownLatch, ExecutionException, Executors, LinkedBlockingQueue, TimeoutException, TimeUnit}
import java.util.concurrent.atomic.AtomicInteger

import io.netty.buffer.Unpooled
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark._
import org.apache.spark.LocalSparkContext.withSpark
import org.apache.spark.internal.config.SHUFFLE_MANAGER_INCREMENTAL
import org.apache.spark.memory.{TaskMemoryManager, TestMemoryManager}
import org.apache.spark.metrics.MetricsSystem
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.{DataMessage, StreamingShuffleMessage, TerminationControlMessage}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager.QUERY_ID_PROPERTY_KEY
import org.apache.spark.util.ErrorNotifier

/**
 * Reader-side unit tests that do not require a shuffle writer. End-to-end writer <-> reader
 * behavior is covered by `StreamingShuffleSuite` in the tests PR of this stack.
 */
class StreamingShuffleReaderSuite
  extends SparkFunSuite
  with LocalSparkContext
  with Matchers
  with MockitoSugar {

  private def newConf(): SparkConf =
    // StreamingShuffleManager is pipelined, so it belongs in the incremental slot (the default
    // spark.shuffle.manager must be a BlockingShuffleManager). This is what initializes the
    // streaming output tracker that the reader constructor asserts.
    new SparkConf().set(SHUFFLE_MANAGER_INCREMENTAL, classOf[StreamingShuffleManager].getName)

  private def createTaskContext(conf: SparkConf, partitionId: Int): TaskContextImpl = {
    val properties = new Properties()
    properties.setProperty(QUERY_ID_PROPERTY_KEY, "test-query-id")
    val taskMemoryManager = new TaskMemoryManager(new TestMemoryManager(conf), 0)
    new TaskContextImpl(
      stageId = 0,
      stageAttemptNumber = 0,
      partitionId,
      taskAttemptId = 0,
      attemptNumber = 0,
      numPartitions = 1,
      taskMemoryManager = taskMemoryManager,
      localProperties = properties,
      metricsSystem = mock[MetricsSystem],
      cpuAmount = 1)
  }

  // A minimal DataMessage that is only used to exercise the iterator factory's type dispatch;
  // its contents are never decoded here because handleDataMessage is stubbed in these tests.
  private def emptyDataMessage(): DataMessage =
    new DataMessage(0, 0, 0, Unpooled.EMPTY_BUFFER, 0L)

  // The iterator factory drives four collaborators; these tests supply in-memory fakes for all of
  // them so the reader's consumer-loop control flow can be verified without Netty or a SparkEnv.
  private val factory = new StreamingShuffleReaderIteratorFactory()

  private def location(mapIndex: Int): StreamingShuffleTaskLocation =
    StreamingShuffleTaskLocation("executor-1", "writer-host", 7337, mapIndex)

  test("receive session discovers each logical writer once across incremental snapshots") {
    var initialized = 0
    var discoveriesFinished = 0
    var connected = Set.empty[Long]
    val session = new StreamingShuffleReceiveSession(
      7, new ErrorNotifier(), (_, _, _) => (), () => discoveriesFinished += 1)
    def discover(locations: Map[Long, StreamingShuffleTaskLocation]): Unit = {
      session.onWriterSnapshot(ShuffleLocationResponse(locations, 2), _ => initialized += 1) {
        fresh => fresh.map { case (writerId, _) =>
          connected += writerId
          session.registerRoute(
            writerId, mock[TransportClient], mock[StreamingShuffleClientHandler])
          writerId -> CompletableFuture.completedFuture[Void](null)
        }
      }
    }
    try {
      discover(Map(1L -> location(0)))
      session.isDiscoveryFinished shouldBe false
      discoveriesFinished shouldBe 0
      discover(Map(2L -> location(0), 3L -> location(1)))
      connected shouldBe Set(1L, 3L)
      initialized shouldBe 1
      discoveriesFinished shouldBe 1
      session.isDiscoveryFinished shouldBe true
      session.awaitConnections()
      discover(Map(4L -> location(1)))
      connected shouldBe Set(1L, 3L)
    } finally {
      session.close()
    }
    discoveriesFinished shouldBe 1
  }

  test("receive session rejects changed writer counts and excess logical writers") {
    val session = new StreamingShuffleReceiveSession(7, new ErrorNotifier(), (_, _, _) => ())
    try {
      session.onWriterSnapshot(ShuffleLocationResponse(Map.empty, 2), _ => ())(_ => Map.empty)
      intercept[IllegalArgumentException] {
        session.onWriterSnapshot(ShuffleLocationResponse(Map.empty, 3), _ => ())(_ => Map.empty)
      }.getMessage should include("Writer count changed")
      intercept[IllegalArgumentException] {
        session.onWriterSnapshot(ShuffleLocationResponse(
          Map(1L -> location(0), 2L -> location(1), 3L -> location(2)), 2), _ => ()) { _ =>
          fail("Excess writer locations must be rejected before opening connections")
        }
      }.getMessage should include("too many writer locations")
    } finally {
      session.close()
    }
  }

  test("receive session requires all terminal ACKs before signaling drain readiness") {
    var ready = 0
    val session = new StreamingShuffleReceiveSession(
      7, new ErrorNotifier(), (_, _, _) => (), onDrainReady = () => ready += 1)
    try {
      session.onWriterSnapshot(ShuffleLocationResponse(Map.empty, 2), _ => ())(_ => Map.empty)
      session.onTerminationAck(1)
      session.onTerminationAck(1)
      ready shouldBe 0
      session.allTermAcksSentNotice.tryAcquire() shouldBe false
      session.onTerminationAck(2)
      ready shouldBe 1
      session.allTermAcksSentNotice.tryAcquire() shouldBe true
      session.onTerminationAck(2)
      session.allTermAcksSentNotice.tryAcquire() shouldBe false
      ready shouldBe 1
    } finally {
      session.close()
    }
  }

  test("receive session makes empty input drain-ready without terminal messages") {
    var ready = 0
    val session = new StreamingShuffleReceiveSession(
      7, new ErrorNotifier(), (_, _, _) => (), onDrainReady = () => ready += 1)
    try {
      val empty = ShuffleLocationResponse(Map.empty, 0)
      session.onWriterSnapshot(empty, _ => ())(_ => Map.empty)
      session.onWriterSnapshot(empty, _ => ())(_ => Map.empty)
      session.isDiscoveryFinished shouldBe true
      session.awaitConnections()
      ready shouldBe 1
    } finally {
      session.close()
    }
  }

  test("receive session releases both installed and late routes exactly once on close") {
    var released = Vector.empty[Long]
    val session = new StreamingShuffleReceiveSession(
      7, new ErrorNotifier(), (writerId, _, _) => released :+= writerId)
    session.registerRoute(1L, mock[TransportClient], mock[StreamingShuffleClientHandler])
    session.close()
    session.registerRoute(2L, mock[TransportClient], mock[StreamingShuffleClientHandler])
    session.close()
    released shouldBe Vector(1L, 2L)
    session.clients.isEmpty shouldBe true
    session.routes shouldBe empty
  }

  Seq(false, true).foreach { closed =>
    test(s"receive session handles connection failure after discovery (closed=$closed)") {
      var ready = 0
      val notifier = new ErrorNotifier()
      val session = new StreamingShuffleReceiveSession(
        7, notifier, (_, _, _) => (), onDrainReady = () => ready += 1)
      val connection = new CompletableFuture[Void]()
      val error = new IllegalStateException("connection failed")
      try {
        session.onWriterSnapshot(
          ShuffleLocationResponse(Map(1L -> location(0)), 1), _ => ()) { _ =>
          Map(1L -> connection)
        }
        session.isDiscoveryFinished shouldBe true
        ready shouldBe 0
        if (closed) session.close()
        connection.completeExceptionally(error)
        notifier.getError() shouldBe (if (closed) None else Some(error))
        ready shouldBe (if (closed) 0 else 1)
      } finally {
        session.close()
      }
    }
  }

  test("receive session publishes connection failure before releasing connection waiters") {
    val publicationStarted = new CountDownLatch(1)
    val allowPublication = new CountDownLatch(1)
    val publications = new AtomicInteger()
    val error = new SparkException("connection failed", new IllegalStateException("root cause"))
    val notifier = new ErrorNotifier() {
      override def markError(failure: Throwable): Unit = {
        publications.incrementAndGet()
        publicationStarted.countDown()
        assert(allowPublication.await(10, TimeUnit.SECONDS))
        super.markError(failure)
      }
    }
    val session = new StreamingShuffleReceiveSession(7, notifier, (_, _, _) => ())
    val connection = new CompletableFuture[Void]()
    val executor = Executors.newFixedThreadPool(2)
    try {
      // Prepared discovery can share one connection future across multiple writers.
      session.onWriterSnapshot(
          ShuffleLocationResponse(Map(1L -> location(0), 2L -> location(1)), 2), _ => ()) {
        _ => Map(1L -> connection, 2L -> connection)
      }
      val completion = executor.submit(new Runnable {
        override def run(): Unit = {
          connection.completeExceptionally(new CompletionException(error))
        }
      })
      assert(publicationStarted.await(10, TimeUnit.SECONDS))
      val waiter = executor.submit(new Callable[ExecutionException] {
        override def call(): ExecutionException = {
          intercept[ExecutionException] { session.awaitConnections() }
        }
      })
      // A failed raw future is not enough: its original error must be visible first.
      intercept[TimeoutException] { waiter.get(1, TimeUnit.SECONDS) }
      notifier.getError() shouldBe None
      allowPublication.countDown()
      val wrapper = waiter.get(10, TimeUnit.SECONDS)
      completion.get(10, TimeUnit.SECONDS)
      publications.get() shouldBe 1
      notifier.getError() shouldBe Some(error)
      session.failDiscovery(wrapper)
      notifier.getError() shouldBe Some(error)
      error.getSuppressed shouldBe empty
    } finally {
      allowPublication.countDown()
      executor.shutdownNow()
      assert(executor.awaitTermination(10, TimeUnit.SECONDS))
      session.close()
    }
  }

  test("receive session unwraps only future exceptions and preserves the domain error") {
    val error = new SparkException("connection failed", new IllegalStateException("root cause"))
    val causeLessWrapper = new CompletionException(null: Throwable)
    Seq(
      error -> error,
      new CompletionException(error) -> error,
      new ExecutionException(new CompletionException(error)) -> error,
      causeLessWrapper -> causeLessWrapper).foreach { case (failure, expected) =>
      val notifier = new ErrorNotifier()
      val session = new StreamingShuffleReceiveSession(7, notifier, (_, _, _) => ())
      try {
        session.failDiscovery(failure)
        notifier.getError() shouldBe Some(expected)
      } finally {
        session.close()
      }
    }
  }

  test("decompression input reuses direct scratch for a scattered transport frame") {
    val input = new StreamingShuffleDecompressionInput
    val contiguous = Unpooled.directBuffer(3).writeBytes(Array[Byte](11, 12, 13))
    try {
      input.prepare(contiguous, contiguous.readableBytes()).isDirect shouldBe true
      input.scratchCapacity shouldBe 0
    } finally {
      contiguous.release()
    }

    val first = Unpooled.directBuffer(3).writeBytes(Array[Byte](1, 2, 3))
    val second = Unpooled.directBuffer(3).writeBytes(Array[Byte](4, 5, 6))
    val scattered = Unpooled.compositeBuffer()
      .addComponent(true, first)
      .addComponent(true, second)
    try {
      val prepared = input.prepare(scattered, scattered.readableBytes())
      prepared.isDirect shouldBe true
      val bytes = new Array[Byte](prepared.remaining())
      prepared.get(bytes)
      bytes should contain theSameElementsInOrderAs Array[Byte](1, 2, 3, 4, 5, 6)
      input.scratchCapacity shouldBe 6

      val smallerFirst = Unpooled.directBuffer(2).writeBytes(Array[Byte](7, 8))
      val smallerSecond = Unpooled.directBuffer(2).writeBytes(Array[Byte](9, 10))
      val smaller = Unpooled.compositeBuffer()
        .addComponent(true, smallerFirst)
        .addComponent(true, smallerSecond)
      try {
        input.prepare(smaller, smaller.readableBytes()).isDirect shouldBe true
        input.scratchCapacity shouldBe 6
      } finally {
        smaller.release()
      }
    } finally {
      input.close()
      input.close()
      scattered.release()
    }
    input.scratchCapacity shouldBe 0
  }

  test("iterator emits all rows from data messages then stops on termination") {
    val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
    queue.put(emptyDataMessage())
    queue.put(emptyDataMessage())
    queue.put(new TerminationControlMessage(0, 0))

    // Each data message yields a fixed pair of rows; the single termination message ends the read.
    val rowsPerMessage = Seq(Iterator((1, 1), (2, 2)), Iterator((3, 3), (4, 4)))
    val nextRows = rowsPerMessage.iterator
    val it = factory.create[Int, Int](
      queue,
      handleTerminationMessage = _ => true,
      handleDataMessage = _ => nextRows.next(),
      checkTaskFailure = () => ())

    it.toSeq should contain theSameElementsInOrderAs Seq((1, 1), (2, 2), (3, 3), (4, 4))
  }

  test("iterator does not stop until handleTerminationMessage returns true") {
    val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
    // Two writers: the first termination message must not end the read, only the second.
    queue.put(new TerminationControlMessage(0, 0))
    queue.put(emptyDataMessage())
    queue.put(new TerminationControlMessage(1, 0))

    var terminationsSeen = 0
    val it = factory.create[Int, Int](
      queue,
      handleTerminationMessage = _ => {
        terminationsSeen += 1
        terminationsSeen == 2 // only the second termination completes the read
      },
      handleDataMessage = _ => Iterator((1, 1)),
      checkTaskFailure = () => ())

    it.toSeq should contain theSameElementsInOrderAs Seq((1, 1))
    terminationsSeen should be(2)
  }

  test("iterator surfaces a background error before dequeuing the next message") {
    val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
    // A message is available in the queue, but a background error has already been recorded
    // (e.g. the channelInactive premature-disconnect path). Because checkTaskFailure runs before
    // every dequeue, the iterator must throw before this message is dequeued and handled, rather
    // than emitting stale data and only failing later.
    queue.put(emptyDataMessage())

    var dataHandled = false
    val it = factory.create[Int, Int](
      queue,
      handleTerminationMessage = _ => true,
      handleDataMessage = _ => {
        dataHandled = true
        Iterator((1, 1))
      },
      checkTaskFailure = () => throw new SparkException("background failure"))

    val e = intercept[SparkException] {
      it.hasNext
    }
    e.getMessage should include("background failure")
    // The pending message must not have been processed: the error was surfaced first. This is
    // what would keep the reader from emitting rows after a writer has already failed.
    dataHandled should be(false)
  }

  test("iterator terminates when discovery reports a zero-writer shuffle") {
    val queue = new LinkedBlockingQueue[StreamingShuffleMessage]()
    var checked = 0
    val it = factory.create[Int, Int](
      queue,
      handleTerminationMessage = _ => false,
      handleDataMessage = _ => Iterator.empty,
      checkTaskFailure = () => checked += 1,
      inputExhausted = () => true)

    it.hasNext shouldBe false
    checked shouldBe 1
    queue shouldBe empty
  }

  test("getReader routes to a StreamingShuffleReader wired with the given context") {
    // A construction/routing smoke test: the manager must dispatch to the streaming reader (not a
    // fallback shuffle reader), the reader must construct successfully (its constructor asserts the
    // output tracker, starts the task-discovery and client-creation executors, and registers the
    // task-completion listener), and it must be wired with the context we passed in.
    withSpark(new SparkContext("local", "StreamingShuffleReaderSuite", newConf())) { sc =>
      SparkEnv.get.streamingShuffleOutputTracker.get
        .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 1, jobId = 0)
      val rdd = sc.parallelize(1 to 4).map(x => (x, x))
      val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
      val handle = new StreamingShuffleHandle(0, dep)
      val context = createTaskContext(sc.conf, 0)
      try {
        val reader = new StreamingShuffleManager()
          .getReader[Int, Int](handle, 0, 1, 0, 1, context, null)
        reader shouldBe a[StreamingShuffleReader[_, _]]
        val streamingReader = reader.asInstanceOf[StreamingShuffleReader[_, _]]
        streamingReader.context should be theSameInstanceAs context
      } finally {
        // Constructing the reader starts a background task-discovery thread; the task-completion
        // listener (cleanupResources) shuts it down.
        context.markTaskCompleted(None)
      }
    }
  }
}
