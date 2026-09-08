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
import java.util.concurrent.{CountDownLatch, TimeUnit}
import java.util.zip.CRC32C

import io.netty.buffer.{ByteBuf, Unpooled}
import io.netty.channel.{Channel, ChannelConfig, ChannelFuture}
import io.netty.util.concurrent.GenericFutureListener
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.when
import org.scalatest.concurrent.Eventually.eventually
import org.scalatest.concurrent.PatienceConfiguration.Timeout
import org.scalatest.matchers.should.Matchers
import org.scalatest.time.SpanSugar._
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark._
import org.apache.spark.LocalSparkContext.withSpark
import org.apache.spark.internal.config.{SHUFFLE_COMPRESS, SHUFFLE_MANAGER_INCREMENTAL,
  STREAMING_SHUFFLE_CHECKSUM_ENABLED, STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED,
  STREAMING_SHUFFLE_NETWORK_BATCH_SIZE,
  STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE,
  STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED,
  STREAMING_SHUFFLE_WIRE_BUFFER_MAX_MEMORY,
  STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY,
  STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS}
import org.apache.spark.memory.{TaskMemoryManager, TestMemoryManager}
import org.apache.spark.metrics.MetricsSystem
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, DataMessage,
  StreamingShuffleMessage, TerminationControlMessage}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager.QUERY_ID_PROPERTY_KEY
import org.apache.spark.util.ErrorNotifier

/**
 * Writer-side unit tests that do not require a shuffle reader. End-to-end writer <-> reader
 * behavior is covered by `StreamingShuffleSuite` in the tests PR of this stack.
 */
class StreamingShuffleWriterSuite
  extends SparkFunSuite
  with LocalSparkContext
  with Matchers
  with MockitoSugar {

  private def newConf(): SparkConf =
    // StreamingShuffleManager is pipelined, so it belongs in the incremental slot (the default
    // spark.shuffle.manager must be a BlockingShuffleManager). This is what initializes the
    // streaming output tracker that the writer constructor asserts.
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

  test("terminal cannot overtake a timer-detached shard buffer") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        val shard = writer.shards(0)
        val pending = writer.TimestampedBuffer(Unpooled.buffer(1024, 1024), 1024)
        pending.buffer.writeInt(1)
        pending.updateChecksum()
        shard.putBuffer(pending)

        val bufferDetached = new CountDownLatch(1)
        val allowDataPublication = new CountDownLatch(1)
        val closeStarted = new CountDownLatch(1)
        val timerThread = new Thread(() => shard.withSendSequenceLock {
          val detached = shard.takeBuffer()
          bufferDetached.countDown()
          allowDataPublication.await()
          shard.enqueue(detached)
        })
        val closeThread = new Thread(() => {
          closeStarted.countDown()
          shard.close()
        })

        timerThread.start()
        try {
          assert(bufferDetached.await(10, TimeUnit.SECONDS))
          closeThread.start()
          assert(closeStarted.await(10, TimeUnit.SECONDS))
          closeThread.join(100L)
          closeThread.isAlive shouldBe true
          shard.lastSentSequenceNum.get() shouldBe -1L
        } finally {
          allowDataPublication.countDown()
          timerThread.join(TimeUnit.SECONDS.toMillis(10L))
          if (closeThread.getState != Thread.State.NEW) {
            closeThread.join(TimeUnit.SECONDS.toMillis(10L))
          }
        }
        timerThread.isAlive shouldBe false
        closeThread.isAlive shouldBe false
        shard.lastSentSequenceNum.get() shouldBe 1L
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("getWriter returns a StreamingShuffleWriter") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      SparkEnv.get.streamingShuffleOutputTracker.get
        .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 1, jobId = 0)
      val rdd = sc.parallelize(1 to 4).map(x => (x, x))
      val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
      val handle = new StreamingShuffleHandle(0, dep)
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = new StreamingShuffleManager()
          .getWriter[Int, Int](handle, 0, context, null)
        writer shouldBe a[StreamingShuffleWriter[_, _]]
      } finally {
        // Constructing the writer starts a Netty server; the task-completion listener
        // (cleanupResources) tears it down.
        context.markTaskCompleted(None)
      }
    }
  }

  test("writer rejects a memory budget that overflows the Int range") {
    // With a large network buffer size, numPartitions * BUFFER_SIZE * 2 exceeds Int.MaxValue
    // for even a handful of readers. The writer must reject this up front rather than let the
    // 32-bit product wrap negative and hang on a semaphore that can never grant permits. The
    // guard fires in the constructor before the Netty server is started, so nothing to clean up.
    val conf = newConf().set(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE, 256 * 1024 * 1024)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      SparkEnv.get.streamingShuffleOutputTracker.get
        .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 16, jobId = 0)
      val rdd = sc.parallelize(1 to 4).map(x => (x, x))
      val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(16))
      val handle = new StreamingShuffleHandle(0, dep)
      val context = createTaskContext(sc.conf, 0)
      val e = intercept[IllegalArgumentException] {
        new StreamingShuffleWriter[Int, Int](handle, 0, context)
      }
      assert(e.getMessage.contains("memory budget"))
    }
  }

  test("executor raw pool accounts oversized buffers by exact capacity") {
    val pool = new StreamingShuffleRawBufferPool(bufferSize = 128, maxMemoryBytes = 512)
    val oversized = pool.tryBorrow(minCapacity = 384)
    try {
      assert(oversized != null && oversized.capacity() === 384)
      assert(pool.stats === (384L, 384L, 512L))
      assert(pool.tryBorrow(minCapacity = 256) == null,
        "384 allocated bytes must leave only 128 bytes, not another count-based buffer slot")
    } finally {
      pool.recycle(oversized)
    }

    val afterRelease = pool.tryBorrow(minCapacity = 256)
    try {
      assert(afterRelease != null && afterRelease.capacity() === 256)
      assert(pool.stats === (256L, 384L, 512L))
    } finally {
      pool.recycle(afterRelease)
      pool.close()
    }
  }

  test("executor raw pool falls back to its bounded heap budget at the JVM direct limit") {
    val directOomConstructor =
      classOf[_root_.io.netty.util.internal.OutOfDirectMemoryError]
        .getDeclaredConstructor(classOf[String])
    directOomConstructor.setAccessible(true)
    val pool = new StreamingShuffleRawBufferPool(
      bufferSize = 128,
      maxMemoryBytes = 256,
      allocateDirect = _ => throw directOomConstructor.newInstance("test direct limit"))

    val fallback = pool.tryBorrow()
    try {
      assert(fallback != null && !fallback.isDirect && fallback.capacity() === 128)
      assert(pool.stats === (128L, 128L, 256L))
      assert(pool.heapFallbackStats === (1L, 128L))
    } finally {
      pool.recycle(fallback)
      pool.close()
    }
  }

  test("writer does not spill a live transport frame before its reader connects") {
    val conf = newConf().set(STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY, 1L)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        val bytes = Array.fill[Byte](128)(1)
        val buffer = Unpooled.wrappedBuffer(bytes)
        val data = new DataMessage(0, 0, bytes.length, buffer, 0L)
        buffer.release()

        writer.shards(0).send(data)
        writer.stop(success = true)
        val firstReportedBytes = context.taskMetrics.diskBytesSpilled
        firstReportedBytes shouldBe 0L

        writer.stop(success = true)
        context.taskMetrics.diskBytesSpilled shouldBe firstReportedBytes
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("prepared inbox delivery retires replay without spilling") {
    val conf = newConf()
      .set(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, true)
      .set(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, false)
      .set(STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY, 1L)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        bindMockClient(writer, 0)(_ => ())
        val bytes = Array.fill[Byte](128)(1)
        val buffer = Unpooled.wrappedBuffer(bytes)
        val data = new DataMessage(0, 0, bytes.length, buffer, 0L)
        buffer.release()

        writer.shards(0).send(data)
        writer.stop(success = true)

        context.taskMetrics.diskBytesSpilled shouldBe 0L
        writer.errorNotifier.getError() shouldBe empty
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("writer replay spill has an independent task metric") {
    val conf = newConf()
      .set(STREAMING_SHUFFLE_NETWORK_BATCH_SIZE, 1)
      .set(STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY, 1L)
      .set(STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED, true)
      .set(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, false)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        SparkEnv.get.streamingShuffleOutputTracker.get
          .asInstanceOf[StreamingShuffleOutputTrackerMaster]
          .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 1, jobId = 0)
        val rdd = sc.parallelize(1 to 4).map(x => (x, x))
        val dep = new PipelinedShuffleDependency[Int, Int, Int](
          rdd, new HashPartitioner(1))
        dep.markReplayLeaseAvailable()
        val writer = new StreamingShuffleWriter[Int, Int](
          new StreamingShuffleHandle(0, dep), 0, context)
        val client = bindMockClient(writer, 0)(_ => ())
        writer.transportServerHandler.handleMessage(client, new CreditControlMessage(
          0, 0, 0, StreamingShuffleClientHandler.ZERO_WINDOW_CREDIT))

        def sendFrame(): Unit = {
          val bytes = Array.fill[Byte](128)(1)
          val buffer = Unpooled.wrappedBuffer(bytes)
          val data = new DataMessage(0, 0, bytes.length, buffer, 0L)
          buffer.release()
          writer.shards(0).send(data)
        }

        sendFrame()
        sendFrame()
        writer.shards(0).spillOnePendingData() shouldBe true
        writer.stop(success = true)

        val replaySpilled = context.taskMetrics.streamingShuffleWriterReplayBytesSpilled
        replaySpilled should be > 0L
        context.taskMetrics.diskBytesSpilled shouldBe replaySpilled
        context.taskMetrics.streamingShuffleReaderQueueBytesSpilled shouldBe 0L
        writer.stop(success = true)
        context.taskMetrics.streamingShuffleWriterReplayBytesSpilled shouldBe replaySpilled
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("relaxed writer spills its raw fallback before network dispatch") {
    val conf = newConf()
      .set(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, true)
      .set(STREAMING_SHUFFLE_WIRE_BUFFER_MAX_MEMORY, 40L << 10)
      .set(STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED, false)
      .set(STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY, 1L << 30)
      .set(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, false)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        SparkEnv.get.streamingShuffleOutputTracker.get
          .asInstanceOf[StreamingShuffleOutputTrackerMaster]
          .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 1, jobId = 0)
        val rdd = sc.parallelize(1 to 4).map(x => (x, x))
        val dep = new PipelinedShuffleDependency[Int, Int, Int](
          rdd, new HashPartitioner(1))
        dep.markReplayLeaseAvailable()
        val handle = new StreamingShuffleHandle(0, dep)
        val server = new StreamingShuffleExecutorServer()
        val writer = new StreamingShuffleWriter[Int, Int](
          handle, 0, context, sharedExecutorServer = Some(server))
        val reserved = writer.allocateWireBuffer(40 << 10)
        try {
          reserved._1 should not be null
          reserved._2 shouldBe (40 << 10)
          writer.allocateWireBuffer(40 << 10) shouldBe (null, 0)

          val raw = server.rawBufferPool.tryBorrow()
          val pending = writer.TimestampedBuffer(raw, raw.capacity())
          pending.buffer.writeZero(1024)
          writer.shards(0).send(pending)
          writer.stop(success = true)
          context.taskMetrics.streamingShuffleWriterReplayBytesSpilled should be > 0L
        } finally {
          reserved._1.release()
          writer.releaseWireReservation(reserved._2)
          server.close()
        }
      } finally {
        val cleanupError = new RuntimeException("test cleanup")
        context.markTaskFailed(cleanupError)
        context.markTaskCompleted(Some(cleanupError))
      }
    }
  }

  test("server handler uses credit-map presence as the route control marker") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      var creditWakeups = 0
      val handler = new StreamingShuffleServerHandler(
        (_, _) => (),
        shuffleId = 0,
        numReaders = 1,
        context = context,
        errorNotifier = new ErrorNotifier(),
        onCreditAvailable = (_, _) => creditWakeups += 1)
      val client = mock[TransportClient]

      try {
        // A positive grant before the initial negative window is still an unbounded legacy route.
        handler.handleMessage(client, new CreditControlMessage(0, 0, 0, 25))
        handler.isCreditControlled(0, client) shouldBe false
        handler.availableDataCredit(0, client) shouldBe Long.MaxValue

        handler.handleMessage(client, new CreditControlMessage(0, 0, 0, -100))
        handler.isCreditControlled(0, client) shouldBe true
        handler.availableDataCredit(0, client) shouldBe 100L
        // Retrying discovery before any data is sent is an idempotent no-op.
        handler.handleMessage(client, new CreditControlMessage(0, 0, 0, -100))
        handler.availableDataCredit(0, client) shouldBe 100L

        handler.consumeDataCredit(0, client, 40L)
        handler.availableDataCredit(0, client) shouldBe 60L
        // An absolute initial-window retry cannot manufacture credit after data is in flight.
        handler.handleMessage(client, new CreditControlMessage(0, 0, 0, -100))
        handler.availableDataCredit(0, client) shouldBe 60L

        val released40 = new CreditControlMessage(0, 0, 0, 0)
        released40.setSeqNum(40L)
        handler.handleMessage(client, released40)
        handler.availableDataCredit(0, client) shouldBe 100L
        val wakeupsBeforeRepair = creditWakeups
        // Repeating the cumulative acknowledgement does not grant the same bytes twice.
        handler.handleMessage(client, released40)
        handler.availableDataCredit(0, client) shouldBe 100L
        creditWakeups shouldBe (wakeupsBeforeRepair + 1)

        handler.consumeDataCredit(0, client, 30L)
        handler.handleMessage(client, released40)
        handler.availableDataCredit(0, client) shouldBe 70L
        val released70 = new CreditControlMessage(0, 0, 0, 0)
        released70.setSeqNum(70L)
        handler.handleMessage(client, released70)
        handler.availableDataCredit(0, client) shouldBe 100L
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("zero-window discovery registers a bounded route without admitting data") {
    withSpark(new SparkContext("local", "zero-window-route", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      val handler = new StreamingShuffleServerHandler(
        (_, _) => (),
        shuffleId = 0,
        numReaders = 1,
        context = context,
        errorNotifier = new ErrorNotifier())
      val client = mock[TransportClient]
      try {
        handler.handleMessage(client, new CreditControlMessage(
          0, 0, 0, StreamingShuffleClientHandler.ZERO_WINDOW_CREDIT))
        handler.isCreditControlled(0, client) shouldBe true
        handler.availableDataCredit(0, client) shouldBe 0L
        handler.hasDataCredit(0, client, 128L) shouldBe false

        handler.handleMessage(client, new CreditControlMessage(0, 0, 0, -64))
        handler.availableDataCredit(0, client) shouldBe 64L
        handler.hasDataCredit(0, client, 128L) shouldBe true
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  // Builds a single-partition writer against a freshly registered shuffle. The caller must run
  // this inside a withSpark block and must eventually call context.markTaskCompleted(None) to
  // tear down the Netty server the writer starts in its constructor.
  private def newWriter(
      sc: SparkContext,
      context: TaskContext,
      errorNotifier: ErrorNotifier = new ErrorNotifier()): StreamingShuffleWriter[Int, Int] = {
    SparkEnv.get.streamingShuffleOutputTracker.get
      .asInstanceOf[StreamingShuffleOutputTrackerMaster]
      .registerShuffle(shuffleId = 0, numMaps = 1, numReduces = 1, jobId = 0)
    val rdd = sc.parallelize(1 to 4).map(x => (x, x))
    val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
    val handle = new StreamingShuffleHandle(0, dep)
    new StreamingShuffleWriter[Int, Int](handle, 0, context, errorNotifier = errorNotifier)
  }

  // A mock TransportClient whose send(ByteBuf) invokes `onSend` and then completes the write
  // successfully (its returned ChannelFuture reports isSuccess = true so the writer's normal
  // done()/buffer-recycling path runs). Binding it into a shard's futureClients makes the shard
  // send directly to this mock instead of over the network.
  private def bindMockClient(
      writer: StreamingShuffleWriter[Int, Int],
      shardId: Int)(onSend: ByteBuf => Unit): TransportClient = {
    val client = mock[TransportClient]
    val channel = mock[Channel]
    val channelConfig = mock[ChannelConfig]
    when(client.getChannel).thenReturn(channel)
    when(channel.config).thenReturn(channelConfig)
    val succeededFuture = mock[ChannelFuture]
    when(succeededFuture.isSuccess).thenReturn(true)
    when(succeededFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        invocation.getArgument[GenericFutureListener[ChannelFuture]](0)
          .operationComplete(succeededFuture)
        succeededFuture
      }
    when(client.send(any[ByteBuf])).thenAnswer { invocation =>
      val sent = invocation.getArgument[ByteBuf](0)
      onSend(sent)
      // Emulate the transport's ownership transfer: the real send(ByteBuf) releases the buffer
      // once the write completes, dropping the composite's retainedSlice on the data buffer so
      // rawBuffer.refCnt() is back to 1 at the done() callback (the normal recycling path).
      sent.release()
      succeededFuture
    }
    writer.transportServerHandler.futureClients(shardId).complete(client)
    client
  }

  test("an idle route probe immediately retransmits an unacknowledged terminal") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        val sends = new java.util.concurrent.atomic.AtomicInteger(0)
        val client = bindMockClient(writer, 0) { _ => sends.incrementAndGet() }

        writer.shards(0).send(new TerminationControlMessage(0, 0))
        eventually(Timeout(10.seconds)) {
          sends.get() shouldBe 1
        }

        // The transport write completed, but no TerminationAckMessage was returned. A duplicate
        // cumulative credit frame for this physical route must actively repair the terminal
        // instead of merely waking an already-empty outbound action queue.
        writer.shards(0).creditAvailable(client)
        eventually(Timeout(10.seconds)) {
          sends.get() shouldBe 2
        }
        writer.errorNotifier.getError() shouldBe empty
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("a synchronous transport failure is surfaced through the ErrorNotifier") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      val errorNotifier = new ErrorNotifier()
      try {
        val writer = newWriter(sc, context, errorNotifier)
        // Bind a client whose send throws synchronously; the shard's send must record the failure
        // via the ErrorNotifier and rethrow.
        val client = mock[TransportClient]
        val channel = mock[Channel]
        val channelConfig = mock[ChannelConfig]
        when(client.getChannel).thenReturn(channel)
        when(channel.config).thenReturn(channelConfig)
        when(client.send(any[ByteBuf])).thenThrow(new RuntimeException("send failed"))
        writer.transportServerHandler.futureClients(0).complete(client)

        writer.shards(0).send(new TerminationControlMessage(0, 0))
        eventually(Timeout(10.seconds)) {
          writer.errorNotifier.getError() shouldBe defined
          writer.errorNotifier.getError().get.getMessage should include("send failed")
        }
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("an asynchronous write failure is surfaced through the ErrorNotifier") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      val errorNotifier = new ErrorNotifier()
      try {
        val writer = newWriter(sc, context, errorNotifier)
        // Bind a client whose send is accepted but whose write completes unsuccessfully (the
        // common network-failure case). The shard's send-completion listener must record the
        // future's cause via the ErrorNotifier.
        val client = mock[TransportClient]
        val channel = mock[Channel]
        val channelConfig = mock[ChannelConfig]
        when(client.getChannel).thenReturn(channel)
        when(channel.config).thenReturn(channelConfig)
        val failedFuture = mock[ChannelFuture]
        when(failedFuture.isSuccess).thenReturn(false)
        when(failedFuture.cause()).thenReturn(new RuntimeException("write failed"))
        when(failedFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
          .thenAnswer { invocation =>
            invocation.getArgument[GenericFutureListener[ChannelFuture]](0)
              .operationComplete(failedFuture)
            failedFuture
          }
        when(client.send(any[ByteBuf])).thenAnswer { invocation =>
          // The transport frees the buffer on completion, including on a failed write.
          invocation.getArgument[ByteBuf](0).release()
          failedFuture
        }
        writer.transportServerHandler.futureClients(0).complete(client)

        writer.shards(0).send(new TerminationControlMessage(0, 0))

        eventually(Timeout(10.seconds)) {
          writer.errorNotifier.getError() shouldBe defined
          writer.errorNotifier.getError().get.getMessage should include("write failed")
        }
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("cleanupResources releases queued pooled buffers") {
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", newConf())) { sc =>
      val context = createTaskContext(sc.conf, 0)
      val writer = newWriter(sc, context)
      val buf = Unpooled.buffer(16)
      writer.bufferPool.offerLast(buf)
      buf.refCnt() should be(1)
      writer.bufferPool.size() should be(1)

      // cleanupResources is idempotent; call it directly so we can observe the buffer's refcount.
      writer.cleanupResources()

      writer.bufferPool.size() should be(0)
      buf.refCnt() should be(0)
      // The task-completion listener will call cleanupResources again (a no-op now).
      context.markTaskCompleted(None)
    }
  }

  test("compressed input releases its writer buffer permit exactly once") {
    val conf = newConf()
      .set(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE, 128 << 10)
      .set(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, false)
      .set(SHUFFLE_COMPRESS, true)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        bindMockClient(writer, 0)(_ => ())
        val (_, permitLimit) = writer.writerBufferPermitStats

        // A run of identical Java-serialized values produces an independent compressed wire
        // buffer. The producer returns its raw input immediately, then the dispatcher invokes
        // PendingSend.releaseInput() for the same envelope. Both callbacks must share one permit
        // ownership fence.
        writer.write(Iterator.fill(5000)((0, 0)))

        eventually(Timeout(10.seconds)) {
          val (rawBytes, wireBytes, messages) = writer.transferStats
          messages should be > 0L
          wireBytes should be < rawBytes
          writer.writerBufferPermitStats shouldBe (permitLimit, permitLimit)
        }
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }

  test("checksum is computed and embedded in the DataMessage sent on the wire") {
    // Keep the wire bytes identical to the uncompressed record bytes whose checksum is stored in
    // DataMessage. Compression/decompression correctness is covered by the end-to-end suite.
    val conf = newConf()
      .set(STREAMING_SHUFFLE_CHECKSUM_ENABLED, true)
      .set(SHUFFLE_COMPRESS, false)
    withSpark(new SparkContext("local", "StreamingShuffleWriterSuite", conf)) { sc =>
      val context = createTaskContext(sc.conf, 0)
      try {
        val writer = newWriter(sc, context)
        val sentBuffers = new java.util.concurrent.CopyOnWriteArrayList[ByteBuf]()
        // Capture a copy of every buffer the writer sends (the original is released by the
        // transport layer after the write completes). The send completes synchronously since the
        // client future is already resolved.
        bindMockClient(writer, 0) { buf => sentBuffers.add(buf.copy()) }

        // Serialize a record through the writer's own buffer/checksum path and send it.
        val tsBuffer = writer.TimestampedBuffer(Unpooled.directBuffer(1024))
        val serializationStream = tsBuffer.serializationStream.get
        serializationStream.writeKey(1.asInstanceOf[Any])
        serializationStream.writeValue(2.asInstanceOf[Any])
        serializationStream.flush()
        writer.shards(0).send(tsBuffer)

        eventually(Timeout(10.seconds)) {
          sentBuffers.size() should be(1)
        }
        val decoded = StreamingShuffleMessage.decode(sentBuffers.get(0))
        decoded shouldBe a[DataMessage]
        val dataMessage = decoded.asInstanceOf[DataMessage]

        // The checksum embedded on the wire must match an independent CRC32C over the payload.
        // Compute the expected value with java.util.zip.CRC32C directly (not ShuffleChecksum) so
        // this stays independent of the production checksum wrapper.
        val payload = dataMessage.getRecordData()
        val expectedCrc = new CRC32C()
        expectedCrc.update(payload.nioBuffer(payload.readerIndex(), payload.readableBytes()))
        dataMessage.checksum should be(expectedCrc.getValue)
        dataMessage.checksum should not be 0L
        // The mock released the sent buffer (as the transport would), so the writer's normal
        // recycling path ran (rawBuffer.refCnt() == 1) and recorded no error.
        writer.errorNotifier.getError() shouldBe empty

        dataMessage.release()
        sentBuffers.forEach(_.release())
      } finally {
        context.markTaskCompleted(None)
      }
    }
  }
}
