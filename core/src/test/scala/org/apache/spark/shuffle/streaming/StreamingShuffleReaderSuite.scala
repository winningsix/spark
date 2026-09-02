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
import java.util.concurrent.{ConcurrentHashMap, LinkedBlockingQueue, Semaphore}
import java.util.concurrent.atomic.AtomicInteger

import io.netty.buffer.Unpooled
import org.mockito.Mockito.when
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark._
import org.apache.spark.LocalSparkContext.withSpark
import org.apache.spark.internal.config.SHUFFLE_MANAGER_INCREMENTAL
import org.apache.spark.memory.{TaskMemoryManager, TestMemoryManager}
import org.apache.spark.metrics.MetricsSystem
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

  test("prepared reader does not create task-owned discovery or client executors") {
    withSpark(new SparkContext("local", "StreamingShuffleReaderSuite", newConf())) { sc =>
      val rdd = sc.parallelize(1 to 4).map(x => (x, x))
      val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
      val context = createTaskContext(sc.conf, 0)
      val session = mock[StreamingShufflePreparedReceiveSession]
      when(session.errorNotifier).thenReturn(new ErrorNotifier())
      when(session.totalNumShuffleWriters).thenReturn(new AtomicInteger(0))
      when(session.terminationAckControlMessageSet)
        .thenReturn(ConcurrentHashMap.newKeySet[Long]())
      when(session.allTermAcksSentNotice).thenReturn(new Semaphore(0))
      val inbox = new StreamingShuffleReceiveInbox(
        StreamingShuffleReceiveInboxId(0, 0, 0, 0, -1L),
        new LinkedBlockingQueue[StreamingShuffleMessage]())
      inbox.startPreparedSession(session)
      val lease = new StreamingShuffleReceiveInboxLease(inbox, () => inbox.close())
      try {
        val reader = new StreamingShuffleReader[Int, Int](
          new StreamingShuffleHandle(0, dep),
          context,
          sharedExecutorClient = Some(mock[StreamingShuffleExecutorClient]),
          receiveInbox = Some(lease))
        reader.taskOwnedExecutorsCreated shouldBe (false, false)
      } finally {
        context.markTaskCompleted(None)
        lease.close()
      }
    }
  }

  test("prepared reader reports inbox queue spill in task metrics") {
    withTempDir { spillDir =>
      withSpark(new SparkContext("local", "StreamingShuffleReaderSuite", newConf())) { sc =>
        val rdd = sc.parallelize(1 to 4).map(x => (x, x))
        val dep = new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(1))
        val context = createTaskContext(sc.conf, 0)
        val session = mock[StreamingShufflePreparedReceiveSession]
        when(session.errorNotifier).thenReturn(new ErrorNotifier())
        when(session.totalNumShuffleWriters).thenReturn(new AtomicInteger(0))
        when(session.terminationAckControlMessageSet)
          .thenReturn(ConcurrentHashMap.newKeySet[Long]())
        when(session.allTermAcksSentNotice).thenReturn(new Semaphore(0))
        val queue = new StreamingShuffleMessageQueue(1L, Some(spillDir))
        val inbox = new StreamingShuffleReceiveInbox(
          StreamingShuffleReceiveInboxId(0, 0, 0, 0, -1L), queue)
        inbox.startPreparedSession(session)
        val lease = new StreamingShuffleReceiveInboxLease(inbox, () => inbox.close())
        val bytes = Array.fill[Byte](128)(1)
        val buffer = Unpooled.wrappedBuffer(bytes)
        queue.put(new DataMessage(0, 0, bytes.length, buffer, 0L))
        buffer.release()

        val reader = new StreamingShuffleReader[Int, Int](
          new StreamingShuffleHandle(0, dep),
          context,
          sharedExecutorClient = Some(mock[StreamingShuffleExecutorClient]),
          receiveInbox = Some(lease))
        context.markTaskCompleted(None)

        context.taskMetrics.diskBytesSpilled shouldBe bytes.length.toLong
        reader.cleanupResources()
        context.taskMetrics.diskBytesSpilled shouldBe bytes.length.toLong
      }
    }
  }

  test("spilled inbox data releases payload ownership but defers producer credit") {
    withTempDir { spillDir =>
      val queue = new StreamingShuffleMessageQueue(1L, Some(spillDir))
      val payloadReleases = new AtomicInteger(0)
      val creditReleases = new AtomicInteger(0)
      val bytes = Array.fill[Byte](128)(1)
      val buffer = Unpooled.wrappedBuffer(bytes)
      val data = new DataMessage(0, 0, bytes.length, buffer, 0L)
      buffer.release()
      data.setResourceReleaseCallback(() => payloadReleases.incrementAndGet())
      data.setReleaseCallback(() => creditReleases.incrementAndGet())

      queue.put(data)

      queue.spilledBytesCount shouldBe bytes.length.toLong
      payloadReleases.get() shouldBe 1
      creditReleases.get() shouldBe 0

      val materialized = queue.take()
      creditReleases.get() shouldBe 0
      materialized.release()
      creditReleases.get() shouldBe 1
      queue.close()
    }
  }
}
