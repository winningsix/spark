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

package org.apache.spark.sql.execution

import java.util.concurrent.{ConcurrentLinkedQueue, CountDownLatch, TimeUnit}
import java.util.concurrent.atomic.{AtomicLong, AtomicReference}

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters._

import org.scalatest.concurrent.PatienceConfiguration.{Interval, Timeout}
import org.scalatest.time.{Millis, Seconds, Span}

import org.apache.spark.{PipelinedShuffleDependency, SparkConf}
import org.apache.spark.internal.config.{
  STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE,
  STREAMING_SHUFFLE_READER_MAX_MEMORY,
  STREAMING_SHUFFLE_WRITER_MAX_MEMORY}
import org.apache.spark.scheduler.{SparkListener, SparkListenerStageCompleted, SparkListenerStageSubmitted}
import org.apache.spark.sql.{QueryTest, SparkSessionExtensions}
import org.apache.spark.sql.catalyst.plans.physical.RangePartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.exchange.ShuffleExchangeExec
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.test.{SharedSparkSession, TestSparkSession}
import org.apache.spark.util.ThreadUtils

class PipelinedBatchShuffleTestExtensions extends (SparkSessionExtensions => Unit) {
  override def apply(extensions: SparkSessionExtensions): Unit = {
    extensions.injectColumnar(_ => new ColumnarRule {
      override def preColumnarTransitions: Rule[SparkPlan] = plan => plan.transformUp {
        case exchange: ShuffleExchangeExec
            if !exchange.pipelined &&
              !exchange.outputPartitioning.isInstanceOf[RangePartitioning] =>
          exchange.copy(pipelined = true)
      }
    })
  }
}

private object PipelinedBatchShuffleBackpressureProbe {
  @volatile var readerStarted = new CountDownLatch(1)
  @volatile var releaseReader = new CountDownLatch(1)
  @volatile var rowsProduced = new AtomicLong(0)
  @volatile var producerThread = new AtomicReference[Thread]()

  def reset(): Unit = {
    readerStarted = new CountDownLatch(1)
    releaseReader = new CountDownLatch(1)
    rowsProduced = new AtomicLong(0)
    producerThread = new AtomicReference[Thread]()
  }
}

class PipelinedBatchShuffleSuite extends QueryTest with SharedSparkSession {

  override protected def sparkConf: SparkConf = {
    super.sparkConf
      .set("spark.shuffle.manager.incremental",
        "org.apache.spark.shuffle.streaming.StreamingShuffleManager")
      // Keep the data-plane window deliberately small so the back-pressure test reaches its
      // blocking point after only a few network buffers.
      .set(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE, 64 << 10)
      .set(STREAMING_SHUFFLE_READER_MAX_MEMORY, 1)
      .set(STREAMING_SHUFFLE_WRITER_MAX_MEMORY, 128 << 10)
      .set("spark.sql.extensions", classOf[PipelinedBatchShuffleTestExtensions].getName)
      .set(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key, "false")
      .set(SQLConf.SHUFFLE_PARTITIONS.key, "2")
  }

  override protected def createSparkSession: TestSparkSession =
    new TestSparkSession(sparkConf, numCores = 4)

  test("a two-stage batch aggregate executes producer and consumer concurrently") {
    val events = new ConcurrentLinkedQueue[String]()
    val listener = new SparkListener {
      override def onStageSubmitted(event: SparkListenerStageSubmitted): Unit =
        events.add(s"submitted:${event.stageInfo.stageId}")

      override def onStageCompleted(event: SparkListenerStageCompleted): Unit =
        events.add(s"completed:${event.stageInfo.stageId}")
    }
    spark.sparkContext.addSparkListener(listener)

    try {
      spark.sparkContext.listenerBus.waitUntilEmpty()
      events.clear()

      val result = spark
        .range(0, 10000, 1, 2)
        .selectExpr("id % 8 AS k")
        .repartition(2, org.apache.spark.sql.functions.col("k"))
        .groupBy("k")
        .count()

      val exchange = result.queryExecution.executedPlan.collectFirst {
        case shuffle: ShuffleExchangeExec => shuffle
      }.get
      assert(exchange.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])
      assert(result.collect().map(_.getLong(1)).sum == 10000)

      spark.sparkContext.listenerBus.waitUntilEmpty()
      val orderedEvents = events.iterator().asScala.toSeq
      val firstCompletion = orderedEvents.indexWhere(_.startsWith("completed:"))
      assert(firstCompletion >= 2, s"Expected overlapping stages, observed $orderedEvents")
      assert(
        orderedEvents.take(firstCompletion).count(_.startsWith("submitted:")) >= 2,
        s"Expected both stages submitted before either completed, observed $orderedEvents")
    } finally {
      spark.sparkContext.removeSparkListener(listener)
    }
  }

  test("CPU pipelined shuffle back-pressures its producer and completes after end of stream") {
    val testSpark = spark
    import testSpark.implicits._

    PipelinedBatchShuffleBackpressureProbe.reset()
    val numRows = 1000000L
    val input = spark.range(0, numRows, 1, 1).as[Long].mapPartitions { rows =>
      rows.map { row =>
        PipelinedBatchShuffleBackpressureProbe.producerThread.compareAndSet(
          null, Thread.currentThread())
        PipelinedBatchShuffleBackpressureProbe.rowsProduced.incrementAndGet()
        row
      }
    }.toDF("k")
    val shuffled = input.repartition(1, org.apache.spark.sql.functions.col("k"))
    val exchange = shuffled.queryExecution.executedPlan.collectFirst {
      case shuffle: ShuffleExchangeExec => shuffle
    }.get
    assert(exchange.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])

    // The consumer task is resident but deliberately does not drain its input. The one-byte reader
    // window disables Netty auto-read after the first message; TCP pressure then propagates to the
    // writer's bounded buffer semaphore.
    val output = shuffled.rdd.mapPartitions { rows =>
      PipelinedBatchShuffleBackpressureProbe.readerStarted.countDown()
      if (!PipelinedBatchShuffleBackpressureProbe.releaseReader.await(30, TimeUnit.SECONDS)) {
        throw new IllegalStateException("Timed out waiting to release the shuffle reader")
      }
      rows.map(_.getLong(0))
    }
    val executor = ThreadUtils.newDaemonSingleThreadExecutor("pipelined-backpressure-test")
    val executionContext = ExecutionContext.fromExecutorService(executor)
    val result = Future(output.count())(executionContext)

    try {
      assert(PipelinedBatchShuffleBackpressureProbe.readerStarted.await(30, TimeUnit.SECONDS))
      // Inspect the producer task's stack rather than inferring back-pressure from elapsed time.
      eventually(
          Timeout(Span(30, Seconds)),
          Interval(Span(10, Millis))) {
        val producerThread = PipelinedBatchShuffleBackpressureProbe.producerThread.get()
        assert(producerThread != null)
        val produced = PipelinedBatchShuffleBackpressureProbe.rowsProduced.get()
        assert(produced > 0 && produced < numRows)
        assert(!result.isCompleted)
        assert(producerThread.getStackTrace.exists { frame =>
          frame.getClassName ==
            "org.apache.spark.shuffle.streaming.StreamingShuffleWriter" &&
            frame.getMethodName == "newBuffer"
        })
      }

      PipelinedBatchShuffleBackpressureProbe.releaseReader.countDown()
      // Consuming every row and completing the job also proves that the reader observed EOS and
      // that the writer received its termination acknowledgment.
      assert(Await.result(result, 30.seconds) == numRows)
      assert(PipelinedBatchShuffleBackpressureProbe.rowsProduced.get() == numRows)
    } finally {
      PipelinedBatchShuffleBackpressureProbe.releaseReader.countDown()
      executionContext.shutdown()
      executionContext.awaitTermination(30, TimeUnit.SECONDS)
    }
  }
}
