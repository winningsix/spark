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

package org.apache.spark.sql.streaming

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.{AtomicInteger, AtomicLong}

import org.apache.spark.{PipelinedShuffleDependency, SparkConf, SparkContext, SparkException}
import org.apache.spark.scheduler.{SparkListener, SparkListenerJobStart, SparkListenerStageCompleted, SparkListenerStageSubmitted, SparkListenerTaskEnd, SparkListenerTaskStart}
import org.apache.spark.shuffle.{PipelinedGroupSchedulingRequirements, PipelinedShuffleGroupMetadata, PipelinedShuffleSchedulingProvider, ReaderResidencyWithElasticProducers}
import org.apache.spark.shuffle.streaming.StreamingShuffleManager
import org.apache.spark.sql.SparkSessionExtensions
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{ColumnarRule, SparkPlan}
import org.apache.spark.sql.execution.datasources.v2.RealTimeStreamScanExec
import org.apache.spark.sql.execution.exchange.ShuffleExchangeExec
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.sql.execution.streaming.runtime.StreamExecution
import org.apache.spark.sql.execution.streaming.sources.{ContinuousMemorySink, LowLatencyMemoryStream}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.test.TestSparkSession

private object PipelinedRealTimeModeResourceSuite {
  val SourcePartitions = 2
  val StaticProducerPartitions = 32
  val JoinPartitions = 2
  val RotatingStaticProducerTasks = 1
  val AvailableTaskSlots = SourcePartitions + JoinPartitions + RotatingStaticProducerTasks
  val FullGroupTaskSlots = SourcePartitions + StaticProducerPartitions + JoinPartitions
  val StaticValueStart = 1000L
  val StaticRowCount = 32
}

/** Test-only opt-in for a bounded static shuffle attached to an actual RTM query. */
class PipelinedRtmStaticShuffleTestExtensions extends (SparkSessionExtensions => Unit) {

  override def apply(extensions: SparkSessionExtensions): Unit = {
    extensions.injectColumnar(_ =>
      new ColumnarRule {
        override def preColumnarTransitions: Rule[SparkPlan] = plan =>
          plan.transformUp {
            case exchange: ShuffleExchangeExec
                if !exchange.pipelined &&
                  !exchange.exists(_.isInstanceOf[RealTimeStreamScanExec]) =>
              exchange.copy(pipelined = true)
          }
      })
  }
}

object ElasticCpuRtmShuffleManager {
  val schedulingRequirementCalls = new AtomicLong(0L)

  def reset(): Unit = schedulingRequirementCalls.set(0L)
}

/**
 * Keeps RTM readers resident while bounded static producer tasks rotate within a two-task cap.
 */
class ElasticCpuRtmShuffleManager(_conf: SparkConf, _isDriver: Boolean)
    extends StreamingShuffleManager
    with PipelinedShuffleSchedulingProvider {
  import PipelinedRealTimeModeResourceSuite._

  override def schedulingRequirements(
      group: PipelinedShuffleGroupMetadata): PipelinedGroupSchedulingRequirements = {
    ElasticCpuRtmShuffleManager.schedulingRequirementCalls.incrementAndGet()
    PipelinedGroupSchedulingRequirements(residencyPolicy = ReaderResidencyWithElasticProducers(
      minProducerTasksPerStage = SourcePartitions,
      maxProducerTasksPerStage = Some(SourcePartitions)))
  }
}

abstract class PipelinedRealTimeModeResourceSuiteBase
    extends StreamRealTimeModeManualClockSuiteBase {
  import PipelinedRealTimeModeResourceSuite._

  protected def incrementalShuffleManagerClass: String

  override protected def sparkConf: SparkConf = {
    super.sparkConf
      .set("spark.shuffle.manager.incremental", incrementalShuffleManagerClass)
      .set("spark.sql.extensions", classOf[PipelinedRtmStaticShuffleTestExtensions].getName)
      .set(SQLConf.SHUFFLE_PARTITIONS.key, JoinPartitions.toString)
      .set(SQLConf.STREAMING_REAL_TIME_MODE_ALLOWLIST_CHECK.key, "false")
  }

  override protected def createSparkSession: TestSparkSession =
    new TestSparkSession(
      new SparkContext(
        s"local[$AvailableTaskSlots]",
        "pipelined-rtm-elastic-producer-context",
        sparkConf.set("spark.sql.testkey", "true")))

  protected def newInput(): LowLatencyMemoryStream[Long] = {
    import testImplicits._
    LowLatencyMemoryStream[Long](SourcePartitions)
  }

  protected def withBoundedStaticShuffle(input: LowLatencyMemoryStream[Long]) = {
    import testImplicits._

    val staticInput = spark
      .range(
        StaticValueStart,
        StaticValueStart + StaticRowCount,
        step = 1L,
        numPartitions = StaticProducerPartitions)
      .mapPartitions { rows =>
        Thread.sleep(100L)
        rows
      }
      .toDF("key")
      .repartition(JoinPartitions, $"key")
      .hint("SHUFFLE_HASH")

    input.toDF().toDF("key").join(staticInput, Seq("key"), "inner").select($"key")
  }

  protected def allCauseMessages(error: Throwable): String = {
    Iterator
      .iterate(Option(error))(_.flatMap(value => Option(value.getCause)))
      .takeWhile(_.nonEmpty)
      .flatten
      .flatMap(value => Option(value.getMessage))
      .mkString("\n")
  }

  protected def assertBoundedStaticShuffleIsPipelined(query: StreamExecution): Unit = {
    val plan = query.lastExecution.executedPlan
    assert(plan.collect { case scan: RealTimeStreamScanExec => scan }.nonEmpty)
    assert(
      plan.collect { case join: ShuffledHashJoinExec => join }.nonEmpty,
      s"expected a streaming-side shuffled hash join, got $plan")

    val exchanges = plan.collect { case exchange: ShuffleExchangeExec => exchange }
    assert(exchanges.size == 2, s"expected streaming and static shuffles, got $exchanges")
    val staticExchanges = exchanges.filterNot(_.exists(_.isInstanceOf[RealTimeStreamScanExec]))
    assert(
      staticExchanges.size == 1,
      s"expected exactly one bounded static shuffle, got $staticExchanges")
    assert(exchanges.forall(_.pipelined))
    assert(
      exchanges.forall(_.shuffleDependency
        .isInstanceOf[PipelinedShuffleDependency[_, _, _]]))
  }
}

class PipelinedRealTimeModeFullResidencySuite extends PipelinedRealTimeModeResourceSuiteBase {
  import PipelinedRealTimeModeResourceSuite._

  override protected def incrementalShuffleManagerClass: String =
    classOf[StreamingShuffleManager].getName

  test("CPU RTM full residency rejects a large bounded producer stage") {
    val input = newInput()
    val output = withBoundedStaticShuffle(input)

    testStream(output, OutputMode.Update, Map.empty, new ContinuousMemorySink())(
      AddData(input, 1L, 2L),
      StartStream(defaultTrigger),
      ExpectFailure[SparkException] { error =>
        val messages = allCauseMessages(error)
        assert(messages.contains(s"needs $FullGroupTaskSlots concurrent task slots"), messages)
        assert(messages.contains(s"only $AvailableTaskSlots are currently free"), messages)
      })
  }
}

class PipelinedRealTimeModeElasticProducerSuite extends PipelinedRealTimeModeResourceSuiteBase {
  import PipelinedRealTimeModeResourceSuite._

  override protected def incrementalShuffleManagerClass: String =
    classOf[ElasticCpuRtmShuffleManager].getName

  test("CPU RTM keeps readers resident while bounded static producers rotate") {
    import testImplicits._

    val runningStages = ConcurrentHashMap.newKeySet[Int]()
    val queryStageIds = ConcurrentHashMap.newKeySet[Int]()
    val producerTasksByStage =
      new ConcurrentHashMap[Int, java.util.Set[Int]]()
    val residentTaskStartsByStage =
      new ConcurrentHashMap[Int, java.util.Set[Int]]()
    val residentTaskEndsByStage =
      new ConcurrentHashMap[Int, java.util.Set[Int]]()
    val maxConcurrentStages = new AtomicInteger(0)
    val listener = new SparkListener {
      override def onJobStart(event: SparkListenerJobStart): Unit = {
        if (Option(event.properties)
            .exists(_.getProperty(StreamExecution.QUERY_ID_KEY) != null)) {
          event.stageIds.foreach(queryStageIds.add)
        }
      }

      override def onStageSubmitted(event: SparkListenerStageSubmitted): Unit = {
        val stageInfo = event.stageInfo
        if (queryStageIds.contains(stageInfo.stageId)) {
          runningStages.add(stageInfo.stageId)
          maxConcurrentStages.accumulateAndGet(runningStages.size(), Math.max)
          if (stageInfo.numTasks == StaticProducerPartitions) {
            producerTasksByStage.put(stageInfo.stageId, ConcurrentHashMap.newKeySet[Int]())
          } else if (stageInfo.numTasks == SourcePartitions) {
            residentTaskStartsByStage.put(stageInfo.stageId, ConcurrentHashMap.newKeySet[Int]())
            residentTaskEndsByStage.put(stageInfo.stageId, ConcurrentHashMap.newKeySet[Int]())
          }
        }
      }

      override def onTaskStart(event: SparkListenerTaskStart): Unit = {
        Option(residentTaskStartsByStage.get(event.stageId)).foreach(_.add(event.taskInfo.index))
      }

      override def onTaskEnd(event: SparkListenerTaskEnd): Unit = {
        Option(producerTasksByStage.get(event.stageId)).foreach(_.add(event.taskInfo.index))
        Option(residentTaskEndsByStage.get(event.stageId)).foreach(_.add(event.taskInfo.index))
      }

      override def onStageCompleted(event: SparkListenerStageCompleted): Unit = {
        runningStages.remove(event.stageInfo.stageId)
      }
    }

    ElasticCpuRtmShuffleManager.reset()
    spark.sparkContext.addSparkListener(listener)
    val input = newInput()
    val output = withBoundedStaticShuffle(input)
    val initialValues = Seq(1000L, 1001L)
    val liveValues = Seq(1002L, 1003L)
    try {
      testStream(output, OutputMode.Update, Map.empty, new ContinuousMemorySink())(
        AddData(input, initialValues: _*),
        StartStream(defaultTrigger),
        CheckAnswerWithTimeout(60000, initialValues: _*),
        AddData(input, liveValues: _*),
        CheckAnswerWithTimeout(60000, (initialValues ++ liveValues): _*),
        Execute { query =>
          spark.sparkContext.listenerBus.waitUntilEmpty()
          assertBoundedStaticShuffleIsPipelined(query)
          assert(ElasticCpuRtmShuffleManager.schedulingRequirementCalls.get() >= 1L)
          assert(
            maxConcurrentStages.get() >= 2,
            s"expected bounded producer and RTM reader stages to overlap, saw " +
              maxConcurrentStages.get())

          val completedProducerStages = producerTasksByStage
            .values()
            .toArray
            .toSeq
            .map(_.asInstanceOf[java.util.Set[Int]])
            .count(_.size() == StaticProducerPartitions)
          assert(
            completedProducerStages >= 1,
            s"expected all $StaticProducerPartitions bounded producer tasks to finish, got " +
              producerTasksByStage)
          val residentStages = residentTaskEndsByStage
            .keySet()
            .toArray
            .toSeq
            .map(_.asInstanceOf[Int])
          assert(
            residentStages.size == 2 &&
              residentStages.forall(runningStages.contains) &&
              residentStages.forall(
                residentTaskStartsByStage.get(_).size() == SourcePartitions) &&
              residentStages.forall(residentTaskEndsByStage.get(_).isEmpty),
            s"expected both RTM source and reader task sets to remain resident, got " +
              s"starts=$residentTaskStartsByStage, ends=$residentTaskEndsByStage")
        },
        advanceRealTimeClock,
        WaitUntilBatchProcessed(0),
        StopStream)
    } finally {
      spark.sparkContext.removeSparkListener(listener)
    }
  }
}
