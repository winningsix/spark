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

import java.util.concurrent.ConcurrentLinkedQueue

import scala.jdk.CollectionConverters._

import org.apache.spark.{PipelinedShuffleDependency, SparkConf}
import org.apache.spark.scheduler.{SparkListener, SparkListenerStageCompleted, SparkListenerStageSubmitted}
import org.apache.spark.sql.QueryTest
import org.apache.spark.sql.execution.exchange.ShuffleExchangeExec
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.test.{SharedSparkSession, TestSparkSession}

class PipelinedBatchShuffleSuite extends QueryTest with SharedSparkSession {

  override protected def sparkConf: SparkConf = {
    super.sparkConf
      .set("spark.shuffle.manager.incremental",
        "org.apache.spark.shuffle.streaming.StreamingShuffleManager")
      .set(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key, "false")
      .set(SQLConf.SHUFFLE_PARTITIONS.key, "2")
      .set(SQLConf.PIPELINED_SHUFFLE_ENABLED.key, "true")
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
}
