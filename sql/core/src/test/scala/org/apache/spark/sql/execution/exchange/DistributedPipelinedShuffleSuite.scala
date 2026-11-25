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

package org.apache.spark.sql.execution.exchange

import java.nio.file.{Files, Path}

import scala.concurrent.duration._

import org.scalatest.concurrent.Eventually

import org.apache.spark.{PipelinedShuffleDependency, SparkEnv, SparkFunSuite, StreamingShuffleOutputTrackerMaster}
import org.apache.spark.sql.classic.SparkSession
import org.apache.spark.sql.execution.QueryExecution
import org.apache.spark.sql.functions.udf
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.util.QueryExecutionListener
import org.apache.spark.tags.ExtendedSQLTest

@ExtendedSQLTest
class DistributedPipelinedShuffleSuite extends SparkFunSuite with Eventually {
  private val inputs = Seq(
    "single source" ->
      """SELECT observe(writer, id) AS id
        |FROM (SELECT /*+ REPARTITION(2, id) */ id, producer(id) AS writer
        |      FROM (SELECT /*+ REPARTITION(2, bucket) */ id, bucket
        |            FROM (SELECT id, id + 1 AS bucket FROM range(0, 20000, 1, 2))))""")

  inputs.foreach { case (name, sqlText) =>
    test(s"$name drains a remote row before the last producer finishes") {
      checkFullInput(sqlText.stripMargin)
    }
  }

  private def checkFullInput(sqlText: String): Unit = {
    withTempDir { dir =>
      val marker = dir.toPath.resolve("remote-reader").toString
      val spark = SparkSession.builder().master("local-cluster[2,2,1536]")
        .appName(getClass.getSimpleName)
        .config("spark.executor.cores", "2")
        .config("spark.executor.memory", "1g")
        .config(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key, "false")
        .config(SQLConf.SHUFFLE_PARTITIONS.key, "2")
        .config(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key, "true")
        .getOrCreate()
      try {
        val sc = spark.sparkContext
        eventually(timeout(60.seconds)) {
          assert(sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile) == 4)
        }
        // The writer cannot finish until a different executor decodes a row.
        val writer = udf { (id: Long) =>
          if (id == 19999) {
            val deadline = 60.seconds.fromNow
            while (!Files.exists(Path.of(marker)) && deadline.hasTimeLeft()) Thread.sleep(20)
            require(Files.exists(Path.of(marker)), "remote reader did not consume an early row")
          }
          SparkEnv.get.executorId
        }.asNondeterministic()
        val reader = udf { (producer: String, id: Long) =>
          val executor = SparkEnv.get.executorId
          if (producer != executor && !Files.exists(Path.of(marker))) {
            Files.writeString(Path.of(marker), s"$producer -> $executor, row $id")
          }
          id
        }.asNondeterministic()
        spark.udf.register("producer", writer)
        spark.udf.register("observe", reader)
        @volatile var observed: Seq[ShuffleExchangeExec] = Nil
        spark.listenerManager.register(new QueryExecutionListener {
          override def onSuccess(name: String, qe: QueryExecution, nanos: Long): Unit = {
            observed = qe.executedPlan.collect { case s: ShuffleExchangeExec => s }
          }
          override def onFailure(name: String, qe: QueryExecution, error: Exception): Unit = ()
        })
        val query = spark.sql(sqlText)
        sc.setJobGroup("full-input", "run both shuffle stages in one job")
        val actual = query.collect().sortBy(_.getLong(0))
        sc.clearJobGroup()
        sc.listenerBus.waitUntilEmpty(30000)
        assert(sc.statusTracker.getJobIdsForGroup("full-input").length == 1)
        assert(actual.iterator.map(_.getLong(0)).sameElements(0L until 20000L))
        assert(observed.size == 2)
        val Seq(probe) = observed.filter(_.pipelined)
        assert(probe.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])
        val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
          .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        assert(!tracker.containsShuffle(probe.shuffleId))
        info(s"Shuffle ${probe.shuffleId}: ${Files.readString(Path.of(marker))}")

        val join = spark.sql("SELECT /*+ SHUFFLE_HASH(b) */ a.id FROM range(0, 8) a " +
          "LEFT JOIN range(0, 4) b ON a.id = b.id")
        assert(join.queryExecution.executedPlan.getTagValue(DistributedPipelinedShuffle.fullResult)
          .isEmpty)
        spark.conf.set(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key, false)
        assert(query.collect().sortBy(_.getLong(0)).sameElements(actual))
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.nonEmpty && !observed.exists(_.pipelined))
      } finally {
        spark.stop()
      }
    }
  }
}
