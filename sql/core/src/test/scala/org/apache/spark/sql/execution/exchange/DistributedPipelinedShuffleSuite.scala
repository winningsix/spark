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

import org.apache.spark.{PipelinedShuffleDependency, SparkEnv, SparkException, SparkFunSuite}
import org.apache.spark.StreamingShuffleOutputTrackerMaster
import org.apache.spark.sql.classic.SparkSession
import org.apache.spark.sql.execution.{QueryExecution, SQLExecution}
import org.apache.spark.sql.functions.udf
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.util.QueryExecutionListener
import org.apache.spark.tags.ExtendedSQLTest

@ExtendedSQLTest
class DistributedPipelinedShuffleSuite extends SparkFunSuite with Eventually {
  private def singleSource(
      partitions: Int,
      exchanges: Int,
      innerHint: String = "REPARTITION"): String = {
    val source = s"SELECT id, producer(id) AS writer FROM range(0, 20000, 1, $partitions)"
    val prefix = (1 until exchanges).foldLeft(source) { (input, salt) =>
      s"""SELECT id, producer(observe(writer, id)) AS writer FROM (
         |  SELECT /*+ $innerHint(2, bucket) */ id, writer, hash(writer, id, $salt) AS bucket
         |  FROM ($input))""".stripMargin
    }
    s"SELECT observe(writer, id) AS id FROM (SELECT /*+ REPARTITION(2, id) */ * FROM ($prefix))"
  }

  for (count <- Seq(2, 4)) {
    test(s"$count pipelined shuffles drain a remote row before the source finishes") {
      checkFullInput(singleSource(2, count), pipelinedExchanges = count)
    }
  }

  private def withCluster(cores: Int)(body: SparkSession => Unit): Unit = {
    val spark = SparkSession.builder().master(s"local-cluster[2,$cores,1536]")
      .appName(getClass.getSimpleName)
      .config("spark.executor.cores", cores.toString)
      .config("spark.executor.memory", "1g")
      .config("spark.scheduler.pipelinedGroup.slotCheck.enabled", "true")
      .config(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key, "false")
      .config(SQLConf.SHUFFLE_PARTITIONS.key, "2")
      .config(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key, "true")
      .getOrCreate()
    try {
      val sc = spark.sparkContext
      eventually(timeout(60.seconds)) {
        val profile = sc.resourceProfileManager.defaultResourceProfile
        assert(sc.maxNumConcurrentTasks(profile) == 2 * cores)
      }
      body(spark)
    } finally {
      spark.stop()
    }
  }

  test("cluster batch and laptop flags together use the distributed transport for a file scan") {
    withCluster(2) { spark =>
      withTempDir { dir =>
        spark.conf.set(SQLConf.LOCAL_PIPELINED_SHUFFLE_ENABLED.key, true)
        val path = dir.toPath.resolve("input").toString
        spark.range(0, 12, 1, 2).write.parquet(path)
        val data = spark.read.parquet(path)
        val qe = data.repartition(2, data("id")).queryExecution
        SQLExecution.withNewExecutionId(qe, Some("collect iterator")) {
          val (count, rows) = qe.executedPlan.executeCollectIterator()
          assert(count == 12 && rows.map(_.getLong(0)).toList.sorted == (0L until 12L))
          val id = spark.sparkContext.getLocalProperty(SQLExecution.EXECUTION_ID_KEY).toLong
          val executed = SQLExecution.getQueryExecution(id).executedPlan
          val Seq(exchange) = executed.collect { case s: ShuffleExchangeExec => s }
          assert(exchange.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])
        }
        spark.conf.set(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key, true)
        assert(data.repartition(2, data("id")).queryExecution.executedPlan.nodeName ==
          "AdaptiveSparkPlan")
      }
    }
  }

  private def checkFullInput(sqlText: String, pipelinedExchanges: Int): Unit = {
    withTempDir { dir =>
      val marker = dir.toPath.resolve("remote-reader").toString
      withCluster(pipelinedExchanges + 1) { spark =>
        val sc = spark.sparkContext
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
          if (id == 0 && Files.deleteIfExists(Path.of(marker + ".fail"))) {
            throw new IllegalStateException("injected reader failure")
          }
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
          override def onFailure(name: String, qe: QueryExecution, error: Exception): Unit = {
            observed = qe.executedPlan.collect { case s: ShuffleExchangeExec => s }
          }
        })
        val query = spark.sql(sqlText)
        sc.setJobGroup("full-input", "run both shuffle stages in one job")
        val actual = query.collect().sortBy(_.getLong(0))
        sc.clearJobGroup()
        sc.listenerBus.waitUntilEmpty(30000)
        assert(sc.statusTracker.getJobIdsForGroup("full-input").length == 1)
        assert(actual.iterator.map(_.getLong(0)).sameElements(0L until 20000L))
        assert(observed.size == pipelinedExchanges)
        val active = observed.filter(_.pipelined)
        assert(active.size == pipelinedExchanges)
        val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
          .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        active.foreach { exchange =>
          assert(exchange.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])
          assert(!tracker.containsShuffle(exchange.shuffleId))
        }
        info(s"Shuffles ${active.map(_.shuffleId)}: ${Files.readString(Path.of(marker))}")
        if (pipelinedExchanges == 2) {
          val fail = Files.createFile(Path.of(marker + ".fail"))
          intercept[SparkException](query.collect())
          assert(!Files.exists(fail))
          sc.listenerBus.waitUntilEmpty(30000)
          val failed = observed.filter(_.pipelined).map(_.shuffleId)
          assert(failed.size == 2 && !failed.exists(tracker.containsShuffle))
          assert(query.collect().sortBy(_.getLong(0)).sameElements(actual))
          sc.listenerBus.waitUntilEmpty(30000)
          val retried = observed.filter(_.pipelined).map(_.shuffleId)
          assert(retried.size == 2 && retried.intersect(failed).isEmpty)
          assert(!retried.exists(tracker.containsShuffle))
          for (sql <- Seq(singleSource(3, 2), singleSource(2, 2, "REPARTITION_BY_RANGE"))) {
            val rows = spark.sql(sql).collect().sortBy(_.getLong(0))
            assert(rows.sameElements(actual))
            sc.listenerBus.waitUntilEmpty(30000)
            assert(observed.size == 2 && !observed.exists(_.pipelined))
          }
        }

        val top = query.orderBy("id").limit(3)
        assert(top.toLocalIterator().next().getLong(0) == 0L)
        sc.listenerBus.waitUntilEmpty(30000)
        assert(observed.nonEmpty && !observed.exists(_.pipelined))
        assert(top.take(1).head.getLong(0) == 0L)
        assert(top.collect().map(_.getLong(0)).toSeq == Seq(0L, 1L, 2L))
        sc.listenerBus.waitUntilEmpty(30000)
        assert(observed.count(_.pipelined) == pipelinedExchanges)

        val join = spark.sql("SELECT /*+ SHUFFLE_HASH(b) */ a.id FROM range(0, 8) a " +
          "LEFT JOIN range(0, 4) b ON a.id = b.id")
        assert(!join.queryExecution.executedPlan.isInstanceOf[PipelinedShuffleResultExec])
        spark.conf.set(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED.key, false)
        assert(query.collect().sortBy(_.getLong(0)).sameElements(actual))
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.nonEmpty && !observed.exists(_.pipelined))
      }
    }
  }
}
