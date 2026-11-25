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

import java.nio.file.{FileAlreadyExistsException, Files, Path}

import scala.concurrent.duration._

import org.scalatest.concurrent.Eventually

import org.apache.spark.{PipelinedShuffleDependency, SparkEnv, SparkException, SparkFunSuite, StreamingShuffleOutputTrackerMaster}
import org.apache.spark.sql.classic.SparkSession
import org.apache.spark.sql.execution.{QueryExecution, TakeOrderedAndProjectExec}
import org.apache.spark.sql.functions.{col, udf}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.util.QueryExecutionListener
import org.apache.spark.tags.ExtendedSQLTest

@ExtendedSQLTest
class DistributedBatchShuffleSuite extends SparkFunSuite with Eventually {
  test("full collect drains a remote probe before its final producer can finish") {
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
        // Last probe row cannot leave its producer until a different executor has decoded
        // a probe row and joined it with the materialized build. A regular shuffle times out.
        val writer = udf { (id: Long) =>
          if (id == 19999) {
            val deadline = 60.seconds.fromNow
            while (!Files.exists(Path.of(marker)) && deadline.hasTimeLeft()) Thread.sleep(20)
            require(Files.exists(Path.of(marker)), "remote reader did not consume an early row")
          }
          SparkEnv.get.executorId
        }.asNondeterministic()
        val reader = udf { (producer: String, id: Long, buildId: java.lang.Long) =>
          if (id == 0 && Files.exists(Path.of(marker + ".fail"))) {
            throw new IllegalStateException("injected reader failure")
          }
          val executor = SparkEnv.get.executorId
          if (producer != executor && buildId != null && !Files.exists(Path.of(marker))) {
            try {
              Files.writeString(Path.of(marker), s"$producer -> $executor, row $id",
                java.nio.file.StandardOpenOption.CREATE_NEW)
            } catch {
              case _: FileAlreadyExistsException => // Another reader already recorded its row.
            }
          }
          id
        }.asNondeterministic()
        spark.udf.register("producer", writer)
        spark.udf.register("observe", reader)
        @volatile var observed: Seq[ShuffleExchangeExec] = Nil
        spark.listenerManager.register(new QueryExecutionListener {
          private def record(qe: QueryExecution): Unit = {
            observed = qe.executedPlan.collect { case s: ShuffleExchangeExec => s }
          }
          override def onSuccess(name: String, qe: QueryExecution, nanos: Long): Unit = record(qe)
          override def onFailure(name: String, qe: QueryExecution, error: Exception): Unit = {
            record(qe)
          }
        })
        val query = spark.sql(
          """SELECT /*+ SHUFFLE_HASH(b) */ observe(p.writer, p.id, b.id) AS id, b.id AS matched
            |FROM (SELECT id, producer(id) AS writer FROM range(0, 20000, 1, 2)) p
            |LEFT JOIN range(0, 100, 1, 2) b ON p.id % 101 = b.id""".stripMargin)
        val actual = query.collect().sortBy(_.getLong(0))
        assert(actual.length == 20000)
        actual.zipWithIndex.foreach { case (row, id) =>
          assert(row.getLong(0) == id)
          if (id % 101 == 100) assert(row.isNullAt(1)) else assert(row.getLong(1) == id % 101)
        }
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.size == 2)
        val Seq(probe) = observed.filter(_.pipelined)
        assert(probe.shuffleDependency.isInstanceOf[PipelinedShuffleDependency[_, _, _]])
        val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
          .asInstanceOf[StreamingShuffleOutputTrackerMaster]
        assert(!tracker.containsShuffle(probe.shuffleId))
        info(s"Shuffle ${probe.shuffleId}: ${Files.readString(Path.of(marker))}")

        Files.createFile(Path.of(marker + ".fail"))
        intercept[SparkException](query.collect())
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        val Seq(failed) = observed.filter(_.pipelined)
        assert(failed.shuffleId != probe.shuffleId && !tracker.containsShuffle(failed.shuffleId))
        Files.delete(Path.of(marker + ".fail"))

        assert(query.collectAsList().size() == actual.length)
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        val Seq(second) = observed.filter(_.pipelined)
        assert(second.shuffleId != probe.shuffleId && !tracker.containsShuffle(second.shuffleId))

        Files.delete(Path.of(marker))
        assert(query.orderBy("id").limit(3).collect().map(_.getLong(0)).toSeq == Seq(0L, 1L, 2L))
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.count(_.pipelined) == 1)
        assert(Files.exists(Path.of(marker)), "unordered Top-K did not drain a remote probe")

        // The merge join has an empty buffered partition. Its streamed sort must still drain
        // every row. The aggregate's input shuffle and the join sibling are ordinary prefixes.
        for (codegen <- Seq(true, false)) {
          spark.conf.set(SQLConf.WHOLESTAGE_CODEGEN_ENABLED.key, codegen)
          val nested = spark.sql(
            """SELECT /*+ MERGE(p, b) */ p.k
              |FROM (SELECT id % 7 AS k, COUNT(*) AS n FROM range(0, 20, 1, 2)
              |      GROUP BY id % 7) p
              |JOIN range(3, 4, 1, 2) b ON p.n = b.id
              |ORDER BY p.k DESC LIMIT 3""".stripMargin)
          assert(nested.collect().map(_.getLong(0)).toSeq == Seq(5L, 4L, 3L))
          sc.listenerBus.waitUntilEmpty(30000)
          assert(observed.size >= 3)
          assert(observed.count(_.pipelined) == 1)
          assert(observed.count(_.getTagValue(SelectBatchPipelinedShuffle.candidate).isDefined) > 1)
        }
        spark.conf.unset(SQLConf.WHOLESTAGE_CODEGEN_ENABLED.key)

        val window = spark.sql(
          """SELECT id, SUM(id) OVER (PARTITION BY id % 2) AS total
            |FROM range(0, 6, 1, 2) ORDER BY id DESC LIMIT 2""".stripMargin)
        assert(window.collect().map(r => (r.getLong(0), r.getLong(1))).toSeq ==
          Seq((5L, 9L), (4L, 6L)))
        sc.listenerBus.waitUntilEmpty(30000)
        assert(observed.size == 1 && observed.head.pipelined)

        val ids = spark.range(0, 10, 1, 2).repartition(2, col("id"))
        assert(ids.collect().sorted.toSeq == (0L until 10L))
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.size == 1 && observed.head.pipelined)

        val ordered = ids.sortWithinPartitions("id").queryExecution.executedPlan
        assert(ordered.outputOrdering.nonEmpty)
        val orderedTopK = TakeOrderedAndProjectExec(1, ordered.outputOrdering,
          ordered.output, ordered)
        assert(DistributedBatchShuffle.forCollect(orderedTopK).isEmpty)

        val wide = spark.range(0, 10, 1, 5).repartition(2, col("id"))
        assert(wide.collect().sorted.toSeq == (0L until 10L))
        spark.sparkContext.listenerBus.waitUntilEmpty(30000)
        assert(observed.size == 1 && !observed.head.pipelined)

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
