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

import org.apache.spark.SparkConf
import org.apache.spark.sql.{BenchmarkQueryTest, TPCHBase}
import org.apache.spark.sql.catalyst.util.resourceToString
import org.apache.spark.sql.execution.adaptive.AQEEnablePipelinedShuffle
import org.apache.spark.sql.internal.SQLConf

/**
 * Locks down the transport-only full-plan contract on the complete TPC-H query set.
 *
 * The tables created by [[TPCHBase]] are empty, so these tests only analyze and prepare plans; no
 * benchmark data is scanned. Each test first builds the ordinary BSP plan, then applies the same
 * full-plan rule that AQE invokes before creating query stages. The pipelined bit is deliberately
 * excluded from canonicalization, which lets the test prove both requirements independently:
 * every shuffle uses the streaming transport, while joins, build sides, aggregates, sorts, and
 * partitioning remain identical to BSP.
 */
class PipelinedShuffleTPCHPlanSuite extends BenchmarkQueryTest with TPCHBase {

  override protected def sparkConf: SparkConf = {
    super.sparkConf
      .set("spark.shuffle.manager.incremental",
        "org.apache.spark.shuffle.streaming.StreamingShuffleManager")
      .set("spark.shuffle.streaming.executorReceiveService.enabled", "true")
      .set("spark.shuffle.streaming.readerMessageBatching.enabled", "true")
      .set("spark.shuffle.streaming.readerQueueMaxMemory", "64k")
      .set("spark.shuffle.streaming.sharedWriterServer.enabled", "true")
      .set("spark.shuffle.streaming.sharedConnections.enabled", "true")
      .set(SQLConf.ADAPTIVE_EXECUTION_ENABLED, false)
      .set(SQLConf.SHUFFLE_PARTITIONS, 52)
  }

  tpchQueries.foreach { name =>
    test(s"$name is transport-only fully streaming at p52") {
      val queryText = resourceToString(s"tpch/$name.sql",
        classLoader = Thread.currentThread().getContextClassLoader)
      val bspPlan = withSQLConf(SQLConf.PIPELINED_SHUFFLE_ENABLED.key -> "false") {
        sql(queryText).queryExecution.executedPlan
      }

      val rtmPlan = withSQLConf(
          SQLConf.PIPELINED_SHUFFLE_ENABLED.key -> "true",
          SQLConf.PIPELINED_SHUFFLE_FULL_PLAN_AQE_ENABLED.key -> "true") {
        AQEEnablePipelinedShuffle().apply(bspPlan)
      }
      val directShuffles = rtmPlan.collectWithSubqueries {
        case exchange: ShuffleExchangeExec => exchange
      }
      val reusedShuffles = rtmPlan.collectWithSubqueries {
        case reused @ ReusedExchangeExec(_, _: ShuffleExchangeExec) => reused
      }

      assert(directShuffles.nonEmpty, s"TPC-H $name unexpectedly has no shuffle:\n$rtmPlan")
      assert(directShuffles.forall(_.pipelined),
        s"TPC-H $name retained a visible BSP shuffle:\n$rtmPlan")
      assert(reusedShuffles.forall(_.child.asInstanceOf[ShuffleExchangeExec].pipelined),
        s"TPC-H $name retained a reused BSP shuffle:\n$rtmPlan")
      assert(directShuffles.filter(_.outputPartitioning.numPartitions > 1)
        .forall(_.outputPartitioning.numPartitions == 52),
        s"TPC-H $name has a non-single shuffle whose width is not 52:\n$rtmPlan")
      assert(rtmPlan.canonicalized == bspPlan.canonicalized,
        s"TPC-H $name changed its canonical physical plan instead of only its transport:\n" +
          s"BSP:\n$bspPlan\nRTM:\n$rtmPlan")
    }
  }
}
