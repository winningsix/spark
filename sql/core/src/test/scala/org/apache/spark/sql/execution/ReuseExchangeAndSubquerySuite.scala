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

import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, IdentityBroadcastMode}
import org.apache.spark.sql.execution.exchange.{BroadcastExchangeExec, Exchange, ReusedExchangeExec, ShuffleExchangeExec}
import org.apache.spark.sql.execution.reuse.ReuseExchangeAndSubquery
import org.apache.spark.sql.functions.col
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.test.SharedSparkSession

class ReuseExchangeAndSubquerySuite extends SharedSparkSession {

  val tableFormat: String = "parquet"

  test("pipelined AQE reuses shuffle inputs before broadcast stage preparation") {
    withSQLConf(SQLConf.EXCHANGE_REUSE_ENABLED.key -> "true") {
      val leaf = spark.range(4).queryExecution.sparkPlan
      def broadcast = BroadcastExchangeExec(IdentityBroadcastMode, leaf)
      def shuffle = ShuffleExchangeExec(HashPartitioning(leaf.output, 2), leaf)
      val plan = UnionExec(Seq(broadcast, broadcast, shuffle, shuffle))
      val early = ReuseExchangeAndSubquery.reuseShufflesAndSubqueries(plan)
      assert(early.children.take(2).forall(_.isInstanceOf[BroadcastExchangeExec]))
      assert(early.children.last.asInstanceOf[ReusedExchangeExec].child eq early.children(2))
      val normal = ReuseExchangeAndSubquery(plan)
      assert(normal.children(1).asInstanceOf[ReusedExchangeExec].child eq normal.children.head)
    }
  }

  test("SPARK-32041: No reuse interference inside ReuseExchange") {
    withSQLConf(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      withTable("df1", "df2") {
        spark.range(100)
          .select(col("id"), col("id").as("k"))
          .write
          .partitionBy("k")
          .format(tableFormat)
          .mode("overwrite")
          .saveAsTable("df1")

        spark.range(10)
          .select(col("id"), col("id").as("k"))
          .write
          .format(tableFormat)
          .mode("overwrite")
          .saveAsTable("df2")

        val df = sql(
          """
            |WITH t AS (
            |  SELECT df1.id, df2.k
            |  FROM df1 JOIN df2 ON df1.k = df2.k
            |  WHERE df2.id < 2
            |)
            |SELECT * FROM t AS a JOIN t AS b ON a.id = b.id
            |""".stripMargin)

        val plan = df.queryExecution.executedPlan

        val exchangeIds = plan.collectWithSubqueries { case e: Exchange => e.id }
        val reusedExchangeIds = plan.collectWithSubqueries {
          case re: ReusedExchangeExec => re.child.id
        }

        assert(reusedExchangeIds.forall(exchangeIds.contains(_)),
          "ReusedExchangeExec should reuse an existing exchange")
      }
    }
  }

  test("SPARK-32041: No reuse interference between ReuseExchange and ReuseSubquery") {
    withSQLConf(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      withTable("df1", "df2") {
        spark.range(100)
          .select(col("id"), col("id").as("k"))
          .write
          .partitionBy("k")
          .format(tableFormat)
          .mode("overwrite")
          .saveAsTable("df1")

        spark.range(10)
          .select(col("id"), col("id").as("k"))
          .write
          .format(tableFormat)
          .mode("overwrite")
          .saveAsTable("df2")

        val df = sql(
          """
            |WITH t AS (
            |  SELECT df1.id, df2.k
            |  FROM df1 JOIN df2 ON df1.k = df2.k
            |  WHERE df2.id < 2
            |),
            |t2 AS (
            |  SELECT * FROM t
            |  UNION
            |  SELECT * FROM t
            |)
            |SELECT * FROM t2 AS a JOIN t2 AS b ON a.id = b.id
            |""".stripMargin)

        val plan = df.queryExecution.executedPlan

        val exchangeIds = plan.collectWithSubqueries { case e: Exchange => e.id }
        val reusedExchangeIds = plan.collectWithSubqueries {
          case re: ReusedExchangeExec => re.child.id
        }

        assert(reusedExchangeIds.forall(exchangeIds.contains(_)),
          "ReusedExchangeExec should reuse an existing exchange")
      }
    }
  }
}
