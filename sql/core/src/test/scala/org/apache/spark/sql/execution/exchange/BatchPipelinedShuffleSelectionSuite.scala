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

import org.apache.spark.sql.QueryTest
import org.apache.spark.sql.catalyst.expressions.SortOrder
import org.apache.spark.sql.catalyst.optimizer.BuildLeft
import org.apache.spark.sql.catalyst.plans.physical.RangePartitioning
import org.apache.spark.sql.execution.{SortExec, SparkPlan, TakeOrderedAndProjectExec}
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.sql.functions.col
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.test.SharedSparkSession

class BatchPipelinedShuffleSelectionSuite extends QueryTest with SharedSparkSession {
  private val selection = SQLConf.BATCH_PIPELINED_SHUFFLE_SELECTION_ENABLED.key

  private def candidates(plan: SparkPlan): Seq[ShuffleExchangeExec] = plan.collect {
    case s: ShuffleExchangeExec if s.getTagValue(SelectBatchPipelinedShuffle.candidate).isDefined =>
      s
  }

  private val aggregate =
    "SELECT id % 3 AS k, count(*) AS n FROM range(0, 32, 1, 4) GROUP BY id % 3"

  test("single-reader aggregation is opt-in and visible on the exchange") {
    withSQLConf(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      assert(!spark.sessionState.conf.getConf(SQLConf.BATCH_PIPELINED_SHUFFLE_SELECTION_ENABLED))
      val regular = sql(aggregate)
      val expected = regular.collect()
      assert(candidates(regular.queryExecution.executedPlan).isEmpty)
      withSQLConf(selection -> "true") {
        val selected = sql(aggregate)
        val Seq(exchange) = candidates(selected.queryExecution.executedPlan)
        assert(!exchange.pipelined)
        val explain = sql("EXPLAIN " + aggregate).head().getString(0)
        val marked = explain.linesIterator.filter(_.contains("batchPipelinedCandidate=true")).toList
        assert(marked.size == 1 && marked.head.contains("Exchange"), explain)
        checkAnswer(selected, expected)

        val equivalent = spark.range(0, 32, 1, 4).groupBy((col("id") % 3).as("k")).count()
        val Seq(dfExchange) = candidates(equivalent.queryExecution.executedPlan)
        assert(dfExchange.sameResult(exchange))
        withSQLConf(selection -> "false") {
          assert(candidates(sql(aggregate).queryExecution.executedPlan).isEmpty)
        }
      }
    }
  }

  for (build <- Seq("l", "r")) {
    test(s"shuffled hash join selects the probe when $build is the build side") {
      withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
        val plan = sql(
          s"""SELECT /*+ SHUFFLE_HASH($build) */ l.id
             |FROM range(0, 32, 1, 4) l JOIN range(0, 8, 1, 2) r ON l.id = r.id
             |""".stripMargin).queryExecution.executedPlan
        val Seq(join) = plan.collect { case j: ShuffledHashJoinExec => j }
        assert((join.buildSide == BuildLeft) == (build == "l"))
        val (buildPlan, probePlan) = if (build == "l") {
          (join.left, join.right)
        } else {
          (join.right, join.left)
        }
        assert(buildPlan.exists(_.isInstanceOf[ShuffleExchangeExec]))
        assert(candidates(buildPlan).isEmpty)
        assert(candidates(probePlan).size == 1)
      }
    }
  }

  test("an unrelated aggregation remains a candidate above a reused join input") {
    withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false",
        SQLConf.EXCHANGE_REUSE_ENABLED.key -> "true") {
      val plan = sql(
        """SELECT /*+ SHUFFLE_HASH(r) */ l.id % 3, count(*)
          |FROM range(0, 8, 1, 4) l JOIN range(0, 8, 1, 4) r ON l.id = r.id GROUP BY l.id % 3
          |""".stripMargin).queryExecution.executedPlan
      assert(plan.exists(_.isInstanceOf[ReusedExchangeExec]))
      val Seq(selected) = candidates(plan)
      assert(selected.child.exists(_.isInstanceOf[ShuffledHashJoinExec]))
    }
  }

  test("an exchange referenced twice without a reuse wrapper also forces fallback") {
    withSQLConf(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      val plan = sql(
        """SELECT /*+ SHUFFLE_HASH(r) */ l.id
          |FROM range(0, 8, 1, 4) l JOIN range(0, 16, 1, 4) r ON l.id = r.id
          |""".stripMargin).queryExecution.executedPlan
      val Seq(join) = plan.collect { case j: ShuffledHashJoinExec => j }
      val shared = join.withNewChildren(Seq(join.left, join.left))
      assert(join.left.exists(_.isInstanceOf[ShuffleExchangeExec]))
      withSQLConf(selection -> "true") {
        assert(candidates(SelectBatchPipelinedShuffle(join)).nonEmpty)
        assert(candidates(SelectBatchPipelinedShuffle(shared)).isEmpty)
      }
    }
  }

  test("a scalar subquery leaves an independent main-query edge eligible") {
    withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false",
        SQLConf.EXCHANGE_REUSE_ENABLED.key -> "false") {
      val plan = sql(
        s"""SELECT k, n FROM ($aggregate) t
           |WHERE n > (SELECT max(n) FROM ($aggregate) s)
           |""".stripMargin).queryExecution.executedPlan
      assert(plan.exists(_.subqueries.nonEmpty))
      assert(candidates(plan).size == 1)
      assert(plan.subqueriesAll.forall(candidates(_).isEmpty))
    }
  }

  test("coalescing multiple partitions in one reader prevents selection") {
    withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      val plan = sql(aggregate).coalesce(1).queryExecution.executedPlan
      assert(plan.exists(_.isInstanceOf[ShuffleExchangeExec]))
      assert(candidates(plan).isEmpty)
    }
  }

  test("Top-K can read a single-reader aggregation with ordered or unordered input") {
    withSQLConf(SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      val query = s"$aggregate ORDER BY n DESC, k LIMIT 2"
      val expected = sql(query).collect()
      val top = sql(query).queryExecution.executedPlan.asInstanceOf[TakeOrderedAndProjectExec]
      val sorted = SortExec(top.sortOrder, global = false, top.child)
      for (child <- Seq(top.child, sorted)) {
        val ordered = SortOrder.orderingSatisfies(child.outputOrdering, top.sortOrder)
        assert(ordered == (child == sorted))
        withSQLConf(selection -> "true") {
          val selected = SelectBatchPipelinedShuffle(top.copy(child = child.clone()))
          assert(candidates(selected).size == 1)
          assert(selected.executeCollectPublic().toSeq == expected.toSeq)
        }
      }
    }
  }

  test("sampling for a range exchange reads its input before the shuffle map pass") {
    withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "false") {
      val plan = sql(s"$aggregate ORDER BY k").queryExecution.executedPlan
      val exchanges = plan.collect { case s: ShuffleExchangeExec => s }
      assert(exchanges.size == 2)
      assert(exchanges.head.outputPartitioning.isInstanceOf[RangePartitioning])
      assert(candidates(plan).isEmpty)
    }
  }

  test("AQE owns its shuffle boundaries") {
    withSQLConf(selection -> "true", SQLConf.ADAPTIVE_EXECUTION_ENABLED.key -> "true") {
      val explain = sql("EXPLAIN " + aggregate).head().getString(0)
      assert(explain.contains("AdaptiveSparkPlan"))
      assert(explain.contains("Exchange"))
      assert(!explain.contains("batchPipelinedCandidate"))
    }
  }
}
