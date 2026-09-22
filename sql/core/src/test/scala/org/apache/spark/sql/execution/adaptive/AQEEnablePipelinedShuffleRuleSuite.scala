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

package org.apache.spark.sql.execution.adaptive

import org.apache.spark.SparkEnv
import org.apache.spark.internal.config
import org.apache.spark.sql.QueryTest
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.execution.{SparkPlan, TakeOrderedAndProjectExec, UnionExec}
import org.apache.spark.sql.execution.exchange.{BroadcastExchangeExec, ReusedExchangeExec,
  ShuffleExchangeExec}
import org.apache.spark.sql.execution.joins.HashedRelationBroadcastMode
import org.apache.spark.sql.execution.joins.SortMergeJoinExec
import org.apache.spark.sql.test.SharedSparkSession

/** Plan-level coverage of the conservative AQE channel eligibility policy. */
class AQEEnablePipelinedShuffleRuleSuite extends QueryTest with SharedSparkSession {

  private def exchangesWithPipelined(plan: SparkPlan): Seq[Boolean] =
    plan.collect { case s: ShuffleExchangeExec => s.pipelined }

  test("the local opt-in does not enable the distributed transport") {
    assert(!SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor)
    for (local <- Seq(false, true); distributed <- Seq(false, true)) {
      withSQLConf(
          "spark.sql.shuffle.localPipelined.enabled" -> local.toString,
          "spark.sql.shuffle.distributedPipelined.enabled" -> distributed.toString,
          "spark.sql.adaptive.pipelinedShuffle.fullPlan.enabled" -> "true") {
        val leaf = spark.range(10).queryExecution.executedPlan
        val exchange = ShuffleExchangeExec(HashPartitioning(leaf.output, 4), leaf)
        val rewritten = AQEEnablePipelinedShuffle.apply(exchange)
        assert(exchangesWithPipelined(rewritten) === Seq(distributed))
      }
    }
  }

  test("a regular sibling prevents a mixed pipelined job") {
    // A free candidate and its blocked twin would form a mixed job. The regular sibling must
    // remain recoverable across actions, so the entire plan must retain regular shuffles.
    withSQLConf("spark.sql.exchange.reuse" -> "false") {
      import testImplicits._
      val leaf = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
      val hp = HashPartitioning(leaf.output, 4)

      val otherLeaf = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan

      // E1: free twin as a UnionExec child
      val freeTwin = ShuffleExchangeExec(hp, leaf)

      // E2: blocked twin inside the join's left input (same partitioning, same leaf child)
      val blockedTwin = ShuffleExchangeExec(hp, leaf)
      // Join with E2 on the left, otherLeaf on the right (asymmetric, so no join-paired flip)
      val join = SortMergeJoinExec(
        leaf.output, otherLeaf.output, Inner, None, blockedTwin, otherLeaf)

      // A candidate and a blocked sibling must not become a mixed result job.
      val root = UnionExec(Seq(freeTwin, join))

      val rule = AQEEnablePipelinedShuffle
      val flipped = rule.flipEligibleExchanges(root)

      val flippedUnion = flipped match {
        case u: UnionExec => u
        case other => fail(s"expected a top UnionExec; got:\n$other")
      }
      assert(exchangesWithPipelined(flippedUnion) == Seq(false, false),
        s"both branches must stay regular so the sibling can recover lost outputs: $flipped")
    }
  }

  test("full-plan mode changes exchange transport without changing the join operator") {
    withSQLConf(
        "spark.sql.shuffle.distributedPipelined.enabled" -> "true",
        "spark.sql.adaptive.pipelinedShuffle.fullPlan.enabled" -> "true",
        "spark.sql.exchange.reuse" -> "false") {
      import testImplicits._
      val left = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
      val right = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
      val leftExchange = ShuffleExchangeExec(HashPartitioning(left.output, 4), left)
      val rightExchange = ShuffleExchangeExec(HashPartitioning(right.output, 4), right)
      val join = SortMergeJoinExec(
        left.output, right.output, Inner, None, leftExchange, rightExchange)

      val rewritten = AQEEnablePipelinedShuffle.apply(join)
      assert(rewritten.isInstanceOf[SortMergeJoinExec])
      assert(exchangesWithPipelined(rewritten) === Seq(true, true))
    }
  }

  test("a reused broadcast exchange does not block a pipelined shuffle") {
    withSQLConf(
        "spark.sql.shuffle.distributedPipelined.enabled" -> "true",
        "spark.sql.adaptive.pipelinedShuffle.fullPlan.enabled" -> "true") {
      import testImplicits._
      val leaf = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
      val shuffle = ShuffleExchangeExec(HashPartitioning(leaf.output, 4), leaf)
      val broadcast = BroadcastExchangeExec(
        HashedRelationBroadcastMode(leaf.output), leaf)
      val reusedBroadcast = ReusedExchangeExec(broadcast.output, broadcast)
      val plan = UnionExec(Seq(shuffle, reusedBroadcast))

      val rewritten = AQEEnablePipelinedShuffle.apply(plan)
      assert(exchangesWithPipelined(rewritten) === Seq(true))
      assert(rewritten.collect { case _: ReusedExchangeExec => true }.size === 1)
    }
  }

  test("a reused shuffle is rewired to one shared pipelined exchange") {
    withSQLConf(
        "spark.sql.shuffle.distributedPipelined.enabled" -> "true",
        "spark.sql.adaptive.pipelinedShuffle.fullPlan.enabled" -> "true") {
      import testImplicits._
      val leaf = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
      val shuffle = ShuffleExchangeExec(HashPartitioning(leaf.output, 4), leaf)
      val reused = ReusedExchangeExec(shuffle.output, shuffle)
      val plan = UnionExec(Seq(shuffle, reused))

      val rewritten = AQEEnablePipelinedShuffle.apply(plan).asInstanceOf[UnionExec]
      val rewrittenShuffle = rewritten.children.head.asInstanceOf[ShuffleExchangeExec]
      val rewrittenReuse = rewritten.children(1).asInstanceOf[ReusedExchangeExec]
      assert(rewrittenShuffle.pipelined)
      assert(rewrittenReuse.child.asInstanceOf[ShuffleExchangeExec].pipelined)
      assert(rewrittenReuse.child eq rewrittenShuffle,
        "the original and reused branches must share one pipelined exchange instance")
    }
  }

  test("prepared receive mode pipelines below a limit's hidden regular boundary") {
    val previousEnabled = SparkEnv.get.conf.get(
      config.STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED)
    val previousQueue = SparkEnv.get.conf.get(config.STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY)
    val previousSharedConnections = SparkEnv.get.conf.get(
      config.STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED)
    val previousSharedServer = SparkEnv.get.conf.get(
      config.STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED)
    val previousWaitForAcks = SparkEnv.get.conf.get(
      config.STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS)
    SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, true)
    SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY, 1024L)
    SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, true)
    SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, true)
    SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, false)
    try {
      withSQLConf(
          "spark.sql.shuffle.distributedPipelined.enabled" -> "true",
          "spark.sql.adaptive.pipelinedShuffle.fullPlan.enabled" -> "true") {
        import testImplicits._
        val leaf = spark.range(10).select($"id" as Symbol("k")).queryExecution.executedPlan
        val exchange = ShuffleExchangeExec(HashPartitioning(leaf.output, 4), leaf)
        val limit = TakeOrderedAndProjectExec(1, Nil, exchange.output, exchange)

        val rewritten = AQEEnablePipelinedShuffle.apply(limit)
        assert(rewritten.isInstanceOf[TakeOrderedAndProjectExec])
        assert(exchangesWithPipelined(rewritten) === Seq(true))
      }
    } finally {
      SparkEnv.get.conf.set(
        config.STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED, previousEnabled)
      SparkEnv.get.conf.set(config.STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY, previousQueue)
      SparkEnv.get.conf.set(
        config.STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED, previousSharedConnections)
      SparkEnv.get.conf.set(
        config.STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED, previousSharedServer)
      SparkEnv.get.conf.set(
        config.STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS, previousWaitForAcks)
    }
  }
}
