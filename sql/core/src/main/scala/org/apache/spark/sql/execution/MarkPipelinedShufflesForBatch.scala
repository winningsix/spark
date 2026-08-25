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

import org.apache.spark.sql.catalyst.plans.physical.RangePartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.exchange.ShuffleExchangeExec
import org.apache.spark.sql.internal.SQLConf

/** Marks supported batch shuffle exchanges for incremental, pipelined execution. */
case object MarkPipelinedShufflesForBatch extends Rule[SparkPlan] {

  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConf(SQLConf.BATCH_PIPELINED_SHUFFLE_ENABLED)) {
      plan
    } else {
      mark(plan, belowRangeExchange = false)
    }
  }

  /**
   * A range exchange samples its child in a separate Spark job before executing that child again
   * to produce the real shuffle. Streaming shuffle output is single-consumer and cannot be read by
   * both jobs, so every shuffle below a range exchange must remain materialized.
   */
  private def mark(plan: SparkPlan, belowRangeExchange: Boolean): SparkPlan = {
    val isRangeExchange = plan match {
      case exchange: ShuffleExchangeExec =>
        exchange.outputPartitioning.isInstanceOf[RangePartitioning]
      case _ => false
    }
    val blockChildren = belowRangeExchange || isRangeExchange
    val newPlan = plan.withNewChildren(plan.children.map(mark(_, blockChildren)))
    newPlan match {
      case exchange: ShuffleExchangeExec if !blockChildren && !exchange.pipelined =>
        exchange.copy(pipelined = true)
      case other => other
    }
  }
}
