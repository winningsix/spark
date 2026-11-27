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

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Complete, Count, Sum}
import org.apache.spark.sql.catalyst.plans.logical.{Aggregate, LogicalPlan}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.IntegerType

/** Reuse two existing SUM buffers when their null and non-null indicators partition the rows. */
private[adaptive] object CountComplementarySums extends Rule[LogicalPlan] {
  private def indicator(expr: Expression): Option[(Expression, Boolean)] = {
    val predicate = expr match {
      case CaseWhen(Seq((c, Literal(1, IntegerType))), Some(Literal(0, IntegerType))) => c
      case If(c, Literal(1, IntegerType), Literal(0, IntegerType)) => c
      case _ => return None
    }
    predicate match {
      case IsNull(value) if value.deterministic => Some(value -> true)
      case IsNotNull(value) if value.deterministic => Some(value -> false)
      case _ => None
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming ||
        !conf.getConfString("spark.sql.optimizer.countComplementarySums", "false").toBoolean) {
      return plan
    }
    plan.transformUp { case a: Aggregate =>
      val sums = a.aggregateExpressions.flatMap(_.collect {
        case agg @ AggregateExpression(sum: Sum, Complete, false, None, _)
            if sum.evalContext.evalMode != EvalMode.TRY => indicator(sum.child).map(_ -> agg)
      }).flatten
      val pair = for {
        ((left, true), missing) <- sums.iterator
        ((right, false), present) <- sums.iterator if left.semanticEquals(right)
      } yield (missing, present)
      pair.nextOption().map { case (missing, present) =>
        // COUNT returns zero on empty input and uses a wrapping long counter.
        val total = Coalesce(Seq(Add(missing, present, EvalMode.LEGACY), Literal(0L)))
        val result = a.aggregateExpressions.map(_.transformUp {
          case AggregateExpression(Count(Seq(l: Literal)), Complete, false, None, _)
              if l.value != null => total
        }.asInstanceOf[NamedExpression])
        a.copy(aggregateExpressions = result)
      }.getOrElse(a)
    }
  }
}
