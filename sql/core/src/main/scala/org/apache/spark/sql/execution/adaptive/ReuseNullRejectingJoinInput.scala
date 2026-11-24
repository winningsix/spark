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
import org.apache.spark.sql.catalyst.plans.{LeftAnti, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical.{ConstraintHelper, Filter, Join, LogicalPlan, Project}
import org.apache.spark.sql.catalyst.trees.TreePattern.LEFT_SEMI_OR_ANTI_JOIN
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.execution.exchange.ShuffleExchangeLike

/** Align a build-side scan with an existing filtered scan when NULL keys cannot match. */
private[adaptive] object ReuseNullRejectingJoinInput extends PredicateHelper with ConstraintHelper {
  def rewrite(plan: LogicalPlan): Option[LogicalPlan] = {
    val result = plan.transformUpWithPruning(_.containsPattern(LEFT_SEMI_OR_ANTI_JOIN)) {
      case j @ Join(left, right @ Project(columns, filter @ Filter(pred, _: LogicalRelation)),
          LeftSemi | LeftAnti, Some(condition), _)
          if columns.forall(_.isInstanceOf[Attribute]) && condition.deterministic &&
            right.deterministic && !SubqueryExpression.hasSubquery(pred) =>
        val terms = ExpressionSet(splitConjunctivePredicates(condition))
        val implied = constructIsNotNullConstraints(terms, Nil) ++ terms
        val existing = ExpressionSet(splitConjunctivePredicates(pred))
        val missing = right.output.map(IsNotNull(_)).filter(p => implied.contains(p) &&
          !existing.contains(p))
        if (missing.isEmpty) j else {
          // Keep all existing predicates and their evaluation order. Only build rows that
          // cannot match the original join condition are removed.
          val candidate = right.copy(child = filter.copy(condition = missing.foldLeft(pred)(And)))
          if (left.exists {
              case other: Project => other.sameResult(candidate)
              case _ => false
            }) j.copy(right = candidate) else j
        }
    }
    Option.unless(result fastEquals plan)(result)
  }

  def distinctShuffles(plan: SparkPlan): Int =
    plan.collect { case s: ShuffleExchangeLike => s.canonicalized }.distinct.size
}
