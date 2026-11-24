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
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Max, Min}
import org.apache.spark.sql.catalyst.plans.logical.{Aggregate, Filter, LogicalPlan, Project, RebalancePartitions, Subquery}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.execution.SparkPlan
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.execution.exchange.ShuffleExchangeLike

private[execution] object ShareScalarGroupedInput extends org.apache.spark.sql.catalyst.rules.Rule[LogicalPlan]
    with PredicateHelper {
  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || plan.isInstanceOf[Subquery] || !conf.exchangeReuseEnabled ||
        !conf.getConfString("spark.sql.adaptive.shareScalarGroupedInput.enabled", "false").toBoolean ||
        !conf.getConfString("spark.sql.adaptive.shareCompletedExtremumGroups.enabled", "false").toBoolean) plan
    else rewrite(plan).getOrElse(plan)
  }

  /** Count distinct producers in the main query and in adaptive scalar subqueries. */
  def shuffleCount(plan: SparkPlan): Int = {
    def producers(p: SparkPlan): Seq[SparkPlan] = p.collectWithSubqueries {
      case e: ShuffleExchangeLike => Seq(e.canonicalized)
      case a: AdaptiveSparkPlanExec => producers(a.initialPlan)
    }.flatten
    producers(plan).distinct.size
  }

  private def comparison(e: Expression): Option[(Attribute, ScalarSubquery)] = e match {
    case EqualTo(a: Attribute, s: ScalarSubquery) if !s.isCorrelated => Some((a, s))
    case EqualTo(s: ScalarSubquery, a: Attribute) if !s.isCorrelated => Some((a, s))
    case _ => None
  }

  private def extrema(s: ScalarSubquery): Option[(Aggregate, Attribute)] = s.plan match {
    case Aggregate(Nil, Seq(Alias(a: AggregateExpression, _)), inner: Aggregate, _)
        if a.filter.isEmpty && !a.isDistinct =>
      a.aggregateFunction match {
        case Max(v: Attribute) => Some((inner, v))
        case Min(v: Attribute) => Some((inner, v))
        case _ => None
      }
    case _ => None
  }

  def rewrite(plan: LogicalPlan): Option[LogicalPlan] = {
    val result = plan.transformUp {
      case f @ Filter(predicate, g @ Aggregate(Seq(key: Attribute), output,
          p @ Project(cols, base @ Filter(scanPred, relation: LogicalRelation)), _))
          if output.size == 2 && output.exists(_.semanticEquals(key)) &&
            cols.forall(_.isInstanceOf[Attribute]) && g.deterministic && !g.isStreaming =>
        val (nullChecks, keep) = splitConjunctivePredicates(scanPred).partition {
          case IsNotNull(a: Attribute) => a.semanticEquals(key)
          case _ => false
        }
        if (nullChecks.isEmpty) f else {
          val scan = keep.reduceLeftOption(And).map(e => base.copy(condition = e)).getOrElse(relation)
          val wider = g.copy(child = p.copy(child = scan))
          val matched = splitConjunctivePredicates(predicate).flatMap(comparison).find {
            case (value, scalar) => extrema(scalar).exists { case (other, target) =>
              val comparable = for {
                left <- output.find(_.exprId == value.exprId)
                right <- other.aggregateExpressions.find(_.exprId == target.exprId)
              } yield wider.copy(aggregateExpressions = Seq(left))
                .sameResult(other.copy(aggregateExpressions = Seq(right)))
              other.deterministic && comparable.contains(true)
            }
          }
          matched match {
            case None => f
            case Some((value, scalar)) if SQLConf.get.getConfString(
                "spark.sql.adaptive.shareCompletedExtremumGroups.enabled", "false").toBoolean =>
              // Both keys are required by the exchange even if the scalar only needs the value.
              // Reuse can then identify one producer for the completed grouped result.
              val shared = RebalancePartitions(Seq(key, value), wider,
                Some(SQLConf.get.numShufflePartitions))
              val outer = scalar.plan.asInstanceOf[Aggregate]
              val (_, target) = extrema(scalar).get
              val replaceValue = outer.transformExpressions {
                case a: Attribute if a.exprId == target.exprId => value
              }
              val newScalar = scalar.copy(plan = replaceValue.withNewChildren(Seq(shared)),
                exprId = NamedExpression.newExprId)
              val condition = predicate.transform {
                case s: ScalarSubquery if s.exprId == scalar.exprId => newScalar
              }
              Filter(And(IsNotNull(key), condition), shared)
            case Some(_) => Filter(And(IsNotNull(key), predicate), wider)
          }
        }
    }
    Option.unless(result fastEquals plan)(result)
  }
}
