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

import org.apache.spark.sql.catalyst.expressions.Attribute
import org.apache.spark.sql.catalyst.plans.LeftSemi
import org.apache.spark.sql.catalyst.plans.logical.{Aggregate, Filter, Join, LogicalPlan, Project, RebalancePartitions}
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.execution.{FilterExec, ProjectExec, SortExec, SparkPlan}
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.joins.ShuffledJoin

/**
 * AQE can share filtered aggregate keys only when the producing plan has a stage at that point.
 * A backend can already supply this exchange during stage preparation. Match only unmaterialized
 * producers, after each backend has established its required distribution and ordering.
 */
private[adaptive] object ReuseUnmaterializedSemiJoinKeys {
  private def keyset(join: ShuffledJoin): Option[(LogicalPlan, ProjectExec)] = {
    if (join.joinType != LeftSemi || join.isSkewJoin || join.condition.nonEmpty) return None
    val right = join.right match {
      case sort: SortExec if !sort.global => sort.child
      case other if join.requiredChildOrdering(1).isEmpty => other
      case _ => return None
    }
    right match {
      case p @ ProjectExec(_, FilterExec(_, _: BaseAggregateExec)) =>
        join.logicalLink.collect {
          case j: Join if j.hint.rightHint.isEmpty => j.right
        }.collect {
          case keyPlan @ Project(keys, Filter(having, agg: Aggregate))
              if keys.nonEmpty && keys.forall(_.isInstanceOf[Attribute]) &&
                keys.size == agg.groupingExpressions.size &&
                agg.groupingExpressions.forall(g => keys.exists(_.semanticEquals(g))) &&
                having.references.exists(a => !keyPlan.outputSet.contains(a)) &&
                keyPlan.deterministic && join.rightKeys.size == keys.size &&
                join.rightKeys.forall(k => p.output.exists(_.semanticEquals(k))) &&
                p.outputPartitioning.isInstanceOf[HashPartitioning] =>
            (keyPlan, p)
        }
      case _ => None
    }
  }

  def rewrite(logical: LogicalPlan, physical: SparkPlan): Option[LogicalPlan] = {
    val inputs = physical.collect { case j: ShuffledJoin => keyset(j) }.flatten
    if (inputs.size < 2) return None
    val repeated = inputs.groupBy { case (keys, producer) =>
      (keys.canonicalized, producer.canonicalized)
    }.collect { case ((keys, _), uses) if uses.size >= 2 => keys -> uses.size }
    if (repeated.isEmpty) return None
    // Every logical consumer must correspond to a physically unmaterialized occurrence.
    // This also keeps an existing exchange if a backend materializes just some occurrences.
    val sites = logical.collect {
      case join: Join if join.joinType == LeftSemi => join.right.canonicalized
    }
    val uncovered = repeated.collect { case (keys, count) if sites.count(_ == keys) == count => keys }
      .toSet
    if (uncovered.isEmpty) return None
    Some(logical.transformUp {
      case j: Join if j.joinType == LeftSemi && uncovered.contains(j.right.canonicalized) =>
        j.copy(right = RebalancePartitions(j.right.output, j.right))
    })
  }
}
