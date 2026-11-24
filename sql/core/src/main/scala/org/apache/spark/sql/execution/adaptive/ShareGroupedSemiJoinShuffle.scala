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

import scala.collection.mutable

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Sum}
import org.apache.spark.sql.catalyst.plans.LeftSemi
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.classic.SparkSession
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.DecimalType

/** Co-partition a grouped semi-join key source with an already required shuffle of its raw rows. */
private[adaptive] object ShareGroupedSemiJoinShuffle {
  private case class Group(input: Project, key: Attribute)

  private def groupedKey(plan: LogicalPlan): Option[Group] = plan match {
    case r: RebalancePartitions => groupedKey(r.child)
    case r: RepartitionByExpression => groupedKey(r.child)
    case Project(Seq(outputKey: Attribute), Filter(predicate,
        Aggregate(Seq(groupKey: Attribute), Seq(k: Attribute, Alias(sum: AggregateExpression, _)),
          p @ Project(columns, _: LogicalRelation), _)))
        if predicate.deterministic && k.semanticEquals(groupKey) && outputKey.semanticEquals(groupKey) &&
          !sum.isDistinct && sum.filter.isEmpty && (sum.aggregateFunction match {
            case s: Sum => s.child.isInstanceOf[Attribute] && s.child.dataType.isInstanceOf[DecimalType]
            case _ => false
          }) &&
          columns.forall(_.isInstanceOf[Attribute]) && p.outputSet.contains(groupKey) =>
      Some(Group(p, groupKey))
    case _ => None
  }

  private def filteredKeys(right: LogicalPlan): Option[Project] = right match {
    case p: Project => Some(p)
    case r @ RebalancePartitions(Seq(key), p: Project, None, None)
        if r.output.size == 1 && key.semanticEquals(r.output.head) => Some(p)
    case _ => None
  }

  // A shared exchange also fixes the width of the subsequent grouped aggregation.
  // Use the projected input size to avoid spreading small shuffles across the cluster.
  private def sharedPartitions(input: Project): Option[Int] = {
    val conf = SQLConf.get
    if (!conf.getConfString("spark.sql.adaptive.sizeSharedGroupedShuffle.enabled", "false")
        .toBoolean) return None
    val current = conf.numShufflePartitions
    val bytes = input.stats.sizeInBytes
    val advisory = conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)
    if (bytes >= conf.defaultSizeInBytes || bytes <= BigInt(current) * advisory) return None
    SparkSession.getActiveSession.flatMap { session =>
      val sc = session.sparkContext
      val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
      val target = ((bytes + advisory - 1) / advisory).min(BigInt(slots)).toInt
      Option.when(target > current)(target)
    }
  }

  def rewrite(plan: LogicalPlan): Option[LogicalPlan] = {
    val replacements = mutable.HashMap.empty[Project, LogicalPlan]
    val keyWidths = mutable.HashMap.empty[LogicalPlan, Int]
    plan.foreach {
      case Join(p @ Project(columns, Filter(IsNotNull(rawKey: Attribute), r: LogicalRelation)),
          right, LeftSemi, Some(EqualTo(a: Attribute, b: Attribute)), _)
          if columns.forall(_.isInstanceOf[Attribute]) && p.outputSet.contains(rawKey) =>
        groupedKey(right).foreach { group =>
          val leftInput = p.copy(child = r)
          if (((a.semanticEquals(rawKey) && b.semanticEquals(group.key)) ||
              (b.semanticEquals(rawKey) && a.semanticEquals(group.key))) &&
              leftInput.sameResult(group.input) &&
              p.output.indexWhere(_.semanticEquals(rawKey)) ==
                group.input.output.indexWhere(_.semanticEquals(group.key))) {
            // Both sites read all the same columns and rows. Retain the original null
            // rejection after reading the raw input. This also keeps null groups intact
            // for any other consumers of the aggregate.
            val partitions = sharedPartitions(group.input)
            for (n <- partitions; keys <- filteredKeys(right)) {
              keyWidths(keys.canonicalized) = n
            }
            replacements(p) = Filter(IsNotNull(rawKey),
              RepartitionByExpression(Seq(rawKey), leftInput, partitions))
            replacements(group.input) = RepartitionByExpression(Seq(group.key), group.input, partitions)
          }
        }
      case _ =>
    }
    // Both semi joins consume the same post-HAVING keys. EnsureRequirements may otherwise
    // resize that exchange differently under its two parents and run the grouped sum twice.
    val aligned = if (keyWidths.isEmpty) plan else plan.transformUp {
      case j @ Join(_, right, LeftSemi, Some(EqualTo(a: Attribute, b: Attribute)), hint)
          if hint.rightHint.isEmpty && right.output.size == 1 &&
            (a.semanticEquals(right.output.head) || b.semanticEquals(right.output.head)) =>
        filteredKeys(right).flatMap { keys =>
          keyWidths.get(keys.canonicalized).map { n =>
            j.copy(right = RebalancePartitions(keys.output, keys, Some(n)))
          }
        }.getOrElse(j)
    }
    Option.when(replacements.nonEmpty)(aligned.transformUp {
      case p: Project if replacements.contains(p) => replacements(p)
    })
  }
}
