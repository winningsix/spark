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
import org.apache.spark.sql.catalyst.optimizer.ColumnPruning
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}

/** Move dimension lookups below an inner inequality join when they expose another equi-key. */
private[adaptive] object CompositeFactJoin extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.deriveCompositeFactJoinKeys"

  private case class Lookup(input: LogicalPlan, predicates: Seq[Expression])
  private case class Spine(base: Join, lookups: Vector[Lookup])

  private def fileInput(plan: LogicalPlan): Boolean = plan match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => fileInput(child)
    case Filter(cond, child) if cond.deterministic && !SubqueryExpression.hasSubquery(cond) =>
      fileInput(child)
    case rel: LogicalRelation => !rel.isStreaming && rel.relation.isInstanceOf[HadoopFsRelation]
    case _ => false
  }

  private def spine(plan: LogicalPlan): Option[Spine] = plan match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => spine(child)
    case base @ Join(left, right, Inner, Some(cond), JoinHint.NONE)
        if fileInput(right) && cond.deterministic && !SubqueryExpression.hasSubquery(cond) =>
      val terms = splitConjunctivePredicates(cond)
      if (fileInput(left)) {
        val range = terms.exists {
          case LessThan(_: Attribute, _: Attribute) | GreaterThan(_: Attribute, _: Attribute) => true
          case _ => false
        }
        Option.when(range && terms.exists(connects(_, left.outputSet, right.outputSet))) {
          Spine(base, Vector.empty)
        }
      } else {
        spine(left).map(s => s.copy(lookups = s.lookups :+ Lookup(right, terms)))
      }
    case _ => None
  }

  private def connects(expr: Expression, left: AttributeSet, right: AttributeSet): Boolean =
    expr match {
      case EqualTo(a: Attribute, b: Attribute) =>
        (left.contains(a) && right.contains(b)) || (left.contains(b) && right.contains(a))
      case _ => false
    }

  private def joins(lookup: Lookup, input: LogicalPlan): Boolean =
    lookup.predicates.exists(connects(_, lookup.input.outputSet, input.outputSet))

  private def rewrite(root: Join, moveFilters: Boolean): Option[LogicalPlan] = for {
    Spine(base, lookups) <- spine(root)
    (first, second) <- lookups.indices.iterator.flatMap { i =>
      (i + 1 until lookups.size).iterator.map(j => (i, j))
    }.find { case (i, j) =>
      val a = lookups(i)
      val b = lookups(j)
      joins(b, a.input) && ((joins(a, base.left) && joins(b, base.right)) ||
        (joins(a, base.right) && joins(b, base.left)))
    }
  } yield {
    var left = base.left
    var right = base.right
    var pending = splitConjunctivePredicates(base.condition.get)
    val deferred = Vector.newBuilder[Lookup]
    lookups.zipWithIndex.foreach { case (lookup, index) =>
      val directLeft = joins(lookup, base.left)
      val directRight = joins(lookup, base.right)
      val side = if (directLeft != directRight) Some(directLeft) else {
        val onLeft = joins(lookup, left)
        Option.when(onLeft != joins(lookup, right))(onLeft)
      }
      if ((moveFilters || index == first || index == second) && side.isDefined) {
        val toLeft = side.get
        val fact = if (toLeft) left else right
        val available = fact.outputSet ++ lookup.input.outputSet
        val (local, cross) = lookup.predicates.partition(_.references.subsetOf(available))
        val joined = Join(fact, lookup.input, Inner, local.reduceLeftOption(And), JoinHint.NONE)
        if (toLeft) left = joined else right = joined
        pending ++= cross
      } else {
        deferred += lookup
      }
    }
    val available = left.outputSet ++ right.outputSet
    val (keys, residual) = pending.partition(_.references.subsetOf(available))
    val joined = Join(left, right, Inner, keys.reduceLeftOption(And), JoinHint.NONE)
    val complete = deferred.result().foldLeft[LogicalPlan](joined) { (child, lookup) =>
      Join(child, lookup.input, Inner, lookup.predicates.reduceLeftOption(And), JoinHint.NONE)
    }
    val filtered = residual.reduceLeftOption(And).map(Filter(_, complete)).getOrElse(complete)
    ColumnPruning(Project(root.output, filtered))
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val mode = conf.getConfString(setting, "off")
    if (plan.isStreaming || (mode != "keys" && mode != "filters")) return plan
    plan.transformDown {
      case join: Join if join.joinType == Inner => rewrite(join, mode == "filters").getOrElse(join)
    }
  }
}
