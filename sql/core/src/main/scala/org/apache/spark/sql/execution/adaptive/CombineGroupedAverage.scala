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
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Average}
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.execution.{FileSourceScanExec, SparkPlan}
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.types.DecimalType

/** Evaluate an average over an already key-filtered fact input once for both consumers. */
private[adaptive] object CombineGroupedAverage extends PredicateHelper {
  def scans(plan: SparkPlan): Int = plan.collect { case f: FileSourceScanExec => f }.size

  private case class Input(project: Project, filter: Expression, relation: LogicalRelation)
  private def input(plan: LogicalPlan): Option[Input] = plan match {
    case p @ Project(columns, Filter(cond, rel: LogicalRelation))
        if columns.forall(_.isInstanceOf[Attribute]) && cond.deterministic => Some(Input(p, cond, rel))
    case _ => None
  }
  private def connects(cond: Expression, a: Attribute, b: Attribute): Boolean = cond match {
    case EqualTo(x: Attribute, y: Attribute) =>
      (a.semanticEquals(x) && b.semanticEquals(y)) || (a.semanticEquals(y) && b.semanticEquals(x))
    case _ => false
  }
  private def keyPredicate(e: Expression, key: Attribute): Boolean = e match {
    case IsNotNull(a: Attribute) => a.semanticEquals(key)
    case Coalesce(Seq(b, Literal(true, _))) => keyPredicate(b, key)
    case b: BloomFilterMightContain => b.references == AttributeSet(Seq(key))
    case _ => false
  }
  private def exactInput(avg: AggregateExpression): Boolean = avg.aggregateFunction match {
    case a: Average => a.child match {
      case value: Attribute => value.dataType.isInstanceOf[DecimalType]
      case UnscaledValue(value: Attribute) => value.dataType.isInstanceOf[DecimalType]
      case _ => false
    }
    case _ => false
  }

  private def combine(j: Join): Option[LogicalPlan] = (j.left, j.right, j.condition) match {
    case (outer @ Project(_, dimJoin @ Join(_, _, Inner, Some(dimCondition), _)),
        Filter(IsNotNull(nullGuard: Attribute), Aggregate(Seq(groupKey: Attribute),
          Seq(threshold: Alias, outputKey: Attribute), grouped, _)), Some(cond))
        if j.joinType == Inner && j.hint == JoinHint.NONE && groupKey.semanticEquals(outputKey) &&
          threshold.toAttribute.semanticEquals(nullGuard) && threshold.deterministic &&
          outer.projectList.forall(_.isInstanceOf[Attribute]) =>
      val aggs = threshold.child.collect { case a: AggregateExpression => a }
      if (aggs.size != 1 || aggs.head.isDistinct || aggs.head.filter.isDefined ||
          !exactInput(aggs.head)) return None
      val avg = aggs.head
      val branches = Seq((dimJoin.left, dimJoin.right), (dimJoin.right, dimJoin.left))
      branches.iterator.flatMap { case (fact, dimension) =>
        for {
          raw <- input(fact)
          base <- input(grouped) if base.relation.sameResult(raw.relation)
          attrs = AttributeMap(base.relation.output.zip(raw.relation.output))
          rawKey <- attrs.get(groupKey) if raw.project.outputSet.contains(rawKey)
          dimKey <- dimension.output.find(d => connects(dimCondition, rawKey, d))
          if splitConjunctivePredicates(cond).exists(connects(_, groupKey, dimKey))
          terms = splitConjunctivePredicates(base.filter)
          if terms.forall(keyPredicate(_, groupKey)) &&
            terms.exists(_.exists(_.isInstanceOf[BloomFilterMightContain]))
          moved = terms.map(_.transform { case a: Attribute if attrs.contains(a) => attrs(a) })
          rawTerms = splitConjunctivePredicates(raw.filter)
          if ExpressionSet(moved).subsetOf(ExpressionSet(rawTerms))
          mapped = avg.transform { case a: Attribute if attrs.contains(a) => attrs(a) }.asInstanceOf[AggregateExpression]
          if mapped.references.subsetOf(raw.project.outputSet)
        } yield {
          // Compute the window from the grouped side's rows. Predicates specific to the
          // raw side, including quantity checks, still apply after the average is known.
          val source = raw.project.copy(child = Filter(moved.reduceLeft(And), raw.relation))
          val frame = SpecifiedWindowFrame(RowFrame, UnboundedPreceding, UnboundedFollowing)
          val spec = WindowSpecDefinition(Seq(rawKey), Nil, frame)
          val value = Alias(WindowExpression(mapped, spec), "group_average")()
          val window = Window(Seq(value), Seq(rawKey), Nil, source)
          val extras = rawTerms.filterNot(ExpressionSet(moved).contains)
          val rows = if (extras.isEmpty) window else Filter(extras.reduceLeft(And), window)
          // Preserve the dimension join after the window. This retains duplicate dimension
          // matches without introducing any of those duplicates into the average.
          val joined = if (fact eq dimJoin.left) dimJoin.copy(left = rows) else dimJoin.copy(right = rows)
          val rebuilt = threshold.withNewChildren(Seq(threshold.child.transformDown {
            case a: AggregateExpression if a == avg => value.toAttribute
            case a: Attribute if attrs.contains(a) => attrs(a)
          })).asInstanceOf[NamedExpression]
          val key = Alias(rawKey, outputKey.name)(exprId = outputKey.exprId, qualifier = outputKey.qualifier,
            explicitMetadata = Some(outputKey.metadata))
          val projected = Project(outer.projectList ++ Seq(rebuilt, key), joined)
          Filter(And(IsNotNull(rebuilt.toAttribute), cond), projected)
        }
      }.find(p => p.resolved && p.output == j.output)
    case _ => None
  }

  def rewrite(plan: LogicalPlan): Option[LogicalPlan] = {
    val result = plan.transformUp { case j: Join => combine(j).getOrElse(j) }
    Option.unless(result fastEquals plan)(result)
  }
}
