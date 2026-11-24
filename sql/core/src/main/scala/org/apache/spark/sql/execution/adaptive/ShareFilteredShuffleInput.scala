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
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.catalyst.plans.logical.{Filter, LogicalPlan, Project, RepartitionByExpression}
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.execution.{FileSourceScanExec, FilterExec, ProjectExec, SparkPlan}
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.execution.exchange.{ENSURE_REQUIREMENTS, ShuffleExchangeExec}

/** Read the same durable shuffle twice when a selective scan only adds a key membership test. */
private[adaptive] object ShareFilteredShuffleInput extends PredicateHelper {
  private case class Site(project: Project, predicate: Filter, source: LogicalRelation,
      keys: Seq[Attribute]) {
    val terms: Seq[Expression] = splitConjunctivePredicates(predicate.condition)
    def bound(e: Expression): Expression =
      BindReferences.bindReference(e, source.output).canonicalized
    lazy val normalized: Set[Expression] = terms.map(bound).toSet
    val keyOrdinals: Seq[Int] = keys.map(k => project.output.indexWhere(_.semanticEquals(k)))
  }

  private def member(e: Expression): Boolean = e match {
    case BloomFilterMightContain(s: ScalarSubquery, XxHash64(Seq(_: Attribute), _)) =>
      !s.isCorrelated && s.plan.deterministic
    case _ => false
  }

  private def simpleCommon(e: Expression): Boolean = e match {
    case IsNotNull(_: Attribute) => true
    case cmp: BinaryComparison => cmp.children.forall {
      case _: Attribute | _: Literal => true
      case _ => false
    }
    case _ => false
  }

  private def movable(e: Expression): Boolean = e match {
    case IsNotNull(_: Attribute) => true
    case other => member(other)
  }

  def rewrite(plan: LogicalPlan, physical: SparkPlan, width: Int): Option[LogicalPlan] = {
    val owners = physical.collect {
      case e @ ShuffleExchangeExec(h: HashPartitioning,
          ProjectExec(_, FilterExec(_, _: FileSourceScanExec)), ENSURE_REQUIREMENTS, _, false)
          if h.numPartitions == width && h.expressions.forall(_.isInstanceOf[Attribute]) =>
        e.output.map(_.exprId) -> h.expressions.map(_.asInstanceOf[Attribute])
    }.groupBy(_._1)
    if (owners.size < 2) {
      return None
    }
    val sites = plan.collect {
      case p @ Project(cols, f @ Filter(pred, r: LogicalRelation))
          if cols.forall(_.isInstanceOf[Attribute]) && cols.nonEmpty && pred.deterministic &&
            !p.isStreaming =>
        owners.get(p.output.map(_.exprId)).filter(_.size == 1).map { matches =>
          Site(p, f, r, matches.head._2)
        }.filter(_.keyOrdinals.forall(_ >= 0))
    }.flatten
    val replacements = scala.collection.mutable.HashMap.empty[Project, LogicalPlan]
    val filtered = sites.filter(s => s.terms.exists(member) &&
      s.terms.forall(e => simpleCommon(e) || member(e)))
    for (narrow <- filtered if !replacements.contains(narrow.project)) {
      sites.find { wide =>
        wide.keyOrdinals == narrow.keyOrdinals && wide.terms.forall(simpleCommon) &&
          wide.normalized.subsetOf(narrow.normalized) && wide.normalized != narrow.normalized && {
            val (common, extra) = narrow.terms.partition(e => wide.normalized(narrow.bound(e)))
            common.nonEmpty && extra.exists(member) && extra.forall { e =>
              movable(e) && e.references.subsetOf(narrow.project.outputSet)
            } && narrow.project.copy(child = narrow.predicate.copy(condition = common.reduceLeft(And)))
              .sameResult(wide.project)
          }
      }.foreach { wide =>
        val (common, extra) = narrow.terms.partition(e => wide.normalized(narrow.bound(e)))
        val broadRead = narrow.project.copy(child = narrow.predicate.copy(condition = common.reduceLeft(And)))
        val conf = SQLConf.get
        val target = if (conf.getConfString("spark.sql.adaptive.sizeSharedFilterShuffle.enabled",
            "false").toBoolean) {
          val bytes = wide.project.stats.sizeInBytes
          val advisory = conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)
          val sc = physical.session.sparkContext
          val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
          val n = ((bytes + advisory - 1) / advisory).min(BigInt(slots)).toInt
          Option.when(bytes < conf.defaultSizeInBytes && n > width)(n)
        } else None
        replacements(wide.project) = RepartitionByExpression(wide.keys, wide.project, target)
        replacements(narrow.project) = Filter(extra.reduceLeft(And),
          RepartitionByExpression(narrow.keys, broadRead, target))
      }
    }
    Option.when(replacements.nonEmpty)(plan.transformUp {
      case p: Project if replacements.contains(p) => replacements(p)
    })
  }
}
