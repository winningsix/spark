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

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, BloomFilterAggregate, Max, Min}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.IntegralType

class SelfWitnessDomainExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectPreCBORule(_ => SelfWitnessDomain)
}

private[adaptive] object SelfWitnessDomain extends Rule[LogicalPlan] with PredicateHelper {
  private case class Columns(key: Attribute, value: Attribute) {
    val attributes: AttributeSet = AttributeSet(Seq(key, value))
  }

  private def base(plan: LogicalPlan, cols: Columns, witness: Boolean): Option[LogicalPlan] = {
    if (!cols.attributes.subsetOf(plan.outputSet)) return None
    plan match {
      case rel: LogicalRelation if !rel.isStreaming && rel.relation.isInstanceOf[HadoopFsRelation] =>
        Some(Project(Seq(cols.key, cols.value), rel))
      case Project(expressions, child) if cols.attributes.forall(a => expressions.exists {
          case ref: Attribute => ref.semanticEquals(a)
          case _ => false
        }) => base(child, cols, witness)
      case Filter(condition, child) if !witness || splitConjunctivePredicates(condition).forall {
          case IsNotNull(a: Attribute) => cols.attributes.contains(a)
          case _ => false
        } => base(child, cols, witness)
      case Join(left, right, Inner, _, _) if !witness =>
        base(left, cols, witness).orElse(base(right, cols, witness))
      case _ => None
    }
  }

  private def ordered(l: Expression, r: Expression, left: LogicalPlan, right: LogicalPlan)
      : Option[(Attribute, Attribute)] = Seq((l,r),(r,l)).collectFirst {
    case (x: Attribute, y: Attribute) if left.outputSet.contains(x) && right.outputSet.contains(y) &&
        x.dataType == y.dataType && x.dataType.isInstanceOf[IntegralType] => (x,y)
  }

  private case class Witness(leftKey: Attribute, leftValue: Attribute, key: Attribute, value: Attribute)

  private def witness(left: LogicalPlan, right: LogicalPlan, terms: Seq[Expression])
      : Option[Witness] = for {
    eq <- terms.collectFirst { case EqualTo(a,b) => (a,b) } if terms.size == 2
    ne <- terms.collectFirst { case Not(EqualTo(a,b)) => (a,b) }
    (lk,rk) <- ordered(eq._1, eq._2, left, right)
    (lv,rv) <- ordered(ne._1, ne._2, left, right) if !lk.semanticEquals(lv)
    probe <- base(left, Columns(lk,lv), witness=false)
    universe <- base(right, Columns(rk,rv), witness=true) if probe.sameResult(universe)
  } yield Witness(lk,lv,rk,rv)

  private def domain(left: LogicalPlan, right: LogicalPlan, terms: Seq[Expression])
      : Option[(LogicalPlan, Seq[Expression])] = witness(left,right,terms).map {
    case Witness(lk,lv,rk,rv) =>
    // Every non-null probe value is itself in this key's witness group. Another
    // value exists exactly when the group contains two distinct non-null values.
    val lo = Alias(Min(rv).toAggregateExpression(), "witness_min")()
    val hi = Alias(Max(rv).toAggregateExpression(), "witness_max")()
    val groups = Aggregate(Seq(rk), Seq(rk, lo, hi), right)
    val keys = Project(Seq(rk), Filter(LessThan(lo.toAttribute, hi.toAttribute), groups))
    (keys, Seq(EqualTo(lk,rk), IsNotNull(lv)))
  }

  // The scalar must contain every key that can survive the enclosing inner joins.
  // Only use deterministic projections and inner joins on the path to the target.
  private def candidateParent(root: LogicalPlan, target: Filter, key: Attribute): Option[LogicalPlan] = {
    def onPath(p: LogicalPlan): Boolean = p match {
      case node if node eq target => true
      case Project(_,child) => onPath(child)
      case Filter(cond,child) if !SubqueryExpression.hasSubquery(cond) => onPath(child)
      case Join(left,right,Inner,Some(condition),_) if condition.deterministic =>
        onPath(left) || onPath(right)
      case _ => false
    }
    val parent = root.collectFirst {
      case join @ Join(_,_,Inner,Some(_),_) if join.outputSet.contains(key) && onPath(join) => join
    }
    if (parent.isEmpty || !parent.get.deterministic) return None
    parent
  }

  private def candidateInput(root: LogicalPlan, target: Filter, key: Attribute): Option[LogicalPlan] = {
    val parent = candidateParent(root,target,key)
    if (parent.isEmpty) return None
    val input = parent.get
    val ordinary = splitConjunctivePredicates(target.condition).filterNot(SubqueryExpression.hasSubquery)
    val stripped = input.transformDown {
      case n if n eq target => ordinary.reduceLeftOption(And).map(Filter(_,target.child)).getOrElse(target.child)
    }
    if (!stripped.exists(_.isInstanceOf[Join]) || stripped.exists(_.expressions.exists(SubqueryExpression.hasSubquery))) None
    else Some(stripped)
  }

  private def orderFilter(rows: LogicalPlan, key: Attribute): ScalarSubquery = {
        val hash = new XxHash64(Seq(key))
        val expected = conf.getConfString("spark.sql.optimizer.selfWitnessDomain.expectedNumItems","0").toLong
        val bloom = if (expected > 0 && expected <= Int.MaxValue)
          new BloomFilterAggregate(hash,Literal(expected))
        else new BloomFilterAggregate(hash)
        val collected = Alias(bloom.toAggregateExpression(), "candidate_order_filter")()
        ScalarSubquery(Aggregate(Nil,Seq(collected),rows), Nil)
  }

  private def witnessInput(member: InSubquery): Option[(LogicalPlan,Attribute,Attribute)] =
    member.query.plan match {
      case Project(Seq(key: Attribute),Filter(condition,agg: Aggregate))
          if agg.groupingExpressions.size == 1 && agg.groupingExpressions.head.semanticEquals(key) =>
        val aliases = agg.aggregateExpressions.collect {
          case a @ Alias(e: AggregateExpression,_) if e.filter.isEmpty && !e.isDistinct =>
            a.toAttribute -> e.aggregateFunction
        }
        val terms = splitConjunctivePredicates(condition)
        for {
          (lo,Min(v: Attribute)) <- aliases.iterator.toSeq.collectFirst {
            case (a,fn: Min) => (a,fn)
          }
          (hi,Max(other: Attribute)) <- aliases.iterator.toSeq.collectFirst {
            case (a,fn: Max) => (a,fn)
          } if v.semanticEquals(other) && v.dataType.isInstanceOf[IntegralType]
          test=LessThan(lo,hi) if terms.exists(_.semanticEquals(test))
          if terms.forall {
            case IsNotNull(ref: Attribute) => Seq(key,lo,hi).exists(_.semanticEquals(ref))
            case expr => expr.semanticEquals(test)
          }
        } yield (agg.child,key,v)
      case _ => None
    }

  private def mergedMembers(inputs: Seq[InSubquery], scalar: ScalarSubquery): Option[InSubquery] = {
    if (!conf.getConfString("spark.sql.optimizer.mergePositiveOrderDomains.enabled","false").toBoolean) return None
    val classified = inputs.map(m => m -> witnessInput(m))
    for {
      (member,Some((child,key,v))) <- classified.find(_._2.isDefined)
      (other,None) <- classified.find(_._2.isEmpty)
    } yield {
      val flag = Alias(Literal(0),"has_match")()
      val bounds = Project(Seq(key,v,flag),child)
      val matches = Project(Seq(other.query.plan.output.head,
        Alias(Literal.create(null,v.dataType),"measure")(),Alias(Literal(1),"has_match")()),other.query.plan)
      val updates = Union(Seq(bounds,matches))
      val Seq(k,value,marker) = updates.output
      val narrowed = Filter(BloomFilterMightContain(scalar,new XxHash64(Seq(k))),updates)
      val lo = Alias(Min(value).toAggregateExpression(),"witness_min")()
      val hi = Alias(Max(value).toAggregateExpression(),"witness_max")()
      val present = Alias(Max(marker).toAggregateExpression(),"has_returned_order")()
      val grouped = Aggregate(Seq(k),Seq(k,lo,hi,present),narrowed)
      val keep = And(LessThan(lo.toAttribute,hi.toAttribute),EqualTo(present.toAttribute,Literal(1)))
      member.copy(query=member.query.withNewPlan(Project(Seq(k),Filter(keep,grouped))))
    }
  }

  def filterMembershipInputs(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || !conf.getConfString("spark.sql.optimizer.filterMembershipInputs.enabled","false").toBoolean) return plan
    plan.transformUp { case f: Filter =>
      val terms = splitConjunctivePredicates(f.condition)
      val members = terms.collect {
        case in @ InSubquery(Seq(key: Attribute), list) if key.dataType.isInstanceOf[IntegralType] &&
            list.outerAttrs.isEmpty && list.joinCond.isEmpty && list.hint.isEmpty &&
            list.plan.output.size == 1 && list.plan.output.head.dataType == key.dataType => (key,in)
      }
      val alreadyFiltered = members.exists { case (_,in) => in.query.plan.exists {
        case Filter(condition,_) => condition.exists {
          case BloomFilterMightContain(s: ScalarSubquery, _) => s.plan.output.exists(_.name=="candidate_order_filter")
          case _ => false
        }
        case _ => false
      }}
      val selected = if (!alreadyFiltered && members.size == 2 && members.head._1.semanticEquals(members.last._1) &&
          members.exists(_._2.query.plan.exists(_.isInstanceOf[Aggregate]))) {
        candidateInput(plan,f,members.head._1)
      } else None
      selected.map { rows =>
        val scalar = orderFilter(rows,members.head._1)
        val inputs = members.map(_._2)
        val combined = mergedMembers(inputs, scalar)
        val rewritten = combined.map { domain =>
          terms.collect {
            case t if t == inputs.head => domain
            case t if t != inputs.last => t
          }
        }.getOrElse(terms.map {
          case in: InSubquery if inputs.contains(in) =>
            val source = in.query.plan
            val keep = BloomFilterMightContain(scalar,new XxHash64(Seq(source.output.head)))
            in.copy(query=in.query.withNewPlan(Filter(keep,source)))
          case other => other
        })
        f.copy(condition=rewritten.reduceLeft(And))
      }.getOrElse(f)
    }
  }

  private def mergeExclusion(f: Filter, root: LogicalPlan): Filter = {
    if (!conf.getConfString("spark.sql.optimizer.mergeWitnessExclusion.enabled","false").toBoolean) return f
    val terms = splitConjunctivePredicates(f.condition)
    val probes = terms.collect { case e: Exists if e.hint.isEmpty => e }
    val exclusions = terms.collect { case Not(e: Exists) if e.hint.isEmpty => e }
    if (probes.size != 1 || exclusions.size != 1 || !terms.forall(_.deterministic)) return f
    val probe = probes.head
    val exclusion = exclusions.head
    val replacement = for {
      keys <- witness(f.child, probe.plan, probe.joinCond)
      if exclusion.joinCond.size == 1
      (a,b) <- exclusion.joinCond.collectFirst { case EqualTo(x,y) => (x,y) }
      (outer, excluded) <- ordered(a,b,f.child,exclusion.plan) if outer.semanticEquals(keys.leftKey)
    } yield {
      // Group both inputs on the order key. A return contributes only its
      // exclusion flag, regardless of the number of matching returns.
      val flag = Alias(Literal(0), "is_excluded")()
      val witnesses = Project(Seq(keys.key, keys.value, flag), probe.plan)
      val returned = Project(Seq(excluded, Alias(Literal.create(null,keys.value.dataType),"value")(),
        Alias(Literal(1), "is_excluded")()), exclusion.plan)
      val updates = Union(Seq(witnesses,returned))
      val Seq(key, v, excludedFlag) = updates.output
      val lo = Alias(Min(v).toAggregateExpression(), "witness_min")()
      val hi = Alias(Max(v).toAggregateExpression(), "witness_max")()
      val anyExcluded = Alias(Max(excludedFlag).toAggregateExpression(), "has_exclusion")()
      val candidate = if (conf.getConfString("spark.sql.optimizer.filterOrderUpdates.enabled","false").toBoolean)
        candidateInput(root, f, keys.leftKey) else None
      val filtered = candidate.map { rows =>
        val subquery = orderFilter(rows,keys.leftKey)
        Filter(BloomFilterMightContain(subquery,new XxHash64(Seq(key))),updates)
      }.getOrElse(updates)
      val grouped = Aggregate(Seq(key),Seq(key,lo,hi,anyExcluded),filtered)
      val keep = And(LessThan(lo.toAttribute,hi.toAttribute), EqualTo(anyExcluded.toAttribute,Literal(0)))
      val selected = Project(Seq(key), Filter(keep, grouped))
      probe.copy(plan=selected,joinCond=Seq(EqualTo(keys.leftKey,key),IsNotNull(keys.leftValue)))
    }
    replacement.map { e =>
      val revised = terms.collect {
        case t if t == probe => e
        case t if t != Not(exclusion) => t
      }
      f.copy(condition=revised.reduceLeft(And))
    }.getOrElse(f)
  }

  private def shareCandidate(root: LogicalPlan, f: Filter): Option[LogicalPlan] = {
    val terms = splitConjunctivePredicates(f.condition)
    val subqueries = terms.filter(SubqueryExpression.hasSubquery)
    // Hoist only these two positive WHERE conjuncts. Other subqueries must retain
    // their own evaluation and three-valued semantics.
    if (subqueries.size != 2) return None
    val merged = mergeExclusion(f,root)
    if (merged eq f) return None
    for {
      e <- splitConjunctivePredicates(merged.condition).collectFirst { case x: Exists => x }
      (lk,rk,lv) <- e.joinCond match {
        case Seq(EqualTo(l: Attribute,r: Attribute),IsNotNull(v: Attribute)) => Some((l,r,v))
        case _ => None
      }
      parent <- candidateParent(root,f,lk)
      scalar <- e.plan.collectFirst { case Filter(BloomFilterMightContain(s: ScalarSubquery,_),_) => s }
      agg <- scalar.plan match { case a: Aggregate => Some(a); case _ => None }
    } yield {
      val ordinary = terms.filterNot(SubqueryExpression.hasSubquery)
      val filtered = Filter((ordinary :+ IsNotNull(lv)).reduceLeft(And), f.child)
      // The parent projection may already discard the dimension keys. Put that
      // projection below the shared exchange when it still exposes the order key.
      val sharedRoot = root.collectFirst {
        case p @ Project(cols,child) if (child eq parent) && cols.forall(_.isInstanceOf[Attribute]) &&
            p.outputSet.contains(lk) => p
      }.getOrElse(parent)
      val rows = sharedRoot.transformDown { case node if node eq f => filtered }
      val width = conf.getConfString("spark.sql.optimizer.sharedCandidateOrders.partitions","54").toInt
      val partitioned = RepartitionByExpression(Seq.empty,rows,Some(width))
      val definition = CTERelationDef(partitioned,underSubquery=true,materialized=Some(true))
      def ref = CTERelationRef(definition.id,true,rows.output,false)
      val restricted = e.plan.transformAllExpressions {
        case s: ScalarSubquery if s.exprId == scalar.exprId => s.withNewPlan(agg.copy(child=ref))
      }
      val result = Join(ref,restricted,LeftSemi,Some(EqualTo(lk,rk)),JoinHint.NONE)
      WithCTE(root.transformDown { case node if node eq sharedRoot => result },Seq(definition))
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || !conf.getConfString("spark.sql.optimizer.selfWitnessDomain.enabled","false").toBoolean) return plan
    if (conf.getConfString("spark.sql.optimizer.sharedCandidateOrders.enabled","false").toBoolean &&
        conf.exchangeReuseEnabled && !plan.exists(_.isInstanceOf[WithCTE])) {
      val shared = plan.collect { case f: Filter => f }.iterator.flatMap(shareCandidate(plan,_)).nextOption()
      if (shared.isDefined) return shared.get
    }
    plan.transformUp {
      case f: Filter => mergeExclusion(f,plan).transformExpressionsUp {
        case e: Exists if e.hint.isEmpty =>
          domain(f.child, e.plan, e.joinCond).map { case (keys, conditions) =>
            e.copy(plan=keys, joinCond=conditions)
          }.getOrElse(e)
      }
      case j @ Join(left,right,LeftSemi,Some(condition),JoinHint.NONE) =>
        domain(left, right, splitConjunctivePredicates(condition)).map { case (keys,conditions) =>
          j.copy(right=keys, condition=Some(conditions.reduceLeft(And)))
        }.getOrElse(j)
    }
  }
}

class SelfWitnessDomainAfterExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectPreCBORule(_ =>
    new Rule[LogicalPlan] {
      override def apply(plan: LogicalPlan): LogicalPlan = SelfWitnessDomain.filterMembershipInputs(plan)
    })
}
