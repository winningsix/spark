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
import org.apache.spark.sql.catalyst.expressions.aggregate.Max
import org.apache.spark.sql.types.{IntegerType, LongType}
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}

/** Restrict the second lookup of a shared dimension to join-key values admitted by the first. */
private[adaptive] object PruneRelatedLookup extends Rule[LogicalPlan] with PredicateHelper {
  private def relation(p: LogicalPlan): Option[LogicalRelation] = p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute]) => relation(c)
    case Filter(test,c) if test.deterministic && !SubqueryExpression.hasSubquery(test) => relation(c)
    case l: LogicalRelation if !l.isStreaming && l.relation.isInstanceOf[HadoopFsRelation] => Some(l)
    case _ => None
  }

  private def lookup(p: LogicalPlan, key: Attribute): Option[(LogicalPlan,LogicalRelation)] = {
    if (!p.outputSet.contains(key)) return None
    relation(p).map(p -> _).orElse(p match {
      case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute]) => lookup(c,key)
      case Join(l,r,Inner,_,JoinHint.NONE) => lookup(l,key).orElse(lookup(r,key))
      case _ => None
    })
  }

  private def selected(p: LogicalPlan): Boolean = p.exists {
    case f: Filter => splitConjunctivePredicates(f.condition).exists {
      case EqualTo(_:Attribute, l:Literal) => l.value != null
      case EqualTo(l:Literal, _:Attribute) => l.value != null
      case _ => false
    }
    case _ => false
  }

  // For a composite inner join with a strict upper bound, inventory rows at or
  // above the largest possible probe value can never match. Compute that bound
  // from a projection of the original relation so normal Spark snapshot and null
  // semantics also apply to the scalar subquery.
  private def filterRange(target: LogicalPlan, source: LogicalPlan, condition: Expression): LogicalPlan = {
    val candidates = splitConjunctivePredicates(condition).collect {
      case LessThan(lo: Attribute, hi: Attribute) => lo -> hi
      case GreaterThan(hi: Attribute, lo: Attribute) => lo -> hi
    }
    candidates.iterator.flatMap { case (lo, hi) =>
      for {
        (scan, _) <- lookup(target, lo)
        (_, base) <- lookup(source, hi)
        if hi.dataType == lo.dataType && (hi.dataType == IntegerType || hi.dataType == LongType)
        index = base.output.indexWhere(_.semanticEquals(hi)) if index >= 0
      } yield {
        val original = base.newInstance()
        val amount = original.output(index)
        val values = Project(Seq(amount), original)
        // Checking only the overflow lets the data source skip row groups whose
        // maximum is already below the cutoff. Any larger value raises the bound.
        val cutoff = conf.getConfString("spark.sql.optimizer.joinRangeCutoff","off").toLongOption
          .filter(x => amount.dataType==LongType || x==x.toInt.toLong)
          .map(x => if (amount.dataType==IntegerType) Literal(x.toInt) else Literal(x))
        val checked = cutoff.map(x => Filter(GreaterThan(amount,x),values)).getOrElse(values)
        val maximum = Max(amount).toAggregateExpression()
        val upper = cutoff.map(x => Coalesce(Seq(maximum,x))).getOrElse(maximum)
        val bound = Alias(upper,"join_range_max")()
        val limit = ScalarSubquery(Aggregate(Nil,Seq(bound),checked))
        target.transformUp { case n if n eq scan => Filter(LessThan(lo, limit), n) }
      }
    }.nextOption().getOrElse(target)
  }

  private def restrict(j: Join, leftKey: Attribute, rightKey: Attribute): Option[Join] = for {
    (l,ls) <- lookup(j.left,leftKey)
    (r,rs) <- lookup(j.right,rightKey)
    if selected(l) != selected(r) && ls.stats.sizeInBytes <= conf.autoBroadcastJoinThreshold
    if Project(Seq(leftKey),ls).sameResult(Project(Seq(rightKey),rs))
  } yield {
    val (source,key,target,other) = if (selected(l)) (l,leftKey,r,rightKey) else (r,rightKey,l,leftKey)
    val fresh = Alias(key,"eligible_lookup_key")()
    val values = Project(Seq(fresh),source)
    val eligible = Join(target,values,LeftSemi,Some(EqualTo(other,fresh.toAttribute)),JoinHint.NONE)
    def replace(p: LogicalPlan): LogicalPlan = p.transformUp { case n if n eq target => eligible }
    if (target eq r) j.copy(right=filterRange(replace(j.right), j.left, j.condition.get))
    else j.copy(left=filterRange(replace(j.left), j.right, j.condition.get))
  }

  private def rewrite(j: Join): Option[Join] = {
    val predicates = j.condition.toSeq.flatMap(splitConjunctivePredicates)
    val keys = predicates.collect { case EqualTo(a:Attribute,b:Attribute) =>
      if (j.left.outputSet.contains(a)) (a,b) else (b,a)
    }.filter { case (l,r) => j.left.outputSet.contains(l) && j.right.outputSet.contains(r) }
    if (keys.size < 2 || !predicates.exists {
        case LessThan(_:Attribute,_:Attribute) | GreaterThan(_:Attribute,_:Attribute) => true
        case _ => false
      }) None
    else keys.iterator.flatMap { case (l,r) => restrict(j,l,r) }.nextOption()
  }

  // Move a dimension description to the consumer of a chain of fact joins. Carry the
  // foreign key across those joins and perform the original lookup once at the end.
  private case class Delayed(rows: LogicalPlan, dim: LogicalPlan, factKey: Attribute,
      dimKey: Attribute)

  private def delay(p: LogicalPlan, label: Attribute, belowOuter: Boolean): Option[Delayed] = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) =>
      delay(child, label, belowOuter).map { d =>
        val retained = cols.filter(a => d.rows.outputSet.contains(a.toAttribute))
        val payload = if (retained.exists(_.toAttribute.semanticEquals(d.factKey))) retained
          else retained :+ d.factKey
        d.copy(rows = Project(payload, d.rows))
      }
    case j @ Join(l, r, typ, Some(cond), JoinHint.NONE) if typ == Inner || typ == LeftOuter =>
      def detach(fact: LogicalPlan, dim: LogicalPlan): Option[Delayed] = cond match {
        case EqualTo(a: Attribute, b: Attribute) if belowOuter && typ == Inner && dim.outputSet.contains(label) &&
            dim.output.size == 2 && relation(dim).isDefined &&
            dim.stats.sizeInBytes <= conf.autoBroadcastJoinThreshold =>
          val (fk, dk) = if (fact.outputSet.contains(a)) (a,b) else (b,a)
          Option.when(fact.outputSet.contains(fk) && dim.outputSet.contains(dk) &&
            !dk.semanticEquals(label))(Delayed(fact,dim,fk,dk))
        case _ => None
      }
      def below(child: LogicalPlan, left: Boolean): Option[Delayed] = {
        if (!child.outputSet.contains(label)) return None
        val compositeOuter = typ == LeftOuter && splitConjunctivePredicates(cond).count(_.isInstanceOf[EqualTo]) >= 2
        delay(child,label,belowOuter || compositeOuter).flatMap { d =>
          val moved = child.outputSet -- d.rows.outputSet
          Option.when(cond.references.intersect(moved).isEmpty)(
            d.copy(rows = if (left) j.copy(left = d.rows) else j.copy(right = d.rows)))
        }
      }
      detach(l,r).orElse(detach(r,l)).orElse(below(l,true))
        .orElse(if (typ == Inner) below(r,false) else None)
    case _ => None
  }

  private def lateLabels(a: Aggregate): Aggregate = {
    val child = a.child
    val hasCompositeOuter = child.exists {
      case Join(_, _, LeftOuter, Some(c), JoinHint.NONE) =>
        splitConjunctivePredicates(c).count(_.isInstanceOf[EqualTo]) >= 2
      case _ => false
    }
    if (!hasCompositeOuter || !child.deterministic) return a
    val labels = a.groupingExpressions.collect {
      case attr: Attribute if attr.dataType == org.apache.spark.sql.types.StringType => attr
    }
    val rows = labels.foldLeft(child) { (current,label) =>
      delay(current,label,false).filter { d =>
        // All original attributes still needed by this aggregate must be available.
        current.outputSet.subsetOf(d.rows.outputSet ++ d.dim.outputSet)
      }.map { d =>
        val joined = Join(d.rows,d.dim,Inner,Some(EqualTo(d.factKey,d.dimKey)),JoinHint.NONE)
        Project(current.output,joined)
      }.getOrElse(current)
    }
    a.copy(child=rows)
  }

  // When the nullable input contributes only multiplicity, encode two signed
  // Int keys bijectively in one Long. A null component yields a null join key.
  private def compactOuter(p: Project, j: Join): LogicalPlan = {
    if (!p.references.subsetOf(j.left.outputSet)) return p
    val tests = splitConjunctivePredicates(j.condition.get)
    val keys = tests.collect {
      case EqualTo(a: Attribute, b: Attribute) if a.dataType == IntegerType && b.dataType == IntegerType =>
        if (j.left.outputSet.contains(a)) (a,b) else (b,a)
    }
    if (tests.size != 2 || keys.size != 2 || !keys.forall { case (l,r) =>
        j.left.outputSet.contains(l) && j.right.outputSet.contains(r)
      }) return p
    def pack(hi: Attribute, lo: Attribute) =
      BitwiseOr(ShiftLeft(Cast(hi,LongType),Literal(32)),
        BitwiseAnd(Cast(lo,LongType),Literal(0xffffffffL)))
    val Seq((l1,r1),(l2,r2)) = keys
    val lk = Alias(pack(l1,l2),"packed_preserved_key")()
    val rk = Alias(pack(r1,r2),"packed_lookup_key")()
    val kept = j.left.output.filter(p.references.contains)
    val l = Project(kept :+ lk,j.left)
    val r = Project(Seq(rk),j.right)
    val lookup = conf.getConfString("spark.sql.optimizer.exactRepeatSummary","off") match {
      case "sealed" =>
        val partitions = conf.getConfString("spark.sql.shuffle.repeatedKeySummaryPartitions","32").toInt
        RepartitionByExpression(Nil,RepeatedLookupKeys(r),Some(partitions))
      case "direct" => RepeatedLookupKeys(r)
      case _ => r
    }
    p.copy(child = j.copy(left=l,right=lookup,condition=Some(EqualTo(lk.toAttribute,rk.toAttribute))))
  }

  override def apply(p: LogicalPlan): LogicalPlan = {
    if (p.isStreaming) return p
    val pruned = if (conf.getConfString("spark.sql.optimizer.pruneRelatedLookup","true").toBoolean)
      p.transformUp { case j @ Join(_,_,Inner,_,JoinHint.NONE) => rewrite(j).getOrElse(j) }
    else p
    val labeled = if (conf.getConfString("spark.sql.optimizer.delayGroupingLabels","true").toBoolean)
      pruned.transformUp { case a: Aggregate => lateLabels(a) }
    else pruned
    if (conf.getConfString("spark.sql.optimizer.packUnusedOuterKeys","true").toBoolean)
      labeled.transformUp {
        case project @ Project(_, join @ Join(_,_,LeftOuter,Some(_),JoinHint.NONE)) =>
          compactOuter(project,join)
      }
    else labeled
  }
}
