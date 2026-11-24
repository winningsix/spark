package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.BitOrAgg
import org.apache.spark.sql.catalyst.plans.FullOuter
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{IntegerType, LongType}

class DistinctOuterKeysExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectOptimizerRule(_ => DistinctOuterKeys)
}

/** Join two sets of distinct integer tuples by collecting the sides containing each tuple. */
private[adaptive] object DistinctOuterKeys extends Rule[LogicalPlan] with PredicateHelper {
  case class Arm(keys: Seq[Attribute], child: LogicalPlan)

  def distinctArm(plan: LogicalPlan, on: Seq[Attribute]): Option[Arm] = plan match {
    case a: Aggregate if a.output.size == on.size && a.groupingExpressions.size == on.size &&
        a.outputSet == AttributeSet(on) =>
      val mapping = a.aggregateExpressions.collect {
        case al @ Alias(attr: Attribute, _) => al.exprId -> attr
        case attr: Attribute => attr.exprId -> attr
      }.toMap
      val keys = on.flatMap(k => mapping.get(k.exprId))
      Option.when(keys.size == on.size && keys.forall(_.dataType == IntegerType) &&
        AttributeSet(keys) == AttributeSet(a.groupingExpressions) &&
        a.groupingExpressions.forall(_.isInstanceOf[Attribute]))(Arm(keys, a.child))
    case _ => None
  }

  private def attempt(join: Join, mode: String): Option[LogicalPlan] = {
    val predicates = splitConjunctivePredicates(join.condition.get)
    val pairs = predicates.collect { case EqualTo(a: Attribute, b: Attribute) => (a,b) }.collect {
      case (a,b) if join.left.outputSet.contains(a) && join.right.outputSet.contains(b) => (a,b)
      case (a,b) if join.left.outputSet.contains(b) && join.right.outputSet.contains(a) => (b,a)
    }
    if (pairs.size != 2 || predicates.size != pairs.size) return None
    val (left,right) = pairs.unzip
    if (left.distinct.size != 2 || right.distinct.size != 2) return None
    for (l <- distinctArm(join.left,left); r <- distinctArm(join.right,right)) yield {
      if (mode == "hash") {
        val small = if (join.left.stats.sizeInBytes < join.right.stats.sizeInBytes) 0 else 1
        val hint = Some(HintInfo(Some(SHUFFLE_HASH)))
        join.copy(hint = if (small == 0) JoinHint(hint,None) else JoinHint(None,hint))
      } else {
        def branch(arm: Arm, side: Int): LogicalPlan = {
          val a = arm.keys.head; val b = arm.keys.last
          val tag = if (mode == "packed") {
            val nulls = Add(If(IsNull(a),Literal(4),Literal(0)),If(IsNull(b),Literal(8),Literal(0)))
            If(EqualTo(nulls,Literal(0)),Literal(0),Add(nulls,Literal(side)))
          } else If(Or(IsNull(a),IsNull(b)),Literal(side),Literal(0))
          val cols = if (mode == "packed") {
            val high = ShiftLeft(Cast(Coalesce(Seq(a,Literal(0))),LongType),Literal(32))
            val low = BitwiseAnd(Cast(Coalesce(Seq(b,Literal(0))),LongType),Literal(0xffffffffL))
            Seq(Alias(BitwiseOr(high,low),"outer_packed_key")())
          } else arm.keys
          Project(cols ++ Seq(Alias(tag,"outer_null_group")(),Alias(Literal(side),"outer_source")()),arm.child)
        }
        val union = Union(Seq(branch(l,1),branch(r,2)))
        val groupKeys = union.output.dropRight(1)
        val results = groupKeys.zipWithIndex.map { case (key,i) => Alias(key,s"outer_group_$i")() }
        val groups = results.map(_.toAttribute)
        val sides = Alias(BitOrAgg(union.output.last).toAggregateExpression(),"outer_sources")()
        val grouped = Aggregate(groupKeys,results :+ sides,union)
        def unpack(i: Int): Expression = if (mode != "packed") groups(i) else {
          val key = groups.head
          // Sign-extend each half before narrowing, including under ANSI casts.
          val signed = if (i==0) ShiftRight(key,Literal(32))
            else ShiftRight(ShiftLeft(key,Literal(32)),Literal(32))
          If(EqualTo(BitwiseAnd(groups.last,Literal(4 << i)),Literal(0)),Cast(signed,IntegerType),
            Literal.create(null,IntegerType))
        }
        val mappings = Seq((left,1),(right,2)).flatMap { case (keys,side) =>
          val present = EqualTo(BitwiseAnd(sides.toAttribute,Literal(side)),Literal(side))
          keys.zipWithIndex.map { case (a,i) => a.exprId -> If(present,unpack(i),Literal.create(null,IntegerType)) }
        }.toMap
        Project(join.output.map { a =>
          Alias(mappings(a.exprId),a.name)(exprId=a.exprId,qualifier=a.qualifier,explicitMetadata=Some(a.metadata))
        },grouped)
      }
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val mode = conf.getConfString("spark.sql.optimizer.distinctOuterKeys","off")
    if (plan.isStreaming || !Set("hash","group","packed").contains(mode)) return plan
    plan.transformUp {
      case j @ Join(_,_,FullOuter,Some(_),JoinHint.NONE) => attempt(j,mode).getOrElse(j)
    }
  }
}
