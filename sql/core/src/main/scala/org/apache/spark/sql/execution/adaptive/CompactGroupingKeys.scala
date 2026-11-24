package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.AggregateExpression
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{IntegerType, LongType}

/** Pack nullable 32-bit grouping IDs into UnsafeRow's 64-bit slots before the shuffle. */
private[adaptive] object CompactGroupingKeys extends Rule[LogicalPlan] {
  private def compact(a: Aggregate, expand: Expand): LogicalPlan = {
    if (!a.groupingExpressions.forall(_.isInstanceOf[Attribute])) return a
    val keys = a.groupingExpressions.collect {
      case k: Attribute if k.dataType == IntegerType && k.nullable => k
    }.distinct
    if (keys.size < 3) return a
    val used = keys.take(math.min(31, if (keys.size % 2 == 0) keys.size - 1 else keys.size))
    val removed = AttributeSet(used)
    def isKey(e: Expression): Boolean = e match {
      case k: Attribute => removed.contains(k)
      case _ => false
    }
    def recoverable(n: NamedExpression): Boolean = n match {
      case k: Attribute => true
      case Alias(k: Attribute, _) => true
      case Alias(_: AggregateExpression, _) => true
      case x => x.references.intersect(removed).isEmpty
    }
    if (!a.aggregateExpressions.forall(recoverable)) return a

    val bits = Literal(32)
    def unsigned(k: Attribute): Expression =
      BitwiseAnd(Cast(Coalesce(Seq(k,Literal(0))),LongType), Literal(0xffffffffL))
    val pairs = used.dropRight(1).grouped(2).map { pair =>
      Alias(BitwiseOr(ShiftLeft(unsigned(pair.head),bits),unsigned(pair.last)),"packed_group_ids")()
    }.toVector
    val flags = used.zipWithIndex.map { case (k,i) =>
      If(IsNull(k), Literal(1L << (32+i)), Literal(0L))
    }
    val tag = Alias(flags.foldLeft(unsigned(used.last)) { (v,f) => BitwiseOr(v,f) },"packed_group_mask")()
    val encoded = pairs :+ tag
    val grouped = a.groupingExpressions.filterNot(isKey) ++ encoded.map(_.toAttribute)
    val projected = Project(expand.output ++ encoded,expand)
    def decode(k: Attribute): Expression = {
      val i = used.indexWhere(_.semanticEquals(k))
      val word = if (i==used.size-1) tag.toAttribute else pairs(i/2).toAttribute
      // Sign-extend the low half before casting so ANSI narrowing always succeeds.
      val signed = if (i < used.size-1 && i%2==0) ShiftRight(word,bits)
        else ShiftRight(ShiftLeft(word,bits),bits)
      val missing = Not(EqualTo(BitwiseAnd(tag.toAttribute,Literal(1L << (32+i))),Literal(0L)))
      If(missing,Literal.create(null,IntegerType),Cast(signed,IntegerType))
    }
    val values = a.aggregateExpressions.filterNot {
      case k: Attribute => removed.contains(k)
      case Alias(k: Attribute,_) => removed.contains(k)
      case _ => false
    }
    val agg = a.copy(groupingExpressions=grouped,
      aggregateExpressions=values ++ encoded.map(_.toAttribute),child=projected)
    val output = a.aggregateExpressions.map { n =>
      val key = n match {
        case k: Attribute if removed.contains(k) => Some(k)
        case Alias(k: Attribute,_) if removed.contains(k) => Some(k)
        case _ => None
      }
      key.map(k => Alias(decode(k),n.name)(exprId=n.exprId,qualifier=n.qualifier,
        explicitMetadata=Some(n.metadata))).getOrElse(n.toAttribute)
    }
    Project(output,agg)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan.transformUp {
    case a @ Aggregate(_,_,e: Expand,_) if !a.isStreaming && e.projections.size > 1 => compact(a,e)
  }
}
