package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter}
import org.apache.spark.sql.catalyst.plans.QueryPlan
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.DecimalType

/** Compute full and restricted sums together when their inputs differ by one dimension lookup. */
private[adaptive] object ShareRestrictedGroupSum extends Rule[LogicalPlan] with PredicateHelper {
  private case class Group(a: Aggregate, key: Attribute, name: Alias,
      expression: AggregateExpression, sum: Sum)
  private case class FileInput(relation: LogicalRelation, columns: Seq[Attribute], tests: Seq[Expression]) {
    def withColumn(extra: Attribute): LogicalPlan = {
      val filtered = tests.reduceOption(And).map(Filter(_, relation)).getOrElse(relation)
      Project((columns :+ extra).distinct, filtered)
    }
  }

  private def group(p: LogicalPlan): Option[Group] = p match {
    case a: Aggregate if a.groupingExpressions.size == 1 && a.groupingExpressions.head.isInstanceOf[Attribute] =>
      val key = a.groupingExpressions.head.asInstanceOf[Attribute]
      a.aggregateExpressions.collectFirst {
        case n @ Alias(e @ AggregateExpression(s: Sum, Complete, false, None, _), _)
            if s.child.deterministic && s.dataType.isInstanceOf[DecimalType] &&
              a.aggregateExpressions.forall(o => o.eq(n) || o.semanticEquals(key)) =>
          Group(a,key,n,e,s)
      }
    case _ => None
  }

  private def file(p: LogicalPlan): Option[FileInput] = {
    def input(n: LogicalPlan, cols: Seq[Attribute], tests: Seq[Expression]): Option[FileInput] = n match {
      case Project(list, child) if list.forall(_.isInstanceOf[Attribute]) => input(child,cols,tests)
      case Filter(c, child) => input(child,cols,tests ++ splitConjunctivePredicates(c))
      case r: LogicalRelation if !r.isStreaming && r.relation.isInstanceOf[HadoopFsRelation] &&
          cols.forall(r.outputSet.contains) => Some(FileInput(r,cols,tests))
      case _ => None
    }
    input(p,p.output,Nil)
  }

  private def join(p: LogicalPlan): Option[Join] = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => join(child)
    case j @ Join(_,_,Inner,Some(EqualTo(_: Attribute, _: Attribute)),hint) if hint==JoinHint.NONE => Some(j)
    case _ => None
  }

  private def split(j: Join, side: LogicalPlan): Option[(Attribute, Attribute)] =
    j.condition.collect {case EqualTo(a:Attribute,b:Attribute) =>
      if (side.outputSet.contains(a) && !side.outputSet.contains(b)) Some((a,b))
      else if (side.outputSet.contains(b) && !side.outputSet.contains(a)) Some((b,a))
      else None
    }.flatten

  private def conditionallyGroup(f: Group, p: Group): Option[(LogicalPlan, Attribute)] = {
    for {
      full <- join(f.a.child); extra <- join(p.a.child)
      common <- Seq(extra.left,extra.right).flatMap(join).find(_.outputSet.contains(p.key))
      commonSide = if (join(extra.left).contains(common)) extra.left else extra.right
      lookup = if (commonSide.eq(extra.left)) extra.right else extra.left
      if lookup.deterministic
      (peerDate,lookupKey) <- split(extra,commonSide)
      fullDim = if (full.left.outputSet.contains(f.key)) full.left else full.right
      peerDim = if (common.left.outputSet.contains(p.key)) common.left else common.right
      if fullDim.deterministic && peerDim.deterministic && fullDim.output.size==peerDim.output.size && fullDim.sameResult(peerDim)
      fullFact = if (full.left.eq(fullDim)) full.right else full.left
      peerFact = if (common.left.eq(peerDim)) common.right else common.left
      raw <- file(fullFact); restricted <- file(peerFact)
      if raw.relation.relation==restricted.relation.relation &&
        raw.relation.output.map(_.dataType)==restricted.relation.output.map(_.dataType) &&
        raw.tests.forall(_.deterministic)
      dateIndex = restricted.relation.output.indexWhere(_.semanticEquals(peerDate)) if dateIndex>=0
      fullDate = raw.relation.output(dateIndex)
      attrs = AttributeMap(restricted.relation.output.zip(raw.relation.output) ++ peerDim.output.zip(fullDim.output))
      if attrs.get(p.key).exists(_.semanticEquals(f.key))
      mapExpr = (e: Expression) => e.transform {case a: Attribute if attrs.contains(a) => attrs(a)}
      if mapExpr(p.sum).semanticEquals(f.sum) &&
        mapExpr(common.condition.get).semanticEquals(full.condition.get)
      tests = restricted.tests.filterNot {
        case IsNotNull(a) => a.semanticEquals(peerDate)
        case d: DynamicPruningSubquery => d.pruningKey.semanticEquals(peerDate) &&
          d.buildQuery.sameResult(lookup) && d.buildKeys.size==1 &&
          d.buildKeys.head.semanticEquals(lookupKey)
        case _ => false
      }
      if tests.map(t => mapExpr(t).canonicalized).toSet==raw.tests.map(_.canonicalized).toSet
    } yield {
      val expanded = if (full.left.eq(fullFact)) full.copy(left=raw.withColumn(fullDate))
        else full.copy(right=raw.withColumn(fullDate))
      // A duplicate lookup key contributes every match to the restricted sum, and only
      // one copy to the full sum. The key alone is read from the lookup relation.
      val order = Seq(SortOrder(lookupKey,Ascending))
      val spec = WindowSpecDefinition(Seq(lookupKey),order,
        SpecifiedWindowFrame(RowFrame,UnboundedPreceding,CurrentRow))
      val marker = Alias(WindowExpression(Count(Literal(1)).toAggregateExpression(),spec),"lookup_ordinal")()
      val marked = Window(Seq(marker),Seq(lookupKey),order,lookup)
      val rows = Join(expanded,marked,LeftOuter,Some(EqualTo(fullDate,lookupKey)),JoinHint.NONE)
      val ordinal = rows.output.last
      // Use distinct SUM functions and buffer attributes for the two populations.
      // Reusing one declarative aggregate under two FILTERs aliases its partial buffers.
      def sumFor(predicate: Expression): AggregateExpression = {
        val measure = If(predicate,f.sum.child,Literal.create(null,f.sum.child.dataType))
        f.expression.copy(aggregateFunction=f.sum.copy(child=measure),resultId=NamedExpression.newExprId)
      }
      val all = f.name.withNewChildren(Seq(sumFor(Or(IsNull(ordinal),EqualTo(ordinal,Literal(1L))))))
        .asInstanceOf[NamedExpression]
      val part = Alias(sumFor(IsNotNull(ordinal)),"restricted_sum")()
      val together = f.a.copy(aggregateExpressions=Seq(f.key,all,part),child=rows)
      (together,part.toAttribute)
    }
  }

  // A lower local maximum gives a necessary condition only for a monotone threshold.
  private def monotone(e: Expression, scalar: ScalarSubquery): Boolean = e match {
    case s: ScalarSubquery => s.eq(scalar)
    case c: Cast if c.dataType.isInstanceOf[DecimalType] && c.child.dataType.isInstanceOf[DecimalType] =>
      monotone(c.child,scalar)
    case m: Multiply if m.dataType.isInstanceOf[DecimalType] =>
      def nonnegative(v: Expression): Boolean = v match {
        case l: Literal if l.value.isInstanceOf[org.apache.spark.sql.types.Decimal] =>
          l.value.asInstanceOf[org.apache.spark.sql.types.Decimal].toJavaBigDecimal.signum() >= 0
        case _ => false
      }
      (nonnegative(m.left) && monotone(m.right,scalar)) ||
        (nonnegative(m.right) && monotone(m.left,scalar))
    case _ => false
  }

  private def maximum(input: Attribute, partition: Seq[Expression], label: String): Alias = {
    val spec = WindowSpecDefinition(partition,Nil,
      SpecifiedWindowFrame(RowFrame,UnboundedPreceding,UnboundedFollowing))
    Alias(WindowExpression(Max(input).toAggregateExpression(),spec),label)()
  }

  private def rewrite(filter: Filter, full: Group): Option[LogicalPlan] = {
    def fullValue(e: Expression): Boolean = e match {
      case a: Attribute => a.semanticEquals(full.name.toAttribute)
      case c: Cast if c.dataType.isInstanceOf[DecimalType] && c.child.dataType.isInstanceOf[DecimalType] =>
        val to = c.dataType.asInstanceOf[DecimalType]
        val from = c.child.dataType.asInstanceOf[DecimalType]
        to.scale >= from.scale && to.precision-to.scale >= from.precision-from.scale && fullValue(c.child)
      case _ => false
    }
    val scalars = filter.condition.collect {case s: ScalarSubquery => s}
    for {
      scalar <- scalars.headOption if scalars.size==1 && scalar.outerAttrs.isEmpty
      top <- scalar.plan match {case a: Aggregate if a.groupingExpressions.isEmpty => Some(a);case _ => None}
      peer <- group(top.child)
      if (top.aggregateExpressions match {
        case Seq(Alias(AggregateExpression(Max(a: Attribute), Complete, false, None, _), _)) =>
          a.semanticEquals(peer.name.toAttribute)
        case _ => false
      })
      op <- splitConjunctivePredicates(filter.condition).collectFirst {
        case g: GreaterThan if fullValue(g.left) && monotone(g.right,scalar) => g
        case g: GreaterThanOrEqual if fullValue(g.left) && monotone(g.right,scalar) => g
      }
      if splitConjunctivePredicates(filter.condition).forall {
        case IsNotNull(a) => a.semanticEquals(full.name.toAttribute)
        case e => e.eq(op)
      }
      both <- conditionallyGroup(full,peer)
    } yield {
      val (grouped,subtotal) = both
      val bucket = Alias(Pmod(Murmur3Hash(Seq(full.key),42),Literal(conf.numShufflePartitions)),"summary_bucket")()
      val keyed = Project(grouped.output :+ bucket,grouped)
      val local = maximum(subtotal,Seq(bucket.toAttribute),"bucket_max")
      val localWindow = Window(Seq(local),Seq(bucket.toAttribute),Nil,keyed)
      def replace(e: Expression, value: Attribute): Expression = e.transform {
        case s:ScalarSubquery if s.eq(scalar) => value
      }
      val cutoff = TryEval(replace(op.asInstanceOf[BinaryComparison].right,local.toAttribute))
      val localCheck = op.withNewChildren(Seq(op.asInstanceOf[BinaryComparison].left,cutoff))
      // Retain each bucket's maximum as a witness even when no row passes its local test.
      // A missing or unrepresentable local cutoff conveys no information.
      val keep = Or(EqualNullSafe(subtotal,local.toAttribute),Or(IsNull(cutoff),localCheck))
      val candidates = Filter(keep,localWindow)
      val global = maximum(local.toAttribute,Nil,"global_max")
      val globalWindow = Window(Seq(global),Nil,Nil,candidates)
      Project(full.a.output,Filter(replace(filter.condition,global.toAttribute),globalWindow))
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.adaptiveExecutionEnabled || !conf.exchangeReuseEnabled || plan.isStreaming) return plan
    plan.transformUp {case f: Filter => group(f.child).flatMap(rewrite(f,_)).getOrElse(f)}
  }
}
