package org.apache.spark.sql.execution.adaptive

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.sql.execution.exchange.PipelinedShuffleEligibility
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.codegen.CodegenFallback
import org.apache.spark.sql.catalyst.expressions.aggregate.{Count, Max, Min}
import org.apache.spark.sql.catalyst.plans.{LeftAnti, LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.execution.{SparkPlan, SparkStrategy}
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{IntegralType, StructField, StructType}

// Fuse an unequal-value semi join against all rows followed by an anti join
// against the same filtered rows as the probe. Only the two join attributes
// may escape the probe. All other shapes retain their original joins.
private[adaptive] object FuseWitnesses extends SparkStrategy with PredicateHelper {
  private case class Input(relation: LogicalRelation, predicates: Seq[Expression])
  private case class Keys(group: Attribute, otherGroup: Attribute, value: Attribute, otherValue: Attribute)

  private def input(p: LogicalPlan, allowedProbeFilters: AttributeSet = AttributeSet.empty): Option[Input] = p match {
    case Project(cols, c) if cols.forall(_.isInstanceOf[Attribute]) => input(c, allowedProbeFilters)
    case Filter(cond, c) if cond.deterministic && splitConjunctivePredicates(cond).forall(e =>
        !SubqueryExpression.hasSubquery(e) || (e.isInstanceOf[BloomFilterMightContain] &&
          e.references.subsetOf(allowedProbeFilters) && e.references.nonEmpty)) =>
      input(c, allowedProbeFilters).map(i => i.copy(predicates = i.predicates ++ splitConjunctivePredicates(cond)))
    case r: LogicalRelation if !r.isStreaming && r.relation.isInstanceOf[HadoopFsRelation] =>
      Some(Input(r, Nil))
    case _ => None
  }

  private def keys(j: Join): Option[Keys] = {
    def sides(a: Expression,b: Expression): Option[(Attribute, Attribute)] =
      Seq((a,b),(b,a)).collectFirst { case (x: Attribute,y: Attribute)
          if j.left.outputSet.contains(x) && j.right.outputSet.contains(y) &&
            x.dataType == y.dataType && x.dataType.isInstanceOf[IntegralType] => x -> y }
    for {
      c <- j.condition
      ps = splitConjunctivePredicates(c) if ps.size == 2
      (a,b) <- ps.collectFirst { case EqualTo(x,y) => (x,y) }
      (g,h) <- sides(a,b)
      (x,y) <- ps.collectFirst { case Not(EqualTo(x,y)) => (x,y) }
      (v,w) <- sides(x,y) if !g.semanticEquals(v) && !h.semanticEquals(w)
    } yield Keys(g,h,v,w)
  }

  // This repartition belongs to the aggregate implementation. Size its resident
  // readers to fit an admitted group together with a producer window. The
  // ordinary shuffle width still applies outside distributed group admission.
  private def routedPartitions: Option[Int] = {
    val env = SparkEnv.get
    val conf = SQLConf.get
    val fraction = conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    if (env == null || fraction <= 0 || env.pipelinedShuffleManager.requiresSingleExecutor ||
        !env.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary ||
        !env.conf.getBoolean("spark.shuffle.streaming.groupAdmission.enabled", false) ||
        !env.conf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled", false) ||
        !env.conf.getBoolean("spark.shuffle.streaming.readyQuota.enabled", false)) return None
    val charge = PipelinedShuffleEligibility.readerSlotCharge(env.conf)
    val window = math.max(1, env.conf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow", 1))
    SparkContext.getActive.filterNot(_.isLocal).flatMap { sc =>
      val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
      val width = math.floor((math.floor(slots * fraction) - window) / charge).toInt
      Option.when(charge > 0 && width > 0)(math.min(width, conf.numShufflePartitions))
    }
  }

  private def rewrite(anti: Join, semi: Join): Option[LogicalPlan] = for {
    a <- keys(anti)
    s <- keys(semi)
    if a.group.semanticEquals(s.group) && a.value.semanticEquals(s.value) &&
      semi.left.output.size == 2 && semi.left.outputSet == AttributeSet(Seq(s.group,s.value))
    all <- input(semi.right)
    probe <- input(semi.left, semi.left.outputSet)
    subset <- input(anti.right)
    if Seq(probe,subset).forall(i => i.relation.sameResult(all.relation) &&
      i.relation.output.map(_.dataType) == all.relation.output.map(_.dataType))
    anchor = all.relation.output
    remap = (i: Input) => AttributeMap(i.relation.output.zip(anchor))
    pmap = remap(probe)
    amap = remap(subset)
    if pmap.get(s.group).exists(_.semanticEquals(s.otherGroup)) &&
      pmap.get(s.value).exists(_.semanticEquals(s.otherValue)) &&
      amap.get(a.otherGroup).exists(_.semanticEquals(s.otherGroup)) &&
      amap.get(a.otherValue).exists(_.semanticEquals(s.otherValue))
    guarded = (i: Input) => {
      val m = remap(i)
      i.predicates.filterNot(SubqueryExpression.hasSubquery).map(_.transform { case a: Attribute if m.contains(a) => m(a) })
        .filterNot {
          case IsNotNull(a: Attribute) => a.semanticEquals(s.otherGroup) || a.semanticEquals(s.otherValue)
          case _ => false
        }
    }
    late = guarded(subset)
    if late.nonEmpty && guarded(all).isEmpty &&
      ExpressionSet(guarded(probe)) == ExpressionSet(late) &&
      late.forall(_.references.subsetOf(all.relation.outputSet))
  } yield {
    val key = s.otherGroup
    val value = s.otherValue
    val flag = Alias(late.reduceLeft(And), "witness_selected")()
    val source = Project(Seq(key, value, flag),
      Filter(And(IsNotNull(key), IsNotNull(value)), all.relation))
    val routed = RepartitionByExpression(Seq(key), source, routedPartitions)
    val selected = If(flag.toAttribute, value, Literal.create(null,value.dataType))
    val lo = Alias(Min(value).toAggregateExpression(), "witness_lo")()
    val hi = Alias(Max(value).toAggregateExpression(), "witness_hi")()
    val selectedLo = Alias(Min(selected).toAggregateExpression(), "selected_lo")()
    val selectedHi = Alias(Max(selected).toAggregateExpression(), "selected_hi")()
    val count = Alias(Count(Seq(selected)).toAggregateExpression(), "selected_count")()
    val byKey = Aggregate(Seq(key), Seq(key, lo, hi, selectedLo, selectedHi, count), routed)
    val passed = Filter(And(LessThan(lo.toAttribute,hi.toAttribute),
      EqualTo(selectedLo.toAttribute,selectedHi.toAttribute)), byKey)
    val output = semi.left.output
    val values = output.map(a => if (a.semanticEquals(s.group)) key else selectedLo.toAttribute)
    val expanded = Project(output, Generate(RepeatWitnessRows(count.toAttribute +: values),
      Nil, false, None, output, passed))
    probe.predicates.filter(SubqueryExpression.hasSubquery).reduceLeftOption(And)
      .fold[LogicalPlan](expanded)(Filter(_, expanded))
  }

  override def apply(plan: LogicalPlan): Seq[SparkPlan] = plan match {
    case anti @ Join(semi @ Join(_,_,LeftSemi,_,JoinHint.NONE),_,LeftAnti,_,JoinHint.NONE)
        if !anti.isStreaming && SQLConf.get.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) =>
      rewrite(anti,semi).toSeq.map(planLater)
    case _ => Nil
  }
}

// A single hot group can have more rows than a Scala collection can hold.
// Generate them on demand; the payload contains only the two integral keys.
private[adaptive] case class RepeatWitnessRows(children: Seq[Expression])
    extends Generator with CodegenFallback {
  override def elementSchema: StructType = StructType(children.tail.zipWithIndex.map {
    case (value, index) => StructField(s"col$index", value.dataType)
  })

  override def eval(input: InternalRow): IterableOnce[InternalRow] = {
    val copies = children.head.eval(input).asInstanceOf[Long]
    val row = InternalRow.fromSeq(children.tail.map(_.eval(input)))
    new Iterator[InternalRow] {
      private var remaining = copies
      override def hasNext: Boolean = remaining > 0
      override def next(): InternalRow = {
        if (!hasNext) throw new NoSuchElementException("witness rows exhausted")
        remaining -= 1
        row
      }
    }
  }

  override protected def withNewChildrenInternal(
      newChildren: IndexedSeq[Expression]): RepeatWitnessRows = copy(children = newChildren)
}
