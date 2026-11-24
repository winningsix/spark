package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, Average}
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{IntegerType,LongType}

class GroupedThresholdJoinExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectOptimizerRule { session =>
    val experimental = session.experimental
    experimental.synchronized {
      if (!experimental.extraOptimizations.contains(GroupedThresholdJoin))
        experimental.extraOptimizations = GroupedThresholdJoin +: experimental.extraOptimizations
    }
    new Rule[LogicalPlan] { override def apply(plan: LogicalPlan): LogicalPlan = plan }
  }
}

private[adaptive] object GroupedThresholdJoin extends Rule[LogicalPlan] with PredicateHelper {
  private def stripFilters(p: LogicalPlan): LogicalPlan = p match {
    case Filter(c, child) if c.deterministic => stripFilters(child)
    case other => other
  }

  private def detail(p: LogicalPlan): Seq[Aggregate] = p match {
    case a: Aggregate => Seq(a)
    case Project(cols, c) if cols.forall(_.isInstanceOf[Attribute]) => detail(c)
    case Filter(c, child) if c.deterministic => detail(child)
    case Join(l,r,Inner,Some(c),JoinHint.NONE) if c.deterministic => detail(l) ++ detail(r)
    case _ => Nil
  }

  // Remove only grouping-key null checks on the detail path and restore them above its aggregate.
  // The broader grouping input has to compute the same relation as the summary's input.
  private def align(a: Aggregate, peer: Aggregate): Option[LogicalPlan] = {
    if (a.child.sameResult(peer.child)) return Some(a)
    val keys = a.groupingExpressions.collect { case k: Attribute if a.outputSet.contains(k) => k }
    keys.iterator.flatMap { k =>
      // Follow this exact output key only through operators that preserve its value.
      // Moving its null check through an outer join or a computed projection is unsafe.
      def relax(input: LogicalPlan): LogicalPlan = input match {
        case f @ Filter(pred,rel: LogicalRelation) if rel.outputSet.contains(k) =>
          val terms=splitConjunctivePredicates(pred)
          val kept=terms.filterNot {
            case IsNotNull(attr: Attribute) => attr.semanticEquals(k)
            case _ => false
          }
          if (kept.size==terms.size) f else kept.reduceOption(And).map(Filter(_,rel)).getOrElse(rel)
        case p: Project if p.projectList.exists {
          case attr: Attribute => attr.semanticEquals(k)
          case _ => false
        } => p.copy(child=relax(p.child))
        case j @ Join(_,_,Inner,_,JoinHint.NONE) =>
          j.withNewChildren(j.children.map(c => if (c.outputSet.contains(k)) relax(c) else c))
        case other => other
      }
      val common=relax(a.child)
      val full=a.copy(child=common)
      def computed(n: NamedExpression) = !a.groupingExpressions.exists(_.semanticEquals(n))
      def sameMeasure(n: NamedExpression) = peer.aggregateExpressions.exists { other =>
        full.copy(aggregateExpressions=Seq(n)).sameResult(peer.copy(aggregateExpressions=Seq(other)))
      }
      Option.when(common.sameResult(peer.child) && a.aggregateExpressions.filter(computed).forall(sameMeasure))(
        Filter(IsNotNull(k),full))
    }.take(1).toList.headOption
  }

  // Compare group expressions and mapped outputs against their own children including all
  // predicates. Reuse only a completed result that supplies the summary's exact inputs.
  private def completed(base: LogicalPlan,peer: Aggregate,top: Aggregate,summary: LogicalPlan,
      pred: Expression,mode: String): Option[LogicalPlan] = {
    val full = stripFilters(base).asInstanceOf[Aggregate]
    val values = peer.aggregateExpressions.map { out =>
      val compatible = full.aggregateExpressions.find { f =>
        full.copy(aggregateExpressions=Seq(f)).sameResult(peer.copy(aggregateExpressions=Seq(out)))
      }
      compatible.map(f => out.toAttribute -> f.toAttribute)
    }
    if (values.exists(_.isEmpty) || !top.child.eq(peer)) return None
    val attrs = AttributeMap(values.flatten)
    val group = top.groupingExpressions.collect {case k: Attribute if attrs.contains(k) => attrs(k)}
    if (group.size != top.groupingExpressions.size) return None
    def mapped(e: Expression): Expression = e.transform {case a: Attribute if attrs.contains(a) => attrs(a)}
    def detailOnly(child: LogicalPlan): LogicalPlan = base match {
      case f: Filter => f.copy(child=child)
      case _ => child
    }
    if (mode=="replay") {
      val shared = RebalancePartitions(group,full,Some(conf.numShufflePartitions))
      val restored = peer.aggregateExpressions.map { col =>
        Alias(attrs(col.toAttribute),col.name)(exprId=col.exprId,qualifier=col.qualifier)
      }
      val threshold = top.copy(child=Project(restored,shared))
      val checked = summary match {
        case f: Filter if f.child.eq(top) => f.copy(child=threshold)
        case x if x.eq(top) => threshold
        case _ => return None
      }
      return Some(Join(detailOnly(shared),checked,Inner,Some(pred),JoinHint.NONE))
    }
    // A window yields exactly one summary for the current group. A join on a subset
    // of the grouping keys, or on different keys, can match several other summaries.
    val equalities=splitConjunctivePredicates(pred).collect {
      case EqualTo(l: Attribute,r: Attribute) => (l,r)
    }
    if (!top.groupingExpressions.forall {
      case k: Attribute if top.outputSet.contains(k) && attrs.contains(k) =>
        equalities.exists {case (l,r) =>
          (l.semanticEquals(k) && r.semanticEquals(attrs(k))) ||
            (r.semanticEquals(k) && l.semanticEquals(attrs(k)))
        }
      case _ => false
    }) return None
    val frame = SpecifiedWindowFrame(RowFrame,UnboundedPreceding,UnboundedFollowing)
    val spec = WindowSpecDefinition(group,Nil,frame)
    val projected = top.aggregateExpressions.map {
      case k: Attribute if attrs.contains(k) && group.exists(_.semanticEquals(attrs(k))) =>
        Some(Alias(attrs(k),k.name)(exprId=k.exprId): NamedExpression)
      case a @ Alias(agg: AggregateExpression,_) if !agg.isDistinct && agg.filter.isEmpty &&
          agg.aggregateFunction.isInstanceOf[Average] && agg.references.forall(attrs.contains) &&
          agg.references.forall(k => Set("integer","long").contains(k.dataType.typeName) ||
            k.dataType.isInstanceOf[org.apache.spark.sql.types.DecimalType]) =>
        Some(Alias(WindowExpression(mapped(agg),spec),a.name)(exprId=a.exprId): NamedExpression)
      case _ => None
    }
    if (projected.exists(_.isEmpty)) return None
    val outputs = projected.flatten
    val windows = outputs.filter(_.exists(_.isInstanceOf[WindowExpression]))
    if (windows.size != 1) return None
    val enriched = Window(windows,group,Nil,full)
    val cols = outputs.map(x => if (windows.contains(x)) x.toAttribute else x)
    val relation = Project(full.output ++ cols,detailOnly(enriched))
    val condition = summary match {
      case f: Filter if f.child.eq(top) => And(pred,f.condition)
      case p if p.eq(top) => pred
      case _ => return None
    }
    Some(Filter(condition,relation))
  }

  private def rewrite(j: Join, m: String): Option[LogicalPlan] = {
    val pred = j.condition.get
    if (!j.deterministic || !splitConjunctivePredicates(pred).exists {
      case _: LessThan | _: LessThanOrEqual | _: GreaterThan | _: GreaterThanOrEqual => true
      case _ => false
    }) return None
    j.children.indices.iterator.flatMap { i =>
      val summary = j.children(i)
      val wide = j.children(1-i)
      stripFilters(summary) match {
        case top: Aggregate if top.groupingExpressions.nonEmpty &&
            top.aggregateExpressions.exists(_.exists(_.isInstanceOf[Average])) =>
          stripFilters(top.child) match {
            case peer: Aggregate if peer.groupingExpressions.size > top.groupingExpressions.size =>
              detail(wide).iterator.filter(a => a.groupingExpressions.size == peer.groupingExpressions.size &&
                pred.references.subsetOf(a.outputSet ++ summary.outputSet)).flatMap { a =>
                val shared = align(a,peer)
                val early = m!="share"
                val reuse = m!="early"
                if (shared.isEmpty || (early && wide.eq(a))) None
                else {
                  val base = if (reuse) shared.get else a
                  val candidate = if (m=="window" || m=="replay") completed(base,peer,top,summary,pred,m)
                    else Some(if (early) Join(base,summary,Inner,j.condition,JoinHint.NONE) else base)
                  candidate.flatMap { inner =>
                  // Existing dimension projections must pass through summary attributes needed by callers.
                  val needed = summary.output
                  def place(n: LogicalPlan): LogicalPlan = n match {
                    case x if x.eq(a) => inner
                    case p: Project if early && p.child.exists(_.eq(a)) =>
                      p.copy(projectList=p.projectList ++ needed,child=place(p.child))
                    case x => x.mapChildren(place)
                  }
                  val changed = place(wide)
                  if (early) Some(Project(j.output,changed))
                  else if (base.eq(a)) None
                  else Some(j.withNewChildren(j.children.updated(1-i,changed)))
                  }
                }
              }.take(1).toList
            case _ => Nil
          }
        case _ => Nil
      }
    }.take(1).toList.headOption
  }

  override def apply(p: LogicalPlan): LogicalPlan = {
    val mode=conf.getConfString("spark.sql.optimizer.groupedThresholdJoin","off")
    if (p.isStreaming || !Set("early","share","both","window","replay").contains(mode)) return p
    p.transformUp { case j @ Join(_,_,Inner,Some(_),JoinHint.NONE) => rewrite(j,mode).getOrElse(j) }
  }
}
