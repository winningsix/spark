package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression, BitOrAgg, Partial, Sum}
import org.apache.spark.sql.catalyst.plans.FullOuter
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.plans.physical.HashPartitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{ProjectExec, SparkPlan, UnionExec}
import org.apache.spark.sql.execution.aggregate.HashAggregateExec
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.types.{IntegerType,LongType}

class OuterPresenceExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = {
    ext.injectOptimizerRule(_ => OuterPresenceCounts)
    ext.injectOptimizerRule(_ => DistinctOuterKeys)
    ext.injectQueryPostPlannerStrategyRule(_ => ProjectMembershipUpdates)
    ext.injectQueryStagePrepRule(_ => RouteMembershipShuffle)
  }
}

/** Counts distinguish left-only, right-only and matching members of two distinct key sets. */
private[adaptive] object OuterPresenceCounts extends Rule[LogicalPlan] with PredicateHelper {
  private case class Count(alias: Alias, left: Attribute, right: Attribute, l: Boolean, r: Boolean)
  private def presence(e: Expression): Option[(Attribute,Boolean)] = e match {
    case IsNull(a: Attribute) => Some((a,false))
    case IsNotNull(a: Attribute) => Some((a,true))
    case _ => None
  }
  private def count(n: NamedExpression,j: Join): Option[Count] = n match {
    case a @ Alias(x: AggregateExpression,_) if !x.isDistinct && x.filter.isEmpty =>
      x.aggregateFunction match {
        case Sum(CaseWhen(Seq((And(p,q),Literal(1,IntegerType))),Some(Literal(0,IntegerType))),_) =>
          for {
            first <- presence(p); second <- presence(q)
            (left,right) = if (j.left.outputSet.contains(first._1)) (first,second) else (second,first)
            if j.left.outputSet.contains(left._1) && j.right.outputSet.contains(right._1) &&
              (left._2 || right._2)
          } yield Count(a,left._1,right._1,left._2,right._2)
        case _ => None
      }
    case _ => None
  }
  private def rewrite(a: Aggregate,j: Join): Option[LogicalPlan] = {
    if (j.joinType != FullOuter || j.hint != JoinHint.NONE || j.condition.isEmpty ||
        a.groupingExpressions.nonEmpty || a.aggregateExpressions.isEmpty) return None
    val counts = a.aggregateExpressions.flatMap(count(_,j))
    if (counts.size != a.aggregateExpressions.size) return None
    val observed = (counts.head.left,counts.head.right)
    if (!counts.forall(c => (c.left,c.right)==observed)) return None
    val p = splitConjunctivePredicates(j.condition.get)
    val keys = p.collect { case EqualTo(a: Attribute,b: Attribute) => (a,b) }.collect {
      case (a,b) if j.left.outputSet.contains(a) && j.right.outputSet.contains(b) => (a,b)
      case (a,b) if j.right.outputSet.contains(a) && j.left.outputSet.contains(b) => (b,a)
    }
    if (p.size != 2 || !keys.contains(observed) || keys.map(_._1).distinct.size != 2 ||
        keys.map(_._2).distinct.size != 2) return None
    val order = observed +: keys.filterNot(_ == observed)
    for {
      l <- DistinctOuterKeys.distinctArm(j.left,order.map(_._1))
      r <- DistinctOuterKeys.distinctArm(j.right,order.map(_._2))
    } yield {
      def branch(arm: DistinctOuterKeys.Arm,side: Int): LogicalPlan = {
        val first=arm.keys.head; val second=arm.keys.last
        // An incomplete pair never matches across sources. Preserve a group for a NULL
        // observed key so SUM over a nonempty all-NULL input still produces zero.
        val nullSide=If(IsNull(second),Literal(side),Literal(0))
        val bit=If(IsNull(first),Literal(0L),ShiftLeft(Literal(1L),
          BitwiseAnd(Coalesce(Seq(second,Literal(0))),Literal(63))))
        Project(Seq(first,Alias(ShiftRight(second,Literal(6)),"outer_word")(),
          Alias(nullSide,"outer_null_side")(),Alias(if(side==1) bit else Literal(0L),"outer_left_bits")(),
          Alias(if(side==2) bit else Literal(0L),"outer_right_bits")()),arm.child)
      }
      val union=Union(Seq(branch(l,1),branch(r,2)))
      val left=Alias(BitOrAgg(union.output(3)).toAggregateExpression(),"outer_left_word")()
      val right=Alias(BitOrAgg(union.output(4)).toAggregateExpression(),"outer_right_word")()
      val words=Aggregate(union.output.take(3),Seq(left,right),union)
      val x=left.toAttribute;val y=right.toAttribute
      val results=counts.map { c =>
        val mask=if (c.l && c.r) BitwiseAnd(x,y)
          else if (c.l) BitwiseAnd(x,BitwiseNot(y)) else BitwiseAnd(y,BitwiseNot(x))
        c.alias.copy(child=Sum(BitwiseCount(mask)).toAggregateExpression())(
          exprId=c.alias.exprId,qualifier=c.alias.qualifier,explicitMetadata=c.alias.explicitMetadata,nonInheritableMetadataKeys=c.alias.nonInheritableMetadataKeys)
      }
      Aggregate(Nil,results,words)
    }
  }
  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (plan.isStreaming || conf.getConfString("spark.sql.optimizer.distinctOuterKeys","off")!="bitmap")
      return plan
    plan.transformUp {
      case a: Aggregate => a.child match {
        case j: Join => rewrite(a,j).getOrElse(a)
        case p @ Project(cols,j: Join) if cols.forall(_.isInstanceOf[Attribute]) =>
          rewrite(a,j).getOrElse(a)
        case _ => a
      }
    }
  }
}

private[adaptive] object ProjectMembershipUpdates extends Rule[SparkPlan] {
  def buffers(a: HashAggregateExec): Option[Seq[Attribute]] = {
    val input = a.aggregateExpressions.collect {
      case x if x.mode == Partial && x.filter.isEmpty && !x.isDistinct => x.aggregateFunction
    }.collect { case b: BitOrAgg if b.child.isInstanceOf[Attribute] => b.child.asInstanceOf[Attribute] }
    val names=input.map(_.name)
    Option.when(!a.isStreaming && a.groupingExpressions.nonEmpty &&
      a.groupingExpressions.forall(_.isInstanceOf[Attribute]) && input.size==a.aggregateExpressions.size &&
      (names==Seq("outer_source") || names==Seq("outer_left_bits","outer_right_bits")) &&
      a.child.isInstanceOf[UnionExec] && a.output.size == a.groupingExpressions.size+input.size)(input)
  }
  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConfString("spark.sql.execution.projectOuterMembershipUpdates","false").toBoolean) return plan
    plan.transformUp { case a: HashAggregateExec => buffers(a).map { updates =>
      val inputs=a.groupingExpressions++updates
      val cols=inputs.zip(a.output).map { case (in,out) =>
        if (in.exprId==out.exprId) in else Alias(in,out.name)(exprId=out.exprId,qualifier=out.qualifier)
      }
      val p=ProjectExec(cols,a.child);a.logicalLink.foreach(p.setLogicalLink);p
    }.getOrElse(a) }
  }
}

private[adaptive] object RouteMembershipShuffle extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    val mode=conf.getConfString("spark.sql.execution.outerMembershipTransport","default")
    if (mode!="block" && mode!="pipeline") return plan
    val live=mode=="pipeline"
    if (live && !PipelinedShuffleEligibility.enabled(plan,conf)) return plan
    val exchanges=plan.collectWithSubqueries {case e: ShuffleExchangeExec => e}
    if (exchanges.exists(_.pipelined)) return plan
    val matches=plan.collect { case e: ShuffleExchangeExec if e.shuffleOrigin==ENSURE_REQUIREMENTS &&
      e.child.output.exists(a=> Set("outer_null_group","outer_null_side").contains(a.name)) &&
      e.child.exists(_.isInstanceOf[UnionExec]) && e.outputPartitioning.isInstanceOf[HashPartitioning] => e }
    if (matches.size!=1 || exchanges.count(_.canonicalized==matches.head.canonicalized)!=1) return plan
    val e=matches.head
    val sc=plan.session.sparkContext;val slots=sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val fraction=conf.getConf(org.apache.spark.sql.internal.SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val writerWindow=sc.getConf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow",1)
    val h=e.outputPartitioning.asInstanceOf[HashPartitioning]
    val width=(slots/2).min(if(fraction>0) (slots*fraction).toInt else slots).min(slots-writerWindow).min(h.numPartitions)
    if (width<1 || plan.exists {case ReusedExchangeExec(_,x) => x.canonicalized==e.canonicalized
      case _ => false}) return plan
    val replacement=e.copy(outputPartitioning=HashPartitioning(h.expressions,width),pipelined=live)
    replacement.copyTagsFrom(e);e.logicalLink.foreach(replacement.setLogicalLink)
    val result=plan.transformUp {case x: ShuffleExchangeExec if x eq e => replacement}
    if (ValidateRequirements.validate(result)) result else plan
  }
}
