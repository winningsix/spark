package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.{Cross, Inner}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.{DecimalType, IntegerType, IntegralType}

class RangeScalarAggregatesExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectPreCBORule(_ => RangeScalarAggregates)
}

private[adaptive] object RangeScalarAggregates extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.shareDisjointScalarAggregateScan"

  private case class Branch(agg: Aggregate, condition: Expression, scan: LogicalRelation)
  private case class Interval(key: Attribute, low: Long, high: Long, test: Expression)

  private def branches(p: LogicalPlan): Option[Seq[Branch]] = p match {
    case Join(l,r,Inner | Cross,None,JoinHint.NONE) =>
      for (left <- branches(l); right <- branches(r)) yield left ++ right
    case a @ Aggregate(Nil,_,Project(cols,Filter(cond,r:LogicalRelation)),_)
        if cols.forall(_.isInstanceOf[Attribute]) && r.relation.isInstanceOf[HadoopFsRelation] &&
          cond.deterministic && !cond.exists {
            case _:Attribute | _:Literal | _:And | _:Or | _:IsNotNull | _:BinaryComparison => false
            case _ => true
          } => Some(Seq(Branch(a,cond,r)))
    case _ => None
  }

  private def intervals(expr: Expression): Seq[Interval] = {
    val terms=splitConjunctivePredicates(expr)
    for {
      lo @ GreaterThanOrEqual(k:Attribute, l:Literal) <- terms
      if k.dataType.isInstanceOf[IntegralType] && l.dataType==k.dataType && l.value!=null
      hi @ LessThanOrEqual(h:Attribute, u:Literal) <- terms
      if h.semanticEquals(k) && u.dataType==k.dataType && u.value!=null
    } yield Interval(k,l.value.asInstanceOf[Number].longValue,u.value.asInstanceOf[Number].longValue,And(lo,hi))
  }

  private def scalar(n: NamedExpression): Boolean = n match {
    case Alias(e,_) =>
      val aggs=e.collect { case a:AggregateExpression => a }
      aggs.size==1 && !e.exists {
        case _:Alias | _:Cast | _:Literal | _:Divide | _:Attribute | _:AggregateExpression |
             _:UnscaledValue | _:Count | _:Average => false
        case _=>true
      } && aggs.forall { a =>
        a.mode==Complete && a.filter.isEmpty && (a.aggregateFunction match {
          case Count(Seq(_:Attribute)) => true
          case Average(c,_) => !a.isDistinct && (c.dataType.isInstanceOf[DecimalType] || c.isInstanceOf[UnscaledValue])
          case _=>false
        })
      }
    case _=>false
  }

  private def rewrite(all: Seq[Branch]): Option[LogicalPlan] = {
    val head=all.head
    val metrics=head.agg.aggregateExpressions
    if (all.size<2 || !all.forall(b=>b.scan.sameResult(head.scan) && b.agg.aggregateExpressions.size==metrics.size &&
        b.agg.aggregateExpressions.forall(scalar))) return None
    def remap(e:Expression,b:Branch):Expression={
      val attrs=AttributeMap(b.scan.output.zip(head.scan.output))
      e.transform { case a:Attribute => attrs(a) }
    }
    val originals=all.map(_.agg.aggregateExpressions.map(_.asInstanceOf[Alias]))
    if (!all.zip(originals).forall { case (b,cols) => cols.zip(metrics).forall { case(n,m)=>
      remap(n.child,b).semanticEquals(m.asInstanceOf[Alias].child)
    }}) return None
    val conds=all.map(b=>remap(b.condition,b))
    val ranges=conds.map(intervals)
    val pick=ranges.head.iterator.map(_.key).flatMap {key =>
      val spans=ranges.map(_.find(_.key.semanticEquals(key)))
      if (spans.forall(_.nonEmpty)){
        val rs=spans.flatten
        val sorted=rs.sortBy(_.low)
        Option.when(sorted.forall(x=>x.low<=x.high) && sorted.zip(sorted.tail).forall {case(l,r)=>l.high<r.low})(rs)
      } else None
    }.nextOption()
    pick.map {rs=>
      val bucket=Alias(CaseWhen(rs.zipWithIndex.map {case(r,i)=>r.test->Literal(i)}),"range_bucket")()
      val kept=Filter(conds.reduceLeft(Or),head.scan)
      val withBucket=Project(head.scan.output:+bucket,kept)
      val bucketKey=bucket.toAttribute
      val groupMetrics=metrics.map(n=>Alias(n.asInstanceOf[Alias].child,"range_"+n.name)())
      val grouped=Aggregate(Seq(bucketKey),bucketKey+:groupMetrics,withBucket)
      val outputs=originals.zipWithIndex.flatMap {case(cols,i)=>cols.zip(groupMetrics).map {case(orig,m)=>
        val v=m.toAttribute
        val chosen=Max(If(EqualTo(bucketKey,Literal(i)),v,Literal.create(null,v.dataType))).toAggregateExpression()
        val empty=orig.child.transformDown {
          case a:AggregateExpression => a.aggregateFunction.defaultResult.getOrElse(Literal.create(null,a.dataType))
        }
        val restored=if(!orig.nullable) Coalesce(Seq(chosen,empty))
        else if(orig.child.exists(_.isInstanceOf[Count])) {
          // A nullable wrapper around COUNT can be non-null on an absent scalar group.
          // Preserve an actual null from a present group independently of this fallback.
          val seen=Max(If(EqualTo(bucketKey,Literal(i)),Literal(1),Literal.create(null,IntegerType)))
            .toAggregateExpression()
          If(IsNull(seen),empty,chosen)
        } else chosen
        orig.withNewChildren(Seq(restored)).asInstanceOf[NamedExpression]
      }}
      Aggregate(Nil,outputs,grouped)
    }
  }

  override def apply(p:LogicalPlan):LogicalPlan =
    if (p.isStreaming || !conf.getConfString(setting,"false").toBoolean) p
    else p.transformDown {case j:Join=>branches(j).flatMap(rewrite).getOrElse(j)}
}
