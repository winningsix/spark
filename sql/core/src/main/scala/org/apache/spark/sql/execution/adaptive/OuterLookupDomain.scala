package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{AggregateExpression,BloomFilterAggregate}
import org.apache.spark.sql.catalyst.optimizer.CollapseProject
import org.apache.spark.sql.catalyst.plans.{Inner, LeftOuter, LeftSemi, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreeNodeTag
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.types.{IntegerType, LongType}

class OuterLookupDomainExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectOptimizerRule { session =>
    val experimental=session.experimental
    experimental.synchronized {
      if (!experimental.extraOptimizations.contains(OuterLookupDomain)) {
        experimental.extraOptimizations=experimental.extraOptimizations :+ OuterLookupDomain
      }
    }
    new Rule[LogicalPlan] { override def apply(p:LogicalPlan):LogicalPlan=p }
  }
}

/** A match on a composite outer join can only use keys that survived the other side's inner lookup. */
private[adaptive] object OuterLookupDomain extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.restrictOuterMatchToLookup"
  private val applied = TreeNodeTag[Boolean]("spark.outerLookupDomainApplied")

  private def scan(p: LogicalPlan): Boolean = p match {
    case Project(fields, child) if fields.forall(_.isInstanceOf[Attribute]) => scan(child)
    case Filter(c, child) if c.deterministic && !SubqueryExpression.hasSubquery(c) => scan(child)
    case l: LogicalRelation => !l.isStreaming && l.relation.isInstanceOf[HadoopFsRelation]
    case _ => false
  }

  private def hasSelection(p: LogicalPlan): Boolean = p.exists {
    case Filter(c, _) => splitConjunctivePredicates(c).exists {
      case EqualTo(_: Attribute, l: Literal) => l.value != null
      case EqualTo(l: Literal, _: Attribute) => l.value != null
      case _ => false
    }
    case _ => false
  }

  private def crossing(c: Expression, left: LogicalPlan, right: LogicalPlan): Seq[(Attribute,Attribute)] =
    splitConjunctivePredicates(c).flatMap {
      case EqualTo(a: Attribute,b: Attribute) if a.dataType==b.dataType &&
          (a.dataType==IntegerType || a.dataType==LongType) =>
        Seq(a->b,b->a).find { case (l,r)=>left.outputSet.contains(l) && right.outputSet.contains(r) }
      case _ => None
    }

  private def source(p: LogicalPlan, key: Attribute): Option[(LogicalPlan,Attribute)] = p match {
    case Project(fields, c) if fields.forall(_.isInstanceOf[Attribute]) => source(c,key)
    case Filter(c, child) if c.deterministic => source(child,key)
    case Join(l,r,Inner,Some(c),JoinHint.NONE) if c.deterministic =>
      val (fact,lookup)=if(l.outputSet.contains(key)) (l,r) else (r,l)
      val dimension=if(scan(lookup) && hasSelection(lookup)) crossing(c,fact,lookup)
        .find(_._1.semanticEquals(key)).map {case (_,k)=>lookup->k} else None
      dimension.orElse(source(fact,key))
    case _ => None
  }

  private type Scalar = org.apache.spark.sql.catalyst.expressions.ScalarSubquery
  private case class Domain(keys:LogicalPlan, bitmap:Scalar, seed:Long)
  private def projection(k:Attribute,input:LogicalPlan):LogicalPlan = CollapseProject(Project(Seq(k),input))
  private def domainOf(s:Scalar):Option[Domain]=s.plan match {
    case agg:Aggregate if agg.groupingExpressions.isEmpty && agg.aggregateExpressions.size==1 =>
      agg.aggregateExpressions.head match {
      case Alias(a:AggregateExpression,_) if !s.isCorrelated &&
        s.plan.deterministic && !a.isDistinct && a.filter.isEmpty =>
      a.aggregateFunction match {
        case b:BloomFilterAggregate=>b.child match {
          case XxHash64(Seq(k:Attribute),seed)=>Some(Domain(projection(k,agg.child),s,seed))
          case _=>None
        }
        case _=>None
      }
      case _=>None
      }
    case _=>None
  }
  private def restrict(domains:Seq[Domain],preserved:LogicalPlan, nullable:LogicalPlan, cond:Expression, mode:String):Option[LogicalPlan]={
    val keys=crossing(cond,preserved,nullable)
    if(keys.size<2 || !scan(nullable)) return None
    keys.iterator.flatMap {case (foreign,target)=>source(preserved,foreign).map {case (dim,key)=>
      if(mode=="semi") {
        val projected=Project(Seq(Alias(key,"outer_lookup_key")()),dim)
        Join(nullable,projected,LeftSemi,Some(EqualTo(target,projected.output.head)),JoinHint.NONE)
      } else {
        val projected=projection(key,dim)
        val filter=domains.find(_.keys.sameResult(projected)).map { d=>
          BloomFilterMightContain(d.bitmap,XxHash64(Seq(target),d.seed))
        }.getOrElse {
        val hashed=new XxHash64(Seq(key))
        val value=Alias(new BloomFilterAggregate(hashed).toAggregateExpression(),"outer_lookup_bloom")()
        val bitmap=org.apache.spark.sql.catalyst.expressions.ScalarSubquery(Aggregate(Nil,Seq(value),dim))
        BloomFilterMightContain(bitmap,new XxHash64(Seq(target)))
        }
        Filter(filter,nullable)
      }
    }}.nextOption()
  }

  override def apply(p: LogicalPlan): LogicalPlan = {
    val mode=conf.getConfString(setting,"off")
    if(p.isStreaming || !Set("semi","bloom").contains(mode)) return p
    lazy val domains=p.collect {case f:Filter=>f.condition.collect {
      case BloomFilterMightContain(s:Scalar,_)=>domainOf(s)
    }.flatten}.flatten.distinct
    p.transformUp {
      case j @ Join(l,r,kind,Some(c),JoinHint.NONE) if c.deterministic && !j.getTagValue(applied).contains(true) &&
          (kind==LeftOuter || kind==RightOuter) =>
        val next=if(kind==LeftOuter) restrict(domains,l,r,c,mode).map(n=>j.copy(right=n))
          else restrict(domains,r,l,c,mode).map(n=>j.copy(left=n))
        next.foreach(_.setTagValue(applied,true))
        next.getOrElse(j)
    }
  }
}
