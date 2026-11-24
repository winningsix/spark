package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.BitOrAgg
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{DateType,IntegralType,StringType}

class GroupedSetCountExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit=ext.injectPostHocResolutionRule(_=>GroupedSetCount)
}

private[adaptive] object GroupedSetCount extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.groupDistinctTextSets"

  private def intersections(p:LogicalPlan):Seq[LogicalPlan]=p match {
    case i:Intersect if !i.isAll=>intersections(i.left)++intersections(i.right)
    case other=>Seq(other)
  }

  // EXCEPT is left associative. A nested right-hand difference is a single operand.
  private def differences(p:LogicalPlan):Seq[LogicalPlan]=p match {
    case e:Except if !e.isAll=>differences(e.left):+e.right
    case other=>Seq(other)
  }

  private def grouped(op:LogicalPlan,arms:Seq[LogicalPlan],intersect:Boolean):LogicalPlan={
    val keys=op.output
    if (arms.size<3 || arms.size>63 || !keys.exists(_.dataType==StringType) ||
        !keys.forall(a=>a.dataType==StringType || a.dataType==DateType || a.dataType.isInstanceOf[IntegralType]) ||
        !arms.forall(_.output.map(a=>(a.dataType,a.nullable))==keys.map(a=>(a.dataType,a.nullable)))) return op
    val tagged=arms.zipWithIndex.map { case (in,i)=>
      val rows=in match {case Distinct(child)=>child;case other=>other}
      Project(rows.output:+Alias(Literal(1L<<i),"set_source")(),rows)
    }
    val union=Union(tagged)
    val groups=union.output.dropRight(1)
    val mask=Alias(BitOrAgg(union.output.last).toAggregateExpression(),"source_membership")()
    val expected=if(intersect) -1L >>> (64-arms.size) else 1L
    Project(keys,Filter(EqualTo(mask.toAttribute,Literal(expected)),Aggregate(groups,groups:+mask,union)))
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"false")
    if(!Set("true","intersection","difference").contains(mode) || !p.resolved || p.isStreaming) return p
    p.resolveOperatorsDown {
      case i:Intersect if !i.isAll && mode!="difference"=>grouped(i,intersections(i),intersect=true)
      case e:Except if !e.isAll && mode!="intersection"=>grouped(e,differences(e),intersect=false)
    }
  }
}
