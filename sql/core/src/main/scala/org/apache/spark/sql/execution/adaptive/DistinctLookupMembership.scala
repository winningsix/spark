package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.{Inner,LeftSemi}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation,LogicalRelation}

class DistinctLookupMembershipExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit=ext.injectPreCBORule(_=>DistinctLookupMembership)
}

private[adaptive] object DistinctLookupMembership extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.distinctLookupMembership"
  private def scan(p:LogicalPlan):Boolean=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>scan(c)
    case Filter(cond,c) if cond.deterministic && !SubqueryExpression.hasSubquery(cond)=>scan(c)
    case r:LogicalRelation => !r.isStreaming && r.relation.isInstanceOf[HadoopFsRelation]
    case _=>false
  }

  private def candidate(a:Aggregate, j:Join, e:EqualTo):Option[LogicalPlan] = {
    val groups=a.groupingExpressions
    if (groups.isEmpty || !groups.forall(_.isInstanceOf[Attribute]) ||
        !a.aggregateExpressions.forall {
          case _:Attribute|Alias(_:Attribute,_)=>true
          case _=>false
        }) return None
    Seq((j.left,j.right),(j.right,j.left)).collectFirst {
      case (dim,keys) if scan(dim) && keys.output.size==1 &&
          keys.exists(_.isInstanceOf[Union]) && keys.exists(_.isInstanceOf[Join]) &&
          groups.forall(_.references.subsetOf(dim.outputSet)) &&
          a.aggregateExpressions.forall(_.references.subsetOf(dim.outputSet)) &&
          Seq(e.left->e.right,e.right->e.left).exists {
            case (d:Attribute,k:Attribute)=>dim.outputSet.contains(d) && k.semanticEquals(keys.output.head)
            case _=>false
          } =>
        val fk=keys.output.head
        val distinctKeys=Aggregate(Seq(fk),Seq(fk),keys)
        a.copy(child=Join(dim,distinctKeys,LeftSemi,Some(e),JoinHint.NONE))
    }
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    if(p.isStreaming || !conf.getConfString(setting,"false").toBoolean) return p
    p.transformUp {
      case a @ Aggregate(_,_,Project(cols,j @ Join(_,_,Inner,Some(e:EqualTo),JoinHint.NONE)),_)
          if cols.forall(_.isInstanceOf[Attribute]) => candidate(a,j,e).getOrElse(a)
    }
  }
}
