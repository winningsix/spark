package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.{Inner, LeftAnti, LeftOuter, LeftSemi, RightOuter}
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.types.{IntegerType, LongType}

class GroupByDimensionConstantExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectOptimizerRule(_ => GroupByDimensionConstant)
}

/** Drop a composite grouping component fixed by a filter in a joined input. */
private[adaptive] object GroupByDimensionConstant extends Rule[LogicalPlan] with PredicateHelper {
  private def value(plan: LogicalPlan, key: Attribute, joined: Boolean): Option[Literal] = plan match {
    case Filter(c,child) =>
      val local = if (!joined) None else splitConjunctivePredicates(c).collectFirst {
        case EqualTo(a: Attribute, v: Literal) if a.semanticEquals(key) &&
            v.value != null && v.dataType == key.dataType => v
        case EqualTo(v: Literal, a: Attribute) if a.semanticEquals(key) &&
            v.value != null && v.dataType == key.dataType => v
      }
      local.orElse(value(child,key,joined))
    case Project(cols,child) => cols.find(_.exprId == key.exprId).flatMap {
      case a: Attribute => value(child,a,joined)
      case Alias(a: Attribute,_) => value(child,a,joined)
      case _ => None
    }
    case j: Join if j.left.outputSet.contains(key) &&
        Set[org.apache.spark.sql.catalyst.plans.JoinType](Inner,LeftOuter,LeftSemi,LeftAnti).contains(j.joinType) =>
      value(j.left,key,true)
    case j: Join if j.right.outputSet.contains(key) && (j.joinType == Inner || j.joinType == RightOuter) =>
      value(j.right,key,true)
    case _ => None
  }

  private def rewrite(a: Aggregate): Aggregate = {
    val constants = AttributeMap(a.groupingExpressions.collect {
      case attr: Attribute if attr.dataType == LongType || attr.dataType == IntegerType => attr
    }.flatMap(k => value(a.child,k,false).map(k -> _)))
    def fixed(e: Expression): Boolean = e match {
      case x: Attribute => constants.contains(x)
      case _ => false
    }
    val grouping = a.groupingExpressions.filterNot(fixed)
    if (constants.isEmpty || grouping.isEmpty) return a
    val outputs = a.aggregateExpressions.map { n =>
      val replacement = n match {
        case x: Attribute => constants.get(x)
        case Alias(x: Attribute,_) => constants.get(x)
        case _ => None
      }
      if (replacement.isEmpty && n.references.exists(constants.contains)) None
      else Some(replacement.map(v => Alias(v,n.name)(exprId=n.exprId,qualifier=n.qualifier,
        explicitMetadata=Some(n.metadata))).getOrElse(n))
    }
    if (outputs.exists(_.isEmpty)) a else a.copy(groupingExpressions=grouping,
      aggregateExpressions=outputs.flatten)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.groupByFixedDimensionKey.enabled",
        "false").toBoolean || plan.isStreaming) return plan
    plan.transformUp { case a: Aggregate if a.groupingExpressions.size > 1 => rewrite(a) }
  }
}
