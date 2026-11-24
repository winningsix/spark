package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{ByteType, ShortType, IntegerType, LongType}

/** A group rejected by a required positive key filter can never match the outer inner join.
 * Restrict the inputs of its composite-key join using that same scalar, hash seed and raw key.
 */
object ReuseGroupedKeyDomain extends Rule[LogicalPlan] with PredicateHelper {
  private type Domain = (Expression, Long)
  private val integralTypes = Set[org.apache.spark.sql.types.DataType](ByteType, ShortType, IntegerType, LongType)

  private def projected(cols: Seq[NamedExpression], key: Attribute): Option[Attribute] =
    cols.find(_.toAttribute.semanticEquals(key)).flatMap {
      case a: Attribute => Some(a)
      case Alias(a: Attribute, _) => Some(a)
      case _ => None
    }

  private def required(p: LogicalPlan, key: Attribute): Option[Domain] = p match {
    case Project(cols, child) if cols.forall(_.deterministic) =>
      projected(cols, key).flatMap(required(child, _))
    case Filter(c, child) if c.deterministic =>
      splitConjunctivePredicates(c).collectFirst {
        case BloomFilterMightContain(s: org.apache.spark.sql.catalyst.expressions.ScalarSubquery,
            XxHash64(Seq(a: Attribute), seed)) if a.semanticEquals(key) &&
              !s.isCorrelated && s.plan.deterministic => (s, seed)
      }.orElse(required(child, key))
    case Join(l, r, Inner, Some(c), _) if c.deterministic =>
      if (l.outputSet.contains(key)) required(l, key) else required(r, key)
    case _ => None
  }

  private def add(p: LogicalPlan, key: Attribute, domain: Domain): LogicalPlan = p match {
    case project @ Project(cols, c) if cols.forall(_.deterministic) =>
      projected(cols, key).map(a => project.copy(child = add(c, a, domain))).getOrElse(p)
    case filter @ Filter(c, rel: LogicalRelation) if c.deterministic &&
        rel.outputSet.contains(key) && required(filter, key).isEmpty &&
        rel.stats.sizeInBytes != conf.getConf(SQLConf.DEFAULT_SIZE_IN_BYTES) &&
        rel.stats.sizeInBytes >= conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD) =>
      val predicate = BloomFilterMightContain(domain._1, XxHash64(Seq(key), domain._2))
      filter.copy(condition = And(c, predicate))
    case _ => p
  }

  private def composite(p: LogicalPlan, key: Attribute, domain: Domain): LogicalPlan = p match {
    case project @ Project(cols, c) if cols.forall(_.deterministic) =>
      projected(cols, key).map(a => project.copy(child = composite(c, a, domain))).getOrElse(p)
    case filter @ Filter(c, child) if c.deterministic =>
      filter.copy(child = composite(child, key, domain))
    case j @ Join(l, r, Inner, Some(c), _) if c.deterministic =>
      val keys = splitConjunctivePredicates(c).collect {
        case EqualTo(a: Attribute, b: Attribute) if l.outputSet.contains(a) && r.outputSet.contains(b) => a -> b
        case EqualTo(a: Attribute, b: Attribute) if l.outputSet.contains(b) && r.outputSet.contains(a) => b -> a
      }
      if (keys.size < 2) j else keys.find { case (a,b) =>
        a.semanticEquals(key) || b.semanticEquals(key)
      }.map { case (a,b) => j.copy(left = add(l, a, domain), right = add(r, b, domain)) }.getOrElse(j)
    case _ => p
  }

  private def grouped(p: LogicalPlan, key: Attribute, domain: => Option[Domain]): LogicalPlan = p match {
    case project @ Project(cols, child) if cols.forall(_.deterministic) =>
      projected(cols, key).map(a => project.copy(child = grouped(child, a, domain))).getOrElse(p)
    case filter @ Filter(c, child) if c.deterministic =>
      filter.copy(child = grouped(child, key, domain))
    case agg: Aggregate if agg.groupingExpressions.size == 1 && agg.aggregateExpressions.forall(_.deterministic) =>
      (for {
        a <- projected(agg.aggregateExpressions, key) if agg.groupingExpressions.head.semanticEquals(a)
        src <- domain
      } yield agg.copy(child = composite(agg.child, a, src))).getOrElse(agg)
    case _ => p
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan.transformUp {
    case j @ Join(l, r, Inner, Some(condition), _) if condition.deterministic =>
      splitConjunctivePredicates(condition).foldLeft(j) {
        case (current, EqualTo(a: Attribute, b: Attribute)) if a.dataType == b.dataType &&
            integralTypes(a.dataType) =>
          val (x,y) = if (l.outputSet.contains(a)) (a,b) else (b,a)
          if (!l.outputSet.contains(x) || !r.outputSet.contains(y)) current
          else current.copy(left = grouped(current.left, x, required(current.right, y)),
            right = grouped(current.right, y, required(current.left, x)))
        case (current, _) => current
      }
  }
}
