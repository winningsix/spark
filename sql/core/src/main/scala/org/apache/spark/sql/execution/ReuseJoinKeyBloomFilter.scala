package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.LogicalRelation
import org.apache.spark.sql.internal.SQLConf

/** Reuse an existing scan-side filter on an equal key below an earlier inner join. */
object ReuseJoinKeyBloomFilter extends Rule[LogicalPlan] with PredicateHelper {
  private val enabled = "spark.sql.optimizer.runtime.bloomFilter.reuseOnInnerJoinKeys.enabled"

  private def predicates(plan: LogicalPlan, key: Attribute): Seq[BloomFilterMightContain] =
    plan match {
      case Project(cols, child) if cols.exists(_.semanticEquals(key)) => predicates(child, key)
      case Filter(condition, _: LogicalRelation) =>
        splitConjunctivePredicates(condition).collect {
          case b @ BloomFilterMightContain(s: ScalarSubquery, XxHash64(Seq(a: Attribute), _))
              if a.semanticEquals(key) && !s.isCorrelated && s.plan.deterministic => b
        }
      case _ => Nil
    }

  private def push(plan: LogicalPlan, key: Attribute, predicate: Expression,
      crossedJoin: Boolean): LogicalPlan = plan match {
    case p @ Project(cols, child) if cols.forall(_.deterministic) &&
        cols.exists(_.semanticEquals(key)) =>
      p.copy(child = push(child, key, predicate, crossedJoin))
    case j @ Join(left, right, Inner, Some(condition), _) if condition.deterministic =>
      if (left.outputSet.contains(key)) j.copy(left = push(left, key, predicate, true))
      else if (right.outputSet.contains(key)) j.copy(right = push(right, key, predicate, true))
      else j
    case f @ Filter(condition, rel: LogicalRelation)
        if crossedJoin && condition.deterministic && rel.outputSet.contains(key) &&
          rel.stats.sizeInBytes != conf.getConf(SQLConf.DEFAULT_SIZE_IN_BYTES) &&
          rel.stats.sizeInBytes >= conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD) &&
          predicates(f, key).isEmpty =>
      f.copy(condition = And(condition, predicate))
    case _ => plan
  }

  // A scan that supplies only the keys of a composite inner join can apply
  // a required peer Bloom predicate before the join reads its shuffle.
  private def directKeyScan(join: Join, side: LogicalPlan): Boolean = {
    if (!conf.pipelinedShuffleFullPlanAQEEnabled) return false
    val keys = splitConjunctivePredicates(join.condition.get).collect {
      case EqualTo(a: Attribute, b: Attribute) if a.dataType == b.dataType &&
          join.left.outputSet.contains(a) && join.right.outputSet.contains(b) =>
        if (side eq join.left) a else b
      case EqualTo(a: Attribute, b: Attribute) if a.dataType == b.dataType &&
          join.left.outputSet.contains(b) && join.right.outputSet.contains(a) =>
        if (side eq join.left) b else a
    }
    def bareScan(p: LogicalPlan): Boolean = p match {
      case Project(cols, c) if cols.forall(_.isInstanceOf[Attribute]) => bareScan(c)
      case Filter(c, _: LogicalRelation) => splitConjunctivePredicates(c).forall {
        case IsNotNull(a: Attribute) => keys.exists(_.semanticEquals(a))
        case _ => false
      }
      case _ => false
    }
    keys.distinct.size >= 2 && side.outputSet == AttributeSet(keys) && bareScan(side)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString(enabled, "false").toBoolean || !conf.subqueryReuseEnabled ||
        plan.isStreaming || plan.isInstanceOf[Subquery]) return plan
    val reused = plan.transformUp {
      case join @ Join(_, _, Inner, Some(condition), _) if condition.deterministic =>
        splitConjunctivePredicates(condition).foldLeft(join) {
          case (j, EqualTo(a: Attribute, b: Attribute)) if a.dataType == b.dataType =>
            val keys = Seq(a -> b, b -> a).find { case (l, r) =>
              j.left.outputSet.contains(l) && j.right.outputSet.contains(r)
            }
            keys.map { case (l, r) =>
              def reuse(from: LogicalPlan, source: Attribute, into: LogicalPlan,
                  target: Attribute): LogicalPlan = predicates(from, source).headOption match {
                case Some(BloomFilterMightContain(query, XxHash64(_, seed))) =>
                  push(into, target, BloomFilterMightContain(query, XxHash64(Seq(target), seed)),
                    directKeyScan(j, into))
                case _ => into
              }
              j.copy(left = reuse(j.right, r, j.left, l), right = reuse(j.left, l, j.right, r))
            }.getOrElse(j)
          case (j, _) => j
        }
    }
    val grouped = if (conf.getConfString("spark.sql.optimizer.runtime.bloomFilter.groupedJoinKeys.enabled",
        "false").toBoolean) ReuseGroupedKeyDomain(reused) else reused
    CompositeKeyDomain(grouped, conf.getConfString("spark.sql.optimizer.runtime.bloomFilter.compositeKeyDomain", "off"))
  }
}
