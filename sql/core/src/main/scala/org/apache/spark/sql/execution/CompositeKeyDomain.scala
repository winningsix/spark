package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.BloomFilterAggregate
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{IntegerType, LongType, MetadataBuilder}

object CompositeKeyDomain extends PredicateHelper {
  private type Scalar = org.apache.spark.sql.catalyst.expressions.ScalarSubquery

  private def scan(plan: LogicalPlan): Option[LogicalRelation] = plan match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => scan(child)
    case Filter(condition, child) if condition.deterministic => scan(child)
    case r: LogicalRelation if !r.isStreaming => r.relation match {
      case h: HadoopFsRelation if h.fileFormat.isInstanceOf[ParquetFileFormat] => Some(r)
      case _ => None
    }
    case _ => None
  }

  private def hasDomain(plan: LogicalPlan): Boolean = plan.exists {
    case Filter(c, _) => c.exists {
      case _: BloomFilterMightContain | _: LongKeyBitmapContains => true
      case _ => false
    }
    case _ => false
  }

  private def filteredOnOtherKey(plan: LogicalPlan, keys: Seq[Attribute]): Boolean = plan.exists {
    case Filter(c, _) => splitConjunctivePredicates(c).exists {
      case BloomFilterMightContain(s: Scalar, XxHash64(Seq(key: Attribute), _)) =>
        !s.isCorrelated && s.plan.deterministic && !keys.exists(_.semanticEquals(key))
      case _ => false
    }
    case _ => false
  }

  private def restrict(build: LogicalPlan, probe: LogicalPlan, keys: Seq[(Attribute, Attribute)],
      mode: String): Option[LogicalPlan] = {
    val conf = SQLConf.get
    val longKeys = keys.filter(_._1.dataType == LongType)
    if (longKeys.size != 1 || !keys.exists(_._1.dataType == IntegerType) ||
        !filteredOnOtherKey(build, keys.map(_._1)) || hasDomain(probe)) return None
    val (source, dest) = longKeys.head
    for {
      small <- scan(build)
      large <- scan(probe)
      srcBytes = small.stats.sizeInBytes
      dstBytes = large.stats.sizeInBytes
      if srcBytes > 0 && srcBytes < dstBytes &&
        dstBytes != conf.getConf(SQLConf.DEFAULT_SIZE_IN_BYTES) &&
        dstBytes >= conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD)
      if mode == "bloom" || conf.autoBroadcastJoinThreshold >= 8192
    } yield {
      val input = Project(Seq(source), build)
      val predicate = if (mode != "bloom") {
        val budget = math.min(conf.autoBroadcastJoinThreshold, 64L * 1024 * 1024).toInt
        val metadata = new MetadataBuilder().putBoolean(IntegralKeyBroadcast.marker, true).build()
        val aggregate = if (mode == "compactBitmap") CollectCompactKeyBitmap(source, budget)
          else CollectLongKeyBitmap(source, budget)
        val result = Alias(aggregate.toAggregateExpression(), "joinKeyDomain")(
          explicitMetadata = Some(metadata))
        val sub = org.apache.spark.sql.catalyst.expressions.ScalarSubquery(Aggregate(Nil, Seq(result), input))
        Coalesce(Seq(LongKeyBitmapContains(sub, dest), Literal.TrueLiteral))
      } else {
        val aggregate = new BloomFilterAggregate(new XxHash64(Seq(source)),
          Literal(conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_ITEMS)),
          Literal(conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_BITS)))
        val result = Alias(aggregate.toAggregateExpression(), "joinKeyDomain")()
        val sub = org.apache.spark.sql.catalyst.expressions.ScalarSubquery(Aggregate(Nil, Seq(result), input))
        BloomFilterMightContain(sub, new XxHash64(Seq(dest)))
      }
      Filter(predicate, probe)
    }
  }

  def apply(plan: LogicalPlan, mode: String): LogicalPlan = {
    if (mode != "bitmap" && mode != "compactBitmap" && mode != "bloom") return plan
    plan.transformUp {
      case j @ Join(l, r, Inner, Some(c), _) if c.deterministic =>
        val pairs = splitConjunctivePredicates(c).collect {
          case EqualTo(a: Attribute, b: Attribute) if a.dataType == b.dataType => (a, b)
        }.flatMap {
          case (a, b) if l.outputSet.contains(a) && r.outputSet.contains(b) => Some((a,b))
          case (a, b) if l.outputSet.contains(b) && r.outputSet.contains(a) => Some((b,a))
          case _ => None
        }.distinct
        restrict(r, l, pairs.map(_.swap), mode).map(p => j.copy(left = p))
          .orElse(restrict(l, r, pairs, mode).map(p => j.copy(right = p))).getOrElse(j)
    }
  }
}
