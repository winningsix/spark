package org.apache.spark.sql.execution

import scala.collection.mutable
import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal

import org.apache.hadoop.fs.Path
import org.apache.parquet.hadoop.ParquetFileReader
import org.apache.parquet.hadoop.util.HadoopInputFile
import org.apache.parquet.io.api.Binary
import org.apache.parquet.schema.LogicalTypeAnnotation.DecimalLogicalTypeAnnotation

import org.apache.spark.sql.{SparkSession, SparkSessionExtensions}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.types._

class FactorDecimalSumsExtension extends (SparkSessionExtensions => Unit) {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectPostHocResolutionRule(s => new FactorDecimalSums(s))
}

/** Factor repeated exact decimal rates on a source with bounded, immutable Parquet inputs. */
class FactorDecimalSums(session: SparkSession) extends Rule[LogicalPlan] {
  private case class ColumnBounds(min: BigInt, max: BigInt) {
    def magnitude: BigInt = min.abs.max(max.abs)
  }
  private case class Proof(rows: BigInt, columns: Map[ExprId, ColumnBounds])

  private def decimal(e: Expression): DecimalType = e.dataType.asInstanceOf[DecimalType]

  private def input(p: LogicalPlan): Option[LogicalRelation] = p match {
    case r: LogicalRelation if !r.isStreaming => Some(r)
    case f: Filter => input(f.child)
    case a: SubqueryAlias => input(a.child)
    case v: View => input(v.child)
    case p: Project if p.projectList.forall(_.isInstanceOf[Attribute]) => input(p.child)
    case _ => None
  }

  private def unscaled(v: Any): BigInt = v match {
    case i: java.lang.Integer => BigInt(i.intValue)
    case l: java.lang.Long => BigInt(l.longValue)
    case b: Binary => BigInt(b.getBytes)
    case _ => throw new IllegalArgumentException("unsupported physical decimal")
  }

  // Read only column statistics, requiring every row group to provide exact decimal bounds.
  private def proof(r: LogicalRelation, attrs: Seq[Attribute]): Option[Proof] = {
    if (!attrs.forall(a => r.output.exists(_.exprId == a.exprId))) return None
    val relation = r.relation match {
      case h: HadoopFsRelation if h.fileFormat.isInstanceOf[ParquetFileFormat] => h
      case _ => return None
    }
    if (!attrs.forall(a => relation.dataSchema.fields.exists(f =>
        f.name == a.name && f.dataType == a.dataType && !f.metadata.contains("parquet.field.id")))) {
      return None
    }
    val files = relation.location.inputFiles
    if (files.isEmpty || files.length > 512) return None
    val conf = session.sessionState.newHadoopConf()
    val ranges = mutable.Map.empty[ExprId, ColumnBounds]
    var rows = BigInt(0)
    for (file <- files) {
      val reader = ParquetFileReader.open(HadoopInputFile.fromPath(new Path(file), conf))
      try {
        for (block <- reader.getFooter.getBlocks.asScala) {
          rows += block.getRowCount
          val chunks = block.getColumns.asScala.filter(_.getPath.size() == 1)
            .map(c => c.getPath.toDotString -> c).toMap
          attrs.foreach { a =>
            val c = chunks(a.name)
            val t = decimal(a)
            val ann = c.getPrimitiveType.getLogicalTypeAnnotation
            require(ann.isInstanceOf[DecimalLogicalTypeAnnotation])
            val d = ann.asInstanceOf[DecimalLogicalTypeAnnotation]
            require(d.getScale == t.scale && d.getPrecision == t.precision)
            val stats = c.getStatistics
            require(stats != null && stats.hasNonNullValue && stats.isNumNullsSet)
            val lo = unscaled(stats.genericGetMin)
            val hi = unscaled(stats.genericGetMax)
            require(lo <= hi && lo.abs.max(hi.abs) < BigInt(10).pow(t.precision))
            val old = ranges.getOrElse(a.exprId, ColumnBounds(lo, hi))
            ranges(a.exprId) = ColumnBounds(old.min.min(lo), old.max.max(hi))
          }
        }
      } finally reader.close()
    }
    Option.when(rows > 0 && rows <= Long.MaxValue)(Proof(rows, ranges.toMap))
  }

  // Products must be left-associated. A rate is a single decimal column or a
  // decimal column adjusted by a constant. No per-row rounding may be removed.
  private def factors(e: Expression): List[Expression] = e match {
    case m: Multiply => factors(m.left) :+ m.right
    case other => List(other)
  }
  private def simpleRate(e: Expression): Boolean = e.dataType.isInstanceOf[DecimalType] && (e match {
    case _: Attribute => true
    case _: Add | _: Subtract =>
      e.children.forall(c => c.dataType.isInstanceOf[DecimalType] &&
        (c.isInstanceOf[Attribute] || c.foldable)) && e.references.size == 1
    case _ => false
  })

  // Validate all source arithmetic, including intermediate scales. Bound absolute sums
  // across the entire input so cancellation or a different merge order cannot hide overflow.
  private def magnitude(e: Expression, proof: Proof): BigInt = {
    val target = decimal(e)
    def align(n: BigInt, scale: Int): BigInt = {
      require(target.scale >= scale)
      n * BigInt(10).pow(target.scale - scale)
    }
    val m = e match {
      case a: Attribute => proof.columns(a.exprId).magnitude
      case f if f.foldable => BigInt(f.eval().asInstanceOf[Decimal].toJavaBigDecimal.unscaledValue).abs
      case m: Multiply => align(magnitude(m.left, proof) * magnitude(m.right, proof),
        decimal(m.left).scale + decimal(m.right).scale)
      case _: Add | _: Subtract => e.children.map(c => align(magnitude(c, proof), decimal(c).scale)).sum
      case _ => throw new IllegalArgumentException("unbounded decimal expression")
    }
    require(m < BigInt(10).pow(target.precision))
    m
  }

  /** Reuse the Parquet proof when another optimizer rule has isolated a single base-column SUM. */
  private[sql] def useBoundedLong(a: Aggregate, value: Attribute): Aggregate = {
    try {
      if (!value.dataType.isInstanceOf[DecimalType] ||
          decimal(value).precision > Decimal.MAX_LONG_DIGITS) return a
      val leaf = input(a.child).getOrElse(return a)
      val bound = proof(leaf, Seq(value)).getOrElse(return a)
      val magnitude = bound.rows * bound.columns(value.exprId).magnitude
      if (magnitude > BigInt(Long.MaxValue)) return a
      val outputs = a.aggregateExpressions.map {
        case alias @ Alias(call @ AggregateExpression(s @ Sum(v: Attribute, _), Complete, false, None, _), _)
            if v.semanticEquals(value) && magnitude < BigInt(10).pow(decimal(s).precision) =>
          val t = decimal(s)
          val total = call.copy(aggregateFunction = s.copy(child = UnscaledValue(value)))
          alias.withNewChildren(Seq(MakeDecimal(total, t.precision, t.scale,
            nullOnOverflow = !conf.ansiEnabled))).asInstanceOf[NamedExpression]
        case other => other
      }
      a.copy(aggregateExpressions = outputs)
    } catch { case NonFatal(_) => a }
  }

  private def factor(a: Aggregate): Option[LogicalPlan] = {
    if (!a.resolved || a.groupingExpressions.isEmpty ||
        !a.groupingExpressions.forall(_.isInstanceOf[Attribute])) return None
    val leaf = input(a.child).getOrElse(return None)
    val calls = a.aggregateExpressions.flatMap {
      case _: Attribute => None
      case Alias(call: AggregateExpression, _) if !call.isDistinct && call.filter.isEmpty &&
          call.mode == Complete => Some(call.aggregateFunction)
      case _ => return None
    }
    if (!calls.forall {
      case s: Sum => factors(s.child).head.isInstanceOf[Attribute] &&
        factors(s.child).forall(_.dataType.isInstanceOf[DecimalType]) &&
        factors(s.child).tail.forall(simpleRate)
      case av: Average => av.child.isInstanceOf[Attribute] && av.child.dataType.isInstanceOf[DecimalType]
      case Count(Seq(Literal(1, IntegerType))) => true
      case _ => false
    }) return None
    val products = calls.collect { case s: Sum if s.child.isInstanceOf[Multiply] => s.child }
    if (products.size < 2 || products.map(e => factors(e).head).distinct.size != 1) return None
    val rates = products.flatMap(e => factors(e).tail.flatMap(_.references)).distinct
    if (rates.isEmpty || rates.size > 2) return None
    val attrs = calls.flatMap(_.references).distinct
    val bounds = proof(leaf, attrs).getOrElse(return None)
    val combinations = rates.map(r => bounds.columns(r.exprId)).map(r => r.max - r.min + 2).product
    if (combinations > 128) return None

    val groups = a.groupingExpressions.map(_.asInstanceOf[Attribute])
    val innerKeys = (groups ++ rates).distinct
    val partials = mutable.LinkedHashMap.empty[Expression, Alias]
    def partial(f: AggregateFunction): Attribute = partials.getOrElseUpdate(f,
      Alias(f.toAggregateExpression(), s"rate_partial_${partials.size}")()).toAttribute
    def sum(e: Expression): Expression = new Sum(e).toAggregateExpression()
    def boundedSum(e: Expression, t: DataType): Unit =
      require(magnitude(e, bounds) * bounds.rows < BigInt(10).pow(t.asInstanceOf[DecimalType].precision))

    val reuseRateCount = conf.getConfString(
      "spark.sql.optimizer.factorDecimalSums.reuseRateCount", "true").toBoolean
    def total(base: Expression): Expression = {
      val f = new Sum(base)
      boundedSum(base, f.dataType)
      if (reuseRateCount && rates.exists(_.semanticEquals(base))) {
        // Each inner group has one rate (which may be null). Its count suffices for its sum.
        val rows = partial(Count(Seq(Literal(1))))
        val product = Multiply(base, Cast(rows, DecimalType(20, 0)))
        require(decimal(product).scale == decimal(base).scale)
        Cast(product, f.dataType)
      } else if (decimal(base).precision <= Decimal.MAX_LONG_DIGITS &&
          magnitude(base, bounds) * bounds.rows <= BigInt(Long.MaxValue)) {
        // This absolute bound covers every subset and merge order, including signed values.
        // SUM(Long) retains SQL null handling. Restore the decimal type once per rate group.
        val sumType = f.dataType.asInstanceOf[DecimalType]
        MakeDecimal(partial(new Sum(UnscaledValue(base))), sumType.precision, sumType.scale,
          nullOnOverflow = !conf.ansiEnabled)
      } else partial(f)
    }
    def mergedCount(arg: Expression): Expression = {
      val innerCount = if (reuseRateCount && rates.exists(_.semanticEquals(arg))) {
        If(IsNull(arg), Literal(0L), partial(Count(Seq(Literal(1)))))
      } else partial(Count(Seq(arg)))
      Coalesce(Seq(sum(innerCount), Literal(0L)))
    }

    def replace(f: AggregateFunction): Expression = f match {
      case s: Sum =>
        boundedSum(s.child, s.dataType)
        val parts = factors(s.child)
        var current: Expression = total(parts.head)
        var max = magnitude(parts.head, bounds) * bounds.rows
        parts.tail.foreach { rate =>
          val product = Multiply(current, rate)
          require(decimal(product).scale == decimal(current).scale + decimal(rate).scale)
          max *= magnitude(rate, bounds)
          require(max < BigInt(10).pow(decimal(product).precision))
          current = product
        }
        Cast(sum(current), s.dataType)
      case avg: Average =>
        val combined = Cast(sum(total(avg.child)), avg.sumDataType)
        val n = mergedCount(avg.child)
        avg.evaluateExpression.transformDown {
          case ref: Attribute if ref.exprId == avg.sum.exprId => combined
          case ref: Attribute if ref.exprId == avg.count.exprId => n
        }
      case c: Count => mergedCount(c.children.head)
    }
    val outputs = a.aggregateExpressions.map {
      case attr: Attribute => attr
      case al @ Alias(call: AggregateExpression, _) =>
        al.withNewChildren(Seq(replace(call.aggregateFunction))).asInstanceOf[NamedExpression]
    }
    val inner = Aggregate(innerKeys, innerKeys ++ partials.values, a.child)
    val outer = a.copy(aggregateExpressions = outputs, child = inner)
    Option.when(outer.resolved && outer.output.map(a => (a.exprId,a.dataType,a.nullable)) ==
      a.output.map(a => (a.exprId,a.dataType,a.nullable)))(outer)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.factorDecimalSums.enabled", "false").toBoolean ||
        plan.isStreaming) return plan
    plan.resolveOperatorsUp { case a: Aggregate =>
      try factor(a).getOrElse(a) catch { case NonFatal(_) => a }
    }
  }
}
