/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql.execution

import com.google.common.cache.CacheBuilder

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate._
import org.apache.spark.sql.catalyst.expressions.codegen._
import org.apache.spark.sql.catalyst.expressions.codegen.Block._
import org.apache.spark.sql.catalyst.plans.logical.{Aggregate, Filter, LogicalPlan}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.UnaryLike
import org.apache.spark.sql.types.{BinaryType, DataType, LongType, Metadata, MetadataBuilder}

case class CollectLongKeyBitmap(
    child: Expression,
    byteBudget: Int,
    override val mutableAggBufferOffset: Int = 0,
    override val inputAggBufferOffset: Int = 0)
  extends TypedImperativeAggregate[LongKeyBitmap] with UnaryLike[Expression] {

  override def dataType: DataType = BinaryType
  override def nullable: Boolean = true
  override def createAggregationBuffer(): LongKeyBitmap = new LongKeyBitmap(byteBudget)
  override def update(buffer: LongKeyBitmap, row: InternalRow): LongKeyBitmap = {
    val v = child.eval(row)
    if (v != null) buffer.add(v.asInstanceOf[Long])
    buffer
  }
  override def merge(buffer: LongKeyBitmap, other: LongKeyBitmap): LongKeyBitmap = {
    buffer.merge(other)
    buffer
  }
  override def eval(buffer: LongKeyBitmap): Any = buffer.finish()
  override def serialize(buffer: LongKeyBitmap): Array[Byte] = buffer.partial()
  override def deserialize(bytes: Array[Byte]): LongKeyBitmap = LongKeyBitmap.restore(bytes, byteBudget)
  override def withNewMutableAggBufferOffset(offset: Int): CollectLongKeyBitmap =
    copy(mutableAggBufferOffset = offset)
  override def withNewInputAggBufferOffset(offset: Int): CollectLongKeyBitmap =
    copy(inputAggBufferOffset = offset)
  override protected def withNewChildInternal(c: Expression): CollectLongKeyBitmap = copy(child = c)
}

/** One shared bitmap per physical scalar build, including reused subquery wrappers. */
final class IntegralKeyBroadcast(private val bytes: Broadcast[Array[Byte]]) extends Serializable {
  def value: Array[Byte] = bytes.value
  @transient lazy val probe: LongKeyBitmap.Probe = new LongKeyBitmap.Probe(value)
}

object IntegralKeyBroadcast {
  val marker = "__spark_internal_integral_key_domain"
  private val builds = CacheBuilder.newBuilder()
    .weakKeys().weakValues().build[BaseSubqueryExec, IntegralKeyBroadcast]()

  def forPlan(plan: BaseSubqueryExec, bytes: Array[Byte]): IntegralKeyBroadcast = plan match {
    case reused: ReusedSubqueryExec => forPlan(reused.child, bytes)
    case p => builds.get(p, () => new IntegralKeyBroadcast(p.session.sparkContext.broadcast(bytes)))
  }
}

case class LongKeyBitmapContains(left: Expression, right: Expression)
  extends BinaryExpression with Predicate {
  override def nullable: Boolean = true

  @transient private lazy val lookup = {
    shared match {
      case Some(keys) => keys.probe
      case None =>
        val data = left.eval().asInstanceOf[Array[Byte]]
        if (data == null) null else new LongKeyBitmap.Probe(data)
    }
  }

  private def shared: Option[IntegralKeyBroadcast] = left match {
    case scalar: org.apache.spark.sql.execution.ScalarSubquery => scalar.integralKeyBroadcast
    case _ => None
  }

  override def eval(input: InternalRow): Any = {
    if (lookup == null) return null
    val value = right.eval(input)
    if (value == null) null else lookup.contains(value.asInstanceOf[Long])
  }
  override protected def doGenCode(ctx: CodegenContext, ev: ExprCode): ExprCode = {
    val probeClass = classOf[LongKeyBitmap.Probe].getCanonicalName
    val bitmap = shared match {
      case Some(keys) =>
        val handle = ctx.addReferenceObj("integralKeyBroadcast", keys)
        ctx.addMutableState(probeClass, "integralKeyProbe", v => s"$v = $handle.probe();")
      case None =>
        if (lookup == null) return ev.copy(isNull = TrueLiteral, value = JavaCode.defaultLiteral(dataType))
        ctx.addReferenceObj("integralKeyBitmap", lookup, probeClass)
    }
    val key = right.genCode(ctx)
    ev.copy(code = code"""
      ${key.code}
      boolean ${ev.isNull} = ${key.isNull};
      boolean ${ev.value} = !${ev.isNull} && $bitmap.contains(${key.value});""")
  }
  override protected def withNewChildrenInternal(a: Expression, b: Expression): LongKeyBitmapContains =
    copy(left = a, right = b)
}

/** Replace the bounded positive membership test after its probe sites have been selected. */
object UseIntegralRuntimeFilter extends Rule[LogicalPlan] {
  private def build(
      scalar: org.apache.spark.sql.catalyst.expressions.ScalarSubquery,
      seed: Long,
      budget: Int): Option[Expression] = {
    if (!scalar.getTagValue(org.apache.spark.sql.catalyst.optimizer.GeneratedIntegralKeyDomain.tag)
        .contains(true) || scalar.outerAttrs.nonEmpty || scalar.joinCond.nonEmpty) return None
    scalar.plan match {
      case agg: Aggregate if agg.groupingExpressions.isEmpty && agg.aggregateExpressions.length == 1 &&
          agg.child.exists {
            case Filter(condition, _) => condition.exists(_.isInstanceOf[StringPredicate])
            case _ => false
          } =>
        agg.aggregateExpressions.head match {
          case Alias(If(LessThanOrEqual(count: AggregateExpression, _: Literal),
              bits: AggregateExpression, Literal(null, BinaryType)), _) =>
            (bits.aggregateFunction, count.aggregateFunction) match {
              case (BloomFilterAggregate(XxHash64(Seq(key: Attribute), hashSeed), _, _, _, _),
                    Count(Seq(counted))) if hashSeed == seed && key.dataType == LongType &&
                  key.semanticEquals(counted) && !bits.isDistinct && !count.isDistinct &&
                  bits.filter.isEmpty && count.filter.isEmpty =>
                val metadata = if (conf.getConfString(
                    "spark.sql.optimizer.runtime.integralKeyBitmap.broadcast.enabled", "true").toBoolean) {
                  new MetadataBuilder().putBoolean(IntegralKeyBroadcast.marker, true).build()
                } else Metadata.empty
                val result = Alias(CollectLongKeyBitmap(key, budget).toAggregateExpression(), "integralKeys")(
                  explicitMetadata = Some(metadata))
                Some(scalar.copy(plan = agg.copy(aggregateExpressions = Seq(result)),
                  exprId = NamedExpression.newExprId))
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    if (!conf.getConfString("spark.sql.optimizer.runtime.integralKeyBitmap.enabled", "false").toBoolean) return plan
    val threshold = conf.autoBroadcastJoinThreshold
    if (threshold < 8192) return plan
    val budget = math.min(threshold, 64L * 1024 * 1024).toInt
    val reuseOnly = conf.getConfString(
      "spark.sql.optimizer.runtime.integralKeyBitmap.reuseOnly", "false").toBoolean
    if (reuseOnly && !conf.subqueryReuseEnabled) return plan
    // Charge an exact domain to the distinct probe attributes that will share its physical
    // broadcast. Single-probe sites retain the existing bounded Bloom filter.
    val sharedBuilds = if (reuseOnly) {
      val probes = plan.collect { case Filter(condition, _) =>
        condition.collect {
          case Coalesce(Seq(BloomFilterMightContain(
              scalar: org.apache.spark.sql.catalyst.expressions.ScalarSubquery,
              XxHash64(Seq(key: Attribute), _)), Literal(true, _))) if key.dataType == LongType &&
                scalar.getTagValue(org.apache.spark.sql.catalyst.optimizer.GeneratedIntegralKeyDomain.tag)
                  .contains(true) => (scalar.canonicalized, key.exprId)
        }
      }.flatten
      probes.groupMap(_._1)(_._2).collect { case (build, keys) if keys.distinct.size > 1 => build }.toSet
    } else Set.empty[Expression]
    plan.transformUp {
      case filter: Filter =>
        val condition = filter.condition.transformUp {
          case original @ Coalesce(Seq(BloomFilterMightContain(
              scalar: org.apache.spark.sql.catalyst.expressions.ScalarSubquery,
              XxHash64(Seq(key: Attribute), seed)), Literal(true, _))) if key.dataType == LongType &&
                (!reuseOnly || sharedBuilds.contains(scalar.canonicalized)) =>
            build(scalar, seed, budget).map { query =>
              Coalesce(Seq(LongKeyBitmapContains(query, key), Literal.TrueLiteral))
            }.getOrElse(original)
        }
        if (condition.fastEquals(filter.condition)) filter else filter.copy(condition = condition)
    }
  }
}
