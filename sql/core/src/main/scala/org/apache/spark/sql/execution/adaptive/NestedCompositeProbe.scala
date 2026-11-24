package org.apache.spark.sql.execution.adaptive

import scala.collection.mutable.ArrayBuilder

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.codegen.{CodegenContext, ExprCode}
import org.apache.spark.sql.execution.{FilterExec,ProjectExec,SparkPlan}
import org.apache.spark.sql.execution.exchange.{ENSURE_REQUIREMENTS,ShuffleExchangeExec}
import org.apache.spark.sql.execution.joins.ShuffledJoin
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.types.{BooleanType,IntegerType}

private[adaptive] object NestedCompositeProbe {
  private def unproject(input: SparkPlan): SparkPlan = input match {
    case p: ProjectExec if p.projectList.forall(_.isInstanceOf[Attribute]) => unproject(p.child)
    case f: FilterExec if f.condition.deterministic => unproject(f.child)
    case x => x
  }

  def isBuild(input: SparkPlan, outerKeys: Seq[Expression],
      prunedInput: SparkPlan => Boolean): Boolean =
    matchesBuild(input,outerKeys,prunedInput,allowPipelined = false)

  def matchesBuild(input: SparkPlan, outerKeys: Seq[Expression],
      prunedInput: SparkPlan => Boolean, allowPipelined: Boolean): Boolean = input match {
    case s: org.apache.spark.sql.execution.SortExec if !s.global => matchesBuild(s.child,outerKeys,prunedInput,allowPipelined)
    case e: ShuffleExchangeExec if e.shuffleOrigin==ENSURE_REQUIREMENTS && (allowPipelined || !e.pipelined) =>
      unproject(e.child) match {
        case j: ShuffledJoin if j.joinType==Inner && !j.isSkewJoin &&
            j.leftKeys.length>outerKeys.length && j.children.forall(prunedInput) =>
          Seq(j.leftKeys,j.rightKeys).exists(ks=>outerKeys.forall(o=>ks.exists(_.semanticEquals(o))))
        case _ => false
      }
    case _ => false
  }

  def mix(key: Long): Int = {
    val x = (key ^ (key >>> 33)) * 0xff51afd7ed558ccdL
    val y = (x ^ (x >>> 33)) * 0xc4ceb9fe1a85ec53L
    (y ^ (y >>> 33)).toInt
  }

  def pack(first: Int,second: Int): Long =
    (first.toLong << 32) | (second.toLong & 0xffffffffL)

  def exact(build: ShuffleQueryStageExec, keys: Seq[Expression], rows: BigInt,
      budget: Long): Option[PackedPairLookup] = {
    if (keys.size!=2 || !keys.forall(_.dataType==IntegerType) || rows<=0 ||
        rows > (1 << 26) || rows*16 > budget) return None
    val size=Integer.highestOneBit((rows.toInt*2-1).max(1)) << 1
    if (size.toLong*8 > budget) return None
    val output=build.output
    val parts=build.execute().mapPartitions { it =>
      val project=UnsafeProjection.create(keys,output)
      val found=new ArrayBuilder.ofLong
      it.foreach { raw =>
        val k=project(raw)
        if (!k.isNullAt(0) && !k.isNullAt(1)) found+=pack(k.getInt(0),k.getInt(1))
      }
      Iterator.single(found.result())
    }.collect()
    if (parts.iterator.map(_.length.toLong).sum>rows) return None
    val words=new Array[Long](size)
    val mask=size-1
    var zero=false
    parts.foreach(_.foreach { k =>
      if (k==0L) zero=true
      else {
        var pos=mix(k)&mask
        while (words(pos)!=0L && words(pos)!=k) pos=(pos+1)&mask
        words(pos)=k
      }
    })
    Some(new PackedPairLookup(build.session.sparkContext.broadcast(words),zero))
  }
}

final class PackedPairLookup(private val handle: Broadcast[Array[Long]], val zero: Boolean)
    extends Serializable {
  @transient private lazy val words=handle.value
  def contains(a: Int,b: Int): Boolean = {
    val key=NestedCompositeProbe.pack(a,b)
    if (key==0L) return zero
    val data=words;val mask=data.length-1
    var pos=NestedCompositeProbe.mix(key)&mask
    while (data(pos)!=0L && data(pos)!=key) pos=(pos+1)&mask
    data(pos)==key
  }
}

case class NestedPairContains(left: Expression,right: Expression,lookup: PackedPairLookup)
    extends BinaryExpression with Predicate {
  override def dataType=BooleanType
  override protected def nullSafeEval(a: Any,b: Any): Any=lookup.contains(a.asInstanceOf[Int],b.asInstanceOf[Int])
  override protected def doGenCode(ctx: CodegenContext, ev: ExprCode): ExprCode = {
    val ref=ctx.addReferenceObj("pairDomain",lookup,classOf[PackedPairLookup].getName)
    nullSafeCodeGen(ctx,ev,(a,b)=>s"${ev.value} = $ref.contains($a,$b);")
  }
  override protected def withNewChildrenInternal(l: Expression,r: Expression): Expression=copy(left=l,right=r)
}
