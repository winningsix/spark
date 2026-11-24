package org.apache.spark.sql.execution.adaptive

import scala.collection.mutable

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.codegen.{CodegenContext, ExprCode}
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight}
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint}
import org.apache.spark.sql.catalyst.plans.physical.{Distribution, HashPartitioning}
import org.apache.spark.sql.execution.{FileSourceScanExec, FilterExec, SortExec, SparkPlan}
import org.apache.spark.sql.execution.exchange._
import org.apache.spark.sql.execution.joins.{ShuffledHashJoinExec, ShuffledJoin}
import org.apache.spark.sql.internal.SQLConf
import org.apache.spark.sql.types.{BooleanType, IntegerType, LongType}
import org.apache.spark.unsafe.hash.Murmur3_x86_32

private[adaptive] object CompositeKeyBits {
  def bit(hash: Int, seed: Int, words: Int): Int =
    Murmur3_x86_32.hashInt(hash, seed) & (words * 64 - 1)
}

final class CompositeHashLookup(private val handle: Broadcast[Array[Long]],
    val reducers: Int, val words: Int) extends Serializable {
  @transient private lazy val bits = handle.value
  def mightContain(hash: Int): Boolean = {
    val base = Math.floorMod(hash, reducers) * words
    val a = CompositeKeyBits.bit(hash, 17, words)
    val b = CompositeKeyBits.bit(hash, 71, words)
    (bits(base + (a >>> 6)) & (1L << a)) != 0 &&
      (bits(base + (b >>> 6)) & (1L << b)) != 0
  }
}

case class CompositeHashMayMatch(child: Expression, lookup: CompositeHashLookup)
    extends UnaryExpression with Predicate {
  override def dataType = BooleanType
  override protected def nullSafeEval(value: Any): Any = lookup.mightContain(value.asInstanceOf[Int])
  override protected def doGenCode(ctx: CodegenContext, ev: ExprCode): ExprCode = {
    val ref = ctx.addReferenceObj("compositeHash", lookup, classOf[CompositeHashLookup].getName)
    nullSafeCodeGen(ctx, ev, h => s"${ev.value} = $ref.mightContain($h);")
  }
  override protected def withNewChildInternal(c: Expression): Expression = copy(child = c)
}

/** Delay the unpruned writer until its pruned peer reports the actual shuffle size. */
private[sql] class MeasuredCompositeJoin {
  private type Identity = (Seq[ExprId], Seq[ExprId])
  private val pending = mutable.Map.empty[Identity, Int]
  private val nestedBuilds = mutable.Set.empty[Identity]
  private val exactFilters = mutable.Map.empty[(Int,Seq[ExprId]),Option[PackedPairLookup]]
  private def nestedMode = SQLConf.get.getConfString("spark.sql.adaptive.measuredNestedComposite","off")
  private def filterNested = nestedMode == "exact" || nestedMode == "filter"
  private def enabledNested = Set("defer","hash","filter","exact").contains(nestedMode)
  private val filters = mutable.Map.empty[(Int, Seq[ExprId], Int), Option[CompositeHashLookup]]

  private def mode = SQLConf.get.getConfString("spark.sql.adaptive.measuredCompositeJoin", "off")
  private def keys(j: ShuffledJoin, i: Int) = if (i == 0) j.leftKeys else j.rightKeys
  private def id(j: ShuffledJoin): Option[Identity] = {
    def ids(xs: Seq[Expression]) = xs.collect { case a: Attribute
        if a.dataType == IntegerType || a.dataType == LongType => a.exprId }
    val l = ids(j.leftKeys); val r = ids(j.rightKeys)
    Option.when(j.joinType == Inner && !j.isSkewJoin && l.size >= 2 && l.size == j.leftKeys.size &&
      r.size == l.size && r.size == j.rightKeys.size &&
      j.logicalLink.collect { case join: Join => join.hint }.contains(JoinHint.NONE))((l,r))
  }

  private def unsorted(p: SparkPlan): SparkPlan = p match {
    case s: SortExec if !s.global => s.child
    case other => other
  }
  private def edge(p: SparkPlan, allowPipelined: Boolean = false): Option[ShuffleExchangeExec] = unsorted(p) match {
    case e: ShuffleExchangeExec if (allowPipelined || !e.pipelined) && e.shuffleOrigin == ENSURE_REQUIREMENTS &&
        !e.child.exists(n => n.isInstanceOf[Exchange] || n.isInstanceOf[QueryStageExec]) => Some(e)
    case _ => None
  }
  private def rawScan(e: ShuffleExchangeExec) = e.child.collectFirst { case f: FileSourceScanExec => f }
  private def pruned(scan: FileSourceScanExec) = scan.partitionFilters.exists(_.exists {
    case DynamicPruningExpression(_: PlanExpression[_]) => true
    case DynamicPruningExpression(e) => e.exists(_.isInstanceOf[PlanExpression[_]])
    case _ => false
  })
  private def nestedSide(j: ShuffledJoin, planning: Boolean): Option[Int] = {
    def prunedScanSide(p: SparkPlan): Boolean = edge(p, allowPipelined = filterNested).flatMap(rawScan).exists(pruned)
    j.children.indices.find { i =>
      edge(j.children(1-i), allowPipelined = filterNested).flatMap(rawScan).exists { source =>
        pruned(source) && source.relation.sizeInBytes >= SQLConf.get.getConf(
          SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD)
      } && NestedCompositeProbe.matchesBuild(j.children(i),keys(j,i),prunedScanSide,planning)
    }
  }

  private def directBuild(j: ShuffledJoin, planning: Boolean): Option[Int] = for {
    left <- edge(j.left, allowPipelined = mode == "filterHash")
    right <- edge(j.right, allowPipelined = mode == "filterHash")
    a <- rawScan(left); b <- rawScan(right) if pruned(a) != pruned(b)
    index = if (pruned(a)) 0 else 1
    probe = if (index == 0) b else a
    build = if (index == 0) a else b
    if (planning || !(if (index == 0) left else right).pipelined) &&
      probe.relation.sizeInBytes > build.relation.sizeInBytes && probe.relation.sizeInBytes >=
        SQLConf.get.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD)
  } yield index

  private def acceptsLiveProbe(identity: Identity): Boolean =
    if (nestedBuilds(identity)) filterNested else mode == "filterHash"

  // Keep the measured owner while an unsubmitted probe can still take its filter.
  def filterBuild(j: ShuffledJoin): Option[ShuffleExchangeExec] = id(j).flatMap { _ =>
    val direct = if (mode == "filterHash") directBuild(j, planning = true) else None
    direct.orElse(if (filterNested) nestedSide(j, planning = true) else None)
      .flatMap(i => unsorted(j.children(i)) match {
        case e: ShuffleExchangeExec => Some(e)
        case _ => None
      })
  }

  def buildFirst(plan: SparkPlan): Option[Int] = {
    if (mode != "hash" && mode != "filterHash" && !enabledNested) return None
    plan match {
      case j: ShuffledJoin => id(j).flatMap { identity =>
        val fresh = directBuild(j, planning = false)
        if (mode=="hash" || mode=="filterHash") fresh.foreach(i => pending.update(identity,i))
        if (enabledNested && !pending.contains(identity)) {
          val chosen = nestedSide(j, planning = false)
          chosen.foreach { i => pending.update(identity,i);nestedBuilds+=identity }
        }
        pending.get(identity).filter(i => edge(j.children(1-i), acceptsLiveProbe(identity)).isDefined)
      }
      case _ => None
    }
  }

  private def measure(s: ShuffleQueryStageExec, exprs: Seq[Expression], n: Int,
      words: Int): Option[CompositeHashLookup] = {
    val rows = s.execute()
    if (rows.getNumPartitions != n) return None
    val output = s.output
    val parts = rows.mapPartitionsWithIndex { (bucket, it) =>
      val project = UnsafeProjection.create(Seq(Murmur3Hash(exprs, 42)), output)
      val bitmap = new Array[Long](words)
      var valid = true
      it.foreach { row =>
        val hash = project(row).getInt(0)
        if (Math.floorMod(hash,n) != bucket) valid = false
        val a = CompositeKeyBits.bit(hash,17,words); val b = CompositeKeyBits.bit(hash,71,words)
        bitmap(a >>> 6) |= 1L << a
        bitmap(b >>> 6) |= 1L << b
      }
      Iterator.single(if (valid) bitmap else Array.emptyLongArray)
    }.collect()
    if (parts.exists(_.length != words)) return None
    val filled = parts.iterator.flatMap(_.iterator).map(w => java.lang.Long.bitCount(w).toLong).sum
    if (filled * 2 >= n.toLong * words * 64) return None
    val table = new Array[Long](n * words)
    parts.indices.foreach(i => System.arraycopy(parts(i),0,table,i*words,words))
    Some(new CompositeHashLookup(s.session.sparkContext.broadcast(table),n,words))
  }

  def rewrite(plan: SparkPlan, required: Distribution, submitted: SparkPlan => Boolean): SparkPlan = {
    if (pending.isEmpty) return plan
    val used = plan.collectWithSubqueries { case ReusedExchangeExec(_,e: ShuffleExchangeExec) => e.canonicalized }.toSet
    val liveOwners = plan.collectWithSubqueries {
      case e: ShuffleExchangeExec if e.pipelined => e.canonicalized
    }.groupMapReduce(identity)(_ => 1)(_ + _)
    val next = plan.transformUp { case j: ShuffledJoin =>
      val updated = for {
        identity <- id(j); i <- pending.get(identity) if !nestedBuilds(identity) || nestedMode!="defer"
        s <- unsorted(j.children(i)) match { case stage: ShuffleQueryStageExec if stage.isMaterialized => Some(stage); case _ => None }
        target <- edge(j.children(1-i), acceptsLiveProbe(identity)) if !used(target.canonicalized) && !submitted(target.canonicalized)
        if !target.pipelined || (liveOwners.get(target.canonicalized).contains(1) &&
          !submitted(target.copy(pipelined = false).canonicalized))
        file <- rawScan(target)
        stats <- s.computeStats() if stats.isRuntime
        rows <- stats.rowCount if rows > 0
        h <- s.outputPartitioning match { case p: HashPartitioning if p.expressions.size == keys(j,i).size &&
          p.expressions.zip(keys(j,i)).forall { case (a,b) => a.semanticEquals(b) } => Some(p); case _ => None }
        memory = s.session.sparkContext.getConf.getSizeAsBytes("spark.executor.memory", "1g")
        cores = s.session.sparkContext.getConf.getInt("spark.executor.cores",1).max(1)
        // Entire fixed-width build, even if AQE coalesces it onto one reducer.
        if s.output.forall(a => a.dataType == IntegerType || a.dataType == LongType) &&
          rows * (96L + 8L*(s.output.size + keys(j,i).size)) <
            BigInt((memory.toDouble * s.session.sparkContext.getConf.getDouble("spark.memory.fraction",0.6) / (2L*cores)).toLong) &&
          stats.sizeInBytes * SQLConf.get.getConf(SQLConf.SHUFFLE_HASH_JOIN_FACTOR) < file.relation.sizeInBytes
      } yield {
        val n = h.numPartitions
        val budget = SQLConf.get.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
          .getOrElse(SQLConf.get.autoBroadcastJoinThreshold).min(64L << 20)
        val cap = (budget / n / 8).min(Int.MaxValue.toLong).toInt
        val desired = ((rows * 16 + n.toLong*64-1) / (n.toLong*64)).min(BigInt(Int.MaxValue)).toInt
        val words = if (cap > 0) Integer.highestOneBit(cap.min(desired.max(1))) else 0
        val nested=nestedBuilds(identity)
        val keyIds=if(i==0) identity._1 else identity._2
        val exact=if (nested && nestedMode=="exact") {
          exactFilters.getOrElseUpdate((s.shuffle.shuffleId,keyIds),NestedCompositeProbe.exact(s,keys(j,i),rows,budget))
        } else None
        val useBloom=if (nested) nestedMode=="filter" || (nestedMode=="exact" && exact.isEmpty) else mode=="filterHash"
        val lookup = if (useBloom && words > 0)
          filters.getOrElseUpdate((s.shuffle.shuffleId, if(i==0) identity._1 else identity._2, words),
            measure(s,keys(j,i),n,words)) else None
        val probeKeys=keys(j,1-i)
        val predicate=exact.map(t => NestedPairContains(probeKeys.head,probeKeys(1),t): Expression)
          .orElse(lookup.map(t => CompositeHashMayMatch(Murmur3Hash(probeKeys,42),t)))
        val probe = predicate.map { condition =>
          val filter = FilterExec(condition,target.child)
          target.child.logicalLink.foreach(filter.setLogicalLink)
          val exchange = target.withNewChildren(Seq(filter))
          exchange.copyTagsFrom(target); target.logicalLink.foreach(exchange.setLogicalLink)
          exchange
        }.getOrElse(target)
        val inputs = j.children.updated(i,s).updated(1-i,probe)
        val result = ShuffledHashJoinExec(j.leftKeys,j.rightKeys,Inner,
          if(i==0) BuildLeft else BuildRight,j.condition,inputs.head,inputs.last)
        j.logicalLink.foreach(result.setLogicalLink)
        result
      }
      updated.getOrElse(j)
    }
    if ((next ne plan) && ValidateRequirements.validate(next,required)) next else plan
  }
}
