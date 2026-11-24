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

package org.apache.spark.sql.execution.exchange

import scala.collection.mutable

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.sql.catalyst.expressions.{And, Attribute, EqualTo, Expression, Literal}
import org.apache.spark.sql.catalyst.expressions.aggregate.{Final, Partial}
import org.apache.spark.sql.catalyst.optimizer.{BuildLeft, BuildRight, BuildSide, JoinSelectionHelper}
import org.apache.spark.sql.catalyst.plans.logical.{Join, JoinHint}
import org.apache.spark.sql.catalyst.plans.physical.{HashPartitioning, RangePartitioning, UnknownPartitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{ExpandExec, FileSourceScanExec, FileSourceScanLike, FilterExec, ProjectExec, SortExec, SparkPlan, UnionExec}
import org.apache.spark.sql.execution.aggregate.BaseAggregateExec
import org.apache.spark.sql.execution.joins.{ShuffledHashJoinExec, SortMergeJoinExec}
import org.apache.spark.sql.internal.SQLConf

/**
 * Selects pipelined exchanges for opt-in batch queries using the configured transport.
 * Local channel execution requires the complete group to fit local capacity. Distributed
 * execution preserves shuffled-hash-join build boundaries when supported by the transport.
 * Unsupported consumers and exchange reuse retain regular execution unless the transport can
 * serve them. Streaming queries use their own exchange-selection rule.
 *
 * This rule runs during non-AQE preparation and in the opt-in AQE full-plan path once the
 * adaptive plan is visible. [[PipelinedShuffleEligibility]] owns the shared eligibility checks.
 */
object EnablePipelinedShuffle extends Rule[SparkPlan] with JoinSelectionHelper {

  val flexibleGroupedInput = org.apache.spark.sql.catalyst.trees.TreeNodeTag[Boolean](
    "org.apache.spark.sql.flexibleGroupedInput")

  // AQE may materialize the same source-set aggregate for other consumers while
  // sizing a join. A stable shuffle identity lets those consumers reuse its partials
  // instead of scanning the tagged union once per transport.
  private val downstreamMembership = org.apache.spark.sql.catalyst.trees.TreeNodeTag[Boolean](
    "org.apache.spark.sql.membershipSourceSet")
  private def markMembershipInputs(input: SparkPlan): Unit = {
    def mark(build: SparkPlan): Unit = build.foreach {
      case e: ShuffleExchangeExec if taggedUnionPartial(e) =>
        e.child.setTagValue(downstreamMembership, true)
      case _ =>
    }
    input.foreach {
      case j: ShuffledHashJoinExec if j.joinType == org.apache.spark.sql.catalyst.plans.LeftSemi => mark(j.right)
      case j: org.apache.spark.sql.execution.joins.BroadcastHashJoinExec
          if j.joinType == org.apache.spark.sql.catalyst.plans.LeftSemi => mark(j.right)
      case _ =>
    }
  }

  private def isRawMembershipMerge(a: BaseAggregateExec, e: ShuffleExchangeExec): Boolean =
    e.shuffleOrigin == ENSURE_REQUIREMENTS && e.outputPartitioning.isInstanceOf[HashPartitioning] &&
      a.groupingExpressions.nonEmpty && a.aggregateExpressions.size == 1 &&
      a.aggregateExpressions.forall { v =>
        v.mode == Final && !v.isDistinct && v.filter.isEmpty &&
          v.aggregateFunction.isInstanceOf[org.apache.spark.sql.catalyst.expressions.aggregate.BitOrAgg]
      } && (e.child match {
        case p: ProjectExec if p.child.isInstanceOf[UnionExec] =>
          p.child.children.size > 1 && p.projectList.forall {
            case _: Attribute => true
            case a: org.apache.spark.sql.catalyst.expressions.Alias => a.child.isInstanceOf[Attribute]
            case _ => false
          }
        case _ => false
      })

  private def sourceSetShuffle(e: ShuffleExchangeExec): Boolean =
    e.child.getTagValue(downstreamMembership).contains(true) && taggedUnionPartial(e)

  private def taggedUnionPartial(e: ShuffleExchangeExec): Boolean = e.child match {
    case p: BaseAggregateExec if p.child.isInstanceOf[UnionExec] =>
      val union = p.child.asInstanceOf[UnionExec]
      union.children.size > 1 && p.groupingExpressions.nonEmpty &&
        p.aggregateExpressions.size == 1 && p.aggregateExpressions.forall { a =>
          a.mode == Partial && !a.isDistinct && a.filter.isEmpty &&
            a.aggregateFunction.isInstanceOf[
              org.apache.spark.sql.catalyst.expressions.aggregate.BitOrAgg]
        }
    case _ => false
  }

  private val originalBucketCount = org.apache.spark.sql.catalyst.trees.TreeNodeTag[Int](
    "org.apache.spark.sql.originalHashPipelineBucketCount")

  // Resizing serves resident readers. When an entire set of matching inputs stays
  // materialized, allow AQE to coalesce its original buckets using measured sizes.
  private[sql] def restoreMaterializedWidths(plan: SparkPlan): SparkPlan = {
    if (preserveTransport.get()) return plan
    val active = plan.collectWithSubqueries {
      case q: org.apache.spark.sql.execution.adaptive.QueryStageExec => q.plan.canonicalized
    }.toSet
    val widths = plan.collect {
      case e: ShuffleExchangeExec if !e.pipelined && e.shuffleOrigin == ENSURE_REQUIREMENTS &&
          e.outputPartitioning.isInstanceOf[HashPartitioning] && !active(e.canonicalized) &&
          e.getTagValue(originalBucketCount).exists(_ > e.outputPartitioning.numPartitions) =>
        e.id -> e.getTagValue(originalBucketCount).get
    }.toMap
    if (widths.isEmpty) return plan
    val memo = mutable.HashMap.empty[Int,SparkPlan]
    def restore(p: SparkPlan): SparkPlan = memo.getOrElseUpdate(p.id,p match {
      case r @ ReusedExchangeExec(_, owner) if widths.contains(owner.id) =>
        val updated = r.copy(child = restore(owner).asInstanceOf[Exchange])
        updated.copyTagsFrom(r)
        updated
      case other =>
        val next = other.mapChildren(restore)
        next match {
          case e: ShuffleExchangeExec if widths.contains(other.id) =>
            val part = e.outputPartitioning.asInstanceOf[HashPartitioning]
            val updated = e.copy(outputPartitioning = part.copy(numPartitions = widths(other.id)))
            updated.copyPipelinedTransportStateFrom(e)
            updated.copyTagsFrom(e)
            e.logicalLink.foreach(updated.setLogicalLink)
            updated
          case _ => next
        }
    })
    val restored = restore(plan)
    if (ValidateRequirements.validate(restored)) restored else plan
  }

  private val preserveTransport = ThreadLocal.withInitial[Boolean](() => false)

  /** Apply only the reuse rewiring, keeping every exchange's current transport. */
  def rewireReuseOnly(plan: SparkPlan): SparkPlan = {
    preserveTransport.set(true)
    try apply(plan) finally preserveTransport.set(false)
  }

  // This policy uses a bounded resident group and the transport's existing credit
  // control. Static byte-window selection remains available on the original path.
  private def useTopologyPlanning: Boolean = {
    val settings = SparkEnv.get.conf
    conf.adaptiveExecutionEnabled &&
      conf.coalesceShufflePartitionsEnabled &&
      conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION) > 0 &&
      !SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor &&
      SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary &&
      settings.getBoolean("spark.shuffle.streaming.groupAdmission.enabled", false) &&
      settings.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled", false) &&
      settings.getBoolean("spark.shuffle.streaming.readyQuota.enabled", false)
  }

  // A completed broadcast of a scan contributes no shuffle partitioning and
  // owns no shuffle outputs. An AQE replan can still size its unsubmitted
  // exchanges. Keep the original width if a stage depends on any shuffle.
  private[sql] def hasFixedShuffleStages(input: SparkPlan): Boolean = {
    import org.apache.spark.sql.execution.adaptive.{BroadcastQueryStageExec, QueryStageExec}
    def containsShuffle(plan: SparkPlan): Boolean = plan.exists {
      case _: ShuffleExchangeLike | _: QueryStageExec => true
      case r: ReusedExchangeExec => containsShuffle(r.child)
      case node => node.subqueries.nonEmpty
    }
    input.exists {
      case b: BroadcastQueryStageExec => !b.isMaterialized || containsShuffle(b.plan)
      case _: QueryStageExec => true
      case _ => false
    }
  }

  // An explicit repartition or materialized input fixes the shape of its segment.
  // Each fresh segment ends at a broadcast, range, or single-partition boundary.
  // Hash exchanges in a segment use the same upper bound so a join retains
  // matching partitions even when either child contains intermediate joins.
  private def sizePipelineSegments(input: SparkPlan, alignReuse: Boolean, reserveWriterWave: Boolean = false): SparkPlan = {
    if (preserveTransport.get() ||
        hasFixedShuffleStages(input)) {
      return input
    }
    val sc = input.session.sparkContext
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val budget = math.floor(slots * conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION))
    val charge = PipelinedShuffleEligibility.readerSlotCharge(SparkEnv.get.conf)
    val window = math.max(1, SparkEnv.get.conf.getInt(
      "spark.shuffle.streaming.groupAdmission.producerWindow", 1))
    if (budget <= window || charge <= 0) return input
    val widths = mutable.HashMap.empty[Int, Int]
    // AQE may still reuse canonical twins across subqueries. Keep both ends at
    // their current width so later stage-cache lookups continue to match.
    val copies = input.collectWithSubqueries {
      case e: ShuffleExchangeExec => e.canonicalized
      case r: ReusedExchangeExec => r.child.canonicalized
    }.groupMapReduce(identity)(_ => 1)(_ + _)

    val direct = input.collect { case e: Exchange => e.id -> e }.toMap
    val localRefs = input.collect { case r: ReusedExchangeExec => r.child }
    val localForms = (direct.valuesIterator ++ localRefs.iterator).toSeq.groupBy(_.canonicalized)
    // Resize a reused family only when every reference and its owner are visible
    // in this scope. Query stages and cross-subquery references retain their width.
    val localShared = if (!alignReuse) Set.empty[SparkPlan] else localForms.collect {
      case (form, xs) if xs.size > 1 && copies.get(form).contains(xs.size) &&
          xs.forall(e => direct.contains(e.id)) => form
    }.toSet
    // Co-partitioned children must agree on the partition count. Link only the
    // frontiers of the same operator. A reused input pins its peers but does not
    // pin an unrelated join on the far side of a hash exchange.
    val parent = mutable.HashMap.empty[Int, Int]
    def group(id: Int): Int = {
      val next = parent.getOrElse(id, id)
      if (next == id) id else {
        val root = group(next)
        parent(id) = root
        root
      }
    }
    localShared.foreach { form =>
      val family = localForms(form)
      family.tail.foreach(e => parent(group(e.id)) = group(family.head.id))
    }
    val fixed = mutable.HashSet.empty[Int]
    fixed ++= input.collect { case e: ShuffleExchangeExec if sourceSetShuffle(e) => e.id }
    val preferred = mutable.HashMap.empty[Int, Int]
    val minimumWidth = mutable.HashMap.empty[Int, Int]
    def front(p: SparkPlan): Seq[ShuffleExchangeExec] = p match {
      case e: ShuffleExchangeExec => Seq(e)
      case ReusedExchangeExec(_, e: ShuffleExchangeExec) => Seq(e)
      case _: Exchange => Nil
      case other => other.children.flatMap(front)
    }
    // Size both uses of a materialized grouped CTE independently of which
    // broadcasts have finished in the enclosing adaptive query stage.
    val sharedDepth = mutable.HashMap.empty[Int,Int]
    def hashDepth(p: SparkPlan): Int = p match {
      case e: ShuffleExchangeExec if e.shuffleOrigin == ENSURE_REQUIREMENTS &&
          e.outputPartitioning.isInstanceOf[HashPartitioning] => 1 + hashDepth(e.child)
      case _: Exchange | _: ReusedExchangeExec => 0
      case other => other.children.iterator.map(hashDepth).maxOption.getOrElse(0)
    }
    input.foreach {
      case e: ShuffleExchangeExec if e.logicalLink.exists(_.getTagValue(
          org.apache.spark.sql.execution.adaptive.CommonGroupThreshold.sharedOutput).contains(true)) =>
        // Only the shared subtree participates in its bucket choice. All
        // consumers therefore see the same count after independent AQE replans.
        val depth = math.max(1, hashDepth(e.child))
        e.child.foreach {
          case h: ShuffleExchangeExec if h.shuffleOrigin == ENSURE_REQUIREMENTS &&
              h.outputPartitioning.isInstanceOf[HashPartitioning] =>
            sharedDepth(h.id) = sharedDepth.getOrElse(h.id,0).max(depth)
          case _ =>
        }
      case _ =>
    }
    def sharedWidth(id: Int): Int = {
      val depth = sharedDepth(id)
      math.max(1, math.floor((budget - depth * window) / (depth * charge)).toInt)
    }
    // A composite fact join can stream billions of probe rows through a small set of
    // resident reducers even when Catalyst estimates a very selective build. For an
    // unpruned, direct file scan on each side, also budget the scan-to-shuffle segment.
    val scanBytesByExchange = mutable.HashMap.empty[Int, BigInt]
    def scanBytes(p: SparkPlan): Option[BigInt] = p match {
      case scan: FileSourceScanLike if scan.partitionFilters.isEmpty =>
        Some(BigInt(scan.relation.location.sizeInBytes))
      case f: FilterExec => scanBytes(f.child)
      case p: ProjectExec => scanBytes(p.child)
      case _ => None
    }
    if (sharedDepth.nonEmpty) input.foreach {
      case j: ShuffledHashJoinExec if j.leftKeys.size > 1 =>
        val left = front(j.left)
        val right = front(j.right)
        (left, right) match {
          case (Seq(l), Seq(r)) =>
            for (lb <- scanBytes(l.child); rb <- scanBytes(r.child)) {
              val bytes = lb.min(rb)
              Seq(l, r).foreach(e => scanBytesByExchange(e.id) =
                scanBytesByExchange.getOrElse(e.id, BigInt(0)).max(bytes))
            }
          case _ =>
        }
      case _ =>
    }
    val targetBytes = conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)
    // A nested hash build can delay all of a large fact scan's reducers.
    // Keep the original matching buckets when the resident reader width would
    // push even the projected probe bytes per reducer past the advisory target.
    val probeBytes = mutable.HashMap.empty[Int, BigInt]
    def nullChecks(e: Expression): Boolean = e match {
      case And(a, b) => nullChecks(a) && nullChecks(b)
      case org.apache.spark.sql.catalyst.expressions.IsNotNull(_: Attribute) => true
      case _ => false
    }
    def plainScan(p: SparkPlan): Option[FileSourceScanLike] = p match {
      case f: FileSourceScanLike if f.partitionFilters.isEmpty && f.dataFilters.forall(nullChecks) => Some(f)
      case p: ProjectExec => plainScan(p.child)
      case f: FilterExec if nullChecks(f.condition) => plainScan(f.child)
      case _ => None
    }
    input.foreach {
      case j: ShuffledHashJoinExec if j.leftKeys.size == 1 && j.rightKeys.size == 1 &&
          j.leftKeys.head.dataType == org.apache.spark.sql.types.LongType &&
          j.rightKeys.head.dataType == org.apache.spark.sql.types.LongType =>
        val (build,probe) = if (j.buildSide == BuildLeft) (j.left,j.right) else (j.right,j.left)
        if (front(build).exists(_.child.exists(_.isInstanceOf[ShuffledHashJoinExec]))) {
          front(probe).foreach { exchange =>
            plainScan(exchange.child).foreach { scan =>
              val full = scan.relation.dataSchema.fields.map(_.dataType.defaultSize.toLong).sum.max(1L)
              val projected = scan.requiredSchema.fields.map(_.dataType.defaultSize.toLong).sum.min(full)
              val bytes = BigInt(scan.relation.location.sizeInBytes) * projected / full
              probeBytes(exchange.id) = probeBytes.getOrElse(exchange.id,BigInt(0)).max(bytes)
            }
          }
        }
      case _ =>
    }
    val taskCpus = sc.getConf.getInt("spark.task.cpus", 1)
    val taskSlotsPerExecutor = math.max(1, sc.getConf.getInt("spark.executor.cores", 1) / taskCpus)
    val executorCount = (slots + taskSlotsPerExecutor - 1) / taskSlotsPerExecutor
    def streamedScanBytes(p: SparkPlan): Option[BigInt] = p match {
      case scan: FileSourceScanLike => Some(BigInt(scan.relation.location.sizeInBytes))
      case p: ProjectExec => streamedScanBytes(p.child)
      case f: FilterExec => streamedScanBytes(f.child)
      case j: org.apache.spark.sql.execution.joins.BroadcastHashJoinExec =>
        streamedScanBytes(if (j.buildSide == BuildLeft) j.right else j.left)
      case _ => None
    }
    def segment(root: SparkPlan): Unit = {
      val hashes = mutable.ArrayBuffer.empty[ShuffleExchangeExec]
      val readerStages = mutable.HashSet.empty[Int]
      var leaves = 0
      def visit(p: SparkPlan, stage: Int): Unit = p match {
        case e: ShuffleExchangeExec if (e.shuffleOrigin == ENSURE_REQUIREMENTS ||
            (e.shuffleOrigin == REPARTITION_BY_COL &&
              e.logicalLink.exists(_.getTagValue(flexibleGroupedInput).contains(true)))) &&
            e.outputPartitioning.isInstanceOf[HashPartitioning] =>
          hashes += e
          if (e.pipelined || (copies.getOrElse(e.canonicalized, 0) != 1 && !localShared(e.canonicalized))) fixed += e.id
          readerStages += stage
          visit(e.child, e.id)
        case e: Exchange =>
          leaves += 1
          fixed += e.id
          segment(e.child)
        case ReusedExchangeExec(_, e) =>
          leaves += 1
          if (!localShared(e.canonicalized)) fixed += e.id
        case leaf if leaf.children.isEmpty => leaves += 1
        case other =>
          val clustered = other.children.zip(other.requiredChildDistribution).collect {
            case (c, _: org.apache.spark.sql.catalyst.plans.physical.ClusteredDistribution) => c
          }
          if (clustered.size > 1) {
            val fronts = clustered.map(front)
            val all = fronts.flatten
            all.headOption.foreach { first =>
              all.tail.foreach(e => parent(group(e.id)) = group(first.id))
              if (fronts.exists(_.isEmpty)) fixed += first.id
            }
          }
          other.children.foreach(visit(_, stage))
      }
      visit(root, -1)
      if (hashes.nonEmpty) {
        val remaining = budget - math.max(1, leaves).toDouble * window
        // Readers remain resident until all writers drain. For the alternate
        // placement, leave a full wave of slots for writers even when a stage
        // needs to take over from its upstream readers.
        val totalCharge = charge * readerStages.size + (if (reserveWriterWave) 1.0 else 0.0)
        val width = math.floor(remaining / totalCharge).toInt
        hashes.foreach { e =>
          if (width < 1 || probeBytes.get(e.id).exists(_ > BigInt(width) * targetBytes) ||
              (sharedDepth.contains(e.id) &&
              scanBytesByExchange.get(e.id).exists(_ > BigInt(width) * targetBytes))) fixed += e.id
          else {
            preferred(e.id) = math.min(if (sharedDepth.contains(e.id)) sharedWidth(e.id) else width,
              e.outputPartitioning.numPartitions)
            // Size a large scan for a resident reader stage. Group admission may
            // separate branches when their combined reader demand exceeds the budget.
            if (width < executorCount) streamedScanBytes(e.child).foreach { bytes =>
              if (bytes > BigInt(width) * targetBytes) {
                val resident = math.max(1, math.floor((budget - window) / charge).toInt)
                val needed = (bytes + targetBytes - 1) / targetBytes
                minimumWidth(e.id) = needed.min(BigInt(resident)).toInt
              }
            }
          }
        }
      }
    }
    segment(input)
    val fixedGroups = fixed.iterator.map(group).toSet
    preferred.toSeq.groupBy(x => group(x._1)).foreach { case (g, members) =>
      if (!fixedGroups(g)) {
        val preferredWidth = members.map(_._2).min
        val lowerBound = members.iterator.map { case (id, _) => minimumWidth.getOrElse(id, 1) }.max
        val upperBound = members.iterator.map { case (id, _) => direct(id).outputPartitioning.numPartitions }.min
        val width = preferredWidth.max(lowerBound).min(upperBound)
        members.foreach { case (id, _) => widths(id) = width }
      }
    }
    if (widths.isEmpty) return input
    val rebuilt = mutable.HashMap.empty[Int, SparkPlan]
    def rebuild(p: SparkPlan): SparkPlan = rebuilt.getOrElseUpdate(p.id, p match {
      case r: ReusedExchangeExec if alignReuse && direct.contains(r.child.id) =>
        val owner = rebuild(r.child).asInstanceOf[Exchange]
        if (owner eq r.child) r else {
          val result = r.copy(child = owner)
          result.copyTagsFrom(r)
          result
        }
      case other =>
        val withChildren = other.mapChildren(rebuild)
        withChildren match {
          case e: ShuffleExchangeExec if widths.get(other.id)
              .exists(_ != e.outputPartitioning.numPartitions) =>
            val h = e.outputPartitioning.asInstanceOf[HashPartitioning]
            val result = e.copy(outputPartitioning = h.copy(numPartitions = widths(other.id)))
            result.copyPipelinedTransportStateFrom(e)
            result.copyTagsFrom(e)
            result.setTagValue(originalBucketCount,
              e.getTagValue(originalBucketCount).getOrElse(h.numPartitions))
            e.logicalLink.foreach(result.setLogicalLink)
            result
          case _ => withChildren
        }
    })
    val sized = rebuild(input)
    val preservesTwins = localShared.forall { form =>
      localForms(form).map(e => rebuilt(e.id).canonicalized).distinct.size == 1
    }
    if (preservesTwins && ValidateRequirements.validate(sized)) sized else input
  }

  def planHashPipelines(input: SparkPlan): SparkPlan = {
    if (!conf.getConf(SQLConf.DISTRIBUTED_PIPELINED_SHUFFLE_ENABLED) ||
        input.exists(_.logicalLink.exists(_.isStreaming)) ||
        preserveTransport.get() ||
        hasFixedShuffleStages(input)) {
      return input
    }
    val joins = org.apache.spark.sql.execution.adaptive.PipelinedHashJoinConversion(input)
    if (!ValidateRequirements.validate(joins)) return input
    markMembershipInputs(joins)
    if (!PipelinedShuffleEligibility.enabled(joins, conf) || !useTopologyPlanning) return joins
    def selectSized(sized: SparkPlan): SparkPlan = {
      val selected = selectTransport(sized, topology = true)
      if (!ValidateRequirements.validate(selected)) joins
      else if ((sized ne joins) && !selected.exists {
        case e: ShuffleExchangeExec => e.pipelined
        case _ => false
      }) selectTransport(joins, topology = true) else selected
    }
    val baseline = sizePipelineSegments(joins, alignReuse = false)
    val original = selectSized(baseline)
    val aligned = sizePipelineSegments(joins, alignReuse = true)
    def pipelines(p: SparkPlan): Set[Int] = p.collectWithSubqueries {
      case e: ShuffleExchangeExec if e.pipelined => e.pipelinedReuseKey
    }.toSet
    def improve(current: SparkPlan, alternative: SparkPlan): SparkPlan = {
      val before = pipelines(current)
      val candidate = selectSized(alternative)
      val after = pipelines(candidate)
      if (after.size > before.size && before.subsetOf(after)) candidate else current
    }
    val best = if (aligned.fastEquals(baseline)) original else improve(original, aligned)
    val hasRegularHash = best.exists {
      case e: ShuffleExchangeExec => !e.pipelined && e.shuffleOrigin == ENSURE_REQUIREMENTS &&
        e.outputPartitioning.isInstanceOf[HashPartitioning]
      case _ => false
    }
    if (!hasRegularHash) return best
    val reserved = sizePipelineSegments(joins, alignReuse = true, reserveWriterWave = true)
    if (reserved.fastEquals(aligned) || reserved.fastEquals(baseline)) best else improve(best, reserved)
  }

  override def apply(input: SparkPlan): SparkPlan = restoreMaterializedWidths(selectTransport(input, topology = false))

  private def selectTransport(inputPlan: SparkPlan, topology: Boolean): SparkPlan = {
    // Shared environment gate (opt-in flag and manager-specific deployment requirements),
    // identical to the AQE rule's -- see PipelinedShuffleEligibility for why it is a correctness
    // gate. Under normal query preparation AQE hides the exchanges from this rule; AQE full-plan
    // mode also invokes it directly after the adaptive plan is visible.
    if (!PipelinedShuffleEligibility.enabled(inputPlan, conf)) return inputPlan

    // The final hash aggregate accepts successive partial buffers. Select an isolated grouping
    // sets exchange with fixed-width keys, never a user-requested repartition or a reused input.
    val mergeMode = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.compactGroupingSetsMerge", "default")
    val trial = (mergeMode == "block" || mergeMode == "pipeline") && !preserveTransport.get() &&
      SparkEnv.get.conf.getBoolean("spark.shuffle.streaming.sharedTaskPermits.enabled", false) &&
      SparkEnv.get.conf.getBoolean("spark.shuffle.streaming.readyQuota.enabled", false)
    def compactInput(a: BaseAggregateExec): Option[ShuffleExchangeExec] = a.child match {
      case e @ ShuffleExchangeExec(h: HashPartitioning, p: BaseAggregateExec,
          ENSURE_REQUIREMENTS, _, _) if a.aggregateExpressions.nonEmpty &&
          a.aggregateExpressions.forall(_.mode == Final) && p.aggregateExpressions.nonEmpty &&
          p.aggregateExpressions.forall(_.mode == Partial) && p.child.isInstanceOf[ExpandExec] &&
          p.child.asInstanceOf[ExpandExec].projections.size > 1 && h.expressions.nonEmpty &&
          h.expressions.size == p.groupingExpressions.size &&
          h.expressions.zip(p.groupingExpressions).forall { case (k, g) =>
            k.semanticEquals(g) && (k.dataType == org.apache.spark.sql.types.IntegerType ||
              k.dataType == org.apache.spark.sql.types.LongType)
          } => Some(e)
      case _ => None
    }
    // AQE replans between stages, so a canonical twin of an exchange that is already a
    // materialized (or materializing) query stage is no longer linked to it by reuse. Pipelining
    // the twin would compute the same shuffle again and give it a second, independent route set.
    // Keep it regular: AQE's stage cache then reuses the existing stage.
    // Query stages are leaves: descend into their plans (a broadcast stage can hold the twin).
    val materializedStageKeys: Set[SparkPlan] = {
      val keys = mutable.HashSet.empty[SparkPlan]
      def walk(p: SparkPlan): Unit = p.foreach {
        case q: org.apache.spark.sql.execution.adaptive.ShuffleQueryStageExec =>
          keys += q.canonicalized
          walk(q.plan)
        case q: org.apache.spark.sql.execution.adaptive.QueryStageExec => walk(q.plan)
        case r: ReusedExchangeExec => walk(r.child)
        case other => other.subqueries.foreach(walk)
      }
      walk(inputPlan)
      keys.toSet
    }
    def notMaterializedTwin(exchange: ShuffleExchangeExec): Boolean =
      materializedStageKeys.isEmpty ||
        !materializedStageKeys.contains(exchange.copy(pipelined = false).canonicalized)
    val plan = if (!trial) inputPlan else {
      val slots = inputPlan.session.sparkContext.maxNumConcurrentTasks(
        inputPlan.session.sparkContext.resourceProfileManager.defaultResourceProfile)
      val reused = inputPlan.collectWithSubqueries {
        case ReusedExchangeExec(_, e: ShuffleExchangeExec) => e.canonicalized
      }.toSet
      val candidate = inputPlan.transformUp {
        case a: BaseAggregateExec => compactInput(a).filter { e =>
          slots >= 2 && e.outputPartitioning.numPartitions > slots && !reused(e.canonicalized) &&
            notMaterializedTwin(e) 
        }.map { e =>
          val h = e.outputPartitioning.asInstanceOf[HashPartitioning]
          val copy = e.copy(outputPartitioning = h.copy(numPartitions = slots / 2))
          copy.copyTagsFrom(e)
          e.logicalLink.foreach(copy.setLogicalLink)
          a.withNewChildren(Seq(copy))
        }.getOrElse(a)
      }
      if (candidate.fastEquals(inputPlan) || ValidateRequirements.validate(candidate)) candidate
      else inputPlan
    }
    val compactMerges = if (trial) plan.collect {
      case a: BaseAggregateExec => compactInput(a).map(_.pipelinedReuseKey)
    }.flatten.toSet else Set.empty[Int]

    val shuffles = plan.collectWithSubqueries { case s: ShuffleExchangeExec => s }
    if (shuffles.isEmpty) return plan

    // Treat the main plan and each subquery as separate execution scopes. Reuse inside one scope
    // is concurrent fan-out; reuse whose selected exchange lives in another scope is a sequential
    // consumer and needs retained replay instead of an additional current-job reader inbox.
    val scopes = plan +: plan.subqueriesAll
    val directExchanges = scopes.flatMap(_.collect { case s: ShuffleExchangeExec => s })
    val reuseTargetByChildKey = mutable.HashMap.empty[Int, ShuffleExchangeExec]
    val sameScopeReuseCountByExchangeKey = mutable.HashMap.empty[Int, Int]
    val sequentialReplayCountByExchangeKey = mutable.HashMap.empty[Int, Int]
    scopes.foreach { scope =>
      val scopeExchanges = scope.collect { case s: ShuffleExchangeExec => s }
      val reused = scope.collect {
        case r @ ReusedExchangeExec(_, _: ShuffleExchangeExec) => r
      }
      reused.foreach { reusedExchange =>
        val reusedChild = reusedExchange.child.asInstanceOf[ShuffleExchangeExec]
        // AQE's result-stage codegen may copy the direct exchange while ReusedExchangeExec, a
        // leaf, still wraps the pre-codegen instance. Fall back to canonical identity so the
        // final transport rewrite reconnects both branches to the actual direct exchange.
        val target = scopeExchanges.find(_.pipelinedReuseKey == reusedChild.pipelinedReuseKey)
          .orElse(scopeExchanges.find(_.canonicalized == reusedChild.canonicalized))
          .orElse(directExchanges.find(
            _.pipelinedReuseKey == reusedChild.pipelinedReuseKey))
          .orElse(directExchanges.find(_.canonicalized == reusedChild.canonicalized))
          .getOrElse(reusedChild)
        reuseTargetByChildKey.update(reusedChild.pipelinedReuseKey, target)
        if (scopeExchanges.exists(_.pipelinedReuseKey == target.pipelinedReuseKey)) {
          sameScopeReuseCountByExchangeKey.update(
            target.pipelinedReuseKey,
            sameScopeReuseCountByExchangeKey.getOrElse(target.pipelinedReuseKey, 0) + 1)
        } else {
          sequentialReplayCountByExchangeKey.update(
            target.pipelinedReuseKey,
            sequentialReplayCountByExchangeKey.getOrElse(target.pipelinedReuseKey, 0) + 1)
        }
      }
    }
    val supportsFanOut = SparkEnv.get.pipelinedShuffleManager.supportsFanOut
    val supportsSequentialReplay =
      SparkEnv.get.pipelinedShuffleManager.supportsSequentialReplay

    // Only a finite, single-consumer merge of raw membership updates can wait for
    // full frames after the first producer has made its reader runnable.
    val membershipKeys = plan.collect {
      case a: BaseAggregateExec if a.child.isInstanceOf[ShuffleExchangeExec] =>
        val exchange = a.child.asInstanceOf[ShuffleExchangeExec]
        Option.when(isRawMembershipMerge(a, exchange))(exchange.pipelinedReuseKey)
    }.flatten.toSet

    def rewriteExchanges(decided: ShuffleExchangeExec => Boolean): SparkPlan = {
      // After stage creation (AQE result-stage rerun) only rewire reuse: changing an inline
      // exchange's transport there would leave a subtree that never went through stage creation.
      val shouldPipeline: ShuffleExchangeExec => Boolean =
        if (preserveTransport.get()) (e: ShuffleExchangeExec) => e.pipelined else decided
      val rewrittenByExchangeKey = mutable.HashMap.empty[Int, ShuffleExchangeExec]
      def rewritten(exchange: ShuffleExchangeExec): ShuffleExchangeExec = {
        rewrittenByExchangeKey.getOrElseUpdate(exchange.pipelinedReuseKey, {
          val asPipelined = shouldPipeline(exchange)
          val copied = if (exchange.pipelined == asPipelined) {
            exchange
          } else {
            val result = exchange.copy(pipelined = asPipelined)
            result.copyPipelinedTransportStateFrom(exchange)
            result.copyTagsFrom(exchange)
            exchange.logicalLink.foreach(result.setLogicalLink)
            result
          }
          if (asPipelined) {
            if (membershipKeys.contains(exchange.pipelinedReuseKey) &&
                !sameScopeReuseCountByExchangeKey.contains(exchange.pipelinedReuseKey) &&
                !sequentialReplayCountByExchangeKey.contains(exchange.pipelinedReuseKey)) {
              copied.setTagValue(ShuffleExchangeExec.finiteMembershipFrames, true)
            }
            copied.setPipelinedReaderRouteMultiplicity(
              1 + sameScopeReuseCountByExchangeKey.getOrElse(exchange.pipelinedReuseKey, 0))
            sequentialReplayCountByExchangeKey.get(exchange.pipelinedReuseKey).foreach {
              copied.addPipelinedSequentialReplays
            }
          }
          copied
        })
      }
      plan.transformUpWithSubqueries {
        // ReusedExchangeExec is a leaf in the SparkPlan tree, so its wrapped exchange is not
        // visited by an ordinary transformUp. Rewire it explicitly to the same copied instance.
        case r @ ReusedExchangeExec(_, s: ShuffleExchangeExec) =>
          r.copy(child = rewritten(reuseTargetByChildKey.getOrElse(s.pipelinedReuseKey, s)))
        case s: ShuffleExchangeExec => rewritten(s)
      }
    }

    if ((sameScopeReuseCountByExchangeKey.nonEmpty && !supportsFanOut) ||
        (sequentialReplayCountByExchangeKey.nonEmpty && !supportsSequentialReplay)) {
      // Not a warning: this is a normal, expected fallback (reuse is routine optimizer output,
      // e.g. self-joins), the query still runs correctly as a regular shuffle, and the user has
      // nothing to act on. Log at DEBUG as diagnostic ("why this query did not go pipelined")
      // rather than WARN, which would fire on every reuse-bearing query and read as a fault.
      logDebug("EnablePipelinedShuffle: plan has a reused shuffle exchange but the configured " +
        "manager lacks fan-out or sequential replay; leaving it regular.")
      return rewriteExchanges(_ => false)
    }

    // An operator that would read a shuffle in a way the configured transport cannot serve, or that
    // builds its own hidden regular shuffle, forces the whole plan regular (see class doc). Like
    // the reuse fallback this is a normal, expected outcome, so log at DEBUG rather than WARN.
    val supportsUnmaterializedRegularBoundary =
      SparkEnv.get.pipelinedShuffleManager.supportsUnmaterializedRegularBoundary
    // Cut a two-input hash-join chain at its probe when the probe producer itself
    // reads two shuffled inputs. A later build or AQE broadcast collection may open
    // that probe after the upstream reader has drained its streaming messages.
    def joinsBeforeExchange(p: SparkPlan): Boolean = p match {
      case j: ShuffledHashJoinExec =>
        val (probe, keys) =
          if (j.buildSide == BuildLeft) (j.right, j.rightKeys) else (j.left, j.leftKeys)
        val keyAttrs = org.apache.spark.sql.catalyst.expressions.AttributeSet(keys.flatMap(_.references))
        // A scalar runtime key filter opens another job before the streamed
        // input can run. Partition pruning on an unrelated scan or key does
        // not make this particular join probe replayable.
        val waitsForKeyFilter = probe.exists {
          case f: FilterExec => f.condition.exists { predicate =>
            predicate.children.exists(_.isInstanceOf[org.apache.spark.sql.execution.ScalarSubquery]) &&
              predicate.references.intersect(keyAttrs).nonEmpty
          }
          case _ => false
        }
        exchangeFrontier(j.left).nonEmpty && exchangeFrontier(j.right).nonEmpty && waitsForKeyFilter
      case _: Exchange | _: ReusedExchangeExec => false
      case other => other.children.exists(joinsBeforeExchange)
    }
    def nestedProbe(p: SparkPlan): Seq[Int] = p match {
      case e: ShuffleExchangeExec if joinsBeforeExchange(e.child) => Seq(e.pipelinedReuseKey)
      case r: ReusedExchangeExec => nestedProbe(r.child)
      case _: Exchange => Nil
      case other => other.children.flatMap(nestedProbe)
    }
    val retainedJoinProbes = plan.collectWithSubqueries {
      case j: ShuffledHashJoinExec =>
        val (build, probe) = if (j.buildSide == BuildLeft) (j.left, j.right) else (j.right, j.left)
        if (exchangeFrontier(build).nonEmpty) nestedProbe(probe) else Nil
    }.flatten.toSet
    val blockedReaders = if (topology) plan.collectWithSubqueries {
      case p if PipelinedShuffleEligibility.isUnsupportedConsumer(
          p, supportsUnmaterializedRegularBoundary) => p
    }.iterator.flatMap(_.children.flatMap(exchangeFrontier)).toSet else Set.empty[Int]
    if (!topology &&
        readsShuffleThroughUnsupportedConsumer(plan, supportsUnmaterializedRegularBoundary)) {
      logDebug("EnablePipelinedShuffle: a shuffle is read through an operator the configured " +
        "transport cannot serve (coalesce / cartesian product / a limit operator that builds a " +
        "hidden shuffle); leaving the plan regular.")
      return rewriteExchanges(_ => false)
    }

    if (SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor &&
        !PipelinedShuffleEligibility.fitsLocalCapacity(plan, shuffles.map(_.id).toSet)) {
      return rewriteExchanges(_ => false)
    }

    // A regular range-partitioned exchange samples its child in a separate job (RangePartitioner
    // sketch) before its own map job. Pipelined exchanges feeding that child would be consumed by
    // both jobs: the producers are recomputed (the whole scan runs twice) and the second job's
    // readers depend on cross-job replay. Keep that frontier regular so both jobs read the same
    // materialized output; deeper exchanges form an independent segment and may still pipeline.
    // The range exchange itself also stays regular: its partitioner is built from that same
    // sample, and a columnar transport may not support range partitioning on a pipelined route.
    val rangeSampledKeys: Set[Int] = plan.collectWithSubqueries {
      case s: ShuffleExchangeExec if s.outputPartitioning.isInstanceOf[RangePartitioning] => s
    }.iterator.flatMap(s => s.pipelinedReuseKey +: exchangeFrontier(s.child)).toSet
    // A union that concatenates its children (unknown output partitioning) runs task i over
    // partition (i - offset) of one child. Streaming receive inboxes are keyed by the task's
    // partition id, so a pipelined exchange read through such a union would register its readers
    // for reduce partitions the writers never produce and hang. Keep that frontier regular.
    val concatenatedUnionKeys: Set[Int] = plan.collectWithSubqueries {
      case u: UnionExec if u.outputPartitioning.isInstanceOf[UnknownPartitioning] => u
    }.iterator.flatMap(_.children.flatMap(exchangeFrontier)).toSet
    // A reused exchange stays regular. Its ReusedExchangeExec leaf hides the wrapped subtree from
    // the backend's columnar rules inside any non-result stage, so a pipelined reuse would run an
    // unconverted (row) producer there; AQE's stage cache already shares a regular stage.
    val reusedKeys: Set[Int] = plan.collectWithSubqueries {
      case ReusedExchangeExec(_, e: ShuffleExchangeExec) => e.pipelinedReuseKey
    }.toSet
    // A partial aggregate's exchange feeds a final aggregate that does little work and cannot emit
    // before its input ends. Pipelining it only parks the readers on slots for the whole producer
    // phase (taking capacity from producers) and saves at most the tiny final stage. Keep it
    // regular unless explicitly requested.
    val pipelinePartialAggregates = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.partialAggregateExchanges", "true").toBoolean
    def feedsFromPartialAggregate(exchange: ShuffleExchangeExec): Boolean = {
      def strip(p: SparkPlan): SparkPlan = p match {
        case project: ProjectExec => strip(project.child)
        case other => other
      }
      strip(exchange.child) match {
        case agg: BaseAggregateExec => agg.requiredChildDistributionExpressions.isEmpty
        case _ => false
      }
    }
    // Large shuffles: their producers saturate the cluster on their own, so resident readers only
    // take slots from them, while a materialized shuffle lets every slot run producers and then
    // readers. Pipeline only exchanges whose estimated input is at most this many bytes. The
    // estimate comes from the child's logical statistics (an upper bound without CBO); unknown
    // estimates are treated as small.
    val maxPipelinedBytes = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.maxEstimatedBytes", "-1").toLong
    // Tiny shuffles: a pipelined group pays a fixed cost (all readers launched and resident,
    // group admission, writer discovery) that dwarfs the few milliseconds its producers run, and
    // it gives up AQE partition coalescing. Keep exchanges whose estimated input is below this
    // many bytes regular. Unknown estimates keep the previous behaviour (eligible).
    val minPipelinedBytes = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.minEstimatedBytes", "-1").toLong
    def estimatedInputBytes(exchange: ShuffleExchangeExec): Option[BigInt] =
      exchange.child.logicalLink.orElse(exchange.child.collectFirst {
        case p if p.logicalLink.isDefined => p.logicalLink.get
      }).map(_.stats.sizeInBytes)
    val logSizeDecisions = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.logSizeDecisions", "false").toBoolean
    def smallEnough(exchange: ShuffleExchangeExec): Boolean = {
      val estimate = estimatedInputBytes(exchange)
      val ok = (maxPipelinedBytes < 0 || estimate.forall(_ <= maxPipelinedBytes)) &&
        (minPipelinedBytes < 0 || estimate.forall(_ >= minPipelinedBytes))
      if (logSizeDecisions) {
        logInfo(s"PipelinedSizeDecision key=${exchange.pipelinedReuseKey} " +
          s"partitions=${exchange.outputPartitioning.numPartitions} " +
          s"estimatedBytes=${estimate.getOrElse(-1)} small=$ok")
      }
      ok
    }
    // An inline exchange has no map statistics for AQE. When a large probe input
    // already needs a durable shuffle, keep a filtered build key eligible for
    // conversion to broadcast instead of forcing a sort-merge reader.
    val adaptiveBuildKeys = if (!preserveTransport.get() && conf.adaptiveExecutionEnabled &&
        maxPipelinedBytes >= 0 && conf.getConf(SQLConf.ADAPTIVE_AUTO_BROADCASTJOIN_THRESHOLD)
          .getOrElse(conf.autoBroadcastJoinThreshold) > 0 && conf.getConfString(
          "spark.sql.shuffle.distributedPipelined.preserveAdaptiveBroadcastKey.enabled",
          "false").toBoolean) {
      def direct(input: SparkPlan): Option[ShuffleExchangeExec] = input match {
        case s: SortExec if !s.global => direct(s.child)
        case e @ ShuffleExchangeExec(_: HashPartitioning, _, ENSURE_REQUIREMENTS, _, _) => Some(e)
        case _ => None
      }
      def matchesLiteral(pred: Expression, key: Attribute): Boolean = pred match {
        case And(a, b) => matchesLiteral(a, key) || matchesLiteral(b, key)
        case EqualTo(a: Attribute, l: Literal) => l.value != null && !a.semanticEquals(key)
        case EqualTo(l: Literal, a: Attribute) => l.value != null && !a.semanticEquals(key)
        case _ => false
      }
      def filteredScan(input: SparkPlan, key: Attribute): Boolean = input match {
        case ProjectExec(columns, child) if columns.forall(_.isInstanceOf[Attribute]) =>
          filteredScan(child, key)
        case FilterExec(pred, _: FileSourceScanExec) => pred.deterministic && matchesLiteral(pred, key)
        case _ => false
      }
      def durableKey(build: SparkPlan, keys: Seq[Expression], probe: SparkPlan): Option[Int] = for {
        b <- direct(build)
        p <- direct(probe)
        bytes <- estimatedInputBytes(p) if bytes > maxPipelinedBytes
        key <- b.output match { case Seq(k) => Some(k); case _ => None }
        if keys.size == 1 && keys.head.semanticEquals(key) && smallEnough(b) && filteredScan(b.child, key)
      } yield b.pipelinedReuseKey
      plan.collectWithSubqueries {
        case j: SortMergeJoinExec if j.logicalLink.collect { case join: Join => join.hint }
            .forall(_ == JoinHint.NONE) =>
          val left = if (canBuildBroadcastLeft(j.joinType)) durableKey(j.left, j.leftKeys, j.right) else None
          val right = if (canBuildBroadcastRight(j.joinType)) durableKey(j.right, j.rightKeys, j.left) else None
          left.toSeq ++ right
      }.flatten.toSet
    } else Set.empty[Int]
    // A partial runtime Bloom filter is serialized as binary, but its bitset
    // is bounded by the filter configuration. Account for the word rounding
    // and serialized header of each filter in the single partial row per map.
    def boundedBufferRow(a: BaseAggregateExec): Boolean = {
      import org.apache.spark.sql.catalyst.expressions.UnsafeRow
      import org.apache.spark.sql.catalyst.expressions.aggregate.BloomFilterAggregate
      import org.apache.spark.sql.types.DecimalType
      val bitmap = (BigInt(conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_BITS)) + 63) / 64 * 8
      def boundedType(v: Attribute): Boolean =
        UnsafeRow.isFixedLength(v.dataType) || v.dataType.isInstanceOf[DecimalType]
      val functions = a.aggregateExpressions.map(_.aggregateFunction)
      // Project the buffer attributes themselves. A computed binary expression
      // could exceed the bound of the aggregate that supplied its input.
      val buffers = functions.flatMap(f => f.aggBufferAttributes ++ f.inputAggBufferAttributes)
      val onlyBuffers = a.resultExpressions.forall {
        case v: Attribute => buffers.exists(_.semanticEquals(v))
        case _ => false
      }
      val blooms = functions.count(_.isInstanceOf[BloomFilterAggregate])
      onlyBuffers && functions.forall(f => f.isInstanceOf[BloomFilterAggregate] ||
        f.aggBufferAttributes.forall(boundedType)) &&
        blooms * (bitmap + 64) + BigInt(a.output.size) * 32 <=
          conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)
    }
    def topologyExchange(e: ShuffleExchangeExec): Boolean = topology && (e.outputPartitioning match {
        // These origins keep the original hash keys and number of buckets.
        // Rebalancing can still require materialized map statistics for skew handling.
        case _: HashPartitioning =>
          e.shuffleOrigin == ENSURE_REQUIREMENTS || e.shuffleOrigin == REPARTITION_BY_NUM ||
            e.shuffleOrigin == REPARTITION_BY_COL
        case org.apache.spark.sql.catalyst.plans.physical.SinglePartition
            if e.shuffleOrigin == ENSURE_REQUIREMENTS =>
          e.child match {
            case a: BaseAggregateExec => !a.isStreaming && a.groupingExpressions.isEmpty &&
              a.aggregateExpressions.nonEmpty &&
              a.aggregateExpressions.forall(x => x.mode == org.apache.spark.sql.catalyst.expressions.aggregate.Partial ||
                x.mode == org.apache.spark.sql.catalyst.expressions.aggregate.PartialMerge) &&
              (a.output.forall(v => org.apache.spark.sql.catalyst.expressions.UnsafeRow.isFixedLength(v.dataType)) || boundedBufferRow(a))
            case _ => false
          }
        case _ => false
      })
    val filteringBuilds = if (
        conf.getConfString("spark.sql.adaptive.measuredCompositeJoin", "off") == "filterHash" ||
        (topology && Set("exact", "filter").contains(
          conf.getConfString("spark.sql.adaptive.measuredNestedComposite", "off")))) {
      val measured = new org.apache.spark.sql.execution.adaptive.MeasuredCompositeJoin
      plan.collectWithSubqueries {
        case j: org.apache.spark.sql.execution.joins.ShuffledJoin => measured.filterBuild(j).map(_.pipelinedReuseKey)
      }.flatten.toSet
    } else Set.empty[Int]
    def notRangeSampled(exchange: ShuffleExchangeExec): Boolean =
      !sourceSetShuffle(exchange) && !filteringBuilds(exchange.pipelinedReuseKey) &&
      !retainedJoinProbes.contains(exchange.pipelinedReuseKey) &&
      !blockedReaders.contains(exchange.pipelinedReuseKey) &&
        !rangeSampledKeys.contains(exchange.pipelinedReuseKey) &&
        !reusedKeys.contains(exchange.pipelinedReuseKey) &&
        !concatenatedUnionKeys.contains(exchange.pipelinedReuseKey) &&
        !adaptiveBuildKeys.contains(exchange.pipelinedReuseKey) &&
        (if (compactMerges.contains(exchange.pipelinedReuseKey)) mergeMode == "pipeline"
         else topologyExchange(exchange) ||
           ((pipelinePartialAggregates || !feedsFromPartialAggregate(exchange)) && smallEnough(exchange))) &&
        notMaterializedTwin(exchange)

    // A shuffled hash join retains its build relation while it consumes the streamed side. Keep
    // every shuffle in each build subtree regular by default, so those smaller inputs materialize
    // before the corresponding probe pipeline starts. The experimental nested-probe mode keeps
    // only the immediate build frontiers regular. Exchanges on the streamed spine pipeline.
    // This asymmetric boundary lets a sampled reader build from durable input while an
    // unadmitted probe route applies real credit backpressure; it therefore needs neither an
    // all-reader memory reservation nor pre-attachment disk staging. A reused exchange is keyed
    // by pipelinedReuseKey so one physical exchange never receives contradictory transport modes.
    // A backend that executes sort-merge joins as hash joins (Gluten with
    // spark.gluten.sql.columnar.forceShuffledHashJoin) retains a build relation too; its build
    // side is chosen later, so mirror its choice: the only buildable side, else the smaller one.
    val sortMergeAsHash = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.sortMergeJoinAsHashJoin", "false").toBoolean
    val memoryRetainingJoins: Seq[SparkPlan] = plan.collectWithSubqueries {
      case join: ShuffledHashJoinExec =>
        if (join.buildSide == BuildLeft) join.left else join.right
      case smj: SortMergeJoinExec if sortMergeAsHash =>
        if (assumedHashBuildSide(smj) == BuildLeft) smj.left else smj.right
    }
    if (memoryRetainingJoins.nonEmpty && supportsUnmaterializedRegularBoundary) {
      val pipelineNestedProbes = conf.getConf(SQLConf.PIPELINED_SHUFFLE_NESTED_PROBE_ENABLED)
      // A durable exchange cuts the consumer's build dependency. Exchanges below that cut
      // belong to another execution segment and need not all be materialized. Still protect
      // every join's own build frontier, including joins nested inside another build subtree.
      def buildFrontier(node: SparkPlan): Seq[Int] = node match {
        case exchange: ShuffleExchangeExec => Seq(exchange.pipelinedReuseKey)
        case ReusedExchangeExec(_, exchange: ShuffleExchangeExec) =>
          Seq(exchange.pipelinedReuseKey)
        case other => other.children.flatMap(buildFrontier)
      }
      val regularBuildExchangeKeys: Set[Int] = memoryRetainingJoins.iterator.flatMap { buildPlan =>
        if (pipelineNestedProbes || topology) {
          buildFrontier(buildPlan)
        } else {
          buildPlan.collect {
            case exchange: ShuffleExchangeExec => exchange.pipelinedReuseKey
            case ReusedExchangeExec(_, exchange: ShuffleExchangeExec) =>
              exchange.pipelinedReuseKey
          }
        }
      }.toSet
      logDebug("EnablePipelinedShuffle: using regular build inputs and pipelined streamed " +
        "inputs for shuffled hash joins.")
      val base = capacityLimited(plan, e =>
        notRangeSampled(e) && !regularBuildExchangeKeys(e.pipelinedReuseKey))
      if (!topology ||
          !org.apache.spark.shuffle.streaming.HashShuffleTree.enabled(SparkEnv.get.conf)) {
        return rewriteExchanges(base)
      }
      val probes = shuffles.iterator.filter(base).map(_.pipelinedReuseKey).toSet
      val builds = shuffles.iterator.filter { e =>
        regularBuildExchangeKeys(e.pipelinedReuseKey) &&
          topologyExchange(e) && notRangeSampled(e)
      }.map(_.pipelinedReuseKey).toSet
      if (builds.isEmpty) return rewriteExchanges(base)
      val selected = capacityLimited(plan,
        e => probes(e.pipelinedReuseKey) || builds(e.pipelinedReuseKey), builds)
      // A materialized side dependency may have forced a cut during admission.
      // Keep the original placement if that cut would discard an existing probe.
      if (shuffles.exists(e => probes(e.pipelinedReuseKey) && !selected(e))) {
        return rewriteExchanges(base)
      }
      return rewriteExchanges(selected)
    }

    rewriteExchanges(capacityLimited(plan, notRangeSampled))
  }

  /** Build side a hash-join backend picks for a sort-merge join (mirrors Gluten's choice). */
  private def assumedHashBuildSide(smj: SortMergeJoinExec): BuildSide = {
    val leftOk = canBuildShuffledHashJoinLeft(smj.joinType)
    val rightOk = canBuildShuffledHashJoinRight(smj.joinType)
    if (!leftOk) BuildRight
    else if (!rightOk) BuildLeft
    else smj.logicalLink.collect { case j: Join =>
      val (l, r) = (j.left.stats, j.right.stats)
      if (l.sizeInBytes == r.sizeInBytes && l.rowCount.isDefined && r.rowCount.isDefined) {
        if (r.rowCount.get <= l.rowCount.get) BuildRight else BuildLeft
      } else if (r.sizeInBytes <= l.sizeInBytes) BuildRight else BuildLeft
    }.getOrElse(BuildLeft)
  }

  /** The nearest shuffle exchanges below `node`, without crossing another exchange. */
  private def exchangeFrontier(node: SparkPlan): Seq[Int] = node match {
    case exchange: ShuffleExchangeExec => Seq(exchange.pipelinedReuseKey)
    case ReusedExchangeExec(_, exchange: ShuffleExchangeExec) => Seq(exchange.pipelinedReuseKey)
    case other => other.children.flatMap(exchangeFrontier)
  }

  /**
   * Bound each connected pipelined group by the cluster's concurrent task capacity.
   *
   * Group admission must place every task of every stage that reads a pipelined exchange at
   * the same time (plus a minimum window for each pure producer). A long chain of pipelined
   * joins therefore needs several times the available slots and can never be admitted. This
   * mixes batch and pipelined execution instead: exchanges are kept pipelined bottom-up (the
   * deepest exchanges move the most data) while the resulting group's reader demand fits the
   * budget; an exchange that would exceed it is materialized as a regular shuffle, which cuts
   * the group into independently admitted segments. Stage task counts are taken from the
   * exchanges' partition counts.
   */
  private def capacityLimited(
      plan: SparkPlan,
      base: ShuffleExchangeExec => Boolean,
      treeBuilds: Set[Int] = Set.empty): ShuffleExchangeExec => Boolean = {
    val fraction = conf.getConf(SQLConf.PIPELINED_SHUFFLE_GROUP_SLOT_FRACTION)
    val budget = if (fraction <= 0 ||
        SparkEnv.get.pipelinedShuffleManager.requiresSingleExecutor) {
      0
    } else {
      SparkContext.getActive.map { sc =>
        val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
        math.floor(slots * fraction).toInt
      }.getOrElse(0)
    }
    if (budget <= 0) return e => base(e) && !treeBuilds(e.pipelinedReuseKey)

    // Assign stage ids by walking exchange boundaries. A stage is the plan root, a subquery
    // root, a broadcast build or an exchange's child; an exchange edge connects its producer
    // stage (rooted at the exchange child) to the consumer stage that contains the exchange.
    case class Edge(key: Int, consumer: Int, consumerTasks: Long, depth: Int)
    // A union concatenates its children's partitions unless it reports a known (co-partitioned)
    // output partitioning, so a stage reading pipelined input below a union runs the sum of its
    // branches' partitions as tasks, not the width of any single input exchange.
    val unknownWidth = Long.MaxValue / 4
    val unionTasks = mutable.HashMap.empty[Int, Long]
    val producerOf = mutable.HashMap.empty[Int, Int]
    val exchangeOf = mutable.HashMap.empty[Int, ShuffleExchangeExec]
    val edges = mutable.ArrayBuffer.empty[Edge]
    // Materialized boundaries (broadcast builds, subqueries): (producer stage, consumer stage).
    val barriers = mutable.ArrayBuffer.empty[(Int, Int)]
    // Total (unpruned) file bytes scanned per stage, to estimate scan stages' task counts.
    val scanBytes = mutable.HashMap.empty[Int, Long]
    var nextStage = 0
    def newStage(): Int = { nextStage += 1; nextStage }
    def visit(node: SparkPlan, stage: Int, depth: Int): Unit = node match {
      case e: ShuffleExchangeExec =>
        edges += Edge(e.pipelinedReuseKey, stage, e.outputPartitioning.numPartitions.toLong, depth)
        if (!producerOf.contains(e.pipelinedReuseKey)) {
          val producer = newStage()
          producerOf(e.pipelinedReuseKey) = producer
          exchangeOf(e.pipelinedReuseKey) = e
          visit(e.child, producer, depth + 1)
        }
      case ReusedExchangeExec(_, e: ShuffleExchangeExec) =>
        edges += Edge(e.pipelinedReuseKey, stage, e.outputPartitioning.numPartitions.toLong, depth)
      case u: UnionExec =>
        val width = u.outputPartitioning match {
          case _: UnknownPartitioning =>
            val parts = u.children.map(_.outputPartitioning.numPartitions.toLong)
            if (parts.exists(_ <= 0)) unknownWidth else parts.sum
          case p => p.numPartitions.toLong
        }
        unionTasks(stage) = unionTasks.getOrElse(stage, 0L) max width
        u.children.foreach(visit(_, stage, depth))
      case b: BroadcastExchangeLike =>
        val build = newStage()
        barriers += ((build, stage))
        visit(b.child, build, depth + 1)
      case other =>
        other match {
          case scan: FileSourceScanLike =>
            scanBytes(stage) = scanBytes.getOrElse(stage, 0L) + scan.relation.location.sizeInBytes
          case _ =>
        }
        other.children.foreach(visit(_, stage, depth))
        other.subqueries.foreach { sub =>
          val subStage = newStage()
          barriers += ((subStage, stage))
          visit(sub, subStage, depth + 1)
        }
    }
    visit(plan, newStage(), 0)

    val parent = mutable.HashMap.empty[Int, Int]
    def find(x: Int): Int = {
      val p = parent.getOrElse(x, x)
      if (p == x) x else { val r = find(p); parent(x) = r; r }
    }
    // Reader width per consumer stage over its kept pipelined inputs.
    val readerTasks = mutable.HashMap.empty[Int, Long]
    // Reader tasks may be charged a fraction of a CPU (spark.shuffle.streaming.reader.taskCpus /
    // readerProducer.taskCpus). Admission reserves that charge, so count reader demand in
    // default-task slots: a reader stage of N tasks needs ceil(N * charge) slots.
    val readerCharge = PipelinedShuffleEligibility.readerSlotCharge(SparkEnv.get.conf)
    def readerWidth(stage: Int, width: Long): Long =
      width max unionTasks.getOrElse(stage, 0L)
    def demand(width: Long): Long =
      if (width >= unknownWidth) width else math.ceil(width * readerCharge).toLong
    // Overlap only pays where the cluster has spare slots: a producer stage that fills the cluster
    // on its own gains nothing from resident readers, which only take slots from it. When set,
    // a pure producer counts its estimated task count against the budget (instead of the minimum
    // window of one slot), so a group is pipelined only if producers and readers fit together.
    val countProducers = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.countProducerTasks", "false").toBoolean
    val maxSplit = conf.filesMaxPartitionBytes
    val openCost = conf.filesOpenCostInBytes
    def producerTasks(stage: Int): Long = {
      val shuffleIn = edges.iterator.filter(_.consumer == stage).map(_.consumerTasks)
      // Mirrors FilePartition.maxSplitBytes; total file size overestimates pruned scans, which
      // only keeps more exchanges regular.
      val scanIn = scanBytes.get(stage).iterator.map { bytes =>
        val split = math.min(maxSplit, math.max(openCost, bytes / math.max(1, budget)))
        (bytes + split - 1) / math.max(1L, split)
      }
      (shuffleIn ++ scanIn ++ unionTasks.get(stage).iterator).foldLeft(1L)(_ max _)
    }
    val minimumProducerSlots = if (treeBuilds.isEmpty) 1L else
      SparkEnv.get.conf.getInt("spark.shuffle.streaming.groupAdmission.producerWindow", 1).toLong
    def stageDemand(widths: mutable.Map[Int, Long], stage: Int): Long =
      widths.get(stage).map(demand).getOrElse(if (countProducers) producerTasks(stage) else minimumProducerSlots)
    val kept = mutable.HashSet.empty[Int]
    val rejected = mutable.HashSet.empty[Int]
    // Optionally keep pipelined chains one level deep: an exchange whose producer stage already
    // reads a pipelined input would make its readers wait for the whole upstream chain while
    // holding slots, for little overlap. Edges are decided deepest-first, so the producer's own
    // inputs are already final here.
    val singleLevel = conf.getConfString(
      "spark.sql.shuffle.distributedPipelined.singleLevelGroups", "false").toBoolean
    // Deepest exchanges first; each reuse key is decided once for all of its consumers.
    edges.groupBy(_.key).toSeq.sortBy { case (key, es) => (treeBuilds(key), -es.map(_.depth).max) }.foreach {
      case (key, es) if exchangeOf.contains(key) && base(exchangeOf(key)) &&
          !(singleLevel && readerTasks.contains(producerOf(key))) =>
        val producer = producerOf(key)
        val stages = (producer +: es.map(_.consumer)).distinct
        val roots = stages.map(find).distinct
        // Tentatively merge: demand over the union of the affected groups.
        val merged = roots.flatMap(r => (1 to nextStage).filter(find(_) == r)).distinct
        val widths = mutable.HashMap.empty[Int, Long] ++=
          merged.flatMap(s => readerTasks.get(s).map(s -> _))
        es.foreach(e => widths(e.consumer) =
          readerWidth(e.consumer, widths.getOrElse(e.consumer, 0L) max e.consumerTasks))
        val total = (merged ++ es.map(_.consumer)).distinct.iterator
          .map(s => stageDemand(widths, s))
          .foldLeft(0L)((a, b) => math.min(unknownWidth, a + b))
        if (total <= budget) {
          kept += key
          es.foreach(e => readerTasks(e.consumer) =
            readerWidth(e.consumer, readerTasks.getOrElse(e.consumer, 0L) max e.consumerTasks))
          stages.tail.foreach(s => parent(find(s)) = find(stages.head))
        } else {
          rejected += key
        }
      case _ =>
    }
    // A group is admitted only after all of its stages are submitted, and a stage is submitted
    // only after its materialized parents finish. So no member may depend, through a regular
    // exchange or another materialized boundary, on a member of its own group. Cutting a group
    // can create such a path (e.g. through a reused exchange); detach the dependent reader.
    var conflict = true
    while (conflict) {
      val group = mutable.HashMap.empty[Int, Int]
      def root(x: Int): Int = {
        val p = group.getOrElse(x, x)
        if (p == x) x else { val r = root(p); group(x) = r; r }
      }
      val members = mutable.HashSet.empty[Int]
      edges.filter(e => kept(e.key) && producerOf.contains(e.key)).foreach { e =>
        members += producerOf(e.key) += e.consumer
        val (a, b) = (root(producerOf(e.key)), root(e.consumer))
        if (a != b) group(a) = b
      }
      val inputs = (edges.iterator.filter(e => producerOf.contains(e.key)).map { e =>
        e.consumer -> (producerOf(e.key), kept(e.key))
      } ++ barriers.iterator.map { case (p, c) => c -> (p, false) }).toSeq
        .groupBy(_._1).view.mapValues(_.map(_._2)).toMap
      def dependsRegularlyOnOwnGroup(stage: Int): Boolean = {
        val seen = mutable.HashSet.empty[(Int, Boolean)]
        def walk(s: Int, crossed: Boolean): Boolean = {
          if (!seen.add((s, crossed))) return false
          (crossed && members(s) && root(s) == root(stage)) ||
            inputs.getOrElse(s, Nil).exists { case (p, pipelined) => walk(p, crossed || !pipelined) }
        }
        inputs.getOrElse(stage, Nil).exists { case (p, pipelined) => walk(p, !pipelined) }
      }
      val bad = members.toSeq.sorted.find(dependsRegularlyOnOwnGroup)
      conflict = bad.isDefined
      bad.foreach { stage =>
        val keys = edges.filter(e => e.consumer == stage && kept(e.key)).map(_.key)
        val detach = if (keys.nonEmpty) keys else {
          edges.filter(e => kept(e.key) && producerOf.get(e.key).contains(stage)).map(_.key)
        }
        kept --= detach
        rejected ++= detach
      }
    }
    if (treeBuilds.nonEmpty) {
      // Verify exactly the kept graph, after capacity and materialized-boundary
      // cuts. The admission layer checks this shape again using actual shuffle IDs.
      val active = edges.filter(e => kept(e.key) && producerOf.contains(e.key))
      val groups = mutable.HashMap.empty[Int, Int]
      def root(id: Int): Int = groups.get(id) match {
        case Some(p) if p != id =>
          val r = root(p)
          groups(id) = r
          r
        case _ => id
      }
      active.foreach(e => groups(root(e.consumer)) = root(producerOf(e.key)))
      val invalid = active.groupBy(e => root(e.consumer)).valuesIterator.filter { group =>
        val inputs = group.groupBy(_.consumer)
        val outputs = group.iterator.map(e => producerOf(e.key) -> e.key).toMap
        val stages = (inputs.keySet ++ outputs.keySet).toSeq.map { id =>
          (id, inputs.get(id).toSeq.flatten.map(_.key).toSeq, outputs.get(id))
        }
        !org.apache.spark.shuffle.streaming.HashShuffleTree.supports(stages)
      }.flatMap(_.map(_.key)).filter(treeBuilds).toSet
      // Removing a tree edge can expose a new materialized dependency. Repeat
      // admission on the reduced candidate set so the cycle check sees that cut.
      if (invalid.nonEmpty) {
        return capacityLimited(plan, e => base(e) && !invalid(e.pipelinedReuseKey),
          treeBuilds -- invalid)
      }
      return e => kept(e.pipelinedReuseKey)
    }
    if (rejected.nonEmpty) {
      logDebug(s"EnablePipelinedShuffle: ${rejected.size} exchange(s) kept regular so every " +
        s"pipelined group fits $budget concurrent slots.")
    }
    exchange => base(exchange) && !rejected.contains(exchange.pipelinedReuseKey)
  }

  /** Check all child branches for a shuffle read through an unsupported consumer. */
  private def readsShuffleThroughUnsupportedConsumer(
      plan: SparkPlan,
      supportsUnmaterializedRegularBoundary: Boolean): Boolean = {
    def reachesShuffle(p: SparkPlan): Boolean = p match {
      case _: ShuffleExchangeExec => true
      case other => other.children.exists(reachesShuffle)
    }
    plan.exists {
      case p if PipelinedShuffleEligibility.isUnsupportedConsumer(
          p, supportsUnmaterializedRegularBoundary) =>
        p.children.exists(reachesShuffle)
      case _ => false
    }
  }
}
