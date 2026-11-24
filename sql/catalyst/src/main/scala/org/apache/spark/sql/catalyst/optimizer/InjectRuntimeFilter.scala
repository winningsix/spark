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

package org.apache.spark.sql.catalyst.optimizer

import scala.annotation.tailrec

import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.aggregate.{BloomFilterAggregate, Count}
import org.apache.spark.sql.catalyst.planning.ExtractEquiJoinKeys
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.catalyst.trees.TreePattern.{INVOKE, JSON_TO_STRUCT, LIKE_FAMLIY, PYTHON_UDF, REGEXP_EXTRACT_FAMILY, REGEXP_REPLACE, SCALA_UDF}
import org.apache.spark.sql.catalyst.util.UnsafeRowUtils
import org.apache.spark.sql.internal.SQLConf

/**
 * Insert a runtime filter on one side of the join (we call this side the application side) if
 * we can extract a runtime filter from the other side (creation side). A simple case is that
 * the creation side is a table scan with a selective filter.
 * The runtime filter is logically an IN subquery with the join keys. Currently it's always
 * bloom filter but we may add other physical implementations in the future.
 */
object InjectRuntimeFilter extends Rule[LogicalPlan] with PredicateHelper with JoinSelectionHelper {

  private case class FilterCreationSide(
      key: Expression,
      plan: LogicalPlan,
      useMaterializedThreshold: Boolean,
      materializedRowCount: Option[BigInt] = None,
      materializedSizeInBytes: Option[BigInt] = None)

  private def deferStringFilters: Boolean = conf.getConfString(
    "spark.sql.optimizer.runtime.bloomFilter.afterProbeFilters.enabled", "false").toBoolean

  private def boundedFilteredKeys(
      creation: LogicalPlan,
      buildKey: Expression,
      application: LogicalPlan,
      probeKey: Expression,
      stringFilter: Boolean): Boolean = {
    val setting = if (stringFilter) {
      "spark.sql.optimizer.runtime.bloomFilter.stringFilteredKeyProjection.enabled"
    } else {
      "spark.sql.optimizer.runtime.bloomFilter.boundedKeyProjection.enabled"
    }
    if (!conf.getConfString(setting, "false").toBoolean || !buildKey.isInstanceOf[Attribute] ||
        !probeKey.isInstanceOf[Attribute] || application.output.size <= 1) return false

    def scan(plan: LogicalPlan): Option[LeafNode] = plan match {
      case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => scan(child)
      case Filter(test, child) if test.deterministic && isSimpleExpression(test) &&
          !SubqueryExpression.hasSubquery(test) => scan(child)
      case leaf: LeafNode if !leaf.isStreaming && leaf.deterministic &&
          leaf.stats.sizeInBytes < conf.defaultSizeInBytes => Some(leaf)
      case _ => None
    }
    def literalFilter(p: LogicalPlan): Boolean = p.exists {
      case Filter(pred, _) => splitConjunctivePredicates(pred).exists {
        case test: StringPredicate if stringFilter =>
          (test.left, test.right) match {
            case (a: Attribute, lit: Literal) =>
              !a.semanticEquals(buildKey) && lit.value != null && lit.value.toString.nonEmpty
            case _ => false
          }
        case EqualTo(a: Attribute, lit: Literal) if !stringFilter => lit.value != null && !a.semanticEquals(buildKey)
        case EqualTo(lit: Literal, a: Attribute) if !stringFilter => lit.value != null && !a.semanticEquals(buildKey)
        case _ => false
      }
      case _ => false
    }
    // A probe already narrowed by a value predicate may write far fewer rows than
    // its file sizes suggest. Estimate avoided shuffle only for a direct, unfiltered scan.
    def groupInput(agg: Aggregate): Option[LogicalPlan] =
      Option.when(agg.deterministic && agg.groupingExpressions.exists(_.semanticEquals(probeKey)) &&
        agg.child.output.exists(_.semanticEquals(probeKey)))(agg.child)
    val probeInput = application match {
      case Filter(_: IsNotNull, agg: Aggregate) => groupInput(agg).getOrElse(application)
      case agg: Aggregate => groupInput(agg).getOrElse(application)
      case other => other
    }
    val unfilteredProbe = !probeInput.exists {
      case Filter(pred, _) => splitConjunctivePredicates(pred).exists {
        case IsNotNull(_: Attribute) => false
        case _ => true
      }
      case _ => false
    }
    unfilteredProbe && creation.output.size == 1 && creation.output.head.semanticEquals(buildKey) &&
      literalFilter(creation) && ((scan(creation), scan(probeInput)) match {
        case (Some(build), Some(probe)) =>
          val bytes = build.stats.sizeInBytes
          bytes > 0 && bytes * conf.getConf(SQLConf.SHUFFLE_HASH_JOIN_FACTOR) <
            probe.stats.sizeInBytes
        case _ => false
      })
  }

  private def injectBloomFilter(
      filterApplicationSideKey: Expression,
      filterApplicationSidePlan: LogicalPlan,
      filterCreationSide: FilterCreationSide,
      stringsOnly: Boolean): LogicalPlan = {
    val filterCreationSideKey = filterCreationSide.key
    val filterCreationSidePlan = filterCreationSide.plan
    val creationSideThreshold = if (filterCreationSide.useMaterializedThreshold) {
      conf.runtimeFilterMaterializedCreationSideThreshold
    } else {
      conf.runtimeFilterCreationSideThreshold
    }
    // Skip if the filter creation side is too big
    val exceeds = filterCreationSide.materializedSizeInBytes
      .getOrElse(filterCreationSidePlan.stats.sizeInBytes) > creationSideThreshold
    def hasBoundedKeys(stringFilter: Boolean): Boolean = exceeds &&
      !filterCreationSide.useMaterializedThreshold &&
      boundedFilteredKeys(filterCreationSidePlan, filterCreationSideKey,
        filterApplicationSidePlan, filterApplicationSideKey, stringFilter)
    val exactLiteral = !stringsOnly && hasBoundedKeys(stringFilter = false)
    val stringLiteral = (stringsOnly || !deferStringFilters) && !exactLiteral &&
      hasBoundedKeys(stringFilter = true)
    if (stringsOnly && !stringLiteral) return filterApplicationSidePlan
    val boundedKeys = exactLiteral || stringLiteral
    if (exceeds && !boundedKeys) {
      return filterApplicationSidePlan
    }
    val rowCount = filterCreationSide.materializedRowCount
      .orElse(filterCreationSidePlan.stats.rowCount)
    val bloomFilterAgg =
      if (stringLiteral) {
        // Substring and prefix filters may keep many distinct keys. Build within the
        // existing maximum sketch budget and check its expected saturation at runtime.
        new BloomFilterAggregate(new XxHash64(Seq(filterCreationSideKey)),
          Literal(conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_ITEMS)),
          Literal(conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_BITS)))
      } else if (boundedKeys) {
        new BloomFilterAggregate(new XxHash64(Seq(filterCreationSideKey)))
      } else if (rowCount.isDefined && rowCount.get.longValue > 0L) {
        new BloomFilterAggregate(new XxHash64(Seq(filterCreationSideKey)), rowCount.get.longValue)
      } else if (conf.pipelinedHashJoinPolicyEnabled) {
        // Without a row count the default sizing (1M items in 8M bits) saturates on a large
        // filtered dimension and passes nearly every row. Size for the policy's expected key
        // count instead, within the configured maximum number of bits.
        val expectedNumItems =
          conf.getConf(SQLConf.PIPELINED_HASH_JOIN_POLICY_RUNTIME_FILTER_EXPECTED_NUM_ITEMS)
        // A creation side far larger than the filter's capacity yields a saturated filter that
        // costs a full aggregation job and filters nothing, so do not build one.
        if (pipelinedPolicyRowEstimate(filterCreationSidePlan, conf) >
            conf.getConf(SQLConf.PIPELINED_HASH_JOIN_POLICY_RUNTIME_FILTER_MAX_ESTIMATED_ITEMS)) {
          return filterApplicationSidePlan
        }
        val numBits = math.min(
          org.apache.spark.util.sketch.BloomFilter.optimalNumOfBits(expectedNumItems, 0.03),
          conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_BITS))
        new BloomFilterAggregate(new XxHash64(Seq(filterCreationSideKey)),
          Literal(expectedNumItems), Literal(numBits))
      } else {
        new BloomFilterAggregate(new XxHash64(Seq(filterCreationSideKey)))
      }

    val bits = bloomFilterAgg.toAggregateExpression()
    val result = if (boundedKeys) {
      // Count the actual surviving keys in the same aggregation. An oversized creation
      // side returns NULL; the probe then passes through and the original join stays exact.
      val count = Count(Seq(filterCreationSideKey)).toAggregateExpression()
      val items = conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_ITEMS)
      val limit = if (stringLiteral) {
        val bitCount = conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_BITS).toDouble
        val hashes = math.max(1L, math.round(bitCount / items * math.log(2.0)))
        // Invert (1 - exp(-k * n / m))^k = 0.5. Beyond this load more than
        // half the absent keys are expected to pass the sketch. Duplicate keys
        // increase the count conservatively and never affect join correctness.
        (-bitCount / hashes * math.log1p(-math.pow(0.5, 1.0 / hashes))).toLong
      } else items
      If(LessThanOrEqual(count, Literal(limit)),
        bits, Literal.create(null, bits.dataType))
    } else bits
    val alias = Alias(result, "bloomFilter")()
    val aggregate =
      ConstantFolding(ColumnPruning(Aggregate(Nil, Seq(alias), filterCreationSidePlan)))
    // Runtime filters are introduced after subquery optimization, so Python UDFs in a new
    // creation-side subquery cannot be extracted into a Python evaluation operator.
    if (aggregate.containsPattern(PYTHON_UDF)) {
      return filterApplicationSidePlan
    }
    val bloomFilterSubquery = ScalarSubquery(aggregate, Nil)
    if (stringLiteral && conf.getConfString(
        "spark.sql.optimizer.runtime.integralKeyBitmap.enabled", "false").toBoolean) {
      bloomFilterSubquery.setTagValue(GeneratedIntegralKeyDomain.tag, true)
    }
    val filter = BloomFilterMightContain(bloomFilterSubquery,
      new XxHash64(Seq(filterApplicationSideKey)))
    val predicate = if (boundedKeys) Coalesce(Seq(filter, Literal.TrueLiteral)) else filter
    Filter(predicate, filterApplicationSidePlan)
  }

  /**
   * Extracts either a safely materialized leaf with accurate statistics or a simple selective
   * filter over a scan. Filter conditions and the expressions they reference must remain simple,
   * so the runtime-filter subquery does not introduce expensive computation. The extracted plan
   * must produce a superset of the creation side's join keys.
   */
  private def extractSelectiveFilterOverScan(
      plan: LogicalPlan,
      filterCreationSideKey: Expression,
      allowMaterializedCache: Boolean,
      applicationDistinctCount: => Option[BigInt],
      onMaterializedLeaf: => Unit = ()): Option[FilterCreationSide] = {
    def extract(
        p: LogicalPlan,
        predicateReference: AttributeSet,
        hasHitFilter: Boolean,
        hasHitSelectiveFilter: Boolean,
        currentPlan: LogicalPlan,
        targetKey: Expression): Option[FilterCreationSide] = p match {
      case Project(projectList, child) if hasHitFilter =>
        // We need to make sure all expressions referenced by filter predicates are simple
        // expressions.
        val referencedExprs = projectList.filter(predicateReference.contains)
        if (referencedExprs.forall(isSimpleExpression)) {
          extract(
            child,
            referencedExprs.map(_.references).foldLeft(AttributeSet.empty)(_ ++ _),
            hasHitFilter,
            hasHitSelectiveFilter,
            currentPlan,
            targetKey)
        } else {
          None
        }
      case Project(_, child) =>
        assert(predicateReference.isEmpty && !hasHitSelectiveFilter)
        extract(child, predicateReference, hasHitFilter, hasHitSelectiveFilter, currentPlan,
          targetKey)
      case Filter(condition, child) if isSimpleExpression(condition) =>
        extract(
          child,
          predicateReference ++ condition.references,
          hasHitFilter = true,
          hasHitSelectiveFilter = hasHitSelectiveFilter || isLikelySelective(condition),
          currentPlan,
          targetKey)
      case ExtractEquiJoinKeys(joinType, lkeys, rkeys, _, _, left, right, _) =>
        // Runtime filters use one side of the [[Join]] to build a set of join key values and prune
        // the other side of the [[Join]]. It's also OK to use a superset of the join key values
        // (ignore null values) to do the pruning. We can also extract from the other side if the
        // join keys are transitive, and the other side always produces a superset output of join
        // key values. Any join side always produce a superset output of its corresponding
        // join keys, but for transitive join keys we need to check the join type.
        // We assume other rules have already pushed predicates through join if possible.
        // So the predicate references won't pass on anymore.
        if (left.output.exists(_.semanticEquals(targetKey))) {
          extract(left, AttributeSet.empty, hasHitFilter = false, hasHitSelectiveFilter = false,
            currentPlan = left, targetKey = targetKey).orElse {
            // An example that extract from the right side if the join keys are transitive.
            //     left table: 1, 2, 3
            //     right table, 3, 4
            //     right outer join output: (3, 3), (null, 4)
            //     right key output: 3, 4
            if (canPruneLeft(joinType)) {
              lkeys.zip(rkeys).find(_._1.semanticEquals(targetKey)).map(_._2)
                .flatMap { newTargetKey =>
                  extract(right, AttributeSet.empty,
                    hasHitFilter = false, hasHitSelectiveFilter = false, currentPlan = right,
                    targetKey = newTargetKey)
                }
            } else {
              None
            }
          }
        } else if (right.output.exists(_.semanticEquals(targetKey))) {
          extract(right, AttributeSet.empty, hasHitFilter = false, hasHitSelectiveFilter = false,
            currentPlan = right, targetKey = targetKey).orElse {
            // An example that extract from the left side if the join keys are transitive.
            // left table: 1, 2, 3
            // right table, 3, 4
            // left outer join output: (1, null), (2, null), (3, 3)
            // left key output: 1, 2, 3
            if (canPruneRight(joinType)) {
              rkeys.zip(lkeys).find(_._1.semanticEquals(targetKey)).map(_._2)
                .flatMap { newTargetKey =>
                  extract(left, AttributeSet.empty,
                    hasHitFilter = false, hasHitSelectiveFilter = false, currentPlan = left,
                    targetKey = newTargetKey)
                }
            } else {
              None
            }
          }
        } else {
          None
        }
      case leaf: MaterializedLeafNode =>
        onMaterializedLeaf
        val safeLineage = currentPlan.deterministic &&
          findExpressionAndTrackLineageDown(targetKey, currentPlan).exists {
            case (trackedKey, _) => isSimpleExpression(trackedKey)
          }
        val materializedMetadata = if (allowMaterializedCache && safeLineage &&
            leaf.mayHaveUsableMaterializedStats &&
            (hasHitSelectiveFilter || leaf.hasSelectivePredicate ||
              applicationDistinctCount.isDefined)) {
          leaf.materializedMetadata.filter(_.statsAvailable).flatMap { metadata =>
            val creationSize = if (currentPlan eq leaf) {
              metadata.sizeInBytes
            } else {
              currentPlan.stats.sizeInBytes
            }
            Option.when(creationSize <= conf.runtimeFilterMaterializedCreationSideThreshold) {
              metadata -> creationSize
            }
          }
        } else {
          None
        }
        materializedMetadata match {
          case Some((metadata, creationSize)) =>
            val rowCount = metadata.rowCount
            Option.when(
              rowCount <= conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_MAX_NUM_ITEMS) &&
                (hasHitSelectiveFilter || leaf.hasSelectivePredicate ||
                  applicationDistinctCount.exists(_ > rowCount))) {
              FilterCreationSide(
                targetKey,
                currentPlan,
                useMaterializedThreshold = true,
                materializedRowCount = Some(rowCount),
                materializedSizeInBytes = Some(creationSize))
            }
          case None if hasHitSelectiveFilter =>
            Some(FilterCreationSide(
              targetKey,
              currentPlan,
              useMaterializedThreshold = false))
          case _ => None
        }
      case _: LeafNode if hasHitSelectiveFilter =>
        Some(FilterCreationSide(
          targetKey,
          currentPlan,
          useMaterializedThreshold = false))
      case _ => None
    }

    if (!plan.isStreaming) {
      extract(plan, AttributeSet.empty, hasHitFilter = false, hasHitSelectiveFilter = false,
        currentPlan = plan, targetKey = filterCreationSideKey)
    } else {
      None
    }
  }

  private def isSimpleExpression(e: Expression): Boolean = {
    !e.containsAnyPattern(PYTHON_UDF, SCALA_UDF, INVOKE, JSON_TO_STRUCT, LIKE_FAMLIY,
      REGEXP_EXTRACT_FAMILY, REGEXP_REPLACE)
  }

  private def isProbablyShuffleJoin(left: LogicalPlan,
      right: LogicalPlan, hint: JoinHint): Boolean = {
    !hintToBroadcastLeft(hint) && !hintToBroadcastRight(hint) &&
      !canBroadcastBySize(left, conf) && !canBroadcastBySize(right, conf)
  }

  private def probablyHasShuffle(plan: LogicalPlan): Boolean = {
    plan.exists {
      case Join(left, right, _, _, hint) => isProbablyShuffleJoin(left, right, hint)
      case _: Aggregate => true
      case _: Window => true
      case _ => false
    }
  }

  // Returns the max scan byte size in the subtree rooted at `filterApplicationSide`.
  private def maxScanByteSize(filterApplicationSide: LogicalPlan): BigInt = {
    val defaultSizeInBytes = conf.getConf(SQLConf.DEFAULT_SIZE_IN_BYTES)
    filterApplicationSide.collect({
      case leaf: LeafNode => leaf
    }).map(scan => {
      // DEFAULT_SIZE_IN_BYTES means there's no byte size information in stats. Since we avoid
      // creating a Bloom filter when the filter application side is very small, so using 0
      // as the byte size when the actual size is unknown can avoid regression by applying BF
      // on a small table.
      if (scan.stats.sizeInBytes == defaultSizeInBytes) BigInt(0) else scan.stats.sizeInBytes
    }).max
  }

  // Returns true if `filterApplicationSide` satisfies the byte size requirement to apply a
  // Bloom filter; false otherwise.
  private def satisfyByteSizeRequirement(filterApplicationSide: LogicalPlan): Boolean = {
    // In case `filterApplicationSide` is a union of many small tables, disseminating the Bloom
    // filter to each small task might be more costly than scanning them itself. Thus, we use max
    // rather than sum here.
    val maxScanSize = maxScanByteSize(filterApplicationSide)
    maxScanSize >=
      conf.getConf(SQLConf.RUNTIME_BLOOM_FILTER_APPLICATION_SIDE_SCAN_SIZE_THRESHOLD)
  }

  /**
   * Extracts the beneficial filter creation plan with check show below:
   * - The filterApplicationSideKey can be pushed down through joins, aggregates and windows
   *   (ie the expression references originate from a single leaf node)
   * - The filter creation side has a selective predicate, or its exact materialized row count
   *   is smaller than the application side's distinct join-key count
   * - The max filterApplicationSide scan size is greater than a configurable threshold
   */
  private def extractBeneficialFilterCreatePlan(
      filterApplicationSide: LogicalPlan,
      filterCreationSide: LogicalPlan,
      filterApplicationSideKey: Expression,
      filterCreationSideKey: Expression): Option[FilterCreationSide] = {
    if (findExpressionAndTrackLineageDown(
      filterApplicationSideKey, filterApplicationSide).isDefined &&
      satisfyByteSizeRequirement(filterApplicationSide)) {
      val allowMaterializedCache = UnsafeRowUtils.isBinaryStable(filterCreationSideKey.dataType) &&
        UnsafeRowUtils.isBinaryStable(filterApplicationSideKey.dataType)
      def distinctCount(key: Expression, plan: LogicalPlan): Option[BigInt] = key match {
        case attribute: Attribute =>
          plan.stats.attributeStats.get(attribute).flatMap(_.distinctCount)
        case _ => None
      }
      def hasOnlyJoinKeyNullChecksOverScan(
          plan: LogicalPlan,
          targetKey: Expression): Boolean = plan match {
        case project: Project =>
          hasOnlyJoinKeyNullChecksOverScan(
            project.child, replaceAlias(targetKey, getAliasMap(project)))
        case Filter(condition, child) =>
          splitConjunctivePredicates(condition).forall {
            case IsNotNull(expression) => expression.semanticEquals(targetKey)
            case _ => false
          } && hasOnlyJoinKeyNullChecksOverScan(child, targetKey)
        case _: LeafNode => true
        case _ => false
      }
      lazy val currentDistinctCount =
        distinctCount(filterApplicationSideKey, filterApplicationSide)
      lazy val lineageDistinctCount = findExpressionAndTrackLineageDown(
        filterApplicationSideKey, filterApplicationSide).flatMap {
        case (trackedKey, origin) => distinctCount(trackedKey, origin)
      }
      lazy val applicationDistinctCount = {
        if (hasOnlyJoinKeyNullChecksOverScan(
            filterApplicationSide, filterApplicationSideKey)) {
          lineageDistinctCount.orElse(currentDistinctCount)
        } else {
          currentDistinctCount
        }
      }
      if (allowMaterializedCache) {
        var sawMaterializedLeaf = false
        val selectiveCreationSide = extractSelectiveFilterOverScan(
          filterCreationSide,
          filterCreationSideKey,
          allowMaterializedCache = false,
          applicationDistinctCount = None,
          onMaterializedLeaf = { sawMaterializedLeaf = true })
        selectiveCreationSide
          .filter(_.plan.stats.sizeInBytes <= conf.runtimeFilterCreationSideThreshold)
          .orElse {
            if (sawMaterializedLeaf) {
              extractSelectiveFilterOverScan(
                filterCreationSide,
                filterCreationSideKey,
                allowMaterializedCache = true,
                applicationDistinctCount = applicationDistinctCount)
            } else {
              selectiveCreationSide
            }
          }
      } else {
        extractSelectiveFilterOverScan(
          filterCreationSide,
          filterCreationSideKey,
          allowMaterializedCache = false,
          applicationDistinctCount = None)
      }
    } else {
      None
    }
  }

  // This checks if there is already a DPP filter, as this rule is called just after DPP.
  @tailrec
  private def hasDynamicPruningSubquery(
      left: LogicalPlan,
      right: LogicalPlan,
      leftKey: Expression,
      rightKey: Expression): Boolean = {
    (left, right) match {
      case (Filter(DynamicPruningSubquery(pruningKey, _, _, _, _, _, _), plan), _) =>
        pruningKey.fastEquals(leftKey) || hasDynamicPruningSubquery(plan, right, leftKey, rightKey)
      case (_, Filter(DynamicPruningSubquery(pruningKey, _, _, _, _, _, _), plan)) =>
        pruningKey.fastEquals(rightKey) ||
          hasDynamicPruningSubquery(left, plan, leftKey, rightKey)
      case _ => false
    }
  }

  private def hasBloomFilter(plan: LogicalPlan, key: Expression): Boolean = {
    plan.exists {
      case Filter(condition, _) =>
        splitConjunctivePredicates(condition).exists {
          case BloomFilterMightContain(_, XxHash64(Seq(valueExpression), _))
            if valueExpression.fastEquals(key) => true
          case Coalesce(Seq(BloomFilterMightContain(_, XxHash64(Seq(valueExpression), _)),
              Literal.TrueLiteral)) if valueExpression.fastEquals(key) => true
          case _ => false
        }
      case _ => false
    }
  }

  private def tryInjectRuntimeFilter(plan: LogicalPlan, stringsOnly: Boolean = false): LogicalPlan = {
    // The later pass shares the existing query budget with predicates already in the plan.
    var filterCounter = if (stringsOnly) plan.collect {
      case Filter(condition, _) => condition.collect { case _: BloomFilterMightContain => 1 }.sum
    }.sum else 0
    val numFilterThreshold = conf.getConf(SQLConf.RUNTIME_FILTER_NUMBER_THRESHOLD)
    plan transformUp {
      case join @ ExtractEquiJoinKeys(joinType, leftKeys, rightKeys, _, _, left, right, hint) =>
        var newLeft = left
        var newRight = right
        leftKeys.lazyZip(rightKeys).foreach((l, r) => {
          // Check if:
          // 1. There is already a DPP filter on the key
          // 2. The keys are simple cheap expressions
          if (filterCounter < numFilterThreshold &&
            !hasDynamicPruningSubquery(left, right, l, r) &&
            isSimpleExpression(l) && isSimpleExpression(r)) {
            val oldLeft = newLeft
            val oldRight = newRight
            // Check if:
            // 1. The current join type supports prune the left side with runtime filter
            // 2. The current join is a shuffle join or a broadcast join that
            //    has a shuffle below it
            // 3. There is no bloom filter on the left key yet
            val hasShuffle = isProbablyShuffleJoin(left, right, hint)
            if (canPruneLeft(joinType) && (hasShuffle || probablyHasShuffle(left)) &&
              !hasBloomFilter(newLeft, l)) {
              extractBeneficialFilterCreatePlan(left, right, l, r).foreach { creationSide =>
                newLeft = injectBloomFilter(l, newLeft, creationSide, stringsOnly)
              }
            }
            // Did we actually inject on the left? If not, try on the right
            // Check if:
            // 1. The current join type supports prune the right side with runtime filter
            // 2. The current join is a shuffle join or a broadcast join that
            //    has a shuffle below it
            // 3. There is no bloom filter on the right key yet
            if (newLeft.fastEquals(oldLeft) && canPruneRight(joinType) &&
              (hasShuffle || probablyHasShuffle(right)) && !hasBloomFilter(newRight, r)) {
              extractBeneficialFilterCreatePlan(right, left, r, l).foreach { creationSide =>
                newRight = injectBloomFilter(r, newRight, creationSide, stringsOnly)
              }
            }
            if (!newLeft.fastEquals(oldLeft) || !newRight.fastEquals(oldRight)) {
              filterCounter = filterCounter + 1
            }
          }
        })
        join.withNewChildren(Seq(newLeft, newRight))
    }
  }

  private[sql] def applyAfterProbeFilters(plan: LogicalPlan): LogicalPlan = {
    if (!deferStringFilters || !conf.runtimeFilterBloomFilterEnabled ||
        !conf.getConfString("spark.sql.optimizer.runtime.bloomFilter.stringFilteredKeyProjection.enabled",
          "false").toBoolean || !plan.exists(_.expressions.exists(_.exists(_.isInstanceOf[StringPredicate])))) {
      return plan
    }
    plan match {
      // The parent can still decorrelate a predicate subquery into a semi join and
      // propagate cheaper filters onto this probe. Decide once its parent is optimized.
      case _: Subquery => plan
      case _ => tryInjectRuntimeFilter(plan, stringsOnly = true)
    }
  }

  override def apply(plan: LogicalPlan): LogicalPlan = plan match {
    case s: Subquery if s.correlated => plan
    case _ if !conf.runtimeFilterBloomFilterEnabled => plan
    case _ => tryInjectRuntimeFilter(plan)
  }

}

/** Consider an additional large key sketch only after the other rules have pruned scan inputs. */
object InjectStringFilterAfterProbeFilters extends Rule[LogicalPlan] {
  override def apply(plan: LogicalPlan): LogicalPlan = InjectRuntimeFilter.applyAfterProbeFilters(plan)
}


/** Only optimizer-created positive join prefilters may replace approximate membership by exact. */
object GeneratedIntegralKeyDomain {
  val tag = org.apache.spark.sql.catalyst.trees.TreeNodeTag[Boolean]("generatedIntegralJoinKeyDomain")
}
