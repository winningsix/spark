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

package org.apache.spark.shuffle.streaming

import scala.collection.mutable
import scala.collection.mutable.HashMap

import org.apache.spark.{NarrowDependency, Partition, PipelinedShuffleDependency, ShuffleDependency, SparkConf, SparkContext}
import org.apache.spark.internal.config.STREAMING_SHUFFLE_PRODUCER_UNION_AFFINITY_ENABLED
import org.apache.spark.rdd.{RDD, UnionPartition}
import org.apache.spark.scheduler.{ExecutorCacheTaskLocation, TaskLocation}
import org.apache.spark.shuffle.PipelinedShuffleManager
import org.apache.spark.storage.BlockManagerId

/** Graph-derived transport metadata and optional placement policy, not scheduler state. */
private[spark] object StreamingShuffleStagePlanning {
  /** Pipelined shuffle ids read directly by the stage containing `rdd`. */
  def shuffleIdsReadByStage(rdd: RDD[_]): Seq[Int] = {
    // Count occurrences in this stage, not the producer's total routes across all stages.
    // Memoize each narrow subtree but include its counts once per consuming dependency: two
    // branches can execute the same reader RDD twice, while two separate stages each read it once.
    val counts = new HashMap[RDD[_], Map[Int, Int]]
    val pending = mutable.Stack[(RDD[_], Boolean)]((rdd, false))
    while (pending.nonEmpty) {
      val entry: (RDD[_], Boolean) = pending.pop()
      val current = entry._1
      val expanded = entry._2
      if (!counts.contains(current)) {
        if (expanded) {
          val result = new HashMap[Int, Int]
          current.dependencies.foreach {
            case dependency: PipelinedShuffleDependency[_, _, _] =>
              result.update(dependency.shuffleId, result.getOrElse(dependency.shuffleId, 0) + 1)
            case dependency: NarrowDependency[_] =>
              counts(dependency.rdd).foreach { case (shuffleId, count) =>
                result.update(shuffleId, result.getOrElse(shuffleId, 0) + count)
              }
            case _ =>
          }
          counts.update(current, result.toMap)
        } else {
          pending.push((current, true))
          current.dependencies.foreach {
            case dependency: NarrowDependency[_] => pending.push((dependency.rdd, false))
            case _ =>
          }
        }
      }
    }
    counts(rdd).toSeq.sortBy(_._1).flatMap { case (shuffleId, count) =>
      Seq.fill(count)(shuffleId)
    }
  }


  case class UnionTaskAffinityPlan(
      orderedPartitionIds: Seq[Int],
      preferredLocations: Map[Int, Seq[TaskLocation]],
      executorLocations: Seq[ExecutorCacheTaskLocation])

  /**
   * Build an executor-affinity plan for an opt-in repeated UnionRDD scan. Matching partition
   * indices from each union parent are assigned to one executor and placed next to one another in
   * that executor's pending queue. The executor-scoped input layer can then share cached blocks and
   * in-flight range requests between the repeated scans.
   *
   * Return None unless this is a complete, equal-shaped union. A partial retry, a non-union stage,
   * or differing parent partition sets keeps Spark's original task order and locality behavior.
   */
  def planUnionTaskAffinity(
      partitionIds: Seq[Int],
      partitions: Array[Partition],
      executorLocations: Seq[ExecutorCacheTaskLocation]): Option[UnionTaskAffinityPlan] = {
    if (executorLocations.isEmpty || partitionIds.toSet != partitions.indices.toSet) {
      return None
    }

    val unionPartitions = partitionIds.flatMap { id =>
      partitions(id) match {
        case partition: UnionPartition[_] =>
          Some((id, partition.parentRddIndex, partition.parentPartition.index))
        case _ => None
      }
    }
    if (unionPartitions.size != partitionIds.size) return None

    val byParent = unionPartitions.groupBy(_._2)
    if (byParent.size < 2) return None
    val parentIndices = byParent.keys.toSeq.sorted
    val baseIndices = byParent(parentIndices.head).map(_._3).sorted
    if (baseIndices.isEmpty || byParent.values.exists { entries =>
      entries.map(_._3).sorted != baseIndices || entries.map(_._3).distinct.size != entries.size
    }) {
      return None
    }

    val partitionIdByParentAndBase = unionPartitions.map { case (id, parent, base) =>
      (parent, base) -> id
    }.toMap
    val executors = executorLocations.distinct
    val orderedIds = baseIndices
      .grouped(executors.size)
      .flatMap { baseBatch =>
        parentIndices.iterator.flatMap { parent =>
          baseBatch.iterator.map(base => partitionIdByParentAndBase((parent, base)))
        }
      }
      .toSeq
    val preferredLocations = unionPartitions.iterator.map { case (id, _, base) =>
      id -> Seq(executors(Math.floorMod(base, executors.size)))
    }.toMap
    Some(UnionTaskAffinityPlan(orderedIds, preferredLocations, executors))
  }

  def taskAffinity(
      conf: SparkConf,
      isProducer: Boolean,
      rdd: RDD[_],
      partitionIds: Seq[Int],
      preferredLocations: scala.collection.Map[Int, Seq[TaskLocation]],
      executors: => Iterable[BlockManagerId]): Option[UnionTaskAffinityPlan] = {
    if (!isProducer || !conf.get(STREAMING_SHUFFLE_PRODUCER_UNION_AFFINITY_ENABLED) ||
        !preferredLocations.values.forall(_.isEmpty)) {
      None
    } else {
      val locations = executors.iterator
        .filter(_.executorId != SparkContext.DRIVER_IDENTIFIER)
        .map(id => ExecutorCacheTaskLocation(id.host, id.executorId))
        .toSeq.sortBy(location => (location.host, location.executorId))
      planUnionTaskAffinity(partitionIds, rdd.partitions, locations)
    }
  }

  def supportsMixedShape(
      manager: PipelinedShuffleManager,
      hasPipelined: Boolean,
      hasPipelinedBelowRegular: Boolean,
      hasUnmaterializedRegularBoundary: Boolean): Boolean = {
    val supported = manager.supportsUnmaterializedRegularBoundary
    val regularConsumer = hasPipelinedBelowRegular && !hasPipelined
    val regularFrontier = hasPipelined && hasUnmaterializedRegularBoundary &&
      !hasPipelinedBelowRegular
    val segmented = hasPipelined && hasPipelinedBelowRegular &&
      !manager.requiresWholeGroupSlotAdmission
    supported && (regularConsumer || regularFrontier || segmented)
  }

  def configureReaderRoutes(
      dependency: ShuffleDependency[_, _, _],
      livePartitions: Option[Set[Int]] = None): Unit = dependency match {
    case pipelined: PipelinedShuffleDependency[_, _, _] =>
      val routes = Array.tabulate(pipelined.partitioner.numPartitions) { partition =>
        if (livePartitions.forall(_.contains(partition))) pipelined.readerRouteMultiplicity else 0
      }
      pipelined.setExpectedReaderRoutes(routes)
    case _ =>
  }
}
