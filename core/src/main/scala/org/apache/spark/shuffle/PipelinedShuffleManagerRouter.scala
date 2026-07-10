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

package org.apache.spark.shuffle

import org.apache.spark.{PipelinedShuffleDependency, ShuffleDependency, SparkConf, TaskContext}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.SHUFFLE_MANAGER_INCREMENTAL
import org.apache.spark.util.Utils

/**
 * A [[ShuffleHandle]] that wraps the handle produced by the incremental shuffle manager, so that
 * executor-side calls (which only receive a handle, not the dependency) can be routed back to the
 * incremental manager. See [[PipelinedShuffleManagerRouter]] for why this is needed.
 *
 * @param delegate the handle the incremental manager returned from `registerShuffle`
 */
private[spark] class IncrementalShuffleHandle(val delegate: ShuffleHandle)
  extends ShuffleHandle(delegate.shuffleId)

/**
 * A [[ShuffleManager]] that routes each shuffle to one of two underlying managers by the *type* of
 * its shuffle dependency:
 *
 *  - a [[PipelinedShuffleDependency]] (incrementally readable) is served by the incremental manager
 *    named by `spark.shuffle.manager.incremental`;
 *  - every other [[ShuffleDependency]] is served by the default manager named by
 *    `spark.shuffle.manager`.
 *
 * This lets a single cluster run both regular queries and pipelined (e.g. real-time mode) queries,
 * routing per shuffle rather than per job or per cluster. Routing is driven purely by the
 * dependency type -- there is no query-level flag or thread-local property.
 *
 * '''Cross-JVM routing.''' `registerShuffle` runs on the driver and has the dependency, so it can
 * route by type directly. `getWriter` / `getReader` run on executors and receive only the
 * [[ShuffleHandle]] (from `dependency.shuffleHandle`, minted by `registerShuffle` on the driver and
 * serialized to the executor). To route consistently there, the router wraps the incremental
 * manager's handle in an [[IncrementalShuffleHandle]]: a handle of that type routes to the
 * incremental manager, any other handle routes to the default manager. The router always unwraps
 * before delegating, so each underlying manager only ever sees its own handle type.
 *
 * This router is only installed when `spark.shuffle.manager.incremental` is set; otherwise SparkEnv
 * instantiates the single configured manager exactly as before, so behavior is unchanged for
 * clusters that do not opt in.
 */
private[spark] class PipelinedShuffleManagerRouter(conf: SparkConf, isDriver: Boolean)
  extends ShuffleManager with Logging {

  private val defaultManager: ShuffleManager =
    Utils.instantiateSerializerOrShuffleManager[ShuffleManager](
      ShuffleManager.getShuffleManagerClassName(conf), conf, isDriver)

  /**
   * The manager that serves regular (non-pipelined) shuffles. Exposed so callers that inspect the
   * shuffle manager's concrete type to decide regular-shuffle behavior (e.g.
   * `ShuffleExchangeExec.needToCopyObjectsBeforeShuffle`, which checks for `SortShuffleManager`)
   * see through the router to the manager that actually handles those shuffles, rather than seeing
   * the router itself and falling into a conservative default.
   */
  private[spark] def regularShuffleManager: ShuffleManager = defaultManager

  private val incrementalManager: ShuffleManager = {
    val className = conf.get(SHUFFLE_MANAGER_INCREMENTAL).getOrElse(
      throw new IllegalStateException(
        s"${SHUFFLE_MANAGER_INCREMENTAL.key} must be set to use PipelinedShuffleManagerRouter"))
    Utils.instantiateSerializerOrShuffleManager[ShuffleManager](className, conf, isDriver)
  }

  /** The manager that serves pipelined (incrementally-readable) shuffles. Exposed for testing. */
  private[spark] def incrementalShuffleManager: ShuffleManager = incrementalManager

  logInfo(s"Using PipelinedShuffleManagerRouter: regular shuffles -> " +
    s"${defaultManager.getClass.getName}, pipelined shuffles -> " +
    s"${incrementalManager.getClass.getName}")

  override def registerShuffle[K, V, C](
      shuffleId: Int,
      dependency: ShuffleDependency[K, V, C]): ShuffleHandle = {
    dependency match {
      case _: PipelinedShuffleDependency[_, _, _] =>
        new IncrementalShuffleHandle(incrementalManager.registerShuffle(shuffleId, dependency))
      case _ =>
        defaultManager.registerShuffle(shuffleId, dependency)
    }
  }

  override def getWriter[K, V](
      handle: ShuffleHandle,
      mapId: Long,
      context: TaskContext,
      metrics: ShuffleWriteMetricsReporter): ShuffleWriter[K, V] = {
    handle match {
      case incremental: IncrementalShuffleHandle =>
        incrementalManager.getWriter(incremental.delegate, mapId, context, metrics)
      case _ =>
        defaultManager.getWriter(handle, mapId, context, metrics)
    }
  }

  override def getReader[K, C](
      handle: ShuffleHandle,
      startMapIndex: Int,
      endMapIndex: Int,
      startPartition: Int,
      endPartition: Int,
      context: TaskContext,
      metrics: ShuffleReadMetricsReporter): ShuffleReader[K, C] = {
    handle match {
      case incremental: IncrementalShuffleHandle =>
        incrementalManager.getReader(
          incremental.delegate, startMapIndex, endMapIndex, startPartition, endPartition,
          context, metrics)
      case _ =>
        defaultManager.getReader(
          handle, startMapIndex, endMapIndex, startPartition, endPartition, context, metrics)
    }
  }

  override def unregisterShuffle(shuffleId: Int): Boolean = {
    // A shuffle is owned by exactly one of the two managers, but the id alone does not tell us
    // which, so we ask both. We OR the results: the owning manager reports whether it removed the
    // metadata, and the non-owning manager's result must not veto that (the ShuffleManager
    // contract does not guarantee a specific return value for an unknown shuffleId). Run both
    // regardless of the first's outcome so neither is skipped.
    val incrementalResult = incrementalManager.unregisterShuffle(shuffleId)
    val defaultResult = defaultManager.unregisterShuffle(shuffleId)
    incrementalResult || defaultResult
  }

  override def shuffleBlockResolver: ShuffleBlockResolver = {
    // Regular shuffles use the block manager and need a resolver; pipelined shuffles do not. The
    // resolver contract is only exercised for regular shuffles, so delegate to the default manager.
    defaultManager.shuffleBlockResolver
  }

  override def stop(): Unit = {
    // Stop both managers even if one throws, and do not let the second's failure mask the first's.
    var firstError: Option[Throwable] = None
    try {
      incrementalManager.stop()
    } catch {
      case t: Throwable => firstError = Some(t)
    }
    try {
      defaultManager.stop()
    } catch {
      case t: Throwable =>
        firstError match {
          case Some(first) => first.addSuppressed(t)
          case None => firstError = Some(t)
        }
    }
    firstError.foreach(throw _)
  }
}
