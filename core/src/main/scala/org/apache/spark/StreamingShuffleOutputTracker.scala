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

package org.apache.spark

import java.util.concurrent.{ConcurrentHashMap, LinkedBlockingQueue, ThreadPoolExecutor, TimeUnit}

import scala.jdk.CollectionConverters._
import scala.reflect.ClassTag
import scala.util.control.NonFatal

import org.apache.spark.internal.{Logging, LogKeys}
import org.apache.spark.internal.config.{SHUFFLE_MAPOUTPUT_DISPATCHER_NUM_THREADS,
  STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL}
import org.apache.spark.rpc.{RpcCallContext, RpcEndpoint, RpcEndpointRef, RpcEnv}
import org.apache.spark.shuffle.streaming.{PrepareStreamingShuffleReceiveInbox,
  PrepareStreamingShuffleReceiveInboxes, ReleaseStreamingShuffleReceiveInbox,
  StreamingShuffleReceiveInboxId}
import org.apache.spark.util.ThreadUtils

/**
 * The driver-side registry for a shuffle's output. A regular shuffle is served by the
 * `MapOutputTrackerMaster`, a pipelined (streaming) shuffle by the
 * `StreamingShuffleOutputTrackerMaster` -- split by dependency type, with no overlap. This is the
 * small common surface the DAGScheduler and ContextCleaner drive polymorphically, so they select
 * the right tracker by shuffle-dependency type (see `DAGScheduler.outputTrackerMaster`) rather than
 * special-casing pipelined shuffles at each call site.
 */
private[spark] trait ShuffleOutputTrackerMaster {
  /** Register a shuffle so its outputs can be tracked. `jobId` is used by the streaming tracker. */
  def registerShuffle(shuffleId: Int, numMaps: Int, numReduces: Int, jobId: Int): Unit
  /** Whether the given shuffle is registered with this tracker. */
  def containsShuffle(shuffleId: Int): Boolean
  /** Unregister a shuffle and release its tracked state. */
  def unregisterShuffle(shuffleId: Int): Unit
}

private[spark] sealed trait StreamingShuffleTaskLocationTrackerMessage

private[spark] case class UpdateStreamingShuffleTaskLocation(
    shuffleId: Int,
    mapId: Long,
    location: StreamingShuffleTaskLocation)
  extends StreamingShuffleTaskLocationTrackerMessage

/**
 * Fire-and-forget publication used by executor writers. Streaming writers retain replay state,
 * so readers can safely discover them on a later poll without blocking the producer's scan on a
 * driver RPC round trip. Keep [[UpdateStreamingShuffleTaskLocation]] as the synchronous API used
 * by compatibility callers and tests that need the registration result.
 */
private[spark] case class PublishStreamingShuffleTaskLocation(
    shuffleId: Int,
    mapId: Long,
    location: StreamingShuffleTaskLocation)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class GetAllStreamingShuffleTaskLocations(shuffleId: Int)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class GetAvailableStreamingShuffleTaskLocations(shuffleId: Int)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class GetAvailableStreamingShuffleTaskLocationsBatch(shuffleIds: Seq[Int])
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class IsStreamingShuffleRegistered(shuffleId: Int)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class RegisterStreamingShuffleReceiveEndpoint(
    executorId: String,
    endpoint: RpcEndpointRef)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case class StreamingShuffleInboxDrainReady(
    executorId: String,
    id: StreamingShuffleReceiveInboxId)
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] case object StopStreamingShuffleOutputTracker
  extends StreamingShuffleTaskLocationTrackerMessage

private[spark] sealed trait StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class UpdateStreamingShuffleTaskLocationMasterMessage(
    shuffleId: Int,
    mapId: Long,
    location: StreamingShuffleTaskLocation,
    context: RpcCallContext)
  extends StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class GetAllStreamingShuffleTaskLocationsMasterMessage(
    shuffleId: Int,
    context: RpcCallContext)
  extends StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class GetAvailableStreamingShuffleTaskLocationsMasterMessage(
  shuffleId: Int,
  context: RpcCallContext)
  extends StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class GetAvailableStreamingShuffleTaskLocationsBatchMasterMessage(
  shuffleIds: Seq[Int],
  context: RpcCallContext)
  extends StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class IsStreamingShuffleRegisteredMasterMessage(
    shuffleId: Int,
    context: RpcCallContext)
  extends StreamingShuffleTaskLocationTrackerMasterMessage

private[spark] case class StreamingShuffleTaskLocation(
    executorId: String,
    host: String,
    port: Int,
    // Streaming writers use task-attempt ids as map ids. Keep the logical map index so a retried
    // attempt can replace the stale location instead of exposing both attempts to readers.
    mapIndex: Int = -1)

private[spark] class StreamingShuffleOutputTrackerMasterEndpoint(
    override val rpcEnv: RpcEnv,
    tracker: StreamingShuffleOutputTrackerMaster,
    conf: SparkConf)
  extends RpcEndpoint
  with Logging {

  logDebug("init") // force eager creation of logger

  override def receiveAndReply(context: RpcCallContext): PartialFunction[Any, Unit] = {
    case GetAllStreamingShuffleTaskLocations(shuffleId) =>
      tracker.post(GetAllStreamingShuffleTaskLocationsMasterMessage(shuffleId, context))

    case GetAvailableStreamingShuffleTaskLocations(shuffleId) =>
      tracker.post(GetAvailableStreamingShuffleTaskLocationsMasterMessage(shuffleId, context))

    case GetAvailableStreamingShuffleTaskLocationsBatch(shuffleIds) =>
      tracker.post(
        GetAvailableStreamingShuffleTaskLocationsBatchMasterMessage(shuffleIds, context))

    case IsStreamingShuffleRegistered(shuffleId) =>
      tracker.post(IsStreamingShuffleRegisteredMasterMessage(shuffleId, context))

    case UpdateStreamingShuffleTaskLocation(
          shuffleId: Int,
          mapId: Long,
          location: StreamingShuffleTaskLocation) =>
      tracker.post(
        UpdateStreamingShuffleTaskLocationMasterMessage(shuffleId, mapId, location, context))

    case RegisterStreamingShuffleReceiveEndpoint(executorId, endpoint) =>
      context.reply(tracker.registerReceiveEndpoint(executorId, endpoint))

    case StopStreamingShuffleOutputTracker =>
      logInfo(log"StreamingShuffleOutputTrackerMasterEndpoint stopped!")
      // Unregister the endpoint from the Dispatcher BEFORE completing the reply.
      // This avoids a race where the caller (e.g., initializeShuffleManager) is
      // unblocked by context.reply() and tries to register a new endpoint with the
      // same name before this handler has finished unregistering the old one.
      // stop() synchronously calls Dispatcher.stop(self) which removes the endpoint
      // name from the Dispatcher's endpoints map.
      // context.reply() just completes a local Promise (p.success(true)) and has no
      // dependency on the endpoint's registration state, so it is safe to call after
      // stop().
      stop()
      context.reply(true)
  }

  override def receive: PartialFunction[Any, Unit] = {
    case PublishStreamingShuffleTaskLocation(shuffleId, mapId, location) =>
      tracker.registerShuffleWriterTask(shuffleId, mapId, location)

    case StreamingShuffleInboxDrainReady(executorId, id) =>
      tracker.markInboxDrainReady(executorId, id)
  }
}

case class ShuffleLocationResponse(
  shuffleTaskLocations: Map[Long, StreamingShuffleTaskLocation],
  numShuffleWriterTasks: Int)

/**
 * The purpose of this class is to support get task location information for the streaming
 * shuffle. For the streaming shuffle to work, tasks need to figure out what where upstream tasks
 * are located so it can connect to them to get data. The general usage of the APIs are the
 * following
 *   1. The DAGScheduler will call registerShuffle for the tracker running on the driver to
 *      register the shuffle. This is when information like number of mappers will be passed into
 *      the driver.
 *   2. Mapper / Shuffle writer tasks will call registerShuffleWriterTask to
 *      register themselves with the tracker running on the driver and provide the information
 *      about where it is running
 *   3. Reduce / Shuffle reader tasks will call
 *      getAllShuffleWriterTaskLocations to get the location information of all the writers. The
 *      API "getAllShuffleWriterTaskLocations" returns all the writer task locations or nothing at
 *      all. Partial results will not be returned. Shuffle readers should keep polling this API
 *      until it returns a non-empty response.
 */
private[spark] abstract class StreamingShuffleOutputTracker(conf: SparkConf) extends Logging {

  /** Reference to the master endpoint living on the driver. */
  var trackerEndpoint: RpcEndpointRef = _

  /**
   * Send a message to the trackerEndpoint and get its result within a default timeout, or
   * throw a SparkException if this fails.
   */
  protected def askTracker[T: ClassTag](message: Any): T = {
    try {
      trackerEndpoint.askSync[T](message)
    } catch {
      case e: Exception =>
        logError(log"Error communicating with StreamingShuffleOutputTracker", e)
        throw new SparkException("Error communicating with StreamingShuffleOutputTracker", e)
    }
  }

  /** Send a one-way message to the trackerEndpoint, to which we expect it to reply with true. */
  protected def sendTracker(message: Any): Unit = {
    val response = askTracker[Boolean](message)
    if (response != true) {
      throw new SparkException(
        "Error reply received from StreamingShuffleOutputTracker. Expecting true, got " +
          response.toString)
    }
  }

  def unregisterShuffle(shuffleId: Int): Unit = {}

  def stop(): Unit = {}

  /**
   * Register a shuffle writer task (typically mapper task) for a shuffle and provide information
   * about where it is running. Will return false if the register is not completed successfully
   */
  def registerShuffleWriterTask(
      shuffleId: Int,
      mapId: Long,
      location: StreamingShuffleTaskLocation): Boolean

  /**
   * Publish a writer location without requiring the writer task to wait for the driver. The
   * default remains synchronous for in-process/master implementations; workers override it.
   */
  def publishShuffleWriterTask(
      shuffleId: Int,
      mapId: Long,
      location: StreamingShuffleTaskLocation): Unit = {
    registerShuffleWriterTask(shuffleId, mapId, location)
  }

  /**
   * Get all shuffle writer tasks that are part of the shuffle. This API will return None until
   * all shuffle writer task location info is available.
   * @param shuffleId  The id of the shuffle to get the location information about writer tasks
   * @return A map in which the key is the shuffle writer task map id and the value
   *         is the location information of the task.
   */
  def getAllShuffleWriterTaskLocations(
      shuffleId: Int): Option[Map[Long, StreamingShuffleTaskLocation]]

  /**
   * Get the shuffle writer task locations that are currently available for a shuffle. Please note
   * that this function may not return all the shuffle writer locations if not all of them are
   * available. This contrast with the method "getAllShuffleWriterTaskLocations" in which all
   * locations will be returned or none with be returned.
   * @param shuffleId  The id of the shuffle to get the location information about writer tasks
   * @return ShuffleLocationResponse which contains a map shuffle writer task locations and the
   *         total number of shuffle writers to expect.
   */
  def getAvailableShuffleWriterTaskLocations(shuffleId: Int): Option[ShuffleLocationResponse]

  /** Get the currently available writer locations for several active shuffles in one request. */
  def getAvailableShuffleWriterTaskLocationsBatch(
      shuffleIds: Seq[Int]): Map[Int, ShuffleLocationResponse] = {
    shuffleIds.distinct.flatMap { shuffleId =>
      getAvailableShuffleWriterTaskLocations(shuffleId).map(shuffleId -> _)
    }.toMap
  }

  /** Whether the driver still owns the shuffle's lifecycle state. */
  def containsShuffle(shuffleId: Int): Boolean

  def registerReceiveEndpoint(executorId: String, endpoint: RpcEndpointRef): Boolean

  def markInboxDrainReady(executorId: String, id: StreamingShuffleReceiveInboxId): Unit
}

private[spark] case class StreamingShuffleInfo(numMaps: Int, numReduces: Int, jobId: Int)

private[spark] class StreamingShuffleOutputTrackerMaster(conf: SparkConf)
  extends StreamingShuffleOutputTracker(conf) with ShuffleOutputTrackerMaster {

  // map that stores task location information organized in the following fashion
  // shuffle id -> {mapId -> location}
  private val taskLocations =
    new ConcurrentHashMap[Int, ConcurrentHashMap[Long, StreamingShuffleTaskLocation]]()

  private val shuffleInfos = new ConcurrentHashMap[Int, StreamingShuffleInfo]()
  private val receiveEndpoints = new ConcurrentHashMap[String, RpcEndpointRef]()
  private val drainReadyInboxes =
    ConcurrentHashMap.newKeySet[(String, StreamingShuffleReceiveInboxId)]()
  @volatile private var inboxReadyCallback: () => Unit = () => ()

  private val trackerMasterMessages =
    new LinkedBlockingQueue[StreamingShuffleTaskLocationTrackerMasterMessage]

  // Thread pool used for handling map output status requests. This is a separate thread pool
  // to ensure we don't block the normal dispatcher threads.
  private val threadpool: ThreadPoolExecutor = {
    val numThreads = conf.get(SHUFFLE_MAPOUTPUT_DISPATCHER_NUM_THREADS)
    val pool =
      ThreadUtils.newDaemonFixedThreadPool(numThreads, "streaming-shuffle-location-dispatcher")
    for (i <- 0 until numThreads) {
      pool.execute(new MessageLoop)
    }
    pool
  }
  override def registerShuffle(shuffleId: Int, numMaps: Int, numReduces: Int, jobId: Int): Unit = {
    logInfo(log"Registering shuffleId ${MDC(LogKeys.SHUFFLE_ID, shuffleId)} with ${
      MDC(LogKeys.NUM_MAPPERS, numMaps)} mappers and ${
      MDC(LogKeys.NUM_REDUCERS, numReduces)} reducers")
    if (shuffleInfos.putIfAbsent(
        shuffleId, StreamingShuffleInfo(numMaps, numReduces, jobId)) != null) {
      throw new IllegalArgumentException(s"Shuffle ID $shuffleId registered twice")
    }
  }

  override def containsShuffle(shuffleId: Int): Boolean = shuffleInfos.containsKey(shuffleId)

  // for testing purposes
  private[spark] def getShuffleInfo(shuffleId: Int): Option[StreamingShuffleInfo] = {
    Option(shuffleInfos.get(shuffleId))
  }

  // for testing purposes -- size of the per-shuffle taskLocations map, used to assert
  // the absence of orphan entries left behind by a register/unregister race.
  private[spark] def numShufflesWithTaskLocations: Int = taskLocations.size()

  override def unregisterShuffle(shuffleId: Int): Unit = {
    logInfo(log"Unregistering shuffleId ${MDC(LogKeys.SHUFFLE_ID, shuffleId)}")

    if (!shuffleInfos.containsKey(shuffleId)) {
      logWarning(log"Attempting to unregister a shuffle with id ${
        MDC(LogKeys.SHUFFLE_ID, shuffleId)} that hasn't been registered")
    }
    // Order matters here: remove from shuffleInfos BEFORE taskLocations.
    //
    // A concurrent registerShuffleWriterTask installs into taskLocations from inside a
    // compute() lambda that holds ConcurrentHashMap's per-key bucket lock. Our
    // taskLocations.remove below acquires the same lock, so the two operations are
    // strictly serialized for the same shuffleId. The lambda re-reads
    // shuffleInfos.containsKey, with two possible outcomes:
    //   - If that read happens after our shuffleInfos.remove, the lambda returns null
    //     and no entry is installed.
    //   - If that read happens before our shuffleInfos.remove, the lambda installs the
    //     entry, but our taskLocations.remove then runs strictly after the lambda
    //     releases the bucket lock and clears the entry.
    // Either way, no orphan remains. See registerShuffleWriterTask.
    shuffleInfos.remove(shuffleId)
    taskLocations.remove(shuffleId)
    drainReadyInboxes.removeIf { case (_, id) => id.shuffleId == shuffleId }
  }

  override def registerReceiveEndpoint(
      executorId: String,
      endpoint: RpcEndpointRef): Boolean = {
    receiveEndpoints.put(executorId, endpoint)
    inboxReadyCallback()
    true
  }

  override def markInboxDrainReady(
      executorId: String,
      id: StreamingShuffleReceiveInboxId): Unit = {
    if (drainReadyInboxes.add((executorId, id))) inboxReadyCallback()
  }

  private[spark] def setInboxReadyCallback(callback: () => Unit): Unit = {
    inboxReadyCallback = callback
  }

  private[spark] def receiveExecutorIds: Seq[String] = receiveEndpoints.keySet().asScala.toSeq

  private[spark] def prepareReceiveInbox(
      executorId: String,
      id: StreamingShuffleReceiveInboxId): Boolean = {
    val endpoint = receiveEndpoints.get(executorId)
    endpoint != null && endpoint.askSync[Boolean](PrepareStreamingShuffleReceiveInbox(id))
  }

  private[spark] def prepareReceiveInboxes(
      executorId: String,
      ids: Seq[StreamingShuffleReceiveInboxId]): Boolean = {
    if (ids.isEmpty) {
      true
    } else {
      val endpoint = receiveEndpoints.get(executorId)
      endpoint != null &&
        endpoint.askSync[Boolean](PrepareStreamingShuffleReceiveInboxes(ids))
    }
  }

  private[spark] def releaseReceiveInbox(
      executorId: String,
      id: StreamingShuffleReceiveInboxId): Unit = {
    drainReadyInboxes.remove((executorId, id))
    Option(receiveEndpoints.get(executorId)).foreach(
      _.send(ReleaseStreamingShuffleReceiveInbox(id)))
  }

  private[spark] def removeReceiveExecutor(executorId: String): Unit = {
    receiveEndpoints.remove(executorId)
    drainReadyInboxes.removeIf { case (readyExecutorId, _) =>
      readyExecutorId == executorId
    }
  }

  private[spark] def isReceiveInboxDrainReady(
      executorId: String,
      id: StreamingShuffleReceiveInboxId): Boolean = {
    drainReadyInboxes.contains((executorId, id))
  }

  def post(message: StreamingShuffleTaskLocationTrackerMasterMessage): Unit = {
    trackerMasterMessages.offer(message)
  }

  /** Message loop used for dispatching messages. */
  private class MessageLoop extends Runnable {

    override def run(): Unit = {
      try {
        while (true) {
          try {
            val data = trackerMasterMessages.take()
            if (data == PoisonPill) {
              // Put PoisonPill back so that other MessageLoops can see it.
              trackerMasterMessages.offer(PoisonPill)
              return
            }

            data match {
              case GetAllStreamingShuffleTaskLocationsMasterMessage(shuffleId, context) =>
                val ret = getAllShuffleWriterTaskLocations(shuffleId)
                context.reply(ret)

              case GetAvailableStreamingShuffleTaskLocationsMasterMessage(shuffleId, context) =>
                val ret = getAvailableShuffleWriterTaskLocations(shuffleId)
                context.reply(ret)

              case GetAvailableStreamingShuffleTaskLocationsBatchMasterMessage(
                    shuffleIds,
                    context) =>
                context.reply(getAvailableShuffleWriterTaskLocationsBatch(shuffleIds))

              case IsStreamingShuffleRegisteredMasterMessage(shuffleId, context) =>
                context.reply(containsShuffle(shuffleId))

              case UpdateStreamingShuffleTaskLocationMasterMessage(
                    shuffleId,
                    mapId,
                    location,
                    context) =>
                context.reply(registerShuffleWriterTask(shuffleId, mapId, location))

            }
          } catch {
            case NonFatal(e) => logError(log"${MDC(LogKeys.ERROR, e.getMessage)}", e)
          }
        }
      } catch {
        case ie: InterruptedException => // exit
      }
    }
  }

  /** A poison endpoint that indicates MessageLoop should exit its message loop. */
  private val PoisonPill =
    GetAllStreamingShuffleTaskLocationsMasterMessage(-99, null)

  override def registerShuffleWriterTask(
      shuffleId: Int,
      mapId: Long,
      location: StreamingShuffleTaskLocation): Boolean = {
    if (!shuffleInfos.containsKey(shuffleId)) {
      logWarning(
        log"Attempting to register shuffle writer task for shuffle with id ${
          MDC(LogKeys.SHUFFLE_ID, shuffleId)} that hasn't been registered. Map id ${
          MDC(LogKeys.MAP_ID, mapId)} location ${MDC(LogKeys.TASK_LOCATION, location)}")
      return false
    }
    // Re-check shuffleInfos from inside the compute lambda to make register/unregister
    // concurrency-safe. The lambda runs under ConcurrentHashMap's per-key bucket lock,
    // which serializes with unregisterShuffle's taskLocations.remove. Together with
    // unregisterShuffle's (shuffleInfos.remove, then taskLocations.remove) ordering,
    // any concurrent unregisterShuffle ends with no orphan entry in taskLocations:
    //   - If the lambda observes the already-cleared shuffleInfos, it returns null and
    //     no entry is installed.
    //   - If the lambda observes shuffleInfos still present, it installs the entry, and
    //     the matching unregisterShuffle's taskLocations.remove (which had to wait for
    //     this bucket lock) clears it strictly after.
    var registered = true
    taskLocations.compute(
      shuffleId,
      (
          _: Int,
          shuffleTaskLocationMap: ConcurrentHashMap[Long, StreamingShuffleTaskLocation]) => {
        if (!shuffleInfos.containsKey(shuffleId)) {
          registered = false
          null
        } else {
          val newShuffleTaskLocationMap = if (shuffleTaskLocationMap == null) {
            new ConcurrentHashMap[Long, StreamingShuffleTaskLocation]()
          } else {
            shuffleTaskLocationMap
          }
          if (location.mapIndex >= 0) {
            newShuffleTaskLocationMap.asScala.collect {
              case (existingMapId, existingLocation)
                  if existingMapId != mapId && existingLocation.mapIndex == location.mapIndex =>
                existingMapId
            }.toSeq.foreach(newShuffleTaskLocationMap.remove)
          }
          newShuffleTaskLocationMap.put(mapId, location)
          newShuffleTaskLocationMap
        }
      })
    if (!registered) {
      logWarning(
        log"Shuffle ${MDC(LogKeys.SHUFFLE_ID, shuffleId)} was unregistered " +
          log"during registration of writer task ${MDC(LogKeys.MAP_ID, mapId)}")
    }
    registered
  }

  override def getAllShuffleWriterTaskLocations(
      shuffleId: Int): Option[Map[Long, StreamingShuffleTaskLocation]] = {
    val shuffleInfo = shuffleInfos.get(shuffleId)
    if (shuffleInfo == null) {
      logWarning(log"Attempting to get shuffle writer task location information " +
        log"for shuffle with id ${MDC(LogKeys.SHUFFLE_ID, shuffleId)} that hasn't been registered.")
      return None
    }

    val shuffleTaskLocationMap = taskLocations.get(shuffleId)
    if (shuffleTaskLocationMap == null) {
      return None
    }

    // only return the mapper task location information if all mappers have registered
    if (shuffleInfo.numMaps == shuffleTaskLocationMap.size()) {
      Some(shuffleTaskLocationMap.asScala.toMap)
    } else {
      None
    }
  }

  override def stop(): Unit = {
    trackerMasterMessages.offer(PoisonPill)
    threadpool.shutdown()
    if (trackerEndpoint != null) {
      try {
        sendTracker(StopStreamingShuffleOutputTracker)
      } catch {
        case e: SparkException =>
          logError(log"Could not tell tracker we are stopping.", e)
      }
      trackerEndpoint = null
    }
  }

  override def getAvailableShuffleWriterTaskLocations(
      shuffleId: Int): Option[ShuffleLocationResponse] = {
    val shuffleInfo = shuffleInfos.get(shuffleId)
    if (shuffleInfo == null) {
      logWarning(log"Attempting to get shuffle writer task location information for " +
        log"shuffle with id ${MDC(LogKeys.SHUFFLE_ID, shuffleId)} that hasn't been registered.")
      return None
    }
    val locations = taskLocations.get(shuffleId)
    val shuffleTaskLocationMap = if (locations == null) {
      Map.empty[Long, StreamingShuffleTaskLocation]
    } else {
      locations.asScala.toMap
    }

    Some(ShuffleLocationResponse(shuffleTaskLocationMap, shuffleInfo.numMaps))
  }
}

private[spark] class StreamingShuffleOutputTrackerWorker(conf: SparkConf)
  extends StreamingShuffleOutputTracker(conf) {

  private case class CachedAvailableLocations(
      response: Option[ShuffleLocationResponse], refreshedAtNanos: Long)
  private val availableLocationCache =
    new ConcurrentHashMap[Int, CachedAvailableLocations]()
  private val availableLocationRefreshLocks = new ConcurrentHashMap[Int, Object]()
  private val locationRefreshNanos = TimeUnit.MILLISECONDS.toNanos(
    conf.get(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL))

  private def freshCachedLocations(
      shuffleId: Int,
      nowNanos: Long): Option[Option[ShuffleLocationResponse]] = {
    Option(availableLocationCache.get(shuffleId)).filter { cached =>
      nowNanos - cached.refreshedAtNanos < locationRefreshNanos
    }.map(_.response)
  }

  override def registerShuffleWriterTask(
      shuffleId: Int,
      mapId: Long,
      location: StreamingShuffleTaskLocation): Boolean = {
    askTracker[Boolean](UpdateStreamingShuffleTaskLocation(shuffleId, mapId, location))
  }

  override def publishShuffleWriterTask(
      shuffleId: Int,
      mapId: Long,
      location: StreamingShuffleTaskLocation): Unit = {
    trackerEndpoint.send(PublishStreamingShuffleTaskLocation(shuffleId, mapId, location))
  }

  override def getAllShuffleWriterTaskLocations(
      shuffleId: Int): Option[Map[Long, StreamingShuffleTaskLocation]] = {
    askTracker[Option[Map[Long, StreamingShuffleTaskLocation]]](
      GetAllStreamingShuffleTaskLocations(shuffleId))
  }

  override def getAvailableShuffleWriterTaskLocations(
      shuffleId: Int): Option[ShuffleLocationResponse] = {
    val now = System.nanoTime()
    freshCachedLocations(shuffleId, now).getOrElse {
      val refreshLock = availableLocationRefreshLocks.computeIfAbsent(shuffleId, _ => new Object)
      refreshLock.synchronized {
        val lockedNow = System.nanoTime()
        freshCachedLocations(shuffleId, lockedNow).getOrElse {
          val response = askTracker[Option[ShuffleLocationResponse]](
            GetAvailableStreamingShuffleTaskLocations(shuffleId))
          availableLocationCache.put(
            shuffleId, CachedAvailableLocations(response, System.nanoTime()))
          response
        }
      }
    }
  }

  override def getAvailableShuffleWriterTaskLocationsBatch(
      shuffleIds: Seq[Int]): Map[Int, ShuffleLocationResponse] = {
    val distinctShuffleIds = shuffleIds.distinct.sorted
    val initialNow = System.nanoTime()
    val initiallyFresh = distinctShuffleIds.flatMap { shuffleId =>
      freshCachedLocations(shuffleId, initialNow).map(shuffleId -> _)
    }.toMap
    val initiallyStale = distinctShuffleIds.filterNot(initiallyFresh.contains)

    def refreshUnderLocks(remainingLocks: List[Object]): Unit = remainingLocks match {
      case lock :: tail => lock.synchronized(refreshUnderLocks(tail))
      case Nil =>
        val lockedNow = System.nanoTime()
        val stale = initiallyStale.filter(
          freshCachedLocations(_, lockedNow).isEmpty)
        if (stale.nonEmpty) {
          val responses = askTracker[Map[Int, ShuffleLocationResponse]](
            GetAvailableStreamingShuffleTaskLocationsBatch(stale))
          val refreshedAt = System.nanoTime()
          stale.foreach { shuffleId =>
            availableLocationCache.put(
              shuffleId, CachedAvailableLocations(responses.get(shuffleId), refreshedAt))
          }
        }
    }

    if (initiallyStale.nonEmpty) {
      // A task-owned reader can refresh one shuffle concurrently with the prepared discovery's
      // batch. Acquire the same per-shuffle locks in shuffle-id order so the batch neither races a
      // stale cache overwrite nor deadlocks with another overlapping batch.
      val locks = initiallyStale.sorted.map { shuffleId =>
        availableLocationRefreshLocks.computeIfAbsent(shuffleId, _ => new Object)
      }.toList
      refreshUnderLocks(locks)
    }
    distinctShuffleIds.flatMap { shuffleId =>
      Option(availableLocationCache.get(shuffleId)).flatMap(_.response).map(shuffleId -> _)
    }.toMap
  }

  override def containsShuffle(shuffleId: Int): Boolean = {
    askTracker[Boolean](IsStreamingShuffleRegistered(shuffleId))
  }

  override def registerReceiveEndpoint(
      executorId: String,
      endpoint: RpcEndpointRef): Boolean = {
    askTracker[Boolean](RegisterStreamingShuffleReceiveEndpoint(executorId, endpoint))
  }

  override def markInboxDrainReady(
      executorId: String,
      id: StreamingShuffleReceiveInboxId): Unit = {
    trackerEndpoint.send(StreamingShuffleInboxDrainReady(executorId, id))
  }
}

private[spark] object StreamingShuffleOutputTracker extends Logging {
  val ENDPOINT_NAME = "StreamingShuffleOutputTracker"
}
