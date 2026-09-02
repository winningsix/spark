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

import java.io.File
import java.util.concurrent.{BlockingQueue, CompletableFuture, ConcurrentHashMap,
  CopyOnWriteArrayList, ExecutorService, LinkedBlockingQueue, RejectedExecutionException,
  ScheduledExecutorService, Semaphore, TimeoutException, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicLong}

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import org.apache.spark.{ShuffleLocationResponse, SparkConf, SparkEnv, StreamingShuffleTaskLocation,
  TaskContext}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES,
  STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE,
  STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED,
  STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL,
  STREAMING_SHUFFLE_PREPARED_CLIENT_CREATION_THREADS,
  STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES,
  STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT,
  STREAMING_SHUFFLE_READER_MAX_MEMORY, STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED,
  STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY}
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.StreamingShuffleMessage
import org.apache.spark.rpc.{RpcCallContext, RpcEndpoint, RpcEnv}
import org.apache.spark.util.{ErrorNotifier, ThreadUtils, Utils}

private[spark] case class StreamingShuffleReceiveInboxId(
    shuffleId: Int,
    stageId: Int,
    stageAttemptNumber: Int,
    partitionId: Int,
    taskAttemptId: Long,
    readerOrdinal: Int = 0)

private[spark] case class PrepareStreamingShuffleReceiveInbox(
    id: StreamingShuffleReceiveInboxId)

private[spark] case class PrepareStreamingShuffleReceiveInboxes(
    ids: Seq[StreamingShuffleReceiveInboxId])

private[spark] case class ReleaseStreamingShuffleReceiveInbox(
    id: StreamingShuffleReceiveInboxId)

private[spark] case class StreamingShuffleWriterLocationsAvailable(shuffleIds: Seq[Int])

private[streaming] case class StreamingShuffleReceiveInboxStats(
    spilledBytes: Long,
    spilledMessages: Long)

private[streaming] object StreamingShuffleReceiveService {
  val ENDPOINT_NAME = "StreamingShuffleReceiveService"
}

/**
 * Executor-scoped owner for streaming-shuffle receive queues.
 *
 * An attached inbox is keyed by task attempt and reader ordinal, preserving retry/speculation
 * semantics while allowing one task to read a reused shuffle more than once. The prepare protocol
 * creates those ordinal inboxes before compute and transfers each through a lease without moving
 * queue cleanup back into the task.
 */
private[streaming] class StreamingShuffleReceiveService(
    conf: SparkConf,
    sharedClient: () => Option[StreamingShuffleExecutorClient] = () => None,
    onDrainReady: StreamingShuffleReceiveInboxId => Unit = _ => ()) extends Logging {
  private val inboxes =
    new ConcurrentHashMap[StreamingShuffleReceiveInboxId, StreamingShuffleReceiveInbox]()
  private case class PreparedInboxKey(
      shuffleId: Int,
      stageId: Int,
      stageAttemptNumber: Int,
      partitionId: Int,
      readerOrdinal: Int)
  private val preparedInboxes =
    new ConcurrentHashMap[PreparedInboxKey, StreamingShuffleReceiveInbox]()
  private case class TaskShuffleKey(
      shuffleId: Int,
      stageId: Int,
      stageAttemptNumber: Int,
      partitionId: Int,
      taskAttemptId: Long)
  private val nextReaderOrdinal = new ConcurrentHashMap[TaskShuffleKey, AtomicInteger]()

  private def preparedInboxKey(id: StreamingShuffleReceiveInboxId): PreparedInboxKey = {
    PreparedInboxKey(
      id.shuffleId,
      id.stageId,
      id.stageAttemptNumber,
      id.partitionId,
      id.readerOrdinal)
  }
  private case class PreparedResources(
      discovery: StreamingShufflePreparedReceiveDiscovery,
      clientCreationExecutor: ExecutorService) {
    def close(): Unit = {
      discovery.close()
      clientCreationExecutor.shutdownNow()
    }
  }
  @volatile private var preparedResources: PreparedResources = _

  private def getPreparedResources: PreparedResources = {
    var resources = preparedResources
    if (resources == null) synchronized {
      resources = preparedResources
      if (resources == null) {
        resources = PreparedResources(
          new StreamingShufflePreparedReceiveDiscovery(conf),
          ThreadUtils.newDaemonFixedThreadPool(
            math.max(1, math.min(
              conf.get(EXECUTOR_CORES),
              conf.get(STREAMING_SHUFFLE_PREPARED_CLIENT_CREATION_THREADS))),
            "streaming-shuffle-prepared-client"))
        preparedResources = resources
      }
    }
    resources
  }

  def acquire(
      shuffleId: Int,
      context: TaskContext): StreamingShuffleReceiveInboxLease = {
    val taskShuffleKey = TaskShuffleKey(
      shuffleId,
      context.stageId(),
      context.stageAttemptNumber(),
      context.partitionId(),
      context.taskAttemptId())
    val ordinalCounter = nextReaderOrdinal.computeIfAbsent(
      taskShuffleKey, _ => new AtomicInteger(0))
    val readerOrdinal = ordinalCounter.getAndIncrement()
    context.addTaskCompletionListener[Unit] { _ =>
      nextReaderOrdinal.remove(taskShuffleKey, ordinalCounter)
    }
    val logicalPreparedId = StreamingShuffleReceiveInboxId(
      shuffleId,
      context.stageId(),
      context.stageAttemptNumber(),
      context.partitionId(),
      -1L,
      readerOrdinal)
    val prepared = preparedInboxes.get(preparedInboxKey(logicalPreparedId))
    val preparedId = if (prepared == null) logicalPreparedId else prepared.id
    if (prepared != null) {
      if (prepared.attach(context.taskAttemptId())) {
        return new StreamingShuffleReceiveInboxLease(prepared, () => releaseLease(prepared))
      }
    }
    if (conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED)) {
      val state = if (prepared == null) "was not prepared" else "was already attached"
      throw new IllegalStateException(
        s"Streaming shuffle receive inbox $preparedId $state when task " +
          s"${context.taskAttemptId()} attempted to attach. Prepared receive mode must not " +
          "fall back to a task-owned route because that bypasses the ready acknowledgement.")
    }
    // Compatibility mode for direct users of the executor-scoped queue service. Production
    // prepared receive mode takes the strict branch above and therefore always attaches the
    // scheduler-owned inbox that was routed before task launch.
    val id = preparedId.copy(taskAttemptId = context.taskAttemptId())
    val inbox = new StreamingShuffleReceiveInbox(id, createQueue())
    require(inbox.attach(context.taskAttemptId()), s"Could not attach receive inbox $id")
    val existing = inboxes.putIfAbsent(id, inbox)
    require(existing == null, s"Streaming shuffle receive inbox $id is already active")
    new StreamingShuffleReceiveInboxLease(inbox, () => releaseLease(inbox))
  }

  def prepare(id: StreamingShuffleReceiveInboxId): Boolean = synchronized {
    require(id.taskAttemptId < 0L, s"Prepared inbox must use a negative generation token: $id")
    val key = preparedInboxKey(id)
    val logicalExisting = preparedInboxes.get(key)
    if (logicalExisting != null) {
      return logicalExisting.id == id && logicalExisting.session.isDefined
    }
    val inbox = new StreamingShuffleReceiveInbox(id, createQueue())
    val existing = inboxes.putIfAbsent(id, inbox)
    if (existing != null) {
      inbox.close()
      val logicalRace = preparedInboxes.putIfAbsent(key, existing)
      val current = if (logicalRace == null) existing else logicalRace
      return current.id == id && current.session.isDefined
    }
    val logicalRace = preparedInboxes.putIfAbsent(key, inbox)
    if (logicalRace != null) {
      inboxes.remove(id, inbox)
      inbox.close()
      return logicalRace.id == id && logicalRace.session.isDefined
    }
    try {
      val executorClient = sharedClient().getOrElse(throw new IllegalStateException(
        "Prepared receive inbox requires the shared executor client"))
      val resources = getPreparedResources
      inbox.startPreparedSession(new StreamingShufflePreparedReceiveSession(
        inbox,
        executorClient,
        conf,
        resources.discovery,
        resources.clientCreationExecutor,
        () => onDrainReady(id)))
      logDebug(s"Prepared streaming shuffle receive inbox $id")
    } catch {
      case t: Throwable =>
        preparedInboxes.remove(key, inbox)
        inboxes.remove(id, inbox)
        inbox.close()
        throw t
    }
    inbox.session.isDefined
  }

  def prepareAll(ids: Seq[StreamingShuffleReceiveInboxId]): Boolean = synchronized {
    ids.forall(prepare)
  }

  def releasePrepared(id: StreamingShuffleReceiveInboxId): Boolean = {
    val inbox = inboxes.get(id)
    inbox != null && inboxes.remove(id, inbox) && {
      preparedInboxes.remove(preparedInboxKey(id), inbox)
      inbox.close()
      true
    }
  }

  def unregisterShuffle(shuffleId: Int): Unit = {
    inboxes.entrySet().asScala.foreach { entry =>
      if (entry.getKey.shuffleId == shuffleId && inboxes.remove(entry.getKey, entry.getValue)) {
        preparedInboxes.remove(preparedInboxKey(entry.getKey), entry.getValue)
        entry.getValue.close()
      }
    }
  }

  def writerLocationsAvailable(shuffleIds: Seq[Int]): Unit = {
    SparkEnv.get.streamingShuffleOutputTracker.foreach(
      _.invalidateAvailableShuffleWriterTaskLocations(shuffleIds))
    val resources = preparedResources
    if (resources != null) resources.discovery.writerLocationsAvailable()
  }

  def close(): Unit = synchronized {
    inboxes.entrySet().asScala.foreach { entry =>
      if (inboxes.remove(entry.getKey, entry.getValue)) {
        preparedInboxes.remove(preparedInboxKey(entry.getKey), entry.getValue)
        entry.getValue.close()
      }
    }
    val resources = preparedResources
    if (resources != null) {
      resources.close()
      preparedResources = null
    }
  }

  private[streaming] def activeInboxCount: Int = inboxes.size()

  private def releaseLease(
      inbox: StreamingShuffleReceiveInbox): StreamingShuffleReceiveInboxStats = {
    inboxes.remove(inbox.id, inbox)
    if (inbox.id.taskAttemptId < 0L) {
      preparedInboxes.remove(preparedInboxKey(inbox.id), inbox)
    }
    inbox.close()
  }

  private def createQueue(): BlockingQueue[StreamingShuffleMessage] = {
    if (conf.get(STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED)) {
      new StreamingShuffleMessageQueue(
        conf.get(STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY),
        Some(new File(Utils.getLocalDir(conf))))
    } else {
      new LinkedBlockingQueue[StreamingShuffleMessage]()
    }
  }
}

private[streaming] class StreamingShuffleReceiveInbox(
    val id: StreamingShuffleReceiveInboxId,
    val queue: BlockingQueue[StreamingShuffleMessage]) {
  private val closed = new AtomicBoolean(false)
  private val attached = new AtomicBoolean(false)
  @volatile private var preparedSession: StreamingShufflePreparedReceiveSession = _

  def attach(taskAttemptId: Long): Boolean = attached.compareAndSet(false, true)

  private[streaming] def isAttached: Boolean = attached.get()

  def startPreparedSession(session: StreamingShufflePreparedReceiveSession): Unit = synchronized {
    require(preparedSession == null, s"Prepared session already exists for $id")
    preparedSession = session
    session.start()
  }

  def session: Option[StreamingShufflePreparedReceiveSession] = Option(preparedSession)

  def close(): StreamingShuffleReceiveInboxStats = {
    if (!closed.compareAndSet(false, true)) {
      return StreamingShuffleReceiveInboxStats(0L, 0L)
    }
    if (preparedSession != null) {
      preparedSession.close()
    }
    val messages = new java.util.ArrayList[StreamingShuffleMessage]()
    queue.drainTo(messages)
    messages.forEach(_.release())
    queue match {
      case spillable: StreamingShuffleMessageQueue =>
        val stats = StreamingShuffleReceiveInboxStats(
          spillable.spilledBytesCount,
          spillable.spilledMessagesCount)
        spillable.close()
        stats
      case _ =>
        StreamingShuffleReceiveInboxStats(0L, 0L)
    }
  }
}

private[streaming] class StreamingShuffleReceiveInboxLease(
    private val inbox: StreamingShuffleReceiveInbox,
    release: () => StreamingShuffleReceiveInboxStats) {
  private val closed = new AtomicBoolean(false)

  val id: StreamingShuffleReceiveInboxId = inbox.id
  val queue: BlockingQueue[StreamingShuffleMessage] = inbox.queue
  private[streaming] val preparedSession: Option[StreamingShufflePreparedReceiveSession] =
    inbox.session

  def close(): StreamingShuffleReceiveInboxStats = {
    if (closed.compareAndSet(false, true)) {
      release()
    } else {
      StreamingShuffleReceiveInboxStats(0L, 0L)
    }
  }
}

private[streaming] class StreamingShuffleReceiveServiceEndpoint(
    override val rpcEnv: RpcEnv,
    service: StreamingShuffleReceiveService) extends RpcEndpoint {
  override def receive: PartialFunction[Any, Unit] = {
    case ReleaseStreamingShuffleReceiveInbox(id) => service.releasePrepared(id)
    case StreamingShuffleWriterLocationsAvailable(shuffleIds) =>
      service.writerLocationsAvailable(shuffleIds)
  }

  override def receiveAndReply(context: RpcCallContext): PartialFunction[Any, Unit] = {
    case PrepareStreamingShuffleReceiveInbox(id) => context.reply(service.prepare(id))
    case PrepareStreamingShuffleReceiveInboxes(ids) => context.reply(service.prepareAll(ids))
    case ReleaseStreamingShuffleReceiveInbox(id) =>
      context.reply(service.releasePrepared(id))
  }
}

/**
 * Executor-scoped writer-location discovery for prepared receive inboxes.
 *
 * All resident inboxes for one shuffle consume the same tracker snapshot. This changes the
 * control-plane cost from one polling thread per reducer inbox to one bounded polling loop per
 * executor. Inbox queues and transport handlers remain independent; only immutable location
 * discovery and the client-creation pool are shared.
 */
private[streaming] class StreamingShufflePreparedReceiveDiscovery(
    conf: SparkConf,
    snapshotProvider: Seq[Int] => Map[Int, ShuffleLocationResponse] = shuffleIds =>
      SparkEnv.get.streamingShuffleOutputTracker.get
        .getAvailableShuffleWriterTaskLocationsBatch(shuffleIds)) extends Logging {
  private val closed = new AtomicBoolean(false)
  private val sessions =
    new ConcurrentHashMap[Int, CopyOnWriteArrayList[StreamingShufflePreparedReceiveSession]]()
  private val activeSessions = new AtomicInteger(0)
  private val peakActiveSessions = new AtomicInteger(0)
  private val snapshotRequests = new AtomicLong(0L)
  private val snapshotDeliveries = new AtomicLong(0L)
  private val routeRegistrationRequests = new AtomicLong(0L)
  private val routeRegistrationTasks = new AtomicLong(0L)
  private case class PendingRouteRegistration(
      host: String,
      port: Int,
      executor: ExecutorService,
      registration: () => Unit,
      result: CompletableFuture[Void])
  private val routeRegistrationLock = new Object
  private val pendingRouteRegistrations =
    new mutable.ArrayBuffer[PendingRouteRegistration]()
  private var collectingSnapshotRoutes = false
  private val refreshIntervalMs = conf.get(STREAMING_SHUFFLE_LOCATION_REFRESH_INTERVAL)
  private val immediatePollScheduled = new AtomicBoolean(false)
  private val executor: ScheduledExecutorService =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor(
      "streaming-shuffle-prepared-discovery")

  executor.scheduleWithFixedDelay(
    () => poll(), refreshIntervalMs, refreshIntervalMs, TimeUnit.MILLISECONDS)

  def register(session: StreamingShufflePreparedReceiveSession): Unit = {
    require(!closed.get(), "Prepared receive discovery is closed")
    val added = sessions.computeIfAbsent(
      session.shuffleId, _ => new CopyOnWriteArrayList[StreamingShufflePreparedReceiveSession]())
      .add(session)
    require(added, s"Prepared receive session ${session.shuffleId} is already registered")
    val current = activeSessions.incrementAndGet()
    peakActiveSessions.accumulateAndGet(current, Math.max)
    requestImmediatePoll()
  }

  private def requestImmediatePoll(): Unit = {
    if (!closed.get() && immediatePollScheduled.compareAndSet(false, true)) {
      try {
        executor.schedule(
          new Runnable {
            override def run(): Unit = {
              immediatePollScheduled.set(false)
              if (!closed.get()) poll()
            }
          },
          StreamingShufflePreparedReceiveDiscovery.IMMEDIATE_POLL_DELAY_MS,
          TimeUnit.MILLISECONDS)
      } catch {
        case _: RejectedExecutionException if closed.get() =>
          immediatePollScheduled.set(false)
        case error: Throwable =>
          immediatePollScheduled.set(false)
          throw error
      }
    }
  }

  def writerLocationsAvailable(): Unit = requestImmediatePoll()

  def unregister(session: StreamingShufflePreparedReceiveSession): Unit = {
    val shuffleSessions = sessions.get(session.shuffleId)
    if (shuffleSessions != null) {
      if (shuffleSessions.remove(session)) activeSessions.decrementAndGet()
      if (shuffleSessions.isEmpty) sessions.remove(session.shuffleId, shuffleSessions)
    }
  }

  /**
   * Queue one inbox's routes for an endpoint. During a discovery poll, all inboxes see the same
   * immutable writer snapshot, so delay submission until snapshot delivery finishes and execute
   * every request for the same endpoint as one worker task. Route handlers, futures, and failures
   * remain per inbox; only the executor scheduling envelope is shared.
   */
  def submitRouteRegistration(
      host: String,
      port: Int,
      executor: ExecutorService)(registration: () => Unit): CompletableFuture[Void] = {
    val result = new CompletableFuture[Void]()
    val ready = routeRegistrationLock.synchronized {
      routeRegistrationRequests.incrementAndGet()
      pendingRouteRegistrations +=
        PendingRouteRegistration(host, port, executor, registration, result)
      if (collectingSnapshotRoutes) Seq.empty else drainPendingRouteRegistrations()
    }
    submitRouteRegistrationTasks(ready)
    result
  }

  private def drainPendingRouteRegistrations(): Seq[PendingRouteRegistration] = {
    val ready = pendingRouteRegistrations.toSeq
    pendingRouteRegistrations.clear()
    ready
  }

  private def submitRouteRegistrationTasks(
      requests: Seq[PendingRouteRegistration]): Unit = {
    requests.groupBy(request => (request.executor, request.host, request.port)).foreach {
      case ((executor, _, _), endpointRequests) =>
        routeRegistrationTasks.incrementAndGet()
        try {
          CompletableFuture.runAsync(
            () => {
              val failures = StreamingShuffleExecutorClient.runBatchedRouteRegistrations(
                endpointRequests.map(request => request.result -> request.registration))
              endpointRequests.foreach { request =>
                failures.get(request.result) match {
                  case Some(error) => request.result.completeExceptionally(error)
                  case None => request.result.complete(null)
                }
              }
            },
            executor)
        } catch {
          case error: Throwable =>
            endpointRequests.foreach(_.result.completeExceptionally(error))
        }
    }
  }

  private def poll(): Unit = {
    val activeByShuffle = sessions.entrySet().asScala.flatMap { entry =>
      val active = entry.getValue.asScala.filterNot(_.isClosed).toSeq
      if (active.nonEmpty) Some(entry.getKey -> active) else None
    }.toMap
    if (activeByShuffle.nonEmpty) {
      try {
        val nowNanos = System.nanoTime()
        activeByShuffle.values.flatten.foreach(_.checkRouteRegistrationTimeout(nowNanos))
        snapshotRequests.incrementAndGet()
        val snapshots = snapshotProvider(activeByShuffle.keys.toSeq)
        routeRegistrationLock.synchronized {
          collectingSnapshotRoutes = true
        }
        try {
          activeByShuffle.foreach { case (shuffleId, active) =>
            snapshots.get(shuffleId).foreach { snapshot =>
              snapshotDeliveries.addAndGet(active.size)
              active.foreach { session =>
                try session.onWriterSnapshot(snapshot)
                catch {
                  case error: Throwable => session.failDiscovery(error)
                }
              }
            }
          }
        } finally {
          val ready = routeRegistrationLock.synchronized {
            collectingSnapshotRoutes = false
            drainPendingRouteRegistrations()
          }
          submitRouteRegistrationTasks(ready)
        }
      } catch {
        case error: Throwable => activeByShuffle.values.flatten.foreach(_.failDiscovery(error))
      }
    }
  }

  private[streaming] def stats: (Int, Int, Long, Long) =
    (activeSessions.get(), peakActiveSessions.get(),
      snapshotRequests.get(), snapshotDeliveries.get())

  private[streaming] def routeRegistrationStats: (Long, Long) =
    (routeRegistrationRequests.get(), routeRegistrationTasks.get())

  def close(): Unit = {
    if (closed.compareAndSet(false, true)) {
      executor.shutdownNow()
      logInfo(
        s"Closing prepared shuffle discovery: activeSessions=${activeSessions.get()} " +
          s"peakActiveSessions=${peakActiveSessions.get()} " +
          s"snapshotRequests=${snapshotRequests.get()} " +
          s"snapshotDeliveries=${snapshotDeliveries.get()} " +
          s"routeRegistrationRequests=${routeRegistrationRequests.get()} " +
          s"routeRegistrationTasks=${routeRegistrationTasks.get()}")
      sessions.clear()
      activeSessions.set(0)
    }
  }
}

private[streaming] object StreamingShufflePreparedReceiveDiscovery {
  private val IMMEDIATE_POLL_DELAY_MS = 1L
}

/** Network-only reader lifecycle that starts before the compute task is launched. */
private[streaming] class StreamingShufflePreparedReceiveSession(
    inbox: StreamingShuffleReceiveInbox,
    sharedClient: StreamingShuffleExecutorClient,
    conf: SparkConf,
    discovery: StreamingShufflePreparedReceiveDiscovery,
    clientCreationExecutor: ExecutorService,
    signalDrainReady: () => Unit) extends Logging {
  private val closed = new AtomicBoolean(false)
  private val discoveryComplete = new AtomicBoolean(false)
  private val drainReady = new AtomicBoolean(false)
  private val drainReadyBytes = conf.get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES)
  private val clients = new ConcurrentHashMap[Long, TransportClient]()
  private val handlers = new ConcurrentHashMap[Long, StreamingShuffleClientHandler]()
  private val clientFutures = new ConcurrentHashMap[Long, CompletableFuture[Void]]()
  private val clientFutureStartedNanos =
    new ConcurrentHashMap[CompletableFuture[Void], Long]()
  private val lastIdleDiagnosticNanos = new AtomicLong(0L)
  private val mapIndexes = mutable.HashSet.empty[Int]
  private val routeLifecycleLock = new Object
  private val routeRegistrationTimeoutNanos = TimeUnit.MILLISECONDS.toNanos(
    conf.get(STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT))

  val shuffleId: Int = inbox.id.shuffleId

  val totalNumShuffleWriters = new AtomicInteger(-1)
  val errorNotifier = new ErrorNotifier()
  val terminationAckControlMessageSet = ConcurrentHashMap.newKeySet[Long]()
  val allTermAcksSentNotice = new Semaphore(0)

  private def markDrainReady(): Unit = {
    if (drainReady.compareAndSet(false, true)) {
      logDebug(s"Streaming shuffle receive inbox ${inbox.id} is drain-ready")
      signalDrainReady()
    }
  }

  private def maybeMarkDrainReady(): Unit = inbox.queue match {
    case queue: StreamingShuffleMessageQueue
        if drainReadyBytes == 0L || queue.queuedMemoryBytesCount >= drainReadyBytes =>
      markDrainReady()
    case queue if drainReadyBytes == 0L && !queue.isEmpty =>
      markDrainReady()
    case _ =>
  }

  def start(): Unit = discovery.register(this)

  def isClosed: Boolean = closed.get()

  /** Re-advertise bounded route windows for writers that have not terminated yet. */
  def repairIdleCreditWindows(): Unit = {
    val repairs = handlers.entrySet().asScala.flatMap { entry =>
      Option(clients.get(entry.getKey)).map(_ -> entry.getValue)
    }.toSeq
    sharedClient.repairCreditWindows(repairs)
    val now = System.nanoTime()
    val previous = lastIdleDiagnosticNanos.get()
    if (now - previous >= TimeUnit.SECONDS.toNanos(10L) &&
        lastIdleDiagnosticNanos.compareAndSet(previous, now)) {
      val routeProgress = handlers.entrySet().asScala.map { entry =>
        entry.getKey -> entry.getValue.routeProgressForDiagnostics
      }.toSeq
      val missingTerminals = routeProgress.collect {
        case (writerId, (lastSequence, false, releasedBytes)) =>
          s"$writerId:lastSeq=$lastSequence:released=$releasedBytes"
      }.sorted.take(12)
      logWarning(
        s"Prepared streaming shuffle inbox ${inbox.id} remained idle: " +
          s"attached=${inbox.isAttached} " +
          s"expectedWriters=${totalNumShuffleWriters.get()} " +
          s"advertisedRoutes=${clientFutures.size()} registeredRoutes=${handlers.size()} " +
          s"terminationAcks=${terminationAckControlMessageSet.size()} " +
          s"discoveryComplete=${discoveryComplete.get()} " +
          s"missingTerminalRoutes=${missingTerminals.mkString("[", ",", "]")}")
    }
  }

  def onWriterSnapshot(snapshot: ShuffleLocationResponse): Unit = {
    if (closed.get() || discoveryComplete.get()) return
    val ShuffleLocationResponse(locations, numWriters) = snapshot
    totalNumShuffleWriters.compareAndSet(-1, numWriters)
    require(totalNumShuffleWriters.get() == numWriters,
      s"Writer count changed for prepared inbox ${inbox.id}")
    // With no map partitions there can be no data or termination frame to trigger the normal
    // ready path. Discovery itself proves that the inbox can be attached and drained empty.
    if (numWriters == 0) markDrainReady()
    // Only the configured elastic producer window can publish concurrently for this shuffle.
    // Size the route window from that frontier instead of every lifetime map task.
    val liveWriterWindow = conf
      .get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE)
      .map(math.min(numWriters, _))
      .getOrElse(numWriters)
    val perWriterByteLimit = math.max(
      conf.get(STREAMING_SHUFFLE_READER_MAX_MEMORY) /
        math.max(1, liveWriterWindow), 1L)
    val newlyPublished = locations.filter { case (mapId, location) =>
      val duplicate = location.mapIndex >= 0 && mapIndexes.contains(location.mapIndex)
      if (!duplicate && !clientFutures.containsKey(mapId)) {
        if (location.mapIndex >= 0) mapIndexes += location.mapIndex
        true
      } else {
        false
      }
    }
    // Register every route in one snapshot that targets the same executor as one initial-credit
    // transport body. The shared creation pool bounds this work across all prepared inboxes.
    newlyPublished.groupBy { case (_, location) =>
      (location.host, location.port)
    }.foreach { case ((host, port), routeLocations) =>
      val future = discovery.submitRouteRegistration(host, port, clientCreationExecutor)(() =>
        registerRoutes(host, port, routeLocations.toSeq, perWriterByteLimit))
      clientFutureStartedNanos.putIfAbsent(future, System.nanoTime())
      future.whenComplete { (_, error) =>
        clientFutureStartedNanos.remove(future)
        if (error != null) {
          failDiscovery(Option(error.getCause).getOrElse(error))
        } else {
          maybeCompleteDiscovery()
        }
      }
      routeLocations.foreach { case (mapId, _) => clientFutures.put(mapId, future) }
    }
    maybeCompleteDiscovery()
  }

  private[streaming] def checkRouteRegistrationTimeout(nowNanos: Long): Unit = {
    if (closed.get() || discoveryComplete.get()) return
    clientFutureStartedNanos.entrySet().asScala.find { entry =>
      !entry.getKey.isDone && nowNanos - entry.getValue >= routeRegistrationTimeoutNanos
    }.foreach { _ =>
      val completed = clientFutures.values().asScala.count(_.isDone)
      failDiscovery(new TimeoutException(
        s"Prepared shuffle route registration timed out for ${inbox.id}: " +
          s"completed=$completed, advertised=${clientFutures.size()}, " +
          s"expected=${totalNumShuffleWriters.get()}"))
    }
  }

  /**
   * Stop polling only after every advertised writer route has actually installed its handler and
   * successfully flushed its initial-credit write. Merely submitting the registration worker is
   * not enough: a synchronous transport connection can still be queued or blocked at that point,
   * and removing this session from discovery would leave such a route with neither polling nor
   * credit repair.
   */
  private def maybeCompleteDiscovery(): Unit = {
    val numWriters = totalNumShuffleWriters.get()
    if (numWriters >= 0 && clientFutures.size() >= numWriters &&
        clientFutures.values().asScala.forall { future =>
          future.isDone && !future.isCompletedExceptionally && !future.isCancelled
        } && discoveryComplete.compareAndSet(false, true)) {
      discovery.unregister(this)
    }
  }

  private def registerRoutes(
      host: String,
      port: Int,
      routeLocations: Seq[(Long, StreamingShuffleTaskLocation)],
      perWriterByteLimit: Long): Unit = {
    val routeHandlers = routeLocations.map { case (mapId, _) =>
      val handler = new StreamingShuffleClientHandler(
        mapId.toInt,
        inbox.id.partitionId,
        inbox.queue,
        inbox.id.shuffleId,
        perWriterByteLimit,
        null,
        errorNotifier,
        () => maybeMarkDrainReady())
      handler.setOnTermAckResponseHandler { writerId =>
        terminationAckControlMessageSet.add(writerId.toLong)
        if (terminationAckControlMessageSet.size() == totalNumShuffleWriters.get()) {
          allTermAcksSentNotice.release()
          markDrainReady()
        }
      }
      mapId -> handler
    }
    val routeClients = sharedClient.registerBatch(
      inbox.id.shuffleId,
      inbox.id.partitionId,
      host,
      port,
      routeHandlers.map { case (mapId, handler) => mapId.toInt -> handler })
    routeLifecycleLock.synchronized {
      if (closed.get()) {
        routeHandlers.foreach { case (mapId, handler) =>
          sharedClient.unregister(
            inbox.id.shuffleId, Math.toIntExact(mapId), inbox.id.partitionId, handler)
        }
      } else {
        routeHandlers.foreach { case (mapId, handler) =>
          handlers.put(mapId, handler)
          clients.put(mapId, routeClients(mapId.toInt))
        }
      }
    }
  }

  def failDiscovery(error: Throwable): Unit = {
    if (discoveryComplete.compareAndSet(false, true)) discovery.unregister(this)
    if (!closed.get()) {
      logError(s"Prepared receive session failed for ${inbox.id}", error)
      errorNotifier.markError(error)
      markDrainReady()
    }
  }

  def close(): Unit = {
    if (closed.compareAndSet(false, true)) {
      discovery.unregister(this)
      routeLifecycleLock.synchronized {
        handlers.forEach { (writerId, handler) =>
          sharedClient.unregister(
            inbox.id.shuffleId, Math.toIntExact(writerId), inbox.id.partitionId, handler)
        }
        handlers.clear()
        clients.clear()
        clientFutureStartedNanos.clear()
      }
    }
  }
}
