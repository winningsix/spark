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
  LinkedBlockingQueue, Semaphore}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger}

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import org.apache.spark.{ShuffleLocationResponse, SparkConf, SparkEnv, TaskContext}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE,
  STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES,
  STREAMING_SHUFFLE_READER_CLIENT_CREATION_THREADS,
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
  private case class TaskShuffleKey(
      shuffleId: Int,
      stageId: Int,
      stageAttemptNumber: Int,
      partitionId: Int,
      taskAttemptId: Long)
  private val nextReaderOrdinal = new ConcurrentHashMap[TaskShuffleKey, AtomicInteger]()

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
    val preparedId = StreamingShuffleReceiveInboxId(
      shuffleId,
      context.stageId(),
      context.stageAttemptNumber(),
      context.partitionId(),
      -1L,
      readerOrdinal)
    val prepared = inboxes.get(preparedId)
    if (prepared != null && prepared.attach(context.taskAttemptId())) {
      return new StreamingShuffleReceiveInboxLease(prepared, () => releaseLease(prepared))
    }
    val id = preparedId.copy(taskAttemptId = context.taskAttemptId())
    val inbox = new StreamingShuffleReceiveInbox(id, createQueue())
    require(inbox.attach(context.taskAttemptId()), s"Could not attach receive inbox $id")
    val existing = inboxes.putIfAbsent(id, inbox)
    require(existing == null, s"Streaming shuffle receive inbox $id is already active")
    new StreamingShuffleReceiveInboxLease(inbox, () => releaseLease(inbox))
  }

  def prepare(id: StreamingShuffleReceiveInboxId): Boolean = synchronized {
    require(id.taskAttemptId == -1L, s"Prepared inbox must use taskAttemptId=-1: $id")
    val inbox = new StreamingShuffleReceiveInbox(id, createQueue())
    val existing = inboxes.putIfAbsent(id, inbox)
    val selected = if (existing == null) inbox else existing
    if (existing == null) {
      try {
        val executorClient = sharedClient().getOrElse(throw new IllegalStateException(
          "Prepared receive inbox requires the shared executor client"))
        selected.startPreparedSession(new StreamingShufflePreparedReceiveSession(
          selected,
          executorClient,
          conf,
          () => onDrainReady(id)))
        logDebug(s"Prepared streaming shuffle receive inbox $id")
      } catch {
        case t: Throwable =>
          inboxes.remove(id, selected)
          selected.close()
          throw t
      }
    }
    selected.session.isDefined
  }

  def prepareAll(ids: Seq[StreamingShuffleReceiveInboxId]): Boolean = synchronized {
    ids.forall(prepare)
  }

  def releasePrepared(id: StreamingShuffleReceiveInboxId): Boolean = {
    val inbox = inboxes.get(id)
    inbox != null && inboxes.remove(id, inbox) && {
      inbox.close()
      true
    }
  }

  def unregisterShuffle(shuffleId: Int): Unit = {
    inboxes.entrySet().asScala.foreach { entry =>
      if (entry.getKey.shuffleId == shuffleId && inboxes.remove(entry.getKey, entry.getValue)) {
        entry.getValue.close()
      }
    }
  }

  def close(): Unit = {
    inboxes.entrySet().asScala.foreach { entry =>
      if (inboxes.remove(entry.getKey, entry.getValue)) {
        entry.getValue.close()
      }
    }
  }

  private[streaming] def activeInboxCount: Int = inboxes.size()

  private def releaseLease(
      inbox: StreamingShuffleReceiveInbox): StreamingShuffleReceiveInboxStats = {
    inboxes.remove(inbox.id, inbox)
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
  }

  override def receiveAndReply(context: RpcCallContext): PartialFunction[Any, Unit] = {
    case PrepareStreamingShuffleReceiveInbox(id) => context.reply(service.prepare(id))
    case PrepareStreamingShuffleReceiveInboxes(ids) => context.reply(service.prepareAll(ids))
    case ReleaseStreamingShuffleReceiveInbox(id) =>
      context.reply(service.releasePrepared(id))
  }
}

/** Network-only reader lifecycle that starts before the compute task is launched. */
private[streaming] class StreamingShufflePreparedReceiveSession(
    inbox: StreamingShuffleReceiveInbox,
    sharedClient: StreamingShuffleExecutorClient,
    conf: SparkConf,
    signalDrainReady: () => Unit) extends Logging {
  // Published writer locations are connected incrementally. Polling at a coarser cadence than a
  // task reader keeps the driver's control plane bounded while limiting discovery latency to
  // 50 ms.
  private val discoveryPollIntervalMs = 50L
  private val closed = new AtomicBoolean(false)
  private val drainReady = new AtomicBoolean(false)
  private val drainReadyBytes = conf.get(STREAMING_SHUFFLE_PREPARED_INBOX_READY_BYTES)
  private val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
  private val clients = new ConcurrentHashMap[Long, TransportClient]()
  private val handlers = new ConcurrentHashMap[Long, StreamingShuffleClientHandler]()
  private val clientCreationExecutor = ThreadUtils.newDaemonFixedThreadPool(
    conf.get(STREAMING_SHUFFLE_READER_CLIENT_CREATION_THREADS),
    s"streaming-shuffle-prepared-client-${inbox.id.shuffleId}-${inbox.id.partitionId}")
  private val discoveryExecutor = ThreadUtils.newDaemonSingleThreadExecutor(
    s"streaming-shuffle-prepared-discovery-${inbox.id.shuffleId}-${inbox.id.partitionId}")

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

  def start(): Unit = discoveryExecutor.execute(() => discoverWriters())

  /** Re-advertise bounded route windows for writers that have not terminated yet. */
  def repairIdleCreditWindows(): Unit = {
    handlers.forEach { (writerId, handler) =>
      val client = clients.get(writerId)
      if (client != null) handler.repairCreditWindow(client)
    }
  }

  private def discoverWriters(): Unit = {
    val futures = new ConcurrentHashMap[Long, CompletableFuture[Void]]()
    val mapIndexes = mutable.HashSet.empty[Int]
    try {
      while (!closed.get() &&
          (totalNumShuffleWriters.get() < 0 || futures.size() < totalNumShuffleWriters.get())) {
        tracker.getAvailableShuffleWriterTaskLocations(inbox.id.shuffleId).foreach {
          case ShuffleLocationResponse(locations, numWriters) =>
            totalNumShuffleWriters.compareAndSet(-1, numWriters)
            require(totalNumShuffleWriters.get() == numWriters,
              s"Writer count changed for prepared inbox ${inbox.id}")
            // With no map partitions there can be no data or termination frame to trigger the
            // normal ready path. Discovery itself proves that the inbox can be attached and
            // drained as an empty input.
            if (numWriters == 0) markDrainReady()
            // Only the configured elastic producer window can publish concurrently for this
            // shuffle. Dividing the receive budget by every lifetime map task gives a 1777-map
            // scan an ~18 KiB route window even though at most 52 writers are live, forcing one
            // credit round trip for almost every frame. Size the route window from the live
            // producer frontier; the queue remains the executor-side memory/spill boundary.
            val liveWriterWindow = conf
              .get(STREAMING_SHUFFLE_ELASTIC_PRODUCER_MAX_TASKS_PER_STAGE)
              .map(math.min(numWriters, _))
              .getOrElse(numWriters)
            val perWriterByteLimit = math.max(
              conf.get(STREAMING_SHUFFLE_READER_MAX_MEMORY) /
                math.max(1, liveWriterWindow), 1L)
            val newlyPublished = locations.filter { case (mapId, location) =>
              val duplicate = location.mapIndex >= 0 && mapIndexes.contains(location.mapIndex)
              if (!duplicate && !futures.containsKey(mapId)) {
                if (location.mapIndex >= 0) mapIndexes += location.mapIndex
                true
              } else {
                false
              }
            }
            // Locations published in one tracker snapshot normally represent one elastic wave of
            // producers. Register all routes to the same remote executor together so tens or
            // hundreds of 28-byte discovery frames become one transport write per physical lane.
            newlyPublished.groupBy { case (_, location) =>
              (location.host, location.port)
            }.foreach { case ((host, port), routeLocations) =>
              val future = CompletableFuture.runAsync(() => {
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
                  routeHandlers.toSeq.map { case (mapId, handler) => mapId.toInt -> handler })
                routeHandlers.foreach { case (mapId, handler) =>
                  handlers.put(mapId, handler)
                  clients.put(mapId, routeClients(mapId.toInt))
                }
              }, clientCreationExecutor)
              routeLocations.foreach { case (mapId, _) => futures.put(mapId, future) }
            }
        }
        if (totalNumShuffleWriters.get() < 0 || futures.size() < totalNumShuffleWriters.get()) {
          Thread.sleep(discoveryPollIntervalMs)
        }
      }
      if (!closed.get()) {
        CompletableFuture.allOf(futures.values().asScala.toSeq: _*).get()
      }
    } catch {
      case _: InterruptedException => Thread.currentThread().interrupt()
      case t: Throwable =>
        logError(s"Prepared receive session failed for ${inbox.id}", t)
        errorNotifier.markError(t)
        markDrainReady()
    } finally {
      clientCreationExecutor.shutdown()
    }
  }

  def close(): Unit = {
    if (closed.compareAndSet(false, true)) {
      discoveryExecutor.shutdownNow()
      clientCreationExecutor.shutdownNow()
      handlers.forEach { (writerId, handler) =>
        sharedClient.unregister(
          inbox.id.shuffleId, Math.toIntExact(writerId), inbox.id.partitionId, handler)
      }
      handlers.clear()
      clients.clear()
    }
  }
}
