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

import java.nio.ByteBuffer
import java.util.ArrayDeque
import java.util.concurrent.{ConcurrentHashMap, Executor, LinkedBlockingDeque}
import java.util.concurrent.atomic.AtomicLong

import io.netty.buffer.{ByteBuf, Unpooled}
import io.netty.channel.ChannelOption
import io.netty.util.internal.OutOfDirectMemoryError

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES, EXECUTOR_ID,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_SIZE,
  STREAMING_SHUFFLE_CROSS_ROUTE_MAX_IN_FLIGHT_BYTES,
  STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE,
  STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE, STREAMING_SHUFFLE_RAW_BUFFER_POOL_MAX_MEMORY,
  STREAMING_SHUFFLE_SHARED_WRITER_SERVER_THREADS, STREAMING_SHUFFLE_WIRE_BUFFER_MAX_MEMORY}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.{RpcHandler, StreamManager, TransportServer}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, StreamingShuffleMessage,
  TerminationAckMessage}
import org.apache.spark.util.{ErrorNotifier, ThreadUtils}

/** Executor-scoped transport listener that multiplexes reader control messages to map writers. */
private[streaming] class StreamingShuffleExecutorServer extends Logging {
  private case class PendingCredit(client: TransportClient, message: CreditControlMessage)

  private val handlers = new ConcurrentHashMap[Long, StreamingShuffleServerHandler]()
  // Raw buffers are owned by the executor pool but can remain pinned in a different writer's
  // dormant route. Let a writer that cannot borrow ask its siblings to move one queued frame to
  // replay storage. A task-local scan cannot reclaim buffers retained by completed map tasks.
  private val rawBufferReclaimers = new ConcurrentHashMap[Long, () => Boolean]()
  // Prepared inboxes advertise their receive windows before producer tasks are launched. The
  // executor endpoint therefore has to retain discovery credits that race ahead of a writer's
  // handler registration; dropping them turns a successful prepareInbox ACK into a route that is
  // visible only on the reader side.
  private val pendingCredits =
    new ConcurrentHashMap[Long, ArrayDeque[PendingCredit]]()
  // A retry credit can already be in the physical lane when the last terminal ACK retires a
  // writer. Remember completed route identities so that late control frames are ignored rather
  // than retained forever as if they belonged to a producer that has not launched yet.
  private val retiredRoutes = ConcurrentHashMap.newKeySet[Long]()
  // Registration and early-credit retention must be one atomic route transition. A concurrent
  // queue alone is insufficient: register() can remove and finish draining the queue after a
  // receiver has obtained its reference but before that receiver appends its credit, stranding the
  // append in an object that is no longer reachable from pendingCredits. Striped locks keep the
  // transition bounded without allocating one monitor for every map task.
  private val routeLocks = Array.fill(256)(new Object)
  private val controlBodies = new AtomicLong(0L)
  private val controlFrames = new AtomicLong(0L)

  private def key(shuffleId: Int, writerId: Int): Long =
    (shuffleId.toLong << 32) | (writerId.toLong & 0xffffffffL)

  private def routeLock(routeKey: Long): Object = {
    val mixed = routeKey ^ (routeKey >>> 32)
    routeLocks(mixed.toInt & (routeLocks.length - 1))
  }

  /** Must be called while holding routeLock(routeKey). */
  private def drainPendingCreditsLocked(
      routeKey: Long,
      handler: StreamingShuffleServerHandler): Unit = {
    val pending = pendingCredits.remove(routeKey)
    if (pending != null) {
      var credit = pending.pollFirst()
      while (credit != null) {
        handler.handleMessage(credit.client, credit.message)
        credit = pending.pollFirst()
      }
    }
  }

  private def handlerOrRetainEarlyCredit(
      routeKey: Long,
      client: TransportClient,
      credit: CreditControlMessage): StreamingShuffleServerHandler = {
    routeLock(routeKey).synchronized {
      val registered = handlers.get(routeKey)
      if (registered == null && !retiredRoutes.contains(routeKey)) {
        pendingCredits.computeIfAbsent(routeKey, _ => new ArrayDeque[PendingCredit]())
          .addLast(PendingCredit(client, credit))
      }
      registered
    }
  }

  private[streaming] def handleControlBody(client: TransportClient, buf: ByteBuf): Unit = {
    // One transport body may contain discovery frames for many logical map -> reduce routes.
    // Decoding only the first frame silently strands every later route in a batched body.
    controlBodies.incrementAndGet()
    while (buf.isReadable) {
      val decoded = StreamingShuffleMessage.decode(buf)
      controlFrames.incrementAndGet()
      val route = decoded match {
        case credit: CreditControlMessage => (credit.shuffleId, credit.shuffleWriterId)
        case ack: TerminationAckMessage => (ack.shuffleId, ack.shuffleWriterId)
        case other =>
          throw new IllegalArgumentException(
            s"Unexpected message type in shared shuffle server: ${other.messageType()}")
      }
      val routeKey = key(route._1, route._2)
      decoded match {
        case credit: CreditControlMessage =>
          val handler = handlerOrRetainEarlyCredit(routeKey, client, credit)
          if (handler != null) handler.handleMessage(client, credit)
        case ack: TerminationAckMessage =>
          val handler = handlers.get(routeKey)
          if (handler == null) {
            // A shared physical reader connection may flush a final ACK after the corresponding
            // map task has already unregistered its writer. This is a normal cleanup race.
            logDebug(
              s"Ignoring late streaming shuffle termination ACK for shuffle ${route._1}, " +
                s"writer ${route._2}")
          } else {
            handler.handleMessage(client, ack)
          }
        case _ =>
      }
    }
  }

  private val rpcHandler = new RpcHandler {
    override def channelActive(client: TransportClient): Unit = {
      // The community implementation used a 512-byte receive buffer because each map-to-reduce
      // route had its own connection and only returned that route's credit/terminal ACKs.  The
      // executor endpoint multiplexes thousands of those control streams on one physical lane;
      // retaining the per-route buffer collapses the TCP advertised window (about 1152 bytes on
      // Linux) and can leave a complete cumulative-credit batch permanently queued at the peer.
      // Configure the aggregate lane once here, before any writer observes and reuses it.
      val socketBufferSize = conf.get(STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE)
      client.getChannel.config.setOption(ChannelOption.SO_SNDBUF, Int.box(socketBufferSize))
      client.getChannel.config.setOption(ChannelOption.SO_RCVBUF, Int.box(socketBufferSize))
    }

    override def receive(
        client: TransportClient,
        message: ByteBuffer,
        callback: RpcResponseCallback): Unit = {
      var buf: ByteBuf = null
      try {
        buf = Unpooled.wrappedBuffer(message)
        handleControlBody(client, buf)
      } catch {
        case e: Throwable => logError("Shared streaming shuffle server failed to route message", e)
      } finally {
        if (buf != null) buf.release()
      }
    }

    override def getStreamManager: StreamManager = null
  }

  private val conf = SparkEnv.get.conf
  private val role = conf.get(EXECUTOR_ID).map { id =>
    if (SparkContext.isDriver(id)) "driver" else "executor"
  }
  private val transportConf = SparkTransportConf.fromSparkConf(
    conf,
    "streaming-shuffle-writer-shared",
    conf.get(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_THREADS),
    role)
  private val transportContext = new TransportContext(transportConf, rpcHandler)
  private[streaming] val server: TransportServer = transportContext.createServer()

  // Route drains used to run in ForkJoinPool.commonPool from every map writer. The common pool is
  // sized from all processors visible to the JVM rather than this Spark executor's core grant, so
  // many small executor JVMs on one host collectively created thousands of competing drain
  // workers. Own the dispatcher at the same executor scope as the listener and transport batcher.
  // This bounds runnable network work to the executor's configured CPU domain and gives all map
  // writers one FIFO ready queue instead of one unconstrained work-stealing domain per JVM.
  private val outboundThreads = math.max(1, math.min(
    conf.get(EXECUTOR_CORES),
    conf.get(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_THREADS)))
  private val outboundPool = ThreadUtils.newDaemonFixedThreadPool(
    outboundThreads, "streaming-shuffle-outbound-dispatcher")
  private val outboundSubmitted = new AtomicLong(0L)
  private val outboundCompleted = new AtomicLong(0L)
  private val outboundPeakQueued = new AtomicLong(0L)

  private[streaming] val outboundExecutor: Executor = (command: Runnable) => {
    outboundSubmitted.incrementAndGet()
    val queued = outboundPool.getQueue.size().toLong + 1L
    outboundPeakQueued.accumulateAndGet(queued, Math.max)
    outboundPool.execute(() => {
      try command.run()
      finally outboundCompleted.incrementAndGet()
    })
  }

  private[streaming] def outboundDispatcherStats: (Int, Long, Long, Long) = {
    (outboundThreads, outboundSubmitted.get(), outboundCompleted.get(), outboundPeakQueued.get())
  }

  // All writers on this executor send through the same physical reader connection when shared
  // connections are enabled. Keep one batcher at that scope so bodies from different map tasks
  // can be coalesced; a writer-specific batcher can only combine that writer's own routes.
  private[streaming] val crossRouteBatcher = new StreamingShuffleTransportBatcher(
    server.getPooledByteBufAllocator,
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_SIZE),
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS),
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_MAX_IN_FLIGHT_BYTES),
    new ErrorNotifier())

  // Raw serialization buffers used to be allocated and cached independently by every map task.
  // In a full-streaming multi-input join, three producer stages can have dozens of live writers
  // and thousands of completed writers waiting for downstream ACKs. An executor-scoped pool is
  // the admission boundary: writers can lend idle buffers to siblings without either allocating
  // up to MaxDirectMemorySize or blocking each other behind private semaphores.
  private[streaming] val rawBufferPool = new StreamingShuffleRawBufferPool(
    conf.get(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE),
    conf.get(STREAMING_SHUFFLE_RAW_BUFFER_POOL_MAX_MEMORY))

  // Compression destinations used to come from Netty's pooled allocator independently in every
  // writer. Under a wide pipelined stage, requested 128 KiB buffers materialized and retained 4 MiB
  // arena chunks until the JVM hit MaxDirectMemorySize. Reserve exact unpooled payloads at executor
  // scope. Writers wait at this byte boundary when it is full instead of retaining thousands of
  // uncompressed raw buffers in the transport backlog. A JVM direct-memory allocation failure
  // falls back only for this already-reserved wire payload, keeping heap growth under the same cap.
  private[streaming] val wireBufferBudget = new StreamingShuffleDirectBufferBudget(
    conf.get(STREAMING_SHUFFLE_WIRE_BUFFER_MAX_MEMORY))

  val port: Int = server.getPort

  private[streaming] def controlBodyStats: (Long, Long) =
    (controlBodies.get(), controlFrames.get())

  def register(
      shuffleId: Int,
      writerId: Int,
      handler: StreamingShuffleServerHandler,
      reclaimRawBuffer: () => Boolean = () => false): Unit = {
    val routeKey = key(shuffleId, writerId)
    routeLock(routeKey).synchronized {
      retiredRoutes.remove(routeKey)
      val existing = handlers.putIfAbsent(routeKey, handler)
      require(existing == null,
        s"Streaming shuffle $shuffleId writer $writerId is already active")
      rawBufferReclaimers.put(routeKey, reclaimRawBuffer)
      // Drain while holding the same route lock used by early-credit retention. When this returns,
      // every credit that observed an absent handler is owned by this handler, and every later
      // credit observes the installed handler directly.
      drainPendingCreditsLocked(routeKey, handler)
    }
  }

  def unregister(
      shuffleId: Int,
      writerId: Int,
      handler: StreamingShuffleServerHandler): Unit = {
    val routeKey = key(shuffleId, writerId)
    routeLock(routeKey).synchronized {
      if (handlers.remove(routeKey, handler)) {
        rawBufferReclaimers.remove(routeKey)
        retiredRoutes.add(routeKey)
      }
    }
  }

  /** Spill one queued frame owned by any writer sharing this executor's raw-buffer pool. */
  private[streaming] def reclaimOneRawBuffer(): Boolean = {
    val reclaimers = rawBufferReclaimers.values().iterator()
    while (reclaimers.hasNext) {
      if (reclaimers.next()()) return true
    }
    false
  }

  def close(): Unit = {
    val (_, submitted, completed, peakQueued) = outboundDispatcherStats
    val (bodies, frames) = controlBodyStats
    val (wireUsed, wirePeak, wireLimit, wireRawFallbacks, wireRawFallbackBytes) =
      wireBufferBudget.stats
    val (wireHeapFallbacks, wireHeapFallbackBytes) = wireBufferBudget.heapFallbackStats
    val (batchBodies, batchWrites, transportedBodies, peakBodiesPerWrite) =
      crossRouteBatcher.transportBatchStats
    logInfo(
      s"Closing executor streaming-shuffle outbound dispatcher: threads=$outboundThreads " +
        s"submitted=$submitted completed=$completed peakQueued=$peakQueued " +
        s"controlBodies=$bodies controlFrames=$frames " +
        s"crossRouteSubmittedBodies=$batchBodies crossRouteTransportWrites=$batchWrites " +
        s"crossRouteTransportedBodies=$transportedBodies " +
        s"crossRoutePeakBodiesPerWrite=$peakBodiesPerWrite " +
        s"wireDirectUsedBytes=$wireUsed wireDirectPeakBytes=$wirePeak " +
        s"wireDirectLimitBytes=$wireLimit wireRawFallbacks=$wireRawFallbacks " +
        s"wireRawFallbackBytes=$wireRawFallbackBytes " +
        s"wireHeapFallbacks=$wireHeapFallbacks " +
        s"wireHeapFallbackBytes=$wireHeapFallbackBytes")
    outboundPool.shutdownNow()
    crossRouteBatcher.discard()
    rawBufferPool.close()
    wireBufferBudget.close()
    pendingCredits.clear()
    rawBufferReclaimers.clear()
    retiredRoutes.clear()
    server.close()
  }

  private[streaming] def pendingCreditCount: Int =
    pendingCredits.values().toArray(new Array[ArrayDeque[PendingCredit]](0))
      .iterator.map(_.size()).sum
}

/** Executor-wide accounting for exact, unpooled direct wire payloads. */
private[streaming] final class StreamingShuffleDirectBufferBudget(
    maxMemoryBytes: Long,
    allocateDirect: Int => ByteBuf = size => Unpooled.directBuffer(size, size),
    allocateHeap: Int => ByteBuf = size => Unpooled.buffer(size, size)) {
  require(maxMemoryBytes > 0L, "direct buffer budget must be positive")

  private val usedBytes = new AtomicLong(0L)
  private val peakBytes = new AtomicLong(0L)
  private val rawFallbacks = new AtomicLong(0L)
  private val rawFallbackBytes = new AtomicLong(0L)
  private val heapFallbacks = new AtomicLong(0L)
  private val heapFallbackBytes = new AtomicLong(0L)
  @volatile private var closed = false

  def tryAcquire(bytes: Int): Boolean = {
    require(bytes > 0, "direct buffer reservation must be positive")
    val requested = bytes.toLong
    var acquired = false
    while (!acquired && !closed) {
      val current = usedBytes.get()
      if (current + requested > maxMemoryBytes) return false
      acquired = usedBytes.compareAndSet(current, current + requested)
      if (acquired) peakBytes.accumulateAndGet(current + requested, Math.max)
    }
    acquired
  }

  def canReserve(bytes: Int): Boolean = bytes > 0 && bytes.toLong <= maxMemoryBytes

  /**
   * Reserves and allocates one wire buffer, returning null only while this budget is full. A JVM
   * direct-memory failure can happen before this component's private limit because reader queues,
   * raw buffers, replay, and transport arenas share MaxDirectMemorySize. In that case allocate an
   * exact heap buffer while retaining the same byte reservation; this is a bounded pressure valve,
   * not an untracked heap transport mode.
   */
  def tryAllocate(bytes: Int): ByteBuf = {
    if (!tryAcquire(bytes)) {
      return null
    }
    try allocateDirect(bytes)
    catch {
      case _: OutOfDirectMemoryError =>
        try {
          val buffer = allocateHeap(bytes)
          heapFallbacks.incrementAndGet()
          heapFallbackBytes.addAndGet(bytes.toLong)
          buffer
        } catch {
          case error: Throwable =>
            release(bytes)
            throw error
        }
      case error: Throwable =>
        release(bytes)
        throw error
    }
  }

  /** Wait briefly for a released reservation, then retry allocation. */
  def awaitAllocate(bytes: Int, waitMillis: Long): ByteBuf = {
    require(waitMillis > 0L, "wire-buffer wait must be positive")
    this.synchronized { if (!closed) wait(waitMillis) }
    tryAllocate(bytes)
  }

  def release(bytes: Int): Unit = {
    require(bytes > 0, "direct buffer release must be positive")
    val remaining = usedBytes.addAndGet(-bytes.toLong)
    require(remaining >= 0L, "direct buffer budget released more bytes than it acquired")
    this.synchronized { notifyAll() }
  }

  def recordRawFallback(bytes: Int): Unit = {
    require(bytes > 0, "raw fallback size must be positive")
    rawFallbacks.incrementAndGet()
    rawFallbackBytes.addAndGet(bytes.toLong)
  }

  private[streaming] def stats: (Long, Long, Long, Long, Long) =
    (usedBytes.get(), peakBytes.get(), maxMemoryBytes,
      rawFallbacks.get(), rawFallbackBytes.get())

  private[streaming] def heapFallbackStats: (Long, Long) =
    (heapFallbacks.get(), heapFallbackBytes.get())

  def close(): Unit = {
    closed = true
    this.synchronized { notifyAll() }
  }
}

/** Executor-wide reusable direct buffers for relaxed streaming writers. */
private[streaming] final class StreamingShuffleRawBufferPool(
    bufferSize: Int,
    maxMemoryBytes: Long,
    allocateDirect: Int => ByteBuf = size => Unpooled.directBuffer(size, size),
    allocateHeap: Int => ByteBuf = size => Unpooled.buffer(size, size)) {
  require(bufferSize > 0, "bufferSize must be positive")
  require(maxMemoryBytes >= bufferSize,
    "raw buffer pool must admit at least one serialization buffer")

  // Account exact allocated capacity, not buffer count. UnsafeRow can contain a value larger than
  // the configured network buffer (for example a 1 MiB bloom-filter row). Counting such a grown
  // buffer as one 128 KiB slot understated executor direct memory by 8x and let many writers
  // bypass the raw in-flight budget simultaneously.
  private val usedBytes = new AtomicLong(0L)
  private val peakBytes = new AtomicLong(0L)
  private val heapFallbacks = new AtomicLong(0L)
  private val heapFallbackBytes = new AtomicLong(0L)
  private val available = new LinkedBlockingDeque[ByteBuf]()
  @volatile private var closed = false

  private def tryReserve(bytes: Int): Boolean = {
    val requested = bytes.toLong
    var acquired = false
    while (!acquired && !closed) {
      val current = usedBytes.get()
      if (current + requested > maxMemoryBytes) return false
      acquired = usedBytes.compareAndSet(current, current + requested)
      if (acquired) peakBytes.accumulateAndGet(current + requested, Math.max)
    }
    acquired
  }

  private def allocate(capacity: Int): ByteBuf = {
    if (!tryReserve(capacity)) return null
    try allocateDirect(capacity)
    catch {
      case _: OutOfDirectMemoryError =>
        try {
          val buffer = allocateHeap(capacity)
          heapFallbacks.incrementAndGet()
          heapFallbackBytes.addAndGet(capacity.toLong)
          buffer
        } catch {
          case error: Throwable =>
            usedBytes.addAndGet(-capacity.toLong)
            throw error
        }
      case error: Throwable =>
        usedBytes.addAndGet(-capacity.toLong)
        throw error
    }
  }

  def tryBorrow(minCapacity: Int = bufferSize): ByteBuf = {
    val capacity = math.max(bufferSize, minCapacity)
    val cached = if (capacity == bufferSize) available.pollLast() else null
    if (cached != null) {
      cached.clear()
      cached
    } else {
      allocate(capacity)
    }
  }

  def awaitBorrow(waitMillis: Long, minCapacity: Int = bufferSize): ByteBuf = {
    val capacity = math.max(bufferSize, minCapacity)
    val cached = if (capacity == bufferSize) {
      available.pollLast(waitMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
    } else {
      // Oversized buffers are not cached. Wait for another oversized borrower to release exact
      // capacity, then retry the CAS reservation; callers already loop with task-cancellation
      // checks, so a short timed signal is sufficient and cannot strand a waiter.
      this.synchronized { wait(waitMillis) }
      null
    }
    if (cached != null) {
      cached.clear()
      cached
    } else {
      tryBorrow(capacity)
    }
  }

  def recycle(buffer: ByteBuf): Unit = {
    buffer.clear()
    if (!closed && buffer.capacity() == bufferSize) {
      available.offerLast(buffer)
      // Close the race where close() drains immediately before this offer.
      if (closed && available.removeLastOccurrence(buffer)) destroy(buffer)
    } else {
      destroy(buffer)
    }
  }

  /**
   * Permanently retire a borrowed buffer instead of returning it to the free list.
   *
   * A writer uses this path when it is being torn down and can no longer safely reuse the
   * producer-owned reference. The allocation permit must be returned as well: otherwise the
   * direct buffer can reach refCnt zero while the pool still accounts its slot as allocated,
   * eventually leaving every writer blocked with an empty free list and zero permits.
   */
  def discard(buffer: ByteBuf): Unit = {
    destroy(buffer)
  }

  private[streaming] def stats: (Long, Long, Long) =
    (usedBytes.get(), peakBytes.get(), maxMemoryBytes)

  private[streaming] def heapFallbackStats: (Long, Long) =
    (heapFallbacks.get(), heapFallbackBytes.get())

  private def destroy(buffer: ByteBuf): Unit = {
    val capacity = buffer.capacity()
    buffer.release()
    val remaining = usedBytes.addAndGet(-capacity.toLong)
    require(remaining >= 0L, "raw buffer pool released more bytes than it allocated")
    this.synchronized { notifyAll() }
  }

  def close(): Unit = {
    closed = true
    val buffers = new java.util.ArrayList[ByteBuf]()
    available.drainTo(buffers)
    buffers.forEach(buffer => { destroy(buffer); () })
    this.synchronized { notifyAll() }
  }
}
