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

import java.io.{File, RandomAccessFile}
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.concurrent.{CancellationException, CompletableFuture, CountDownLatch,
  Executor, ForkJoinPool, LinkedBlockingDeque, ScheduledThreadPoolExecutor, Semaphore,
  ThreadFactory, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicLong, AtomicReference}
import javax.annotation.concurrent.NotThreadSafe

import scala.collection.mutable
import scala.concurrent.duration.DurationInt
import scala.util.Try

import io.netty.buffer.{ByteBuf, ByteBufOutputStream, CompositeByteBuf, Unpooled}
import io.netty.channel.{ChannelFuture, ChannelOption}
import net.jpountz.lz4.LZ4Factory

import org.apache.spark.{PipelinedShuffleDependency, SparkContext, SparkEnv,
  StreamingShuffleTaskLocation, TaskContext}
import org.apache.spark.internal.LogKeys
import org.apache.spark.internal.config.{EXECUTOR_ID, SHUFFLE_COMPRESS,
  STREAMING_SHUFFLE_CHECKSUM_ENABLED,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_SIZE,
  STREAMING_SHUFFLE_CROSS_ROUTE_MAX_IN_FLIGHT_BYTES,
  STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE,
  STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED,
  STREAMING_SHUFFLE_NETWORK_BATCH_SIZE,
  STREAMING_SHUFFLE_NETWORK_BUFFER_MAX_WAIT_TIME_MS, STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE,
  STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED,
  STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_WRITER_LINGER_AFTER_TERMINATION_MS,
  STREAMING_SHUFFLE_WRITER_MAX_MEMORY, STREAMING_SHUFFLE_WRITER_MIN_CLIENTS_PER_READER,
  STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY,
  STREAMING_SHUFFLE_WRITER_SERVER_THREADS,
  STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS}
import org.apache.spark.memory.{MemoryConsumer, MemoryMode}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.TransportServer
import org.apache.spark.network.shuffle.streaming.{DataMessage, ShuffleChecksum, StreamingShuffleMessage, StreamingShuffleMessageType, TerminationControlMessage}
import org.apache.spark.scheduler.MapStatus
import org.apache.spark.serializer.{JavaSerializerInstance, SerializationStream}
import org.apache.spark.shuffle.{ShuffleHandle, ShuffleWriter}
import org.apache.spark.util.{ErrorNotifier, Utils}

/** Executor-JVM-wide stateless LZ4 primitives for independent streaming-shuffle blocks. */
private[streaming] object StreamingShuffleCompression {
  // Cache fastestInstance() once: repeated JNI discovery can serialize on LZ4Factory and retry a
  // failed native load. The compressor and decompressor implementations are stateless.
  private lazy val factory = LZ4Factory.fastestInstance()
  lazy val compressor = factory.fastCompressor()
  // The factory's fastDecompressor is a Java implementation for ByteBuffer input in lz4-java
  // 1.11.1, while safeDecompressor is JNI-backed and can validate the compressed input length.
  lazy val decompressor = factory.safeDecompressor()
}

private[streaming] object StreamingShuffleWriter {
  private val TERMINATION_RETRY_DELAY_MS = 500L
  // A single daemon scheduler per executor JVM prevents one native thread per completed writer
  // when a positive late-reader linger is enabled across a wide sequential query sweep.
  private[streaming] val cleanupScheduler = new ScheduledThreadPoolExecutor(1, new ThreadFactory {
    override def newThread(runnable: Runnable): Thread = {
      val thread = new Thread(runnable, "streaming-shuffle-cleanup-scheduler")
      thread.setDaemon(true)
      thread
    }
  })

  cleanupScheduler.setRemoveOnCancelPolicy(true)
}

class StreamingShuffleWriter[K, V](
    handle: ShuffleHandle,
    mapId: Long,
    val context: TaskContext,
    serverHandler: Option[StreamingShuffleServerHandler] = None,
    sharedExecutorServer: Option[StreamingShuffleExecutorServer] = None,
    private[streaming] val errorNotifier: ErrorNotifier = new ErrorNotifier())
    extends ShuffleWriter[K, V] with TaskContextAwareLogging {
  assert(SparkEnv.get.streamingShuffleOutputTracker.isDefined)
  // Spark params.
  private val conf = SparkEnv.get.conf
  private val SEND_BUFFER_SIZE: Integer = conf.get(STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE)
  private val RECV_BUFFER_SIZE: Integer = 512
  // The target network buffer size
  private val BUFFER_SIZE: Integer = conf.get(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE)
  private val BATCH_SIZE: Integer = conf.get(STREAMING_SHUFFLE_NETWORK_BATCH_SIZE)
  private val CROSS_ROUTE_BATCH_SIZE: Integer =
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_SIZE)
  private val CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS: Long =
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS)
  // The interval at which we flush pending messages.
  private val MAX_BUFFERING_TIME_MS = conf.get(STREAMING_SHUFFLE_NETWORK_BUFFER_MAX_WAIT_TIME_MS)
  private val TIME_BASED_FLUSH_ENABLED = MAX_BUFFERING_TIME_MS > 0
  private val CONFIGURED_WAIT_FOR_TERMINATION_ACKS =
    conf.get(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS)
  private val MIN_CLIENTS_PER_READER =
    conf.get(STREAMING_SHUFFLE_WRITER_MIN_CLIENTS_PER_READER)
  private val LINGER_AFTER_TERMINATION_MS =
    conf.get(STREAMING_SHUFFLE_WRITER_LINGER_AFTER_TERMINATION_MS)
  private val WRITER_BACKPRESSURE_ENABLED =
    conf.get(STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED)
  private val EXECUTOR_RECEIVE_SERVICE_ENABLED =
    conf.get(STREAMING_SHUFFLE_EXECUTOR_RECEIVE_SERVICE_ENABLED)
  private val REPLAY_MAX_MEMORY =
    conf.get(STREAMING_SHUFFLE_WRITER_REPLAY_MAX_MEMORY).toLong

  // Shuffle details.
  private val streamingShuffleHandle = handle.asInstanceOf[StreamingShuffleHandle[K, V, _]]
  private val REPLAYABLE_FOR_INTERNAL_CONSUMER = streamingShuffleHandle.dependency match {
    case dependency: PipelinedShuffleDependency[_, _, _] =>
      dependency.replayableForInternalConsumer
    case _ => false
  }
  // A RangePartitioner sampling job is followed by a second consumer of the same stream. Keep
  // that writer endpoint and replay generation alive after its first acknowledgements even when
  // ordinary writers use synchronous termination cleanup.
  private val WAIT_FOR_TERMINATION_ACKS =
    CONFIGURED_WAIT_FOR_TERMINATION_ACKS && !REPLAYABLE_FOR_INTERNAL_CONSUMER
  private val serializerInstance = streamingShuffleHandle.dependency.serializer.newInstance()
  private val byteBufSerializer = serializerInstance match {
    case serializer: StreamingShuffleSerializerInstance => Some(serializer)
    case _ => None
  }
  private val partitioner = streamingShuffleHandle.dependency.partitioner
  private val numPartitions = partitioner.numPartitions
  // Replay history is stored independently by reducer shard, but the configuration is a budget
  // for the whole writer task.  Applying it to every shard multiplies the effective limit by the
  // partition count (for p52, 16 MiB silently becomes 832 MiB per map task).  Divide it here; an
  // individual frame may exceed its shard's share briefly and is then spilled in full.
  private val REPLAY_MAX_MEMORY_PER_SHARD = if (REPLAY_MAX_MEMORY <= 0) {
    0L
  } else {
    math.max(1L, (REPLAY_MAX_MEMORY + numPartitions - 1L) / numPartitions)
  }
  private val expectedReaderRoutes = streamingShuffleHandle.dependency match {
    case dependency: PipelinedShuffleDependency[_, _, _] =>
      val routes = dependency.expectedReaderRoutes
      // Internal preparation and cross-scope exchange reuse create readers after the normal stage
      // graph snapshot. Reserve every bounded replay route carried by the dependency rather than
      // assuming there can be only one late consumer.
      val replayRoutes = dependency.replayReaderRouteCount
      if (replayRoutes > 0) routes.map(_ + replayRoutes) else routes
    case _ => Array.fill(numPartitions)(1)
  }
  // Use the same map identity that is registered in StreamingShuffleOutputTracker and handed to
  // readers. context.partitionId() happened to work while every writer owned a unique port, but
  // it is not the same value as mapId for later stages and cannot route a multiplexed server.
  private[streaming] val shuffleWriterId = Math.toIntExact(mapId)
  // Total size of TCP buffers. Use Long math to avoid 32-bit overflow when numPartitions
  // is large (numPartitions * buffer sizes can exceed Int.MaxValue).
  private val TOTAL_TCPBUF_BYTES: Long =
    numPartitions.toLong * (SEND_BUFFER_SIZE + RECV_BUFFER_SIZE)
  // Total allowed memory for buffered rows, excluding TCP buffers.
  private val MAX_BUFFER_BYTES: Long = math.max(numPartitions.toLong * BUFFER_SIZE * 2,
    conf.get(STREAMING_SHUFFLE_WRITER_MAX_MEMORY).toLong - TOTAL_TCPBUF_BYTES)
  require(MAX_BUFFER_BYTES >= BUFFER_SIZE && MAX_BUFFER_BYTES <= Int.MaxValue,
    s"Streaming shuffle writer memory budget ($MAX_BUFFER_BYTES bytes) is invalid for " +
      s"$numPartitions partitions; increase ${STREAMING_SHUFFLE_WRITER_MAX_MEMORY.key} or " +
      "reduce the number of partitions.")
  // The per-partition floor (2 buffers per partition) can push the total in-force budget above
  // the configured writerMaxMemory when the partition count is high; surface the effective total
  // (including TCP buffers) so operators can see the limit they set is not the one in force.
  private val effectiveBudget = MAX_BUFFER_BYTES + TOTAL_TCPBUF_BYTES
  if (effectiveBudget > conf.get(STREAMING_SHUFFLE_WRITER_MAX_MEMORY).toLong) {
    logWarning(log"Streaming shuffle writer effective memory budget " +
      log"${MDC(LogKeys.MAX_MEMORY_SIZE, Utils.bytesToString(effectiveBudget))} exceeds the " +
      log"configured ${MDC(LogKeys.CONFIG, STREAMING_SHUFFLE_WRITER_MAX_MEMORY.key)}=" +
      log"${MDC(LogKeys.MEMORY_SIZE, Utils.bytesToString(
        conf.get(STREAMING_SHUFFLE_WRITER_MAX_MEMORY).toLong))} because the per-partition " +
      log"minimum for ${MDC(LogKeys.NUM_PARTITIONS, numPartitions)} partitions takes precedence.")
  }
  private val CHECKSUM_ENABLED = conf.get(STREAMING_SHUFFLE_CHECKSUM_ENABLED)
  // Match the standard sort shuffle's spark.shuffle.compress behavior. Each DataMessage is one
  // independent raw block; this avoids constructing a framed OutputStream and copying through
  // it for every message.
  private val compressionCodec = if (conf.get(SHUFFLE_COMPRESS)) {
    Some(StreamingShuffleCompression.compressor)
  } else {
    None
  }
  // A row larger than the network buffer cannot be packed with any neighbor and forces its own
  // (oversized) buffer, defeating the batching that BUFFER_SIZE is meant to enable.
  private val largeRowThreshold = BUFFER_SIZE
  // Warnings about oversized rows are throttled so a run of large rows cannot flood the logs.
  private val largeRowWarningThrottler = LogThrottler(logWarning, 1.second)
  private val hugeRowWarningThrottler = LogThrottler(logWarning, 1.second)

  // Helper objects.

  // Netty invokes the client-registration callback on its event-loop thread. Replay can contain
  // the complete prefix of a long-lived shard, so doing it inline would block control messages
  // and delay every other route on that event loop.
  // Shared-server deployments route all writer/shard drains through one executor-owned bounded
  // dispatcher. Keep the common-pool fallback only for task-scoped servers used by compatibility
  // tests and configurations that explicitly disable the executor-scoped transport.
  private val sendCompletionExecutor: Executor = sharedExecutorServer
    .map(_.outboundExecutor)
    .getOrElse(ForkJoinPool.commonPool())

  // Exposed for testing
  private[streaming] val transportServerHandler: StreamingShuffleServerHandler =
    serverHandler.getOrElse(
      new StreamingShuffleServerHandler(
        onTerminationAckReceived,
        streamingShuffleHandle.shuffleId,
        numPartitions,
        context,
        errorNotifier,
        onTerminationAckReceivedWithClient,
        (readerId, client) =>
          {
            // Install the fence synchronously; defer only the replay-history walk so the
            // transport event-loop thread is not held while a large prefix is prepared.
            shards(readerId).beginReplay(client)
            sendCompletionExecutor.execute(() => shards(readerId).replayTo(client))
          },
        (readerId, _) => shards(readerId).creditAvailable(),
        expectedReaderRoutes))

  private val memoryConsumer = new MemoryConsumer(
    context.taskMemoryManager(), BUFFER_SIZE.longValue(), MemoryMode.OFF_HEAP) {
    // Spilling not supported for simplicity.
    override def spill(size: Long, trigger: MemoryConsumer): Long = 0
  }

  // Runtime state.

  // Will reach zero when we've received termination acks from all readers. Public for testing.
  private[streaming] val allAcksReceived = new CountDownLatch(expectedReaderRoutes.count(_ > 0))

  // Holds per-shard state. Public for testing.
  private[streaming] val shards: Array[ShardState] = Array.tabulate(numPartitions)(ShardState(_))

  // Start accepting reader connections only after the shard array is initialized. A reader can
  // send its first credit message immediately after the writer registers the server; starting
  // the server above this field allowed the connection callback to observe a null `shards`.
  private[streaming] val server: TransportServer = startShuffleServer()

  // When logical reader routes share one executor connection, combine complete per-route bodies
  // before handing them to Netty. The shared writer server owns one batcher per executor so bodies
  // from different map writers can also be coalesced; non-shared connections keep the original
  // one-route path unchanged.
  private val crossRouteBatcher = if (conf.get(STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED)) {
    Some(sharedExecutorServer.map(_.crossRouteBatcher).getOrElse {
      // This should be unreachable because the manager requires a shared writer server whenever
      // shared connections are enabled, but retain a local fallback for low-level tests and
      // direct construction of a writer.
      new StreamingShuffleTransportBatcher(
        server.getPooledByteBufAllocator,
        CROSS_ROUTE_BATCH_SIZE,
        CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS,
        conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_MAX_IN_FLIGHT_BYTES),
        errorNotifier)
    })
  } else {
    None
  }

  // With time-based flushing disabled, only the task thread accesses partially-filled buffers.
  // Keeping them here avoids two AtomicReference.getAndSet operations per record, which is a
  // material CPU cost for UnsafeRow-heavy shuffles. The atomic ShardState buffers remain the
  // correctness path whenever the flush thread is enabled.
  private val singleThreadedBuffers: Array[TimestampedBuffer] =
    if (TIME_BASED_FLUSH_ENABLED) null else new Array[TimestampedBuffer](numPartitions)

  private val allocatedBufferBytesSemaphore: Semaphore = new Semaphore(MAX_BUFFER_BYTES.toInt)
  private val rawBytesSent = new AtomicLong(0L)
  private val wireBytesSent = new AtomicLong(0L)
  private val dataMessagesSent = new AtomicLong(0L)
  private val replaySpilledBytes = new AtomicLong(0L)
  // Counts messages whose TransportClient write callback has not completed. In the relaxed
  // pipelined lifecycle this is the second half of the delivery barrier, after every shard's
  // reader-registration/send chain has completed. It preserves all network writes without
  // waiting for downstream task termination ACKs, which can form a cross-stage cycle.
  private val pendingSends = new AtomicLong(0L)
  private val allMessagesEnqueued = new AtomicBoolean(false)
  private val deliveryBarrierReached = new CompletableFuture[Unit]()
  private val allRegisteredClientsAcked = new CompletableFuture[Unit]()
  private val cleanupStarted = new AtomicBoolean(false)
  // Registration and termination ACKs are separate barriers. A reader can only ACK after it has
  // received its termination message, but a relaxed writer must also wait for readers that have
  // not connected yet before closing its endpoint and replay history. Otherwise an early subset
  // of readers can make allRegisteredClientsAcked complete while a late reader is left waiting.
  private def completeAllRegisteredClientsAckedIfReady(): Unit = {
    if (allAcksReceived.getCount == 0 &&
        transportServerHandler.allExpectedReadersConnectedFuture.isDone &&
        !transportServerHandler.allExpectedReadersConnectedFuture.isCompletedExceptionally &&
        shards.forall(_.allRegisteredClientsAcked)) {
      allRegisteredClientsAcked.complete(())
    }
  }

  transportServerHandler.allExpectedReadersConnectedFuture.whenComplete { (_, error) =>
    if (error != null) {
      allRegisteredClientsAcked.completeExceptionally(error)
    } else {
      completeAllRegisteredClientsAckedIfReady()
    }
  }

  // Data payloads use a dedicated free-list (bufferPool) of fixed BUFFER_SIZE buffers so
  // full-size serialization buffers can be recycled across the task; the small, variable-size
  // message envelopes instead use the server's pooled allocator (see ShardState.send). A writer
  // with semaphore backpressure can safely use direct raw buffers. The relaxed spill-or-progress
  // path uses heap raw buffers so an executor-global Netty direct-memory limit remains reserved
  // for the bounded compressed envelopes and transport bodies.
  private[streaming] val bufferPool = new LinkedBlockingDeque[ByteBuf]()
  // A relaxed pipelined writer can return from write() long before every downstream reader has
  // drained and acknowledged its replay stream.  The raw input buffers are only a writer-side
  // allocation cache; retaining that cache until the reader ACK barrier multiplies its peak by
  // every completed map task in a wide full-streaming DAG.  Stop recycling as soon as the input
  // loop can no longer request another buffer.  Replay envelopes keep their independent leases.
  private val writeInputFinished = new AtomicBoolean(false)

  private def recycleRawBuffer(buffer: ByteBuf): Unit = {
    sharedExecutorServer match {
      case Some(shared) => shared.rawBufferPool.recycle(buffer)
      case None => buffer.release()
    }
  }

  private def discardRawBuffer(buffer: ByteBuf): Unit = {
    sharedExecutorServer match {
      case Some(shared) => shared.rawBufferPool.discard(buffer)
      case None => buffer.release()
    }
  }

  private def releasePooledInputBuffers(): Unit = {
    val buffers = new java.util.ArrayList[ByteBuf]()
    bufferPool.drainTo(buffers)
    buffers.forEach(buffer => { recycleRawBuffer(buffer); () })
  }

  setShuffleIdForLogging(streamingShuffleHandle.shuffleId)

  // Ensure resources are cleaned up on any task completion.
  context.addTaskCompletionListener[Unit] { _ =>
    cleanupResources()
  }

  private def startShuffleServer(): TransportServer = {
    val server = sharedExecutorServer match {
      case Some(shared) =>
        shared.register(
          streamingShuffleHandle.shuffleId, shuffleWriterId, transportServerHandler)
        shared.server
      case None =>
        val role = conf.get(EXECUTOR_ID).map { id =>
          if (SparkContext.isDriver(id)) "driver" else "executor"
        }
        val serverConf = SparkTransportConf.fromSparkConf(
          conf,
          s"streaming-shuffle-writer-${streamingShuffleHandle.shuffleId}-${shuffleWriterId}",
          conf.get(STREAMING_SHUFFLE_WRITER_SERVER_THREADS),
          role)
        val serverContext = new TransportContext(serverConf, transportServerHandler)
        logDebug(log"Creating shuffle server for shuffle writer" +
          log" ${MDC(LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}" +
          log" for shuffle ${MDC(LogKeys.SHUFFLE_ID, streamingShuffleHandle.shuffleId)}")
        serverContext.createServer()
    }
    val hostname = if (SparkEnv.get.rpcEnv.address != null) {
      // used and not null when running in an actual cluster but may be null for running tests
      SparkEnv.get.rpcEnv.address.host
    } else {
      Utils.localCanonicalHostName()
    }
    val tracker = SparkEnv.get.streamingShuffleOutputTracker.get
    val taskLocation = StreamingShuffleTaskLocation(
      SparkEnv.get.executorId, hostname, server.getPort, context.partitionId())
    // The Boolean return is intentionally not acted on: a false means the shuffle was
    // (concurrently) unregistered, which the tracker already logs a warning for. That only
    // happens while the shuffle is being torn down, in which case this writer task is going
    // away too, so there is nothing useful to do here.
    // The writer's replay buffer makes location publication safe to perform asynchronously:
    // readers which race this publication discover the writer on their next tracker poll and
    // drain all data produced in the meantime. Do not stall every producer on a driver RPC.
    tracker.publishShuffleWriterTask(streamingShuffleHandle.shuffleId, mapId, taskLocation)
    logDebug(log"Created shuffle server for writer ${MDC(LogKeys.SHUFFLE_WRITER_ID,
      shuffleWriterId)} at ${MDC(LogKeys.TASK_LOCATION, taskLocation)}" +
      log" for shuffle ${MDC(LogKeys.SHUFFLE_ID, streamingShuffleHandle.shuffleId)}")
    server
  }

  /** A buffer with metadata. Not thread safe: only supports single-threaded access. */
  @NotThreadSafe
  private[streaming] case class TimestampedBuffer(buffer: ByteBuf) {
    val serializationStream: Option[SerializationStream] = byteBufSerializer match {
      case Some(_) => None
      case None => Some(serializerInstance.serializeStream(new ByteBufOutputStream(buffer)))
    }
    private val creationTimeNs = System.nanoTime()
    private val shuffleChecksum = if (CHECKSUM_ENABLED) new ShuffleChecksum() else null

    // Start from beginning to include serialization stream headers
    private var lastBufferPosition = 0

    def totalByteSize(): Long = buffer.readableBytes()
    def ageMs(): Long = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - creationTimeNs)

    /* Checksum calculation for order-dependent per-row checksums. */
    def updateChecksum(): Unit = {
      if (shuffleChecksum != null) {
        val currentPosition = buffer.writerIndex()
        val newDataLength = currentPosition - lastBufferPosition
        shuffleChecksum.updateChecksum(buffer, lastBufferPosition, newDataLength)
        lastBufferPosition = currentPosition
      }
    }

    def getChecksumValue(): Long = if (shuffleChecksum != null) shuffleChecksum.getValue else 0L
  }

  // The state for each shuffle destination.
  private[streaming] case class ShardState(id: Int) {
    // client may be accessed from other threads via cancel(); @volatile to be safe.
    @volatile private var client: Either[TransportClient, CompletableFuture[TransportClient]] =
      Right(transportServerHandler.futureClients(id).thenApply(c => {
        c.getChannel.config.setOption(ChannelOption.SO_SNDBUF, SEND_BUFFER_SIZE)
        c.getChannel.config.setOption(ChannelOption.SO_RCVBUF, RECV_BUFFER_SIZE)
        c
      }))
    val buffer: AtomicReference[TimestampedBuffer] = new AtomicReference(null)
    val lastSentSequenceNum: AtomicLong = new AtomicLong(-1)
    val terminationAckReceived: AtomicBoolean = new AtomicBoolean(false)
    // Keep encoded messages until the writer send barrier completes. A pipelined shuffle can
    // have multiple downstream tasks for one reader partition; replay the missing sequence
    // range when a late client is observed on a subsequent message (including termination).
    private case class ReplayEntry(
        sequenceNum: Long,
        isData: Boolean,
        var buffer: ByteBuf,
        var releaseResources: () => Unit = () => (),
        var fileOffset: Long = -1L,
        var fileLength: Int = 0,
        var resourcesReleased: Boolean = false,
        var activeUsers: Int = 0,
        var retirementRequested: Boolean = false) {
      def length: Int = if (buffer != null) buffer.readableBytes() else fileLength
    }
    private val replayHistory = new mutable.ArrayDeque[ReplayEntry]()
    // The common all-readers-connected path never opens this file. It is created lazily only when
    // a configured replay cap is exceeded, allowing late readers to recover old frames without
    // retaining an unbounded amount of executor direct memory.
    private var replayFile: RandomAccessFile = null
    private var replayFileChannel: FileChannel = null
    private var replayFilePath: File = null
    private var replayFileDir: File = null
    private var replayFilePosition = 0L
    private var inMemoryReplayBytes = 0L
    // A replay action snapshots entries under this shard monitor and encodes them after
    // releasing it. Cleanup/trim can therefore run in between the snapshot and encode. Keep
    // those entries (and a spilled replay file) alive until the encoder drops its references.
    private var activeReplayUsers = 0
    private var replayHistoryReleaseRequested = false
    // Keep data frames in bounded batches before handing them to Netty. The frames remain
    // individually encoded inside the transport body; batching only amortizes transport writes.
    private case class PendingSend(
        sequenceNum: Long,
        var buf: ByteBuf,
        done: () => Unit,
        releaseInputResources: () => Unit = () => (),
        networkComplete: () => Unit = () => (),
        private val inputResourcesReleased: AtomicBoolean = new AtomicBoolean(false),
        private val networkCompletionInvoked: AtomicBoolean = new AtomicBoolean(false),
        private val doneInvoked: AtomicBoolean = new AtomicBoolean(false)) {
      /** Release the producer-owned input buffer without waiting for the network future. */
      def releaseInput(): Unit = {
        if (inputResourcesReleased.compareAndSet(false, true)) {
          releaseInputResources()
        }
      }

      /** Retire the input-buffer permit at most once, including when the entry is spilled. */
      def complete(): Unit = {
        releaseInput()
        try {
          if (networkCompletionInvoked.compareAndSet(false, true)) {
            networkComplete()
          }
        } finally {
          if (doneInvoked.compareAndSet(false, true)) {
            done()
          }
        }
      }
    }
    private sealed trait OutboundAction
    private case class DataAction(entries: Seq[PendingSend]) extends OutboundAction
    private case class ControlAction(sequenceNum: Long, buf: CompositeByteBuf)
      extends OutboundAction
    private case class ReplayAction(target: TransportClient, maxSequenceNum: Long)
      extends OutboundAction
    private val pendingBatch = new mutable.ArrayBuffer[PendingSend]()
    private var pendingBatchBytes = 0
    // State changes (sequence numbers, replay cursors, and the action queue) stay serialized on
    // this shard monitor, while buffer composition and network submission run on the shared
    // completion executor. The old implementation held this monitor through encodeBatch and
    // TransportClient.send, so a slow downstream channel stalled the producer's write loop.
    private val outboundActions = new mutable.ArrayDeque[OutboundAction]()
    private var outboundDrainScheduled = false
    private var connectionListenerInstalled = false
    private var outboundClosed = false
    private val deferredReplayBuffers = new mutable.ArrayBuffer[ByteBuf]()
    private val lastEnqueuedByClient = new mutable.HashMap[TransportClient, Long]()
    // Fence a newly registered physical route until its replay prefix has been enqueued. This is
    // required when a late sibling arrives after a termination action is already queued: a
    // broadcast termination must not overtake that sibling's replay.
    private val replayPendingClients = new mutable.HashSet[TransportClient]()
    private val terminationAckedClients = new mutable.HashSet[TransportClient]()
    // lastEnqueuedByClient is an outbound-queue cursor, not a transport delivery fence. A late
    // route's ReplayAction advances it through the terminal before every preceding data write has
    // completed. Keep a separate fence so the periodic ACK repair cannot send a terminal directly
    // and overtake sequence zero on a replacement connection.
    private val terminalWriteCompletedClients = new mutable.HashSet[TransportClient]()
    // Uncompressed data keeps the producer-owned reference until both replay and network
    // ownership have ended. Keeping the leases here also lets failure cleanup release an owner
    // reference without putting a buffer back in the pool while an in-flight transport slice may
    // still exist.
    private val uncompressedBufferLeases = new mutable.ArrayBuffer[RawBufferLease]()
    private val firstMessageSent = new AtomicBoolean(false)
    // A blocking multi-input operator can stop consuming one input while it consumes another.
    // Bound direct buffers retained by Netty for this route and let queued frames move to the
    // existing replay spill file when this route is full. The limit is per route, so one stalled
    // reader cannot consume the writer task's entire direct-memory budget.
    private val maxInFlightNetworkBytes = math.max(
      BUFFER_SIZE.toLong, MAX_BUFFER_BYTES / math.max(1, numPartitions))
    private var inFlightNetworkBytes = 0L
    /** Return the replay suffix after a client's last enqueued sequence number. */
    private def replayAfter(
        lastEnqueued: Long,
        maxSequenceNum: Long = Long.MaxValue): Seq[ReplayEntry] = {
      var low = 0
      var high = replayHistory.size
      while (low < high) {
        val middle = (low + high) >>> 1
        if (replayHistory(middle).sequenceNum <= lastEnqueued) {
          low = middle + 1
        } else {
          high = middle
        }
      }
      replayHistory.view.drop(low).takeWhile(_.sequenceNum <= maxSequenceNum).toSeq
    }

    private def splitIntoBatches(
        entries: Seq[ReplayEntry]): Seq[Seq[ReplayEntry]] = {
      val batches = new mutable.ArrayBuffer[Seq[ReplayEntry]]()
      var current = new mutable.ArrayBuffer[ReplayEntry]()
      var currentBytes = 0
      entries.foreach { entry =>
        val size = entry.length
        if (current.nonEmpty && currentBytes + size > BATCH_SIZE) {
          batches += current.toSeq
          current = new mutable.ArrayBuffer[ReplayEntry]()
          currentBytes = 0
        }
        current += entry
        currentBytes += size
      }
      if (current.nonEmpty) batches += current.toSeq
      batches.toSeq
    }

    private def encodeBatch(entries: Seq[ReplayEntry]): CompositeByteBuf = {
      val batch = server.getPooledByteBufAllocator.compositeBuffer()
      try {
        entries.foreach { entry =>
          val (source, temporary) = synchronized {
            if (entry.buffer != null) {
              (entry.buffer, false)
            } else {
              (readSpilledReplayEntry(entry), true)
            }
          }
          try {
            source match {
              case composite: CompositeByteBuf =>
                var index = 0
                while (index < composite.numComponents()) {
                  // Replay history and the original pending entry retain independent references;
                  // the final batch owns these component duplicates directly, avoiding a nested
                  // CompositeByteBuf and any later NIO-view merge.
                  batch.addComponent(true, composite.component(index).retainedDuplicate())
                  index += 1
                }
              case _ =>
                batch.addComponent(true, source.retainedDuplicate())
            }
          } finally {
            if (temporary) source.release()
          }
        }
        batch
      } catch {
        case e: Throwable =>
          batch.release()
          throw e
      }
    }

    private def pinReplayEntries(entries: Seq[ReplayEntry]): Unit = synchronized {
      entries.foreach { entry =>
        entry.activeUsers += 1
        activeReplayUsers += 1
      }
    }

    private def unpinReplayEntries(entries: Seq[ReplayEntry]): Unit = synchronized {
      entries.foreach { entry =>
        if (entry.activeUsers > 0) {
          entry.activeUsers -= 1
          activeReplayUsers -= 1
          if (entry.activeUsers == 0 && entry.retirementRequested) {
            releaseReplayEntryNow(entry)
          }
        }
      }
      if (activeReplayUsers == 0 && replayHistoryReleaseRequested) {
        closeReplayFile()
      }
    }

    private def completePendingEntries(entries: Seq[PendingSend]): Unit = {
      var firstFailure: Throwable = null
      entries.foreach { entry =>
        try {
          entry.complete()
        } catch {
          case e: Throwable if firstFailure == null => firstFailure = e
          case _: Throwable =>
        } finally {
          pendingSends.decrementAndGet()
          maybeCompleteDeliveryBarrier()
        }
      }
      if (firstFailure != null) throw firstFailure
    }

    private def replayLength(sequenceNum: Long, fallback: PendingSend): Long = {
      replayHistory.find(_.sequenceNum == sequenceNum)
        .map(_.length.toLong)
        .getOrElse(Option(fallback.buf).map(_.readableBytes().toLong).getOrElse(0L))
    }

    private def estimatedNetworkBytes(entries: Seq[PendingSend]): Long = {
      val bytes = entries.iterator.map(entry => replayLength(entry.sequenceNum, entry)).sum
      // A route normally has one live client, but count replacement/late clients already
      // registered so the reservation remains conservative during replay.
      bytes * math.max(1, transportServerHandler.clientsFor(id).size).toLong
    }

    private def releaseNetworkBytes(bytes: Long): Unit = synchronized {
      if (bytes > 0) {
        inFlightNetworkBytes = math.max(0L, inFlightNetworkBytes - bytes)
      }
      scheduleDrainTaskLocked()
    }

    /** Wake a blocked route when its reader returns receive-window credit. */
    private[streaming] def creditAvailable(): Unit = synchronized {
      // Idle readers repeat their cumulative acknowledgement as a liveness probe. Avoid
      // submitting an empty dispatcher runnable for writers that have already drained, while
      // reliably rescheduling an ordered tail that is still waiting for data credit or EOS.
      if (outboundActions.nonEmpty) scheduleDrainTaskLocked()
    }

    private def connectedTargets(connected: TransportClient): Seq[TransportClient] = {
      (Seq(connected) ++ transportServerHandler.clientsFor(id)).distinct
        .filterNot(replayPendingClients.contains)
    }

    private def dataBodyBytes(entries: Seq[PendingSend]): Long = {
      entries.iterator.map(entry => replayLength(entry.sequenceNum, entry)).sum
    }

    /** Return the next encoded frame that this logical route still needs. */
    private def nextReplayEntry(
        target: TransportClient,
        maxSequenceNum: Long): Option[ReplayEntry] = synchronized {
      replayAfter(lastEnqueuedByClient.getOrElse(target, -1L), maxSequenceNum).headOption
    }

    /** Data credit never gates an ordered control frame such as end-of-stream. */
    private def replayEntryHasCredit(
        target: TransportClient,
        entry: ReplayEntry): Boolean = {
      !entry.isData ||
        !transportServerHandler.isCreditControlled(id, target) ||
        transportServerHandler.hasDataCredit(id, target, entry.length.toLong)
    }

    /** Reserve receive-window bytes only for replayed data, never for control frames. */
    private def consumeReplayEntryCredit(
        target: TransportClient,
        entry: ReplayEntry): Unit = {
      if (entry.isData && transportServerHandler.isCreditControlled(id, target)) {
        transportServerHandler.consumeDataCredit(id, target, entry.length.toLong)
      }
    }

    /** Check credit against the frame that will actually be sent to each target. */
    private def dataCreditAvailableForAction(
        connected: TransportClient,
        maxSequenceNum: Long): Boolean = {
      connectedTargets(connected).forall { target =>
        if (!transportServerHandler.isCreditControlled(id, target)) {
          true
        } else {
          nextReplayEntry(target, maxSequenceNum).forall(replayEntryHasCredit(target, _))
        }
      }
    }

    /** Consume credit for the exact frame selected for each controlled route. */
    private def consumeDataCreditForAction(
        connected: TransportClient,
        maxSequenceNum: Long): Unit = {
      connectedTargets(connected).foreach { target =>
        nextReplayEntry(target, maxSequenceNum).foreach(consumeReplayEntryCredit(target, _))
      }
    }

    /** Check the per-logical-reader credit for a data body. */
    private def dataCreditAvailable(
        connected: TransportClient,
        entries: Seq[PendingSend]): Boolean = {
      val bytes = dataBodyBytes(entries)
      val targets = connectedTargets(connected)
      targets.forall(target => transportServerHandler.hasDataCredit(id, target, bytes))
    }

    private def creditControlledTargets(connected: TransportClient): Boolean = {
      connectedTargets(connected).exists(target =>
        transportServerHandler.isCreditControlled(id, target))
    }

    /**
     * Largest ordered prefix that fits every controlled target's current byte window.
     *
     * Always admit one frame when the route has positive credit: an oversized row or a small
     * fair-share window must not deadlock. Unlike the former unconditional one-frame split, a
     * normal route can now use all of its available credit in one dispatcher action and one
     * transport body.
     */
    private def creditAdmissiblePrefix(
        connected: TransportClient,
        entries: Seq[PendingSend]): Int = {
      val controlledTargets = connectedTargets(connected).filter(target =>
        transportServerHandler.isCreditControlled(id, target))
      if (controlledTargets.isEmpty) return entries.size

      val available = controlledTargets.iterator
        .map(target => transportServerHandler.availableDataCredit(id, target))
        .min
      if (available <= 0L || entries.isEmpty) return 0

      var count = 0
      var bytes = 0L
      while (count < entries.size) {
        val nextBytes = replayLength(entries(count).sequenceNum, entries(count))
        if (count > 0 && bytes + nextBytes > available) return count
        bytes += nextBytes
        count += 1
      }
      count
    }

    /** Reserve the credit after all other writer-side admission checks have passed. */
    private def consumeDataCredit(
        connected: TransportClient,
        entries: Seq[PendingSend]): Unit = {
      val bytes = dataBodyBytes(entries)
      connectedTargets(connected).foreach { target =>
        transportServerHandler.consumeDataCredit(id, target, bytes)
      }
    }

    private def sendDataBody(
        target: TransportClient,
        body: ByteBuf,
        onComplete: () => Unit): Unit = {
      crossRouteBatcher match {
        case Some(batcher) =>
          batcher.submit(target, body, onComplete, this, errorNotifier)
        case None =>
          target.send(body).addListener((future: ChannelFuture) => {
            if (!future.isSuccess) {
              val cause = future.cause()
              if (isExpectedCancellationClose(target, cause)) {
                // Result operators such as TakeOrdered may cancel already-running upstream
                // tasks after obtaining enough rows. Their reader closes the socket while a
                // producer's final in-flight body is still completing. The task is already in
                // Spark's cancellation state, so this close cannot invalidate a successful
                // result; reporting it back through ErrorNotifier would turn normal cancellation
                // into a spurious pipelined-stage failure.
                logDebug(
                  s"Ignoring streaming shuffle send failure after task cancellation for " +
                    s"writer $shuffleWriterId to ${target.getSocketAddress}", cause)
              } else {
                logError(
                  s"Streaming shuffle writer $shuffleWriterId failed to send an outbound body " +
                    s"to ${target.getSocketAddress}: ${cause}", cause)
                errorNotifier.markError(cause)
              }
            }
            onComplete()
          })
      }
    }

    /** Whether Spark has already cancelled this task and the peer close is therefore expected. */
    private def isExpectedCancellationClose(
        target: TransportClient,
        cause: Throwable): Boolean = {
      val taskCancelled = context.isInterrupted() || context.isFailed() || context.isCompleted()
      def isConnectionClose(t: Throwable): Boolean = {
        val className = t.getClass.getName
        val message = Option(t.getMessage).getOrElse("").toLowerCase(java.util.Locale.ROOT)
        className.contains("ClosedChannel") ||
          message.contains("broken pipe") ||
          message.contains("connection reset") ||
          Option(t.getCause).exists(isConnectionClose)
      }
      // A bounded result may close a reducer socket while the producer is still completing an
      // in-flight frame. The reader side reports a genuine pre-termination writer disconnect;
      // the producer must not abort the whole group merely because this peer went away.
      isConnectionClose(cause) && (!target.getChannel.isActive || taskCancelled)
    }

    private def scheduleDrainTaskLocked(): Unit = {
      if (!outboundDrainScheduled && !outboundClosed) {
        outboundDrainScheduled = true
        sendCompletionExecutor.execute(() => drainOutbound())
      }
    }

    private def failAction(action: OutboundAction, error: Throwable): Unit = {
      errorNotifier.markError(error)
      action match {
        case DataAction(entries) =>
          entries.foreach(entry => Option(entry.buf).foreach(_.release()))
          entries.foreach(_.buf = null)
          completePendingEntries(entries)
        case ControlAction(_, buf) =>
          buf.release()
          pendingSends.decrementAndGet()
          maybeCompleteDeliveryBarrier()
        case ReplayAction(_, _) =>
      }
    }

    private def failOutboundActionsLocked(error: Throwable): Seq[OutboundAction] = {
      outboundClosed = true
      val actions = outboundActions.toSeq
      outboundActions.clear()
      actions
    }

    private def scheduleOutboundDrainLocked(): Unit = {
      if (outboundClosed || outboundActions.isEmpty) return
      client match {
        case Left(_) => scheduleDrainTaskLocked()
        case Right(future) if !connectionListenerInstalled =>
          connectionListenerInstalled = true
          future.whenCompleteAsync({ (connected, error) =>
            val failed = synchronized {
              connectionListenerInstalled = false
              if (error == null) {
                client = Left(connected)
                scheduleDrainTaskLocked()
                Nil
              } else {
                failOutboundActionsLocked(error)
              }
            }
            failed.foreach(action => failAction(action, error))
          }, sendCompletionExecutor)
        case _ =>
      }
    }

    private def drainOutbound(): Unit = {
      var continue = true
      var actionsProcessed = 0
      // Yield a busy logical route after a small quantum. A route with a large credit window must
      // not monopolize one executor dispatcher thread while thousands of sibling writer/reducer
      // routes are ready to publish their first frame or termination.
      val maxActionsPerDrain = 4
      while (continue && actionsProcessed < maxActionsPerDrain) {
        val next = synchronized {
          if (outboundClosed || outboundActions.isEmpty) {
            outboundDrainScheduled = false
            None
          } else client match {
            case Left(connected) =>
              val (action, splitRemainder) = outboundActions.head match {
                case DataAction(entries) if entries.size > 1 &&
                    creditControlledTargets(connected) =>
                  val prefixSize = creditAdmissiblePrefix(connected, entries)
                  if (prefixSize > 0 && prefixSize < entries.size) {
                    (DataAction(entries.take(prefixSize)),
                      Some(DataAction(entries.drop(prefixSize))))
                  } else {
                    (DataAction(entries), None)
                  }
                case other =>
                  (other, None)
              }
              val reservedBytes = action match {
                case DataAction(entries) => estimatedNetworkBytes(entries)
                case _ => 0L
              }
              val maxSequenceNum = action match {
                case DataAction(entries) => entries.lastOption.map(_.sequenceNum).getOrElse(-1L)
                case ReplayAction(_, maxSeq) => maxSeq
                case _ => -1L
              }
              val creditReady = action match {
                case DataAction(entries) => dataCreditAvailable(connected, entries)
                case ReplayAction(target, maxSeq) =>
                  nextReplayEntry(target, maxSeq).forall(replayEntryHasCredit(target, _))
                case _ => true
              }
              if (!creditReady) {
                // Shared physical channels cannot use per-stream autoRead. Leave the action at
                // the head of the ordered queue until the corresponding logical reader consumes
                // a frame and returns credit.
                outboundDrainScheduled = false
                None
              } else if (reservedBytes > 0 && inFlightNetworkBytes > 0 &&
                  inFlightNetworkBytes + reservedBytes > maxInFlightNetworkBytes) {
                // Keep the action in order. This may move its direct frame to replay storage;
                // a later network completion will reopen the route window and reschedule drain.
                spillOnePendingData()
                outboundDrainScheduled = false
                None
              } else {
                action match {
                case DataAction(entries) => consumeDataCredit(connected, entries)
                case ReplayAction(target, maxSeq) =>
                  nextReplayEntry(target, maxSeq).foreach(
                    consumeReplayEntryCredit(target, _))
                case _ =>
                }
                inFlightNetworkBytes += reservedBytes
                // Remove the original action only after every admission check succeeds. When a
                // credit window admits just a prefix, process that prefix now and leave only its
                // remainder queued. Removing the head a second time here used to return the
                // remainder as the action and orphan the prefix's buffers and pending counter.
                outboundActions.removeHead()
                splitRemainder.foreach(outboundActions.prepend)
                Some((connected, action, reservedBytes))
              }
            case Right(_) =>
              outboundDrainScheduled = false
              scheduleOutboundDrainLocked()
              None
          }
        }
        next match {
          case None => continue = false
          case Some((connected, action, reservedBytes)) =>
            actionsProcessed += 1
            try {
              processOutboundAction(connected, action, reservedBytes)
            } catch {
              case error: Throwable =>
                failAction(action, error)
                releaseNetworkBytes(reservedBytes)
            }
        }
      }
      if (actionsProcessed >= maxActionsPerDrain) synchronized {
        // The current runnable owns the scheduled bit. Drop it before tail-enqueueing another
        // quantum so concurrent credit callbacks cannot create duplicate drains for this shard.
        outboundDrainScheduled = false
        scheduleOutboundDrainLocked()
      }
    }

    private def clientsAndReplay(
        client: TransportClient,
        maxSequenceNum: Long,
        only: Option[TransportClient] = None,
        batchControlledRoute: Boolean = false): Seq[(TransportClient, Seq[ReplayEntry])] =
      synchronized {
        val candidates = only.toSeq ++ {
          if (only.isDefined) Seq.empty
          else (Seq(client) ++ transportServerHandler.clientsFor(id)).distinct
        }
        // ReplayAction is the only action allowed to target a fenced client. All ordinary
        // broadcast actions wait until that client's prefix has been submitted.
        val clients = candidates.distinct.filter(target =>
          only.isDefined || !replayPendingClients.contains(target))
        clients.distinct.flatMap { target =>
          val lastEnqueued = lastEnqueuedByClient.getOrElse(target, -1L)
          val pending = replayAfter(lastEnqueued, maxSequenceNum)
          // A replacement route always starts its sequence check at zero.  Detect a missing
          // producer-side replay prefix here instead of sending only a retained terminal and
          // surfacing the much less actionable expected=0/actual=N error at the reader.
          if (lastEnqueued < 0 && maxSequenceNum >= 0 &&
              (pending.isEmpty || pending.head.sequenceNum != 0L)) {
            throw new IllegalStateException(
              s"Streaming shuffle replay prefix is unavailable for shuffle " +
                s"${streamingShuffleHandle.shuffleId}, writer $shuffleWriterId, reader $id: " +
                s"maxSequence=$maxSequenceNum, firstRetained=" +
                s"${pending.headOption.map(_.sequenceNum).getOrElse(-1L)}")
          }
          if (transportServerHandler.isCreditControlled(id, target)) {
            val admitted = if (batchControlledRoute) pending else pending.headOption.toSeq
            if (admitted.nonEmpty) {
              pinReplayEntries(admitted)
              lastEnqueuedByClient.update(target, admitted.last.sequenceNum)
              Seq(target -> admitted)
            } else {
              Seq.empty
            }
          } else {
            if (pending.nonEmpty) {
              lastEnqueuedByClient.update(target, pending.last.sequenceNum)
            }
            splitIntoBatches(pending).map { batch =>
              pinReplayEntries(batch)
              (target, batch)
            }
          }
        }
      }

    private def processOutboundAction(
        client: TransportClient,
        action: OutboundAction,
        reservedNetworkBytes: Long): Unit = {
      val maxSequenceNum = action match {
        case DataAction(entries) => entries.lastOption.map(_.sequenceNum).getOrElse(-1L)
        case ControlAction(sequenceNum, _) => sequenceNum
        case ReplayAction(_, maxSequenceNum) => maxSequenceNum
      }
      val sends = action match {
        case ReplayAction(target, _) => clientsAndReplay(client, maxSequenceNum, Some(target))
        case DataAction(_) => clientsAndReplay(
          client, maxSequenceNum, batchControlledRoute = true)
        case _ => clientsAndReplay(client, maxSequenceNum)
      }
      val completion = action match {
        case DataAction(entries) =>
          () => {
            try {
              completePendingEntries(entries)
            } finally {
              releaseNetworkBytes(reservedNetworkBytes)
            }
          }
        case ControlAction(_, buf) =>
          () => {
            buf.release()
            pendingSends.decrementAndGet()
            maybeCompleteDeliveryBarrier()
          }
        case ReplayAction(_, _) => () => ()
      }
      val remaining = new AtomicInteger(sends.size)
      def completeBroadcast(): Unit = {
        if (remaining.decrementAndGet() == 0) completion()
      }
      if (sends.isEmpty) completion()

      sends.foreach { case (target, batchEntries) =>
        var outbound: CompositeByteBuf = null
        try {
          outbound = encodeBatch(batchEntries)
          val containsTerminal = batchEntries.exists(!_.isData)
          sendDataBody(target, outbound, () => {
            if (containsTerminal) synchronized {
              terminalWriteCompletedClients += target
            }
            completeBroadcast()
          })
          outbound = null
        } catch {
          case error: Throwable =>
            if (outbound != null) outbound.release()
            if (!isExpectedCancellationClose(client, error)) {
              errorNotifier.markError(error)
            }
            completeBroadcast()
        } finally {
          // encodeBatch retained the payload in the transport body. The replay-history pin is
          // only needed across the snapshot-to-encode window, including when send fails.
          unpinReplayEntries(batchEntries)
        }
      }
      // A controlled route is intentionally advanced by one frame per action. Requeue its
      // remaining replay suffix at the front so the next frame waits for returned credit and
      // cannot be overtaken by a later DataAction.
      val replayContinuations = sends.collect {
        case (target, batchEntries) if transportServerHandler.isCreditControlled(id, target) &&
            batchEntries.nonEmpty &&
            nextReplayEntry(target, maxSequenceNum).nonEmpty =>
          ReplayAction(target, maxSequenceNum)
      }
      if (replayContinuations.nonEmpty) synchronized {
        replayContinuations.reverse.foreach(outboundActions.prepend)
        scheduleDrainTaskLocked()
      }
      // A client-registration callback installs its replay fence synchronously and walks replay
      // history asynchronously. A control action can therefore observe the fenced route while
      // that callback is still queued on the executor dispatcher. Make end-of-stream a delivery
      // fence as well: every connected client that is still behind this control sequence gets an
      // explicit replay action. lastEnqueuedByClient makes this idempotent with both the original
      // registration replay and the ordinary broadcast path.
      val controlCatchups = action match {
        case ControlAction(_, _) => synchronized {
          transportServerHandler.clientsFor(id).filter { target =>
            nextReplayEntry(target, maxSequenceNum).nonEmpty
          }.map(target => ReplayAction(target, maxSequenceNum))
        }
        case _ => Seq.empty
      }
      if (controlCatchups.nonEmpty) synchronized {
        controlCatchups.foreach(catchup => replayPendingClients += catchup.target)
        controlCatchups.reverse.foreach(outboundActions.prepend)
        scheduleDrainTaskLocked()
      }
      action match {
        case ReplayAction(target, _) if !replayContinuations.exists(_.target == target) =>
          synchronized {
            replayPendingClients -= target
            scheduleDrainTaskLocked()
          }
        case _ =>
      }
      action match {
        case ControlAction(_, _) | ReplayAction(_, _) =>
          sends.map(_._1).distinct.foreach(target => crossRouteBatcher.foreach(_.flush(target)))
        case _ =>
      }
      trimReplayHistory()
      action match {
        case DataAction(entries) => entries.foreach { entry =>
          // encodeBatch retains the replay payload in the outbound body. The producer-owned
          // input buffer can therefore be released as soon as submission has copied/retained the
          // payload; waiting for the network future would consume the writer semaphore while a
          // stalled downstream reader is still draining the socket.
          entry.releaseInput()
          Option(entry.buf).foreach(_.release())
          entry.buf = null
        }
        case _ =>
      }
      // The failed send has already been retired through completeBroadcast(). Keep draining the
      // remaining actions so an asynchronous completion callback cannot double-retire this action.
    }

    private def dispatchBatch(entries: Seq[PendingSend]): Unit = synchronized {
      entries.foreach(_ => pendingSends.incrementAndGet())
      outboundActions.append(DataAction(entries))
      scheduleOutboundDrainLocked()
    }

    private def flushPendingBatch(): Unit = {
      if (pendingBatch.nonEmpty) {
        val entries = pendingBatch.toSeq
        pendingBatch.clear()
        pendingBatchBytes = 0
        dispatchBatch(entries)
      }
    }

    // send will never block on network I/O; push back is instead handled by blocking buffer
    // allocation in write on `allocatedBufferBytesSemaphore`. State changes remain synchronized
    // to preserve message order, while outbound actions are drained asynchronously.
    def send(
        message: StreamingShuffleMessage,
        done: () => Unit = () => (),
        releaseReplayResources: () => Unit = () => (),
        releaseInputResources: () => Unit = () => (),
        networkComplete: () => Unit = () => ()): Unit = synchronized {
      // No downstream task owns this reducer route (for example, a TakeOrdered result stage may
      // read only a prefix). Retire producer-side ownership immediately instead of queuing an
      // action behind a connection future that can never complete.
      if (expectedReaderRoutes(id) == 0) {
        message.release()
        releaseReplayResources()
        releaseInputResources()
        networkComplete()
        return
      }
      if (firstMessageSent.compareAndSet(false, true) &&
          MIN_CLIENTS_PER_READER > 1 && !REPLAYABLE_FOR_INTERNAL_CONSUMER) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (transportServerHandler.clientsFor(id).size < MIN_CLIENTS_PER_READER &&
            System.nanoTime() < deadline) {
          Thread.sleep(10)
        }
      }
      // A control frame must be ordered after every data frame already admitted to the pending
      // batch. Flush before encoding it so the control frame cannot be included in the data batch
      // and cannot overtake the batch through a separate completion callback.
      if (!message.isInstanceOf[DataMessage]) {
        flushPendingBatch()
      }
      val sequenceNum = lastSentSequenceNum.incrementAndGet()
      message.setSeqNum(sequenceNum)
      var buf: CompositeByteBuf = null
      try {
        buf = server.getPooledByteBufAllocator.compositeBuffer().capacity(message.headerLength())
        message.encode(buf)
      } catch {
        case e: Throwable =>
          if (buf != null) buf.release()
          throw e
      } finally {
        message.release()
      }
      val replayEntry = ReplayEntry(
        sequenceNum,
        message.isInstanceOf[DataMessage],
        buf.retainedDuplicate(),
        releaseReplayResources)
      replayHistory += replayEntry
      inMemoryReplayBytes += replayEntry.length

      if (message.isInstanceOf[DataMessage]) {
        pendingBatch += PendingSend(
          sequenceNum, buf, done, releaseInputResources, networkComplete)
        pendingBatchBytes += replayEntry.length
        // Install the PendingSend before enforcing the replay cap. A spilled replay duplicate is
        // not itself a memory bound if the queued send still owns an encoded duplicate of the
        // same payload; retiring both copies is what lets a blocked route release direct memory.
        spillReplayHistoryIfNeeded()
        if (pendingBatchBytes >= BATCH_SIZE) flushPendingBatch()
        return
      }

      spillReplayHistoryIfNeeded()

      // Count control messages as actual network sends in the relaxed delivery barrier. Data
      // actions increment this counter when their batch is dispatched.
      pendingSends.incrementAndGet()
      outboundActions.append(ControlAction(sequenceNum, buf))
      scheduleOutboundDrainLocked()
    }

    // Keep the binary shape used by focused tests and low-level callers that were compiled
    // against the original two- and three-argument helpers while the data path gains an explicit
    // input-resource owner.
    def send(
        message: StreamingShuffleMessage,
        done: () => Unit,
        releaseReplayResources: () => Unit): Unit = {
      send(message, done, releaseReplayResources, () => ())
    }

    /** Preserve the four-argument ABI used by existing low-level tests and callers. */
    def send(
        message: StreamingShuffleMessage,
        done: () => Unit,
        releaseReplayResources: () => Unit,
        releaseInputResources: () => Unit): Unit = {
      send(message, done, releaseReplayResources, releaseInputResources, () => ())
    }

    def send(message: StreamingShuffleMessage, done: () => Unit): Unit = {
      send(message, done, () => ())
    }

    /** Replay all encoded messages not yet enqueued for a newly registered reader client. */
    def replayTo(target: TransportClient): Unit = synchronized {
      if (!outboundClosed) {
        replayPendingClients += target
        val maxSequenceNum = replayHistory.lastOption.map(_.sequenceNum).getOrElse(-1L)
        outboundActions.append(ReplayAction(target, maxSequenceNum))
        scheduleOutboundDrainLocked()
      }
    }

    /** Install the replay fence before the server publishes a newly registered route. */
    private[streaming] def beginReplay(target: TransportClient): Unit = synchronized {
      if (!outboundClosed) replayPendingClients += target
    }

    private[streaming] def isReplayPending(target: TransportClient): Boolean = synchronized {
      replayPendingClients.contains(target)
    }

    /** Release replay entries already enqueued for all currently connected clients. */
    private def trimReplayHistory(): Unit = synchronized {
      // A relaxed writer normally retains replay history until asynchronous cleanup because an
      // elastic reader may register after the producer task has returned. Once every expected
      // reader route has registered, that late-reader window is closed only for task-owned
      // readers. An executor-owned prepared inbox can detach and attach a replacement transport
      // route after the first route satisfied expectedReaderRoutes. That replacement starts at
      // sequence zero, so trimming the prefix here makes it observe only the retained terminal
      // frame. Keep the bounded/spillable replay lease until group cleanup in executor receive
      // service mode. Internal consumers need the same treatment because RangePartitioner (and
      // similar preparation passes) can also register a second logical consumer.
      val allReadersConnected = transportServerHandler.allExpectedReadersConnectedFuture.isDone &&
        !transportServerHandler.allExpectedReadersConnectedFuture.isCompletedExceptionally
      val canTrim = if (WAIT_FOR_TERMINATION_ACKS) {
        LINGER_AFTER_TERMINATION_MS == 0 && allReadersConnected
      } else {
        !REPLAYABLE_FOR_INTERNAL_CONSUMER && !EXECUTOR_RECEIVE_SERVICE_ENABLED &&
          LINGER_AFTER_TERMINATION_MS == 0 && allReadersConnected
      }
      if (!canTrim) return
      val clients = transportServerHandler.clientsFor(id)
      if (clients.nonEmpty) {
        val minEnqueued = clients.iterator
          .map(c => lastEnqueuedByClient.getOrElse(c, -1L))
          .min
        // Keep the final control frame until every physical route has acknowledged it. TCP send
        // completion only proves that Netty accepted the body; the application ACK is the
        // end-to-end delivery fence. Retaining one 24-byte frame lets the retry path repair the
        // rare last-frame race without retaining any data payload.
        val unackedTerminalSequence = replayHistory.lastOption.collect {
          case entry if !entry.isData &&
              transportServerHandler.clientsFor(id).exists(
                client => !terminationAckedClients.contains(client)) => entry.sequenceNum
        }
        while (replayHistory.nonEmpty && replayHistory.head.sequenceNum <= minEnqueued &&
            !unackedTerminalSequence.contains(replayHistory.head.sequenceNum)) {
          val entry = replayHistory.removeHead()
          releaseReplayEntry(entry)
        }
      }
    }

    /** Retransmit only an already-enqueued terminal to routes whose application ACK is missing. */
    private[streaming] def retryUnackedTermination(): Int = {
      val retry = synchronized {
        replayHistory.lastOption.filter(entry => !entry.isData).toSeq.flatMap { terminal =>
          transportServerHandler.clientsFor(id).filter { target =>
            !terminationAckedClients.contains(target) &&
              terminalWriteCompletedClients.contains(target) &&
              !replayPendingClients.contains(target) &&
              lastEnqueuedByClient.getOrElse(target, -1L) >= terminal.sequenceNum
          }.map { target =>
            pinReplayEntries(Seq(terminal))
            (target, terminal)
          }
        }
      }
      retry.foreach { case (target, terminal) =>
        var outbound: CompositeByteBuf = null
        try {
          outbound = encodeBatch(Seq(terminal))
          sendDataBody(target, outbound, () => ())
          outbound = null
          crossRouteBatcher.foreach(_.flush(target))
        } catch {
          case error: Throwable =>
            if (outbound != null) outbound.release()
            if (!isExpectedCancellationClose(target, error)) errorNotifier.markError(error)
        } finally {
          unpinReplayEntries(Seq(terminal))
        }
      }
      retry.size
    }

    def markTerminationAck(client: TransportClient): Unit = synchronized {
      terminationAckedClients += client
    }

    def allRegisteredClientsAcked: Boolean = synchronized {
      val clients = transportServerHandler.clientsFor(id)
      val expectedClients = transportServerHandler.expectedClientsFor(id)
      if (expectedClients == 0) {
        true
      } else if (clients.size < expectedClients) {
        false
      } else clients.isEmpty match {
        case true => terminationAckReceived.get()
        case false => clients.forall(terminationAckedClients.contains)
      }
    }

    // Sends a buffer as a DataMessage to the shuffle reader. Takes ownership of the buffer.
    // The public form flushes a partial batch for low-level callers and tests; the write loop uses
    // enqueue() so full buffers can be coalesced before the next transport write.
    def send(timestampedBuffer: TimestampedBuffer): Unit =
      sendTimestampedBuffer(timestampedBuffer, flushBatch = true)

    private[streaming] def enqueue(timestampedBuffer: TimestampedBuffer): Unit =
      sendTimestampedBuffer(timestampedBuffer, flushBatch = false)

    /** Return a raw input buffer after its network send no longer needs it. */
    private def releaseRawBuffer(rawBuffer: ByteBuf): Unit = {
      rawBuffer.clear()
      if (writeInputFinished.get() || context.isFailed() || context.isCompleted() ||
          rawBuffer.capacity() != BUFFER_SIZE) {
        recycleRawBuffer(rawBuffer)
      } else {
        bufferPool.offerLast(rawBuffer)
        // Close the race where write() marks the input finished after the first check but before
        // this offer.  Either this thread removes and releases the buffer, or the final drain did.
        if (writeInputFinished.get() && bufferPool.removeLastOccurrence(rawBuffer)) {
          recycleRawBuffer(rawBuffer)
        }
      }
    }

    /** Coordinates the producer-owned reference of an uncompressed payload with both consumers. */
    private final class RawBufferLease(val buffer: ByteBuf) {
      private val replayComplete = new AtomicBoolean(false)
      private val networkComplete = new AtomicBoolean(false)
      private val ownerReleased = new AtomicBoolean(false)

      private def retireIfReady(): Unit = {
        if (replayComplete.get() && networkComplete.get() &&
            ownerReleased.compareAndSet(false, true)) {
          releaseRawBuffer(buffer)
          ShardState.this.synchronized {
            uncompressedBufferLeases -= this
          }
        }
      }

      def markReplayComplete(): Unit = retireIfReady()

      def markNetworkComplete(): Unit = retireIfReady()

      /** Release only the producer owner during failure cleanup; never recycle an in-flight buf. */
      def forceRelease(): Unit = {
        if (ownerReleased.compareAndSet(false, true)) {
          discardRawBuffer(buffer)
          ShardState.this.synchronized {
            uncompressedBufferLeases -= this
          }
        }
      }
    }

    private def sendTimestampedBuffer(
        timestampedBuffer: TimestampedBuffer,
        flushBatch: Boolean): Unit = synchronized {
      timestampedBuffer.serializationStream.foreach(_.close())
      val rawBuffer = timestampedBuffer.buffer
      val dataSize = rawBuffer.writerIndex()
      timestampedBuffer.updateChecksum()
      val checksumValue = timestampedBuffer.getChecksumValue()
      val wireBuffer = compressionCodec match {
        case Some(compressor) =>
          // Compress directly between NIO views of the Netty buffers. If compression is not
          // beneficial, discard the destination and send the original buffer.
          val maxCompressedSize = compressor.maxCompressedLength(dataSize)
          val compressed = server.getPooledByteBufAllocator
            .directBuffer(maxCompressedSize, maxCompressedSize)
          try {
            val source = rawBuffer.nioBuffer(rawBuffer.readerIndex(), dataSize)
            val destination = compressed.nioBuffer(0, maxCompressedSize)
            val compressedSize = compressor.compress(
              source, source.position(), dataSize,
              destination, destination.position(), maxCompressedSize)
            compressed.writerIndex(compressedSize)
            if (compressedSize < dataSize) compressed else {
              compressed.release()
              rawBuffer
            }
          } catch {
            case t: Throwable =>
              compressed.release()
              throw t
          }
        case None => rawBuffer
      }
      val wireSize = wireBuffer.readableBytes()
      rawBytesSent.addAndGet(dataSize)
      wireBytesSent.addAndGet(wireSize)
      dataMessagesSent.incrementAndGet()
      val dataMessage = new DataMessage(
        streamingShuffleHandle.shuffleId, shuffleWriterId, id, wireSize, dataSize,
        wireBuffer, checksumValue)

      // A compressed wire buffer is independent of rawBuffer. Return rawBuffer as soon as the
      // encoded body has retained the compressed payload. An uncompressed message shares the
      // raw buffer with both replay and transport, so its producer reference is governed by a
      // separate lease until both owners have finished.
      val rawReleased = new AtomicBoolean(false)
      val wireReleased = new AtomicBoolean(false)
      val uncompressedLease = if (wireBuffer eq rawBuffer) {
        val lease = new RawBufferLease(rawBuffer)
        uncompressedBufferLeases += lease
        Some(lease)
      } else {
        None
      }
      val releaseRawAfterSend: () => Unit = uncompressedLease match {
        case Some(_) => () => ()
        case None => () => {
          if (rawReleased.compareAndSet(false, true)) releaseRawBuffer(rawBuffer)
          ()
        }
      }
      val releaseReplayResources: () => Unit = () => {
        if (wireBuffer ne rawBuffer) {
          if (wireReleased.compareAndSet(false, true)) wireBuffer.release()
        } else {
          uncompressedLease.foreach(_.markReplayComplete())
        }
        ()
      }
      val networkComplete: () => Unit = uncompressedLease match {
        case Some(lease) => () => {
          lease.markNetworkComplete()
          if (WRITER_BACKPRESSURE_ENABLED) {
            allocatedBufferBytesSemaphore.release(BUFFER_SIZE)
          }
        }
        case None => () => ()
      }
      val releaseInputResources: () => Unit = if (uncompressedLease.isDefined) {
        () => ()
      } else {
        () => {
          releaseRawAfterSend()
          if (WRITER_BACKPRESSURE_ENABLED) {
            allocatedBufferBytesSemaphore.release(BUFFER_SIZE)
          }
        }
      }
      send(dataMessage, () => {
        // Completion is accounted separately from input-buffer ownership.
      }, releaseReplayResources, releaseInputResources, networkComplete)
      // DataMessage.encode() installs a retained payload slice in the encoded frame before
      // send() returns. When compression produced a separate wire buffer, rawBuffer is no
      // longer part of either the pending send or replay history and can immediately go back to
      // the executor pool. Delaying this until route credit arrives lets dormant inputs retain
      // one raw buffer per frame and eventually stalls every producer behind the global cap.
      if (uncompressedLease.isEmpty) releaseInputResources()
      if (flushBatch) flushPendingBatch()
    }

    // Consume the current buffer, if it exists, and send it as a DataMessage.
    def send(): Unit = synchronized {
      val b = takeBuffer()
      if (b != null) enqueue(b)
      flushPendingBatch()
    }

    def takeBuffer(): TimestampedBuffer = buffer.getAndSet(null)

    def putBuffer(b: TimestampedBuffer): Unit = assert(buffer.getAndSet(b) == null)

    def close(): Unit = {
      send()
      send(new TerminationControlMessage(streamingShuffleHandle.shuffleId, shuffleWriterId, id))
    }

    def cancel(): Unit = {
      val error = context.getTaskFailure.getOrElse(new CancellationException())
      val (queuedActions, queuedBatch) = synchronized {
        outboundClosed = true
        val actions = outboundActions.toSeq
        outboundActions.clear()
        val batch = pendingBatch.toSeq
        pendingBatch.clear()
        pendingBatchBytes = 0
        (actions, batch)
      }
      queuedActions.foreach { action =>
        try failAction(action, error) catch { case _: Throwable => }
      }
      queuedBatch.foreach { entry =>
        try {
          Option(entry.buf).foreach(_.release())
          entry.buf = null
        } finally {
          try entry.complete() catch { case _: Throwable => }
        }
      }
      transportServerHandler.futureClients(id).completeExceptionally(error)
      client.foreach(_.completeExceptionally(error))
      Option(takeBuffer()).foreach(pending => recycleRawBuffer(pending.buffer))
    }

    def releaseReplayHistory(): Unit = synchronized {
      replayHistoryReleaseRequested = true
      replayHistory.foreach { entry =>
        releaseReplayEntry(entry)
      }
      replayHistory.clear()
      lastEnqueuedByClient.clear()
      replayPendingClients.clear()
      terminalWriteCompletedClients.clear()
      deferredReplayBuffers.foreach(_.release())
      deferredReplayBuffers.clear()
      uncompressedBufferLeases.toSeq.foreach(_.forceRelease())
      uncompressedBufferLeases.clear()
      if (activeReplayUsers == 0) closeReplayFile()
    }

    private def spillReplayHistoryIfNeeded(): Unit = {
      if (REPLAY_MAX_MEMORY_PER_SHARD <= 0 ||
          inMemoryReplayBytes <= REPLAY_MAX_MEMORY_PER_SHARD) {
        return
      }
      val entries = replayHistory.iterator
      while (inMemoryReplayBytes > REPLAY_MAX_MEMORY_PER_SHARD && entries.hasNext) {
        val entry = entries.next()
        if (entry.buffer != null) spillReplayEntry(entry)
      }
    }

    /** Move one encoded frame out of direct memory without releasing its retirement hook. */
    private def spillReplayEntry(entry: ReplayEntry): Unit = {
      require(entry.buffer != null, "cannot spill an empty replay entry")
      ensureReplayFile()
      val length = entry.buffer.readableBytes()
      val bytes = new Array[Byte](length)
      entry.buffer.getBytes(entry.buffer.readerIndex(), bytes)
      val source = ByteBuffer.wrap(bytes)
      while (source.hasRemaining) {
        val written = replayFileChannel.write(source, replayFilePosition)
        if (written <= 0) {
          throw new java.io.IOException("streaming shuffle replay file made no write progress")
        }
        replayFilePosition += written
      }
      entry.fileOffset = replayFilePosition - length
      entry.fileLength = length
      entry.buffer.release()
      entry.buffer = null
      inMemoryReplayBytes -= length
      replaySpilledBytes.addAndGet(length.toLong)
      // The encoded envelope copied above is now the durable replay representation.  Release the
      // original raw/compressed payload as well; otherwise a compressed DataMessage keeps its
      // direct wire buffer alive through releaseResources until the whole writer is cleaned up,
      // defeating the replay memory cap and accumulating one payload per completed map task.
      // Any still-pending send retains the payload through its encoded ByteBuf, and a late reader
      // will reconstruct the envelope from the replay file, so this is safe for both paths.
      releaseReplayEntryResources(entry)
      retireQueuedDataEnvelope(entry.sequenceNum)
    }

    /**
     * Retire the queued duplicate of a data frame that now has a durable replay-file copy.
     *
     * Replay history and PendingSend deliberately own independent encoded references. Spilling
     * only the history reference therefore leaves the same direct payload pinned behind a route
     * with zero credit. At Q21 scale those hidden duplicates exhaust MaxDirectMemorySize even
     * though the configured replay counter reports that every old frame was spilled.
     */
    private def retireQueuedDataEnvelope(sequenceNum: Long): Unit = synchronized {
      val queued = pendingBatch.find(_.sequenceNum == sequenceNum).orElse {
        outboundActions.iterator.collectFirst {
          case DataAction(entries) => entries.find(_.sequenceNum == sequenceNum)
        }.flatten
      }
      queued.foreach { pending =>
        Option(pending.buf).foreach(_.release())
        pending.buf = null
        // This frame has not been submitted to Netty. Its replay file is now the sole payload
        // owner, so input and network-completion leases can both be retired. PendingSend makes
        // this idempotent when the eventual ordered action completes after replaying from disk.
        pending.complete()
      }
    }

    private def ensureReplayFile(): Unit = {
      if (replayFileChannel == null) {
        replayFileDir = Utils.createExecutorLocalTempDir(
          conf, s"streaming-shuffle-replay-${streamingShuffleHandle.shuffleId}-" +
            s"$shuffleWriterId-$id")
        replayFilePath = File.createTempFile("frames-", ".replay", replayFileDir)
        replayFile = new RandomAccessFile(replayFilePath, "rw")
        replayFileChannel = replayFile.getChannel
      }
    }

    private def readSpilledReplayEntry(entry: ReplayEntry): ByteBuf = {
      require(entry.buffer == null && entry.fileOffset >= 0 && entry.fileLength >= 0,
        "spilled replay entry has no file location")
      val result = server.getPooledByteBufAllocator.directBuffer(entry.fileLength, entry.fileLength)
      try {
        val destination = result.nioBuffer(0, entry.fileLength)
        var position = entry.fileOffset
        while (destination.hasRemaining) {
          val read = replayFileChannel.read(destination, position)
          if (read < 0) {
            throw new java.io.EOFException("truncated streaming shuffle replay file")
          }
          if (read == 0) {
            throw new java.io.IOException("streaming shuffle replay file made no read progress")
          }
          position += read
        }
        result.writerIndex(entry.fileLength)
        result
      } catch {
        case t: Throwable =>
          result.release()
          throw t
      }
    }

    private def releaseReplayEntryResources(entry: ReplayEntry): Unit = {
      if (!entry.resourcesReleased) {
        entry.resourcesReleased = true
        entry.releaseResources()
      }
    }

    private def releaseReplayEntryNow(entry: ReplayEntry): Unit = {
      if (entry.buffer != null) {
        inMemoryReplayBytes -= entry.buffer.readableBytes()
        entry.buffer.release()
        entry.buffer = null
      }
      releaseReplayEntryResources(entry)
    }

    private def releaseReplayEntry(entry: ReplayEntry): Unit = synchronized {
      entry.retirementRequested = true
      if (entry.activeUsers == 0) releaseReplayEntryNow(entry)
    }

    /**
     * Spill one queued data send before the producer allocates another network buffer.
     *
     * A chained full-streaming plan can have a downstream operator consuming one input while a
     * sibling input is already registered but not being pulled. The reader queue can spill that
     * sibling, but Netty may still retain the writer's encoded outbound buffers until the socket
     * drains. Waiting for the writer buffer semaphore in that situation recreates the cycle. The
     * replay entry is already the durable representation used for late readers, so move the
     * queued frame there and retire the original direct buffers. The outbound action remains in
     * order and encodeBatch will read the frame back when the socket is ready.
     */
    private[streaming] def spillOnePendingData(): Boolean = synchronized {
      if (REPLAY_MAX_MEMORY <= 0) return false

      val pending = pendingBatch.iterator.find(_.buf != null).orElse {
        outboundActions.iterator.collectFirst {
          case DataAction(entries) => entries.find(_.buf != null)
        }.flatten
      }
      pending.flatMap(entry => replayHistory.find(_.sequenceNum == entry.sequenceNum)) match {
        case Some(replayEntry) =>
          if (replayEntry.buffer != null) {
            spillReplayEntry(replayEntry)
          }
          // spillReplayEntry also retires this queued encoded duplicate. Keep these idempotent
          // calls for entries that had already been moved to disk by the ordinary replay cap.
          Option(pending.get.buf).foreach(_.release())
          pending.get.buf = null
          pending.get.complete()
          // For compressed data the replay entry owns an additional wire buffer. For the
          // uncompressed path this hook is the same raw-buffer release performed above; the
          // idempotent guard makes both cases safe.
          releaseReplayEntryResources(replayEntry)
          true
        case None =>
          false
      }
    }

    private def closeReplayFile(): Unit = {
      Utils.tryLogNonFatalError {
        if (replayFileChannel != null) replayFileChannel.close()
        if (replayFile != null) replayFile.close()
        if (replayFilePath != null) replayFilePath.delete()
        if (replayFileDir != null) replayFileDir.delete()
      }
      replayFileChannel = null
      replayFile = null
      replayFilePath = null
      replayFileDir = null
      replayFilePosition = 0L
      inMemoryReplayBytes = 0L
    }

    def deferReplayBuffer(wireBuffer: ByteBuf, rawBuffer: ByteBuf): Unit = synchronized {
      deferredReplayBuffers += wireBuffer
      if (wireBuffer ne rawBuffer) deferredReplayBuffers += rawBuffer
    }

    // For testing only.
    def hasClient: Boolean = client match {
      case Left(_) => true
      case Right(future) => future.isDone
    }

    /**
     * Completes after the first reader has registered and every message currently queued for this
     * shard has been submitted to its TransportClient. Call this only after close() has appended
     * the termination message, so the returned future covers the complete shard stream.
     */
    def registrationAndEnqueueFuture: CompletableFuture[TransportClient] = synchronized {
      if (expectedReaderRoutes(id) == 0) {
        CompletableFuture.completedFuture(null)
      } else {
        client match {
          case Left(connectedClient) => CompletableFuture.completedFuture(connectedClient)
          case Right(future) => future
        }
      }
    }
  }

  /** Close this writer, passing along whether the map completed */
  override def stop(success: Boolean): Option[MapStatus] = {
    // No-op: the streaming shuffle lifecycle is handled elsewhere. write() blocks until all
    // readers ack termination on the normal path, and the task-completion listener
    // (cleanupResources) closes the server and releases buffers on both success and failure.
    //
    // Streaming shuffle readers locate writers through StreamingShuffleOutputTracker and pull
    // data directly over Netty; they never consult MapStatus block sizes, and streaming shuffle
    // has no standard block-fetch fallback path. This MapStatus is therefore only a placeholder
    // to satisfy the ShuffleWriter contract and the DAGScheduler / MapOutputTracker bookkeeping;
    // its all-zero partition lengths are never read by any reducer.
    Some(MapStatus(
      SparkEnv.get.blockManager.shuffleServerId,
      Array.fill(numPartitions)(0L),
      mapId))
  }

  /** Get the lengths of each partition */
  override def getPartitionLengths(): Array[Long] = {
    Array.fill(numPartitions)(0L)
  }

  /**
   * Invoked on a Netty event-loop thread by [[StreamingShuffleServerHandler]] when a reader's
   * termination ack arrives. Validates the reader's last-seen sequence number against what this
   * writer sent; on a mismatch it throws STREAMING_SHUFFLE_INCORRECT_SEQUENCE_NUMBER, which the
   * handler captures via the shared [[ErrorNotifier]]. The per-partition latch decrement is
   * idempotent, so duplicate acks are ignored. Exposed for testing.
   */
  private[streaming] def onTerminationAckReceived(
      partitionId: Int, lastSeqNumSeenByReader: Long): Unit = {
    val lastSeqNumSent = shards(partitionId).lastSentSequenceNum.get()
    if (lastSeqNumSent != lastSeqNumSeenByReader) {
      throw StreamingShuffleManager.streamingShuffleIncorrectSequenceNumber(
        StreamingShuffleMessageType.TERMINATION_ACK_MESSAGE,
        shuffleWriterId,
        partitionId,
        lastSeqNumSent,
        lastSeqNumSeenByReader)
    }
    if (shards(partitionId).terminationAckReceived.compareAndSet(false, true)) {
      allAcksReceived.countDown()
    }
    val receivedAcks = numPartitions - allAcksReceived.getCount.toInt
    logDebug(log"Received termination ack from reader ${MDC(LogKeys.SHUFFLE_READER_ID,
      partitionId)}. Now have ${MDC(LogKeys.NUM_TERMINATION_ACKS, receivedAcks)} / ${MDC(
      LogKeys.NUM_SHUFFLE_READERS, numPartitions)} termination acks")
  }

  private[streaming] def onTerminationAckReceivedWithClient(
      partitionId: Int, lastSeqNumSeenByReader: Long, client: TransportClient): Unit = {
    shards(partitionId).markTerminationAck(client)
    completeAllRegisteredClientsAckedIfReady()
  }

  /**
   * Cleans up all writer resources.
   * This method should be idempotent.
   */
  private[streaming] def cleanupResources(): Unit = {
    if (!cleanupStarted.compareAndSet(false, true)) return
    if (!WAIT_FOR_TERMINATION_ACKS && context.getTaskFailure.isEmpty) {
      // The relaxed lifecycle removes delivery and ACK waits from the Spark task's critical path.
      // Keep the writer object, replay data, and endpoint alive until both asynchronous barriers
      // complete; this frees the task slot without closing a writer underneath a late reader.
      // A pipelined group may schedule another reader wave, or a later sibling consumer, after
      // this writer has finished producing. Waiting only for clients that have already registered
      // lets the writer unregister while an expected reader is still discovering its location;
      // that reader then cannot receive the terminal frame and waits forever. Keep the endpoint
      // alive until every normal reader partition has registered, in addition to draining the
      // currently registered clients.
      CompletableFuture.allOf(
        deliveryBarrierReached,
        transportServerHandler.allExpectedReadersConnectedFuture,
        allRegisteredClientsAcked)
        .whenComplete { (_, _) => scheduleCleanup() }
    } else {
      scheduleCleanup()
    }
  }

  private def scheduleCleanup(): Unit = {
    // A positive linger lets any late reader connect after the producer has completed. Use the
    // executor-wide scheduler below rather than one sleep thread per writer: a wide sequential
    // query sweep can otherwise accumulate one native thread per completed writer, even though
    // those writers already passed the all-expected-readers barrier.
    if (LINGER_AFTER_TERMINATION_MS > 0) {
      StreamingShuffleWriter.cleanupScheduler.schedule(
        new Runnable {
          override def run(): Unit = cleanupResourcesNow()
        },
        LINGER_AFTER_TERMINATION_MS,
        TimeUnit.MILLISECONDS)
    } else if (!WAIT_FOR_TERMINATION_ACKS) {
      // deliveryBarrierReached, allReadersConnected, and allRegisteredClientsAcked have all
      // completed before this method is reached.  At that point every expected reader has
      // received the terminal frame and acknowledged it, so this writer no longer has a late
      // reader to serve.  Waiting for the driver-side shuffle tracker to remove the shuffle is
      // both unnecessary and unsafe for a long-lived SparkContext: the tracker commonly keeps
      // completed query shuffles until context cleanup, allowing direct buffers to accumulate
      // across sequential queries until the executor exhausts MaxDirectMemorySize.
      cleanupResourcesNow()
    } else {
      cleanupResourcesNow()
    }
  }

  private def cleanupResourcesNow(): Unit = {
    val cleanupStartTime = System.currentTimeMillis()
    // Release any cross-route bodies that were queued but never reached Netty after a failed
    // writer. The normal shared-server path removes only this writer's unsent bodies; in-flight
    // transport bodies are owned by Netty and finish through their callbacks.
    crossRouteBatcher.foreach { batcher =>
      if (sharedExecutorServer.isDefined) batcher.discardOwner(this) else batcher.discard()
    }
    Utils.tryLogNonFatalError {
      shards.foreach(_.cancel())
    }
    Utils.tryLogNonFatalError {
      sharedExecutorServer match {
        case Some(shared) =>
          shared.unregister(
            streamingShuffleHandle.shuffleId, shuffleWriterId, transportServerHandler)
        case None => server.close()
      }
    }
    // Linger keeps replay data available for late readers, but the delayed cleanup must release
    // both replay-history duplicates and deferred wire/raw buffers or direct memory accumulates
    // across shuffle writers and eventually exhausts the executor's Netty direct-memory limit.
    Utils.tryLogNonFatalError {
      shards.foreach(_.releaseReplayHistory())
    }
    Utils.tryLogNonFatalError {
      val list = new java.util.ArrayList[ByteBuf]()
      bufferPool.drainTo(list)
      list.forEach(buf => { recycleRawBuffer(buf); () })
    }
    if (singleThreadedBuffers != null) {
      Utils.tryLogNonFatalError {
        var partitionId = 0
        while (partitionId < singleThreadedBuffers.length) {
          val pending = singleThreadedBuffers(partitionId)
          singleThreadedBuffers(partitionId) = null
          if (pending != null) recycleRawBuffer(pending.buffer)
          partitionId += 1
        }
      }
    }
    Utils.tryLogNonFatalError {
      memoryConsumer.freeMemory(memoryConsumer.getUsed())
    }
    logDebug(log"Resource cleanup took ${MDC(LogKeys.DURATION,
      System.currentTimeMillis() - cleanupStartTime)} ms")
    val rawBytes = rawBytesSent.get()
    val wireBytes = wireBytesSent.get()
    logDebug(s"Streaming shuffle writer transfer summary: messages=${dataMessagesSent.get()}, " +
      s"rawBytes=$rawBytes, wireBytes=$wireBytes, " +
      f"wireRatio=${if (rawBytes == 0) 1.0 else wireBytes.toDouble / rawBytes}%.4f, " +
      s"replaySpilledBytes=${replaySpilledBytes.get()}")
  }

  private def throwErrorIfExists(): Unit = {
    context.killTaskIfInterrupted()
    context.getTaskFailure.foreach { throw _ }
    errorNotifier.throwErrorIfExists()
  }

  private def maybeCompleteDeliveryBarrier(): Unit = {
    if (allMessagesEnqueued.get() && pendingSends.get() == 0) {
      deliveryBarrierReached.complete(())
    }
  }

  private def armDeliveryBarrier(): Unit = {
    // Snapshot only after every shard has queued its termination message. Each shard future is the
    // tail of its completion-stage chain, so completion proves both registration and that every
    // queued Data/Termination message has incremented pendingSends before we inspect that counter.
    val enqueueFutures = shards.iterator.map(_.registrationAndEnqueueFuture).toSeq
    val allEnqueued = CompletableFuture.allOf(enqueueFutures: _*)
    allEnqueued.whenComplete { (_, error) =>
      if (error != null) {
        deliveryBarrierReached.completeExceptionally(error)
      } else {
        allMessagesEnqueued.set(true)
        maybeCompleteDeliveryBarrier()
      }
    }
    // Do not release replay history when the first reader has drained the delivery barrier.
    // RangePartitioner (and other internal consumers) can register a second reader after that
    // barrier has completed.  cleanupResources() waits for all expected reader routes and their
    // termination ACKs before cleanupResourcesNow() releases the history; releasing it here would
    // leave the late reader connected to an endpoint that can only send an empty stream.
  }

  /** Retry the tiny terminal control frame until its end-to-end ACK closes every route. */
  private def armTerminationRetries(): Unit = {
    def schedule(): Unit = {
      StreamingShuffleWriter.cleanupScheduler.schedule(
        new Runnable {
          override def run(): Unit = {
            if (!allRegisteredClientsAcked.isDone &&
                !context.isInterrupted() && !context.isFailed()) {
              shards.foreach(_.retryUnackedTermination())
              schedule()
            }
          }
        },
        StreamingShuffleWriter.TERMINATION_RETRY_DELAY_MS,
        TimeUnit.MILLISECONDS)
    }
    schedule()
  }

  private def newBuffer(): TimestampedBuffer = {
    // Back-pressure is accounted per network buffer (BUFFER_SIZE permits each), not by exact
    // byte size, so this bounds in-flight memory only on a best-effort basis: a single
    // serialized row larger than BUFFER_SIZE (rows are not split across buffers, see write())
    // grows its buffer past BUFFER_SIZE and thus exceeds the tracked budget.
    if (WRITER_BACKPRESSURE_ENABLED) {
      if (!allocatedBufferBytesSemaphore.tryAcquire(BUFFER_SIZE, 10, TimeUnit.MICROSECONDS)) {
        shards.foreach(_.send())
        while (!allocatedBufferBytesSemaphore.tryAcquire(BUFFER_SIZE, 10, TimeUnit.MILLISECONDS)) {
          val spilled = shards.iterator.map(_.spillOnePendingData()).exists(identity)
          if (!spilled) {
            throwErrorIfExists()
          }
        }
      }
    }
    var buffer = bufferPool.pollLast()
    if (buffer == null && !WRITER_BACKPRESSURE_ENABLED && REPLAY_MAX_MEMORY > 0) {
      // A blocking multi-input consumer can leave encoded DataActions queued indefinitely.  The
      // relaxed writer must not wait on the normal semaphore (that closes the cross-input cycle),
      // but allocating a new direct buffer for every queued frame is equally unsafe.  Replay spill
      // is already the durable ordered representation, so retire one oldest pending envelope and
      // reuse its raw input buffer before growing executor direct memory.  If every candidate is
      // genuinely in flight, the executor-level transport window remains the finite bound and a
      // new allocation is required for progress.
      shards.iterator.exists(_.spillOnePendingData())
      buffer = bufferPool.pollLast()
    }
    if (buffer == null) {
      sharedExecutorServer match {
        case Some(shared) =>
          buffer = shared.rawBufferPool.tryBorrow()
          while (buffer == null) {
            // Retiring a queued frame may return its raw owner to this writer's local deque.
            // Prefer that immediately reusable buffer before waiting on a global pool slot.
            shards.iterator.exists(_.spillOnePendingData())
            buffer = bufferPool.pollLast()
            if (buffer == null) buffer = shared.rawBufferPool.tryBorrow()
            if (buffer == null) buffer = shared.rawBufferPool.awaitBorrow(10L)
            if (buffer == null) throwErrorIfExists()
          }
        case None => buffer = Unpooled.directBuffer(BUFFER_SIZE)
      }
    }
    val allocated = buffer
    TimestampedBuffer(allocated)
  }

  /**
   * Write a sequence of records to downstream shuffle readers.
   *
   * For each record, the reader partition is determined using the key and the
   * partitioner. Multiple rows can be packed into a single DataMessage; the maximum
   * number of rows that can be packed depends on the STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE
   * config. Each DataMessage is sent to the reader for its partition over that reader's
   * Netty connection.
   */
  override def write(records: Iterator[Product2[K, V]]): Unit = {
    val isWriteFinished = new CountDownLatch(1)
    val flushThread = if (TIME_BASED_FLUSH_ENABLED) {
      Some(new Thread(() =>
        Try {
          while (!isWriteFinished.await(MAX_BUFFERING_TIME_MS, TimeUnit.MILLISECONDS))
            shards.foreach(_.send())
        }.recover { case e => errorNotifier.markError(e) },
        "time-based-flush-for-shuffle-writer-" +
          s"${streamingShuffleHandle.shuffleId}-${shuffleWriterId}"))
    } else {
      None
    }
    try {
      // Reserve the budget with the task memory manager for accounting/visibility. In-flight
      // buffer memory is bounded by allocatedBufferBytesSemaphore; we ignore the return value
      // because we cannot act on a partial grant here (this consumer cannot spill).
      if (WRITER_BACKPRESSURE_ENABLED) {
        memoryConsumer.acquireMemory(TOTAL_TCPBUF_BYTES + MAX_BUFFER_BYTES)
      }
      flushThread.foreach(_.start())
      records.foreach { record =>
        val shard = shards(partitioner.getPartition(record._1))
        var timestampedBuffer = if (TIME_BASED_FLUSH_ENABLED) {
          shard.takeBuffer()
        } else {
          singleThreadedBuffers(shard.id)
        }
        if (timestampedBuffer == null) {
          timestampedBuffer = newBuffer()
          if (!TIME_BASED_FLUSH_ENABLED) {
            // Publish immediately to the task-owned array so failure cleanup can release it even
            // if serialization throws before this record finishes.
            singleThreadedBuffers(shard.id) = timestampedBuffer
          }
        }
        val dataStartPos = timestampedBuffer.buffer.writerIndex()
        // TODO we are actually not guaranteeing that a buffer used to send data for a
        // partition does not exceed BUFFER_SIZE. We currently are not implementing spanning rows
        // across multiple buffers as it requires interface changes in the serializers
        byteBufSerializer match {
          case Some(serializer) =>
            serializer.writeValueToByteBuf(record._2, timestampedBuffer.buffer)
          case None =>
            val partitionSerializationStream = timestampedBuffer.serializationStream.get
            // UnsafeRowSerializer does not serialize the partitioning key. JavaSerializer is used
            // primarily by tests and does need the key on the reader side.
            if (serializerInstance.isInstanceOf[JavaSerializerInstance]) {
              partitionSerializationStream.writeKey(record._1.asInstanceOf[Any])
            }
            partitionSerializationStream.writeValue(record._2.asInstanceOf[Any])
            partitionSerializationStream.flush()
        }

        // A single row is never split across buffers (see the TODO above), so an oversized row
        // grows its buffer past BUFFER_SIZE and inflates the tracked memory budget. Warn
        // (throttled) so operators can raise the block size or writer memory instead of overshoot.
        // When a row trips both thresholds the more severe memory warning takes precedence.
        val rowSize = timestampedBuffer.buffer.writerIndex() - dataStartPos
        if (rowSize > MAX_BUFFER_BYTES / 4) {
          hugeRowWarningThrottler(
            log"Row size ${MDC(LogKeys.BYTE_SIZE, rowSize)} is >25% of " +
            log"total writer memory " +
            log"${MDC(LogKeys.MEMORY_THRESHOLD_SIZE, MAX_BUFFER_BYTES)}. " +
            log"Consider increasing the maximum writer memory.")
        } else if (rowSize > largeRowThreshold) {
          largeRowWarningThrottler(
            log"Row size ${MDC(LogKeys.BYTE_SIZE, rowSize)} is larger than the block size " +
            log"${MDC(LogKeys.MEMORY_THRESHOLD_SIZE, largeRowThreshold)}. " +
            log"Consider increasing the block size.")
        }

        timestampedBuffer.updateChecksum()

        // Flush immediately if the buffer is almost full or stale.
        if (timestampedBuffer.totalByteSize() < BUFFER_SIZE * 9 / 10 &&
            (!TIME_BASED_FLUSH_ENABLED ||
              timestampedBuffer.ageMs() < MAX_BUFFERING_TIME_MS)) {
          if (TIME_BASED_FLUSH_ENABLED) shard.putBuffer(timestampedBuffer)
        } else {
          if (!TIME_BASED_FLUSH_ENABLED) singleThreadedBuffers(shard.id) = null
          shard.enqueue(timestampedBuffer)
          throwErrorIfExists()
        }
      }
      isWriteFinished.countDown()
      if (!TIME_BASED_FLUSH_ENABLED) {
        var partitionId = 0
        while (partitionId < singleThreadedBuffers.length) {
          val pending = singleThreadedBuffers(partitionId)
          singleThreadedBuffers(partitionId) = null
          if (pending != null) shards(partitionId).enqueue(pending)
          partitionId += 1
        }
      }
      shards.foreach(_.close())
      armTerminationRetries()
      logDebug(log"StreamingShuffleWriter finished writing data and termination messages for " +
        log"shuffle writer ${MDC(LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}. Shutting down now.")
      // Wait for all termination acks. This has no wall-clock timeout by design, and that is
      // deliberate for correctness: a term-ack is the writer's only confirmation that a reader
      // received every message through the final sequence number (validated in
      // onTerminationAckReceived), so finishing write() without all acks would risk marking the
      // map task successful while a reader is silently missing data. The loop instead exits only
      // on all-acks, on an ErrorNotifier error surfaced by throwErrorIfExists(), or on task
      // cancellation. A reader that dies fails its own reduce task, which restarts the query and
      // tears down this writer too, so writer-side reader-liveness detection is unnecessary.
      if (WAIT_FOR_TERMINATION_ACKS) {
        while (!shards.forall(_.allRegisteredClientsAcked)) {
          throwErrorIfExists()
          // Waiting writers still occupy Spark task slots, but they must not also burn an
          // executor CPU while the downstream readers are doing the useful work needed to
          // produce these acknowledgements. Keep the wait interruptible so task cancellation
          // and failures retain their existing prompt escape path.
          Thread.sleep(10L)
        }
        logDebug(log"Received all termination acks for shuffle writer ${MDC(
          LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}. Closing server channel.")
      } else {
        armDeliveryBarrier()
        logDebug(log"Deferred reader registration, network-send, and termination-ack barriers " +
          log"for shuffle writer ${MDC(LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)} to " +
          log"asynchronous cleanup.")
      }
      throwErrorIfExists()
      if (WAIT_FOR_TERMINATION_ACKS && LINGER_AFTER_TERMINATION_MS == 0) {
        shards.foreach(_.releaseReplayHistory())
      }
    } finally {
      writeInputFinished.set(true)
      releasePooledInputBuffers()
      isWriteFinished.countDown() // Duplicate countDowns are a no-op.
      flushThread.foreach(_.join())
    }
  }
}
