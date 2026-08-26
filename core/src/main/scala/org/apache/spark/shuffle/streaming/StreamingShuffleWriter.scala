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

import java.util.concurrent.{CancellationException, CompletableFuture, CountDownLatch, LinkedBlockingDeque, Semaphore, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicLong, AtomicReference}
import javax.annotation.concurrent.NotThreadSafe

import scala.concurrent.duration.DurationInt
import scala.collection.mutable
import scala.util.Try

import io.netty.buffer.{ByteBuf, ByteBufOutputStream, CompositeByteBuf, Unpooled}
import io.netty.channel.{ChannelFuture, ChannelOption}
import net.jpountz.lz4.LZ4Factory

import org.apache.spark.{SparkContext, SparkEnv, StreamingShuffleTaskLocation, TaskContext}
import org.apache.spark.internal.LogKeys
import org.apache.spark.internal.config.{EXECUTOR_ID, SHUFFLE_COMPRESS,
  STREAMING_SHUFFLE_CHECKSUM_ENABLED,
  STREAMING_SHUFFLE_NETWORK_BUFFER_MAX_WAIT_TIME_MS, STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE,
  STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_WRITER_LINGER_AFTER_TERMINATION_MS,
  STREAMING_SHUFFLE_WRITER_MIN_CLIENTS_PER_READER,
  STREAMING_SHUFFLE_WRITER_MAX_MEMORY, STREAMING_SHUFFLE_WRITER_SERVER_THREADS,
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
  private val SEND_BUFFER_SIZE: Integer = 32 << 10 // 32 KB
  private val RECV_BUFFER_SIZE: Integer = 512
  // The target network buffer size
  private val BUFFER_SIZE: Integer = conf.get(STREAMING_SHUFFLE_NETWORK_BUFFER_SIZE)
  // The interval at which we flush pending messages.
  private val MAX_BUFFERING_TIME_MS = conf.get(STREAMING_SHUFFLE_NETWORK_BUFFER_MAX_WAIT_TIME_MS)
  private val TIME_BASED_FLUSH_ENABLED = MAX_BUFFERING_TIME_MS > 0
  private val WAIT_FOR_TERMINATION_ACKS =
    conf.get(STREAMING_SHUFFLE_WRITER_WAIT_FOR_TERMINATION_ACKS)
  private val MIN_CLIENTS_PER_READER =
    conf.get(STREAMING_SHUFFLE_WRITER_MIN_CLIENTS_PER_READER)
  private val LINGER_AFTER_TERMINATION_MS =
    conf.get(STREAMING_SHUFFLE_WRITER_LINGER_AFTER_TERMINATION_MS)
  private val WRITER_BACKPRESSURE_ENABLED =
    conf.get(STREAMING_SHUFFLE_WRITER_BACKPRESSURE_ENABLED)

  // Shuffle details.
  private val streamingShuffleHandle = handle.asInstanceOf[StreamingShuffleHandle[K, V, _]]
  private val serializerInstance = streamingShuffleHandle.dependency.serializer.newInstance()
  private val byteBufSerializer = serializerInstance match {
    case serializer: StreamingShuffleSerializerInstance => Some(serializer)
    case _ => None
  }
  private val partitioner = streamingShuffleHandle.dependency.partitioner
  private val numPartitions = partitioner.numPartitions
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
        (readerId, client) => shards(readerId).replayTo(client)))

  private[streaming] val server: TransportServer = startShuffleServer()

  private val memoryConsumer = new MemoryConsumer(
    context.taskMemoryManager(), BUFFER_SIZE.longValue(), MemoryMode.OFF_HEAP) {
    // Spilling not supported for simplicity.
    override def spill(size: Long, trigger: MemoryConsumer): Long = 0
  }

  // Runtime state.

  // Will reach zero when we've received termination acks from all readers. Public for testing.
  private[streaming] val allAcksReceived = new CountDownLatch(numPartitions)

  // Holds per-shard state. Public for testing.
  private[streaming] val shards: Array[ShardState] = Array.tabulate(numPartitions)(ShardState(_))

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
  // Counts messages whose TransportClient write callback has not completed. In the relaxed
  // pipelined lifecycle this is the delivery barrier: it preserves all network writes without
  // waiting for downstream task termination ACKs, which can form a cross-stage cycle.
  private val pendingSends = new AtomicLong(0L)
  private val pendingSendsNotice = new Semaphore(0)
  private val cleanupStarted = new AtomicBoolean(false)

  // Data payloads use a dedicated direct-buffer free-list (bufferPool) of fixed BUFFER_SIZE
  // buffers so full-size send buffers can be recycled across the task; the small, variable-size
  // message envelopes instead use the server's pooled allocator (see ShardState.send). The two
  // allocation paths are intentionally separate.
  private[streaming] val bufferPool = new LinkedBlockingDeque[ByteBuf]()

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
        logInfo(log"Creating shuffle server for shuffle writer" +
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
    val taskLocation =
      StreamingShuffleTaskLocation(SparkEnv.get.executorId, hostname, server.getPort)
    // The Boolean return is intentionally not acted on: a false means the shuffle was
    // (concurrently) unregistered, which the tracker already logs a warning for. That only
    // happens while the shuffle is being torn down, in which case this writer task is going
    // away too, so there is nothing useful to do here.
    tracker.registerShuffleWriterTask(streamingShuffleHandle.shuffleId, mapId, taskLocation)
    logInfo(log"Created shuffle server for writer ${MDC(LogKeys.SHUFFLE_WRITER_ID,
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
    private val replayHistory = new mutable.ArrayBuffer[(Long, ByteBuf)]()
    private val deferredReplayBuffers = new mutable.ArrayBuffer[ByteBuf]()
    private val lastEnqueuedByClient = new mutable.HashMap[TransportClient, Long]()
    private val terminationAckedClients = new mutable.HashSet[TransportClient]()
    private val firstMessageSent = new AtomicBoolean(false)

    // send will never block; push back is instead handled by blocking buffer allocation in write
    // on `allocatedBufferBytesSemaphore`. All send methods are synchronized to preserve message
    // order.
    def send(message: StreamingShuffleMessage, done: () => Unit = () => ()): Unit = synchronized {
      if (firstMessageSent.compareAndSet(false, true) && MIN_CLIENTS_PER_READER > 1) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (transportServerHandler.clientsFor(id).size < MIN_CLIENTS_PER_READER &&
            System.nanoTime() < deadline) {
          Thread.sleep(10)
        }
      }
      message.setSeqNum(lastSentSequenceNum.incrementAndGet())
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
      val sequenceNum = lastSentSequenceNum.get()
      replayHistory += ((sequenceNum, buf.retainedDuplicate()))

      // Count only actual network sends in the relaxed delivery barrier.  A shuffle partition
      // may legitimately have no downstream reader (for example a single-result aggregate),
      // so an unresolved client-discovery future must not hold the writer forever.
      def beginSend(): Unit = pendingSends.incrementAndGet()
      def completeSend(): Unit = {
        pendingSends.decrementAndGet()
        pendingSendsNotice.release()
      }

      def sendToClient(client: TransportClient): Unit = {
        // The first future establishes the connection. Additional downstream
        // readers for the same partition are already registered by the time a
        // large pipelined producer starts; fan out each encoded message to all
        // of them. The original buffer reference is released after all sends
        // have taken their own retained reference.
        val clients = (Seq(client) ++ transportServerHandler.clientsFor(id)).distinct
        val sends = clients.flatMap { target =>
          val lastEnqueued = lastEnqueuedByClient.getOrElse(target, -1L)
          val pending = replayHistory.iterator.filter(_._1 > lastEnqueued).toSeq
          if (pending.nonEmpty) {
            lastEnqueuedByClient.update(target, pending.last._1)
          }
          pending.map(entry => (target, entry._2))
        }
        val remaining = new AtomicInteger(sends.size)
        def completeBroadcast(): Unit = {
          if (remaining.decrementAndGet() == 0) {
            try done() finally completeSend()
          }
        }
        // A reader may disconnect between resolving the first client future and
        // taking the client snapshot.  There is then no Netty callback to drive
        // the completion path; still retire this send barrier entry so the
        // writer cannot wait forever on a zero-sized broadcast.
        if (sends.isEmpty) {
          try done() finally completeSend()
        }
        var synchronousFailure: Throwable = null
        sends.foreach { case (target, source) =>
          val outbound = source.retainedDuplicate()
          try {
            target.send(outbound).addListener((future: ChannelFuture) => {
              if (!future.isSuccess) {
                errorNotifier.markError(future.cause())
              }
              completeBroadcast()
            })
          } catch {
            case e: Throwable =>
              outbound.release()
              errorNotifier.markError(e)
              completeBroadcast()
              if (synchronousFailure == null) synchronousFailure = e
          }
        }
        // Once every currently registered reader has enqueued a sequence, the
        // replay reference is no longer needed for those readers.  Release the
        // common prefix eagerly instead of retaining the entire shuffle until
        // termination ACKs (which can be many GiB for SF1000).
        trimReplayHistory()
        buf.release()
        if (synchronousFailure != null) throw synchronousFailure
      }

      client match {
        case Left(c) =>
          beginSend()
          sendToClient(c)
        case Right(future) =>
          // Add another completion stage to ensure queued messages are sent in order.
          // If the future is already completed, this will be executed immediately.
          val newFuture = future.whenComplete { (client, ex) =>
            ex match {
              case null =>
                beginSend()
                sendToClient(client)
              case _ =>
                buf.release()
                done()
            }
          }
          // Once the future is completed, stop accumulating CompletionStages.
          client = if (newFuture.isDone) Left(newFuture.join()) else Right(newFuture)
      }
    }

    /** Replay all encoded messages not yet enqueued for a newly registered reader client. */
    def replayTo(target: TransportClient): Unit = synchronized {
      val lastEnqueued = lastEnqueuedByClient.getOrElse(target, -1L)
      val pending = replayHistory.iterator.filter(_._1 > lastEnqueued).toSeq
      if (pending.nonEmpty) {
        lastEnqueuedByClient.update(target, pending.last._1)
        pending.foreach { case (_, source) =>
          val outbound = source.retainedDuplicate()
          try {
            target.send(outbound).addListener((future: ChannelFuture) => {
              if (!future.isSuccess) errorNotifier.markError(future.cause())
            })
          } catch {
            case e: Throwable =>
              outbound.release()
              errorNotifier.markError(e)
          }
        }
        trimReplayHistory()
      }
    }

    /** Release replay entries already enqueued for all currently connected clients. */
    private def trimReplayHistory(): Unit = {
      val clients = transportServerHandler.clientsFor(id)
      if (clients.nonEmpty) {
        val minEnqueued = clients.iterator
          .map(c => lastEnqueuedByClient.getOrElse(c, -1L))
          .min
        while (replayHistory.nonEmpty && replayHistory.head._1 <= minEnqueued) {
          replayHistory.remove(0)._2.release()
        }
      }
    }

    def markTerminationAck(client: TransportClient): Unit = synchronized {
      terminationAckedClients += client
    }

    def allRegisteredClientsAcked: Boolean = synchronized {
      val clients = transportServerHandler.clientsFor(id)
      clients.isEmpty match {
        case true => terminationAckReceived.get()
        case false => clients.forall(terminationAckedClients.contains)
      }
    }

    // Sends buffer as a DataMessage to the shuffle reader. Takes ownership of the buffer.
    def send(timestampedBuffer: TimestampedBuffer): Unit = synchronized {
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

      // We keep a reference to rawBuffer so we can return it to the pool.
      send(dataMessage, () => {
        if (LINGER_AFTER_TERMINATION_MS > 0) {
          deferReplayBuffer(wireBuffer, rawBuffer)
          if (WRITER_BACKPRESSURE_ENABLED) {
            allocatedBufferBytesSemaphore.release(BUFFER_SIZE)
          }
        } else {
          if (wireBuffer ne rawBuffer) wireBuffer.release()
          rawBuffer.clear()
          if (context.isFailed() || context.isCompleted() || rawBuffer.capacity() != BUFFER_SIZE) {
            rawBuffer.release()
          } else {
            bufferPool.offerLast(rawBuffer)
          }
          if (WRITER_BACKPRESSURE_ENABLED) {
            allocatedBufferBytesSemaphore.release(BUFFER_SIZE)
          }
        }
      })
    }

    // Consume the current buffer, if it exists, and send it as a DataMessage.
    def send(): Unit = synchronized {
      val b = takeBuffer()
      if (b != null) send(b)
    }

    def takeBuffer(): TimestampedBuffer = buffer.getAndSet(null)

    def putBuffer(b: TimestampedBuffer): Unit = assert(buffer.getAndSet(b) == null)

    def close(): Unit = {
      send()
      send(new TerminationControlMessage(streamingShuffleHandle.shuffleId, shuffleWriterId, id))
    }

    def cancel(): Unit = {
      val error = context.getTaskFailure.getOrElse(new CancellationException())
      transportServerHandler.futureClients(id).completeExceptionally(error)
      client.foreach(_.completeExceptionally(error))
      Option(takeBuffer()).foreach(_.buffer.release())
    }

    def releaseReplayHistory(): Unit = synchronized {
      replayHistory.foreach { case (_, buffer) => buffer.release() }
      replayHistory.clear()
      lastEnqueuedByClient.clear()
      deferredReplayBuffers.foreach(_.release())
      deferredReplayBuffers.clear()
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
    logInfo(log"Received termination ack from reader ${MDC(LogKeys.SHUFFLE_READER_ID,
      partitionId)}. Now have ${MDC(LogKeys.NUM_TERMINATION_ACKS, receivedAcks)} / ${MDC(
      LogKeys.NUM_SHUFFLE_READERS, numPartitions)} termination acks")
  }

  private[streaming] def onTerminationAckReceivedWithClient(
      partitionId: Int, lastSeqNumSeenByReader: Long, client: TransportClient): Unit = {
    shards(partitionId).markTerminationAck(client)
  }

  /**
   * Cleans up all writer resources.
   * This method should be idempotent.
   */
  private[streaming] def cleanupResources(): Unit = {
    if (!cleanupStarted.compareAndSet(false, true)) return
    if (LINGER_AFTER_TERMINATION_MS > 0) {
      val delayedCleanup = new Thread(() => {
        try {
          Thread.sleep(LINGER_AFTER_TERMINATION_MS)
        } catch {
          case _: InterruptedException => Thread.currentThread().interrupt()
        }
        cleanupResourcesNow()
      }, s"streaming-shuffle-cleanup-$shuffleWriterId")
      delayedCleanup.setDaemon(true)
      delayedCleanup.start()
    } else {
      cleanupResourcesNow()
    }
  }

  private def cleanupResourcesNow(): Unit = {
    val cleanupStartTime = System.currentTimeMillis()
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
    Utils.tryLogNonFatalError {
      val list = new java.util.ArrayList[ByteBuf]()
      bufferPool.drainTo(list)
      list.forEach(buf => { buf.release(); () })
    }
    if (singleThreadedBuffers != null) {
      Utils.tryLogNonFatalError {
        var partitionId = 0
        while (partitionId < singleThreadedBuffers.length) {
          val pending = singleThreadedBuffers(partitionId)
          singleThreadedBuffers(partitionId) = null
          if (pending != null) pending.buffer.release()
          partitionId += 1
        }
      }
    }
    Utils.tryLogNonFatalError {
      memoryConsumer.freeMemory(memoryConsumer.getUsed())
    }
    logInfo(log"Resource cleanup took ${MDC(LogKeys.DURATION,
      System.currentTimeMillis() - cleanupStartTime)} ms")
    val rawBytes = rawBytesSent.get()
    val wireBytes = wireBytesSent.get()
    logInfo(s"Streaming shuffle writer transfer summary: messages=${dataMessagesSent.get()}, " +
      s"rawBytes=$rawBytes, wireBytes=$wireBytes, " +
      f"wireRatio=${if (rawBytes == 0) 1.0 else wireBytes.toDouble / rawBytes}%.4f")
  }

  private def throwErrorIfExists(): Unit = {
    context.getTaskFailure.foreach { throw _ }
    errorNotifier.throwErrorIfExists()
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
          throwErrorIfExists()
        }
      }
    }
    val buffer = bufferPool.pollLast()
    TimestampedBuffer(if (buffer != null) buffer else Unpooled.directBuffer(BUFFER_SIZE))
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
          shard.send(timestampedBuffer)
          throwErrorIfExists()
        }
      }
      isWriteFinished.countDown()
      if (!TIME_BASED_FLUSH_ENABLED) {
        var partitionId = 0
        while (partitionId < singleThreadedBuffers.length) {
          val pending = singleThreadedBuffers(partitionId)
          singleThreadedBuffers(partitionId) = null
          if (pending != null) shards(partitionId).send(pending)
          partitionId += 1
        }
      }
      shards.foreach(_.close())
      logInfo(log"StreamingShuffleWriter finished writing data and termination messages for " +
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
          Thread.`yield`()
        }
        logInfo(log"Received all termination acks for shuffle writer ${MDC(
          LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}. Closing server channel.")
      } else {
        while (pendingSends.get() != 0) {
          throwErrorIfExists()
          pendingSendsNotice.tryAcquire(100, TimeUnit.MILLISECONDS)
        }
        logInfo(log"All network sends completed for shuffle writer ${MDC(
          LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}; skipping termination-ack wait.")
      }
      throwErrorIfExists()
      if (LINGER_AFTER_TERMINATION_MS == 0) {
        shards.foreach(_.releaseReplayHistory())
      }
    } finally {
      isWriteFinished.countDown() // Duplicate countDowns are a no-op.
      flushThread.foreach(_.join())
    }
  }
}
