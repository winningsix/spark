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
import java.util.concurrent.BlockingQueue
import java.util.concurrent.atomic.AtomicLong

import scala.collection.mutable.ArrayBuffer

import io.netty.buffer.{ByteBuf, CompositeByteBuf, Unpooled}
import io.netty.channel.{Channel, ChannelOption}
import io.netty.util.concurrent.{Future, GenericFutureListener}

import org.apache.spark.{SparkEnv, SparkException, TaskContext}
import org.apache.spark.internal.LogKeys
import org.apache.spark.internal.config.{STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE,
  STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED}
import org.apache.spark.network.buffer.ManagedBuffer
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient}
import org.apache.spark.network.server.{RpcHandler, StreamManager}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, DataMessage, StreamingShuffleMessage, StreamingShuffleMessageType, TerminationAckMessage, TerminationControlMessage}
import org.apache.spark.util.ErrorNotifier

/**
 * A StreamingShuffleClientHandler is used by ShuffleReaders to receive data from ShuffleWriters.
 *
 * Our V1 protocol is very simple: the server pushes records to us that we read one-by-one and write
 * them to a concurrent queue that the calling task (StreamingShuffleReader) can dequeue from.
 */
class StreamingShuffleClientHandler(
    // The shuffle writer that we're connected to.
    // TODO: we might remove this field; avoid relying on it in future development.
    shuffleWriterId: Int,
    shuffleReaderId: Int,
    queue: BlockingQueue[StreamingShuffleMessage],
    shuffleId: Int,
    byteLimit: Long,
    val context: TaskContext,
    errorNotifier: ErrorNotifier,
    onMessageAvailable: () => Unit = () => ()) extends RpcHandler with TaskContextAwareLogging {
  private val RECVBUF_SIZE: Integer = Option(SparkEnv.get)
    .map(env => Integer.valueOf(env.conf.get(STREAMING_SHUFFLE_DATA_SOCKET_BUFFER_SIZE)))
    .getOrElse(Integer.valueOf(32 << 10))
  private val DEDICATED_CONTROL_SENDBUF_SIZE = 512

  @volatile private var lastSeqNum = -1L  // The most recent sequence number we have seen.
  // Set once this writer's TerminationControlMessage has been received, so that channelInactive
  // can tell an expected end-of-stream close apart from a premature disconnect (a writer that
  // died before terminating). @volatile because it is written on the Netty event-loop thread in
  // receive() and read in channelInactive().
  @volatile private var terminationReceived = false
  // These variables are used for flow control by updateQuota below.
  private var channel: Channel = _  // The channel to the shuffle writer, captured in channelActive.
  private var remainingBytesQuota: Long = byteLimit // Remaining bytes before pushback.
  // Total encoded data bytes released by the task on this connection. Multiplexed routes send
  // this as an absolute acknowledgement watermark, so an idle retry is idempotent.
  private val cumulativeReleasedBytes = new AtomicLong(0L)
  private val backpressureEnabled =
    Option(SparkEnv.get).forall(_.conf.get(STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED))
  private val messageBatchingEnabled =
    Option(SparkEnv.get).forall(_.conf.get(STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED))
  private var autoReadDisabledTimestamp: Long = _  // Last time pushback condition was triggered.
  @volatile private var perStreamAutoReadEnabled = true
  // A shared executor lane must not emit one Spark transport write for every released data
  // frame. The cumulative watermark is idempotent, so the executor client can retain only the
  // newest watermark for this logical route and publish many routes in one control body.
  @volatile private var multiplexedCreditSender:
      (TransportClient, StreamingShuffleClientHandler) => Unit = _

  setShuffleIdForLogging(shuffleId)

  // Keeps track of the largest seqNum we have seen so far sent by the writer.
  // It should start with 0 and be strictly without gap.
  private def updateLastSeqNum(newSeqNum: Long, messageType: StreamingShuffleMessageType) = {
    if (lastSeqNum + 1 != newSeqNum) {
      throw StreamingShuffleManager.streamingShuffleIncorrectSequenceNumber(
        messageType,
        shuffleWriterId,
        shuffleReaderId,
        lastSeqNum + 1,
        newSeqNum)
    }
    lastSeqNum = newSeqNum
  }

  private[spark] var onTermAckResponse: Int => Unit = (Int) => {}
  private[spark] def setOnTermAckResponseHandler(handler: Int => Unit): Unit = {
    onTermAckResponse = handler
  }

  /** A multiplexed channel cannot safely toggle autoRead for one logical stream. */
  private[streaming] def useMultiplexedChannel(): Unit = {
    perStreamAutoReadEnabled = false
  }

  private[streaming] def setMultiplexedCreditSender(
      sender: (TransportClient, StreamingShuffleClientHandler) => Unit): Unit = {
    multiplexedCreditSender = sender
  }

  private[streaming] def clearMultiplexedCreditSender(): Unit = {
    multiplexedCreditSender = null
  }

  /**
   * A dedicated reader connection sends only one route's credit and terminal ACK frames, for
   * which the historical 512-byte socket buffer is sufficient.  An executor lane multiplexes
   * thousands of routes, though, so retaining that per-route setting serializes late discovery
   * credits behind the complete ACK backlog of the earlier writers.  Use the configured data
   * socket buffer as the aggregate control-plane window for a multiplexed lane.
   */
  private[streaming] def configuredSendBufferSize: Int = {
    if (perStreamAutoReadEnabled) DEDICATED_CONTROL_SENDBUF_SIZE
    else math.max(DEDICATED_CONTROL_SENDBUF_SIZE, RECVBUF_SIZE.intValue())
  }

  private def bindChannel(client: TransportClient, configureSocket: Boolean): Unit = {
    channel = client.getChannel
    if (configureSocket) {
      channel.config.setOption(ChannelOption.SO_RCVBUF, RECVBUF_SIZE)
      channel.config.setOption(
        ChannelOption.SO_SNDBUF, Integer.valueOf(configuredSendBufferSize))
    }
  }

  private def initialCreditAmount: Int = {
    // The first credit both discovers the route and opens its bounded receive window. On a
    // multiplexed channel this is the logical replacement for toggling channel-wide autoRead;
    // each route gets an independent writer-side byte budget even though the physical channel is
    // shared with unrelated readers.
    if (backpressureEnabled && !perStreamAutoReadEnabled) {
      // A negative first credit opts this logical stream into writer-side byte admission. Positive
      // credits retain the historical connection-discovery-only protocol for dedicated channels.
      -math.min(byteLimit, Int.MaxValue.toLong).toInt
    } else {
      // Preserve the original connection-discovery marker when reader backpressure is disabled.
      1
    }
  }

  override def channelActive(client: TransportClient): Unit = {
    bindChannel(client, configureSocket = true)
    sendCreditControlMessage(client, shuffleWriterId, initialCreditAmount)
  }

  /** Bind one logical route and return its discovery frame for an executor-level batch send. */
  private[streaming] def prepareMultiplexedInitialCredit(
      client: TransportClient,
      configureSocket: Boolean): CreditControlMessage = {
    useMultiplexedChannel()
    bindChannel(client, configureSocket)
    new CreditControlMessage(
      shuffleId, shuffleWriterId, shuffleReaderId, initialCreditAmount)
  }

  /** Surface a failed executor-level discovery batch through this route's normal error path. */
  private[streaming] def initialCreditBatchSendFailed(cause: Throwable): Unit = {
    val error = new RuntimeException(
      s"Error sending initial credit batch to shuffle writer $shuffleWriterId", cause)
    logError(log"Streaming shuffle initial credit batch failed", error)
    errorNotifier.markError(error)
  }

  /** Repair initial route discovery or repeat the latest idempotent release acknowledgement. */
  private[streaming] def repairCreditWindow(client: TransportClient): Unit = {
    if (backpressureEnabled && !perStreamAutoReadEnabled && !terminationReceived) {
      if (lastSeqNum < 0) {
        val available = availableReceiveBytes
        if (available > 0) sendAvailableCreditFloor(client, available)
      } else {
        sendCumulativeCreditAck(client, cumulativeReleasedBytes.get())
      }
    }
  }

  /** Build one repair frame so an executor lane can batch many logical-route probes. */
  private[streaming] def prepareMultiplexedCreditRepair(): Option[CreditControlMessage] = {
    if (!backpressureEnabled || perStreamAutoReadEnabled || terminationReceived) return None
    val message = if (lastSeqNum < 0) {
      val available = availableReceiveBytes
      val advertised = math.min(available, Int.MaxValue.toLong).toInt
      if (advertised <= 0) return None
      new CreditControlMessage(shuffleId, shuffleWriterId, shuffleReaderId, -advertised)
    } else {
      val cumulative = new CreditControlMessage(
        shuffleId, shuffleWriterId, shuffleReaderId, 0)
      cumulative.setSeqNum(cumulativeReleasedBytes.get())
      cumulative
    }
    Some(message)
  }

  /** Surface a failed batched repair through the logical route's normal error path. */
  private[streaming] def creditRepairBatchSendFailed(
      client: TransportClient,
      cause: Throwable): Unit = {
    if (!terminationAckFailureIsExpected(cause, client)) {
      val error = new RuntimeException(
        s"Error sending batched credit repair to shuffle writer $shuffleWriterId", cause)
      logError(log"Streaming shuffle batched credit repair failed", error)
      errorNotifier.markError(error)
    }
  }

  /** Snapshot one logical route without mutating its liveness protocol. */
  private[streaming] def routeProgressForDiagnostics: (Long, Boolean, Long) = {
    (lastSeqNum, terminationReceived, cumulativeReleasedBytes.get())
  }

  // Update the number of outstanding bytes from this writer, toggling auto-read if necessary.
  // Can be called from main or Netty threads, so synchronization is required.
  private def updateQuota(bytes: Long): Long = synchronized {
    if (!backpressureEnabled) return byteLimit
    remainingBytesQuota -= bytes
    if (perStreamAutoReadEnabled) {
      val autoRead = remainingBytesQuota > 0
      if (channel.config.isAutoRead != autoRead) {
        channel.config.setAutoRead(autoRead)
        if (autoRead) {
          channel.read()
        } else {
          autoReadDisabledTimestamp = System.nanoTime()
        }
      }
    }
    clampedAvailableReceiveBytes
  }

  private def clampedAvailableReceiveBytes: Long = {
    math.max(0L, math.min(byteLimit, remainingBytesQuota))
  }

  private def availableReceiveBytes: Long = synchronized {
    clampedAvailableReceiveBytes
  }

  private def sendAvailableCreditFloor(client: TransportClient, available: Long): Unit = {
    val advertised = math.min(available, Int.MaxValue.toLong).toInt
    if (advertised > 0) {
      sendCreditControlMessage(client, shuffleWriterId, -advertised)
    }
  }

  protected def sendCumulativeCreditAck(
      client: TransportClient,
      releasedBytes: Long): Unit = {
    val sender = multiplexedCreditSender
    if (!perStreamAutoReadEnabled && sender != null) {
      // releasedBytes has already been committed to cumulativeReleasedBytes. The batcher reads
      // that atomic watermark immediately before encoding, so several releases collapse to the
      // newest value without losing credit.
      sender(client, this)
    } else {
      sendCreditControlMessage(client, shuffleWriterId, 0, releasedBytes)
    }
  }

  protected def sendCreditControlMessage(
      client: TransportClient,
      shuffleWriterId: Int,
      credit: Int
  ): Unit = {
    sendCreditControlMessage(client, shuffleWriterId, credit, 0L)
  }

  private def sendCreditControlMessage(
      client: TransportClient,
      shuffleWriterId: Int,
      credit: Int,
      sequenceNumber: Long
  ): Unit = {
    var buf: CompositeByteBuf = null
    try {
      val creditControlMessage =
        new CreditControlMessage(shuffleId, shuffleWriterId, shuffleReaderId, credit)
      creditControlMessage.setSeqNum(sequenceNumber)
      buf = client.getChannel().alloc().compositeBuffer()
        .capacity(creditControlMessage.headerLength())
      creditControlMessage.encode(buf)

      // send() will release the buffer, so retain to avoid double free in finally clause
      client
        .send(buf.retain())
        .addListener(
          getResponseHandler(
            buf,
            s"Error sending credit control message to shuffle writer ${shuffleWriterId}",
            isExpectedFailure = ex => terminationAckFailureIsExpected(ex, client)))
    } catch {
      case (ex: Throwable) =>
        logError(log"Streaming shuffle client handler sendCreditControlMessage failed", ex)
        errorNotifier.markError(ex)
    } finally {
      if (buf != null) {
        buf.release()
      }
    }
  }

  protected def sendTerminationAckMessage(client: TransportClient, shuffleWriterId: Int): Unit = {
    var buf: CompositeByteBuf = null
    try {
      val terminationAckMessage =
        new TerminationAckMessage(shuffleId, shuffleWriterId, shuffleReaderId)
      terminationAckMessage.setSeqNum(lastSeqNum)
      buf = client.getChannel().alloc().compositeBuffer()
        .capacity(terminationAckMessage.headerLength())
      terminationAckMessage.encode(buf)

      // send() will release the buffer, so retain to avoid double free in finally clause
      client
        .send(buf.retain())
        .addListener(
          getResponseHandler(
            buf,
            s"Error sending termination acknowledgment to shuffle writer ${shuffleWriterId}",
            () => { onTermAckResponse(shuffleWriterId) },
            ex => terminationAckFailureIsExpected(ex, client)
          )
        )
    } catch {
      case (ex: Throwable) =>
        if (terminationAckFailureIsExpected(ex, client)) {
          logWarning(log"Ignoring termination acknowledgment failure after the writer " +
            log"has already closed its endpoint for shuffle writer ${MDC(
              LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}", ex)
        } else {
          logError(log"Streaming shuffle client handler sendTerminationAckMessage failed", ex)
          errorNotifier.markError(ex)
        }
    } finally {
      if (buf != null) {
        buf.release()
      }
    }
  }

  override def receive(
      client: TransportClient,
      message: ByteBuffer,
      callback: RpcResponseCallback): Unit = {
    receiveMessage(client, message, None)
  }

  override def receive(client: TransportClient, message: ManagedBuffer): Unit = {
    val body = message.convertToNetty().asInstanceOf[ByteBuf]
    try {
      receiveMessage(client, body, Some(message))
    } finally {
      body.release()
    }
  }

  /** Reuses the ByteBuf already inspected by the executor-level multiplexing router. */
  private[streaming] def receiveMultiplexed(
      client: TransportClient,
      message: ByteBuf,
      managedBody: ManagedBuffer): Unit = {
    receiveMessage(client, message, Some(managedBody))
  }

  /**
   * Return the length of the next streaming-shuffle message in a transport body.
   *
   * The Spark transport frame contains one OneWayMessage body, but a writer may concatenate several
   * streaming frames in that body to amortize transport writes. DataMessage.decode intentionally
   * requires an exact frame, so callers must slice each frame before decoding it.
   */
  private def nextMessageLength(buf: ByteBuf): Int = {
    val index = buf.readerIndex()
    val readable = buf.readableBytes()
    if (readable < 12) {
      throw new IllegalArgumentException(
        s"Streaming shuffle message is too short: $readable bytes")
    }
    StreamingShuffleMessageType.decode(buf.getInt(index)) match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW =>
        val dataHeaderLength = 40 // common header (12) + DataMessage header (28)
        if (readable < dataHeaderLength) {
          throw new IllegalArgumentException(
            s"Truncated streaming DataMessage header: $readable bytes")
        }
        val dataSize = buf.getInt(index + 24)
        if (dataSize < 0 || dataSize > readable - dataHeaderLength) {
          throw new IllegalArgumentException(
            s"Invalid streaming DataMessage size $dataSize with $readable bytes available")
        }
        dataHeaderLength + dataSize
      case StreamingShuffleMessageType.TERMINATION_CONTROL_MESSAGE => 24
      case StreamingShuffleMessageType.CREDIT_CONTROL_MESSAGE |
          StreamingShuffleMessageType.TERMINATION_ACK_MESSAGE => 28
    }
  }

  private def receiveMessage(
      client: TransportClient,
      message: ByteBuffer,
      managedBody: Option[ManagedBuffer]): Unit = {
    val buf = Unpooled.wrappedBuffer(message).copy()
    receiveMessage(client, buf, managedBody = None)
  }

  /**
   * Decode directly from the Netty body.  The shared-connection path can pass a composite buffer;
   * converting it to a ByteBuffer first may merge all components into a new contiguous allocation.
   * The handler only needs indexed reads and slices, so keep the body in its original zero-copy
   * representation and retain it only for data messages that outlive this callback.
   */
  private def receiveMessage(
      client: TransportClient,
      message: ByteBuf,
      managedBody: Option[ManagedBuffer]): Unit = {
    var buf: ByteBuf = null
    var shuffleMessage: StreamingShuffleMessage = null
    val decodedMessages = new ArrayBuffer[StreamingShuffleMessage]()
    val pendingTerminationAcks = new ArrayBuffer[Int]()
    var publishedMessage = false
    try {
      // TransportRequestHandler owns the incoming ManagedBuffer only until receive() returns.
      // DataMessage processing is asynchronous, so retain that buffer and release it with the
      // decoded message. The direct ByteBuffer entry point has already made its private copy.
      buf = message.duplicate()
      while (buf.isReadable) {
        val messageSize = nextMessageLength(buf)
        val frame = buf.readSlice(messageSize)
        shuffleMessage = StreamingShuffleMessage.decode(frame)
        // End-of-stream is a reliable control frame. A writer may retransmit it until its ACK is
        // observed, including when the first terminal write and the ACK cross during executor
        // teardown. Accept only the exact terminal sequence already seen; data and every other
        // duplicate remain sequence errors. The duplicate is ACKed again but is not published to
        // the task queue, preserving exactly-once end-of-stream for the iterator.
        val duplicateTermination = shuffleMessage match {
          case _: TerminationControlMessage =>
            terminationReceived && shuffleMessage.getSeqNum == lastSeqNum
          case _ => false
        }
        if (!duplicateTermination) {
          updateLastSeqNum(shuffleMessage.getSeqNum, shuffleMessage.messageType())
        }
        shuffleMessage match {
          case dataMessage: DataMessage =>
            updateQuota(messageSize)
            val retainedBody = managedBody.map(_.retain())
            dataMessage.setReleaseCallback(() => {
              try {
                val available = updateQuota(-messageSize)
                if (backpressureEnabled && !terminationReceived) {
                  if (perStreamAutoReadEnabled) {
                    // Dedicated channels retain the original additive-credit protocol; their
                    // channel-level autoRead is the primary admission boundary.
                    sendCreditControlMessage(
                      client,
                      shuffleWriterId,
                      math.min(messageSize.toLong, Int.MaxValue.toLong).toInt)
                  } else {
                    // Carry an absolute released-byte watermark. Repeating it after an idle
                    // interval repairs a delayed final wake-up without adding the same credit
                    // twice or advertising receive capacity that may still be in flight.
                    val released = cumulativeReleasedBytes.addAndGet(messageSize.toLong)
                    sendCumulativeCreditAck(client, released)
                  }
                }
              } finally {
                retainedBody.foreach(_.release())
              }
            })
            // We can only release the frame after all rows in the buffer have been decoded. The
            // release callback returns the exact encoded frame size to the writer, so a shared
            // physical channel cannot continue filling this logical route while its queue is
            // waiting behind another sibling input.
          case controlMessage: TerminationControlMessage =>
            // Mark the route terminated immediately so a later channelInactive is classified
            // correctly, but do not ACK until this body has been published to the inbox queue.
            // The ACK is the writer's cleanup fence; sending it after decode but before queue
            // ownership allowed a relaxed writer to discard its endpoint while the task-visible
            // terminal was still in this callback.
            terminationReceived = true
            pendingTerminationAcks += controlMessage.shuffleWriterId
          case _ =>
            throw new IllegalArgumentException(
              s"Unexpected message type in ShuffleClientHandler: ${shuffleMessage.messageType()}")
        }
        if (duplicateTermination) {
          shuffleMessage.release()
        } else if (messageBatchingEnabled && queue.isInstanceOf[StreamingShuffleMessageQueue]) {
          decodedMessages += shuffleMessage
        } else {
          // Preserve the original streaming behavior when batching is disabled: publish each
          // decoded frame immediately so a reader can start consuming before this body is fully
          // parsed.
          queue.put(shuffleMessage)
          publishedMessage = true
        }
        shuffleMessage = null
      }
      if (decodedMessages.nonEmpty) {
        queue match {
          case batchedQueue: StreamingShuffleMessageQueue if messageBatchingEnabled =>
            batchedQueue.putBatch(decodedMessages.toArray)
            decodedMessages.clear()
            publishedMessage = true
          case _ =>
            // Keep ownership tracking precise if an interrupt happens while putting into a
            // legacy queue. Messages whose put already succeeded belong to the queue; release
            // only the suffix that was not enqueued.
            val messages = decodedMessages.toArray
            decodedMessages.clear()
            var enqueued = 0
            try {
              while (enqueued < messages.length) {
                queue.put(messages(enqueued))
                enqueued += 1
                publishedMessage = true
              }
            } finally {
              while (enqueued < messages.length) {
                messages(enqueued).release()
                enqueued += 1
              }
            }
        }
      }
      if (publishedMessage) {
        onMessageAvailable()
      }
      // Queue publication is the end-to-end delivery point for a prepared inbox. Duplicate
      // terminals are not republished, but are ACKed again here so a lost ACK remains repairable.
      pendingTerminationAcks.foreach(sendTerminationAckMessage(client, _))
    } catch {
      case (ex: Throwable) =>
        logError(log"Streaming shuffle client handler receive failed.", ex)
        errorNotifier.markError(ex)
    } finally {
      if (shuffleMessage != null) {
        shuffleMessage.release()
      }
      decodedMessages.foreach(_.release())
      if (buf != null && managedBody.isEmpty) {
        // If any StreamingShuffleMessage needs buf, then it would have retained it.
        buf.release()
      }
    }
  }

  override def channelInactive(client: TransportClient): Unit = {
    // A clean end-of-stream also closes the channel, but only after this reader has received the
    // writer's TerminationControlMessage (which sets terminationReceived). So a close while the
    // flag is still false means the writer disconnected before terminating -- e.g. the writer
    // task failed, its executor was lost, or the network dropped. Surface it through the shared
    // ErrorNotifier so the reader task fails instead of polling the message queue forever.
    val consumerIsActive = context == null ||
      (!context.isInterrupted() && !context.isFailed() && !context.isCompleted())
    if (!terminationReceived && consumerIsActive) {
      errorNotifier.markError(new SparkException(
        s"Connection to streaming shuffle writer ${shuffleWriterId} closed before termination; " +
          "the writer task likely failed."))
    } else if (!terminationReceived) {
      logDebug(
        s"Ignoring streaming shuffle connection close after reader task cancellation for " +
          s"writer $shuffleWriterId")
    }
  }

  override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
    // The writer closes its endpoint after receiving the termination ACK. Depending on which side
    // wins the TCP close race, Netty can report that close as a reset/broken-pipe exception rather
    // than a clean channelInactive. The termination frame has already proved that this route was
    // drained, so do not turn the expected close into a fatal reader error (which would cancel all
    // downstream writers in a pipelined group).
    if (terminationAckFailureIsExpected(cause, client)) {
      logDebug(log"Ignoring expected streaming shuffle connection close after termination.", cause)
    } else {
      logError(log"Streaming shuffle client handler caught exception.", cause)
      errorNotifier.markError(cause)
    }
  }


  // not needed for streaming shuffle
  // cannot throw UnsupportedException because this function will be called
  // even if this feature is not used.
  override def getStreamManager: StreamManager = null

  private def getResponseHandler(
      buf: ByteBuf,
      errorMsg: String,
      onSuccessFunc: () => Unit = () => {},
      isExpectedFailure: Throwable => Boolean = _ => false)
      : GenericFutureListener[io.netty.util.concurrent.Future[Void]] = {
    new GenericFutureListener[io.netty.util.concurrent.Future[Void]]() {

      override def operationComplete(future: Future[Void]): Unit = {
        try {
          handleResponse(future, errorMsg)
          onSuccessFunc()
        } catch {
          // The code in listener will be executed by another thread, so we need to
          // bubble up the error here
          case (ex: Throwable) =>
            if (isExpectedFailure(ex)) {
              logWarning(log"Ignoring expected streaming shuffle send failure: ${MDC(
                LogKeys.MESSAGE, errorMsg)}", ex)
            } else {
              logError(errorMsg, ex)
              errorNotifier.markError(ex)
            }
        }
      }
    }
  }

  protected def handleResponse(future: Future[Void], errorMsg: String): Unit = {
    if (!future.isSuccess) {
      throw new RuntimeException(
        s"${errorMsg}: ${future.cause().getMessage()}"
      )
    }
  }

  private def terminationAckFailureIsExpected(
      ex: Throwable,
      client: TransportClient): Boolean = {
    // A credit may already be queued when the writer receives our termination ACK and closes its
    // endpoint. Netty can complete that queued write after the close, before channelInactive has
    // been dispatched to this handler. Treat that write failure as expected only when the channel
    // is actually closed; channelInactive still reports a genuine pre-termination disconnect.
    if (!terminationReceived && client.getChannel.isActive) {
      false
    } else {
      def hasClosedEndpoint(t: Throwable): Boolean = {
        val className = t.getClass.getName
        val message = Option(t.getMessage).getOrElse("").toLowerCase(java.util.Locale.ROOT)
        className.contains("ClosedChannel") ||
          message.contains("broken pipe") ||
          message.contains("connection reset") ||
          Option(t.getCause).exists(hasClosedEndpoint)
      }
      hasClosedEndpoint(ex)
    }
  }
}
