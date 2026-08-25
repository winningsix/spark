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
import java.util.concurrent.LinkedBlockingQueue

import io.netty.buffer.{ByteBuf, CompositeByteBuf, Unpooled}
import io.netty.channel.{Channel, ChannelOption}
import io.netty.util.concurrent.{Future, GenericFutureListener}

import org.apache.spark.{SparkException, TaskContext}
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
    queue: LinkedBlockingQueue[StreamingShuffleMessage],
    shuffleId: Int,
    byteLimit: Long,
    val context: TaskContext,
    errorNotifier: ErrorNotifier) extends RpcHandler with TaskContextAwareLogging {
  private val RECVBUF_SIZE: Integer = 32 << 10
  private val SENDBUF_SIZE: Integer = 512

  private var lastSeqNum = -1L  // The most recent sequence number we have seen.
  // Set once this writer's TerminationControlMessage has been received, so that channelInactive
  // can tell an expected end-of-stream close apart from a premature disconnect (a writer that
  // died before terminating). @volatile because it is written on the Netty event-loop thread in
  // receive() and read in channelInactive().
  @volatile private var terminationReceived = false
  // These variables are used for flow control by updateQuota below.
  private var channel: Channel = _  // The channel to the shuffle writer, captured in channelActive.
  private var remainingBytesQuota: Long = byteLimit // Remaining bytes before pushback.
  private var autoReadDisabledTimestamp: Long = _  // Last time pushback condition was triggered.
  @volatile private var perStreamAutoReadEnabled = true

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

  override def channelActive(client: TransportClient): Unit = {
    channel = client.getChannel
    channel.config.setOption(ChannelOption.SO_RCVBUF, RECVBUF_SIZE)
    channel.config.setOption(ChannelOption.SO_SNDBUF, SENDBUF_SIZE)
    // This is a connection-discovery message, not a per-buffer acknowledgement. The writer's
    // flow control is driven by Netty send completion and its in-flight byte semaphore.
    sendCreditControlMessage(client, shuffleWriterId, 1)
  }

  // Update the number of outstanding bytes from this writer, toggling auto-read if necessary.
  // Can be called from main or Netty threads, so synchronization is required.
  private def updateQuota(bytes: Long): Unit = synchronized {
    remainingBytesQuota -= bytes
    if (!perStreamAutoReadEnabled) return
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

  protected def sendCreditControlMessage(
      client: TransportClient,
      shuffleWriterId: Int,
      credit: Int
  ): Unit = {
    var buf: CompositeByteBuf = null
    try {
      val creditControlMessage =
        new CreditControlMessage(shuffleId, shuffleWriterId, shuffleReaderId, credit)
      buf = client.getChannel().alloc().compositeBuffer()
        .capacity(creditControlMessage.headerLength())
      creditControlMessage.encode(buf)

      // send() will release the buffer, so retain to avoid double free in finally clause
      client
        .send(buf.retain())
        .addListener(
          getResponseHandler(buf,
            s"Error sending credit control message to shuffle writer ${shuffleWriterId}"))
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
            () => { onTermAckResponse(shuffleWriterId) }
          )
        )
    } catch {
      case (ex: Throwable) =>
        logError(log"Streaming shuffle client handler sendTerminationAckMessage failed", ex)
        errorNotifier.markError(ex)
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
    receiveMessage(client, message.nioByteBuffer(), Some(message))
  }

  /** Reuses the ByteBuffer already inspected by the executor-level multiplexing router. */
  private[streaming] def receiveMultiplexed(
      client: TransportClient,
      message: ByteBuffer,
      managedBody: ManagedBuffer): Unit = {
    receiveMessage(client, message, Some(managedBody))
  }

  private def receiveMessage(
      client: TransportClient,
      message: ByteBuffer,
      managedBody: Option[ManagedBuffer]): Unit = {
    var buf: ByteBuf = null
    var shuffleMessage: StreamingShuffleMessage = null
    var queued = false
    try {
      // TransportRequestHandler owns the incoming ManagedBuffer only until receive() returns.
      // DataMessage processing is asynchronous, so retain that buffer and release it with the
      // decoded message. Direct ByteBuffer callers (primarily unit tests) keep the legacy copy.
      buf = managedBody match {
        case Some(_) => Unpooled.wrappedBuffer(message)
        case None => Unpooled.wrappedBuffer(message).copy()
      }
      shuffleMessage = StreamingShuffleMessage.decode(buf)
      updateLastSeqNum(shuffleMessage.getSeqNum, shuffleMessage.messageType())
      // At this point, the message type has been read, so the decoders will read the (optional)
      // length int, followed by the actual content.
      shuffleMessage match {
        case dataMessage: DataMessage =>
          val messageSize = buf.capacity()
          updateQuota(messageSize)
          val retainedBody = managedBody.map(_.retain())
          dataMessage.setReleaseCallback(() => {
            try {
              updateQuota(-messageSize)
            } finally {
              retainedBody.foreach(_.release())
            }
          })
          // We can only release the buf after we have decoded all the rows in the buffer. Do not
          // send another CreditControlMessage here: the writer ignores its numeric credit and
          // already discovered this client in channelActive. A per-DataMessage response adds a
          // reverse Netty write and syscall without changing flow control.
        case controlMessage: TerminationControlMessage =>
          // Record termination before sending the ack: the writer only closes its connection
          // after it receives this ack, so setting the flag here guarantees it is visible before
          // the resulting channelInactive fires, avoiding a false "premature disconnect" error.
          terminationReceived = true
          sendTerminationAckMessage(client, controlMessage.shuffleWriterId)
        case _ =>
          throw new IllegalArgumentException(s"Unexpected message type in ShuffleClientHandler: " +
            s"${shuffleMessage.messageType()}");
      }
      queue.put(shuffleMessage)
      queued = true
    } catch {
      case (ex: Throwable) =>
        logError(log"Streaming shuffle client handler receive failed.", ex)
        errorNotifier.markError(ex)
    } finally {
      if (!queued && shuffleMessage != null) {
        shuffleMessage.release()
      }
      if (buf != null) {
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
    if (!terminationReceived) {
      errorNotifier.markError(new SparkException(
        s"Connection to streaming shuffle writer ${shuffleWriterId} closed before termination; " +
          "the writer task likely failed."))
    }
  }

  override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
    logError(log"Streaming shuffle client handler caught exception.", cause)
    errorNotifier.markError(cause)
  }


  // not needed for streaming shuffle
  // cannot throw UnsupportedException because this function will be called
  // even if this feature is not used.
  override def getStreamManager: StreamManager = null

  private def getResponseHandler(
      buf: ByteBuf,
      errorMsg: String,
      onSuccessFunc: () => Unit = () => {})
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
            logError(errorMsg, ex)
            errorNotifier.markError(ex)
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
}
