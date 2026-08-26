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
import java.util.concurrent.{CompletableFuture, CopyOnWriteArrayList}

import scala.jdk.CollectionConverters._

import io.netty.buffer.{ByteBuf, Unpooled}

import org.apache.spark.TaskContext
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient}
import org.apache.spark.network.server.{RpcHandler, StreamManager}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, StreamingShuffleMessage, TerminationAckMessage}
import org.apache.spark.util.ErrorNotifier

/**
 * The workflow of the server handler is the following:
 *
 * 1. Unfulfilled futures are created for each reader client.
 *
 * 2. Shuffle writer receives credit control message from shuffle reader A.
 *    This allows shuffle writer to know that this channel is for communication
 *    with shuffle reader A, allowing the relevant client future to be fulfilled.
 *    This synchronously triggers any pending completion stages; the writer will
 *    queue messages as completion stages until a connection is established.
 *
 *  3. The StreamingShuffleWriter will chain completion stages until it notices
 *     that the future is complete. When it does, it will invoke TransportClient.send directly.
 *
 *  4. The StreamingShuffleWriter limits the number of in-flight messages by acquiring
 *     a semaphore when new buffers are allocated, releasing it when the netty callback
 *     for that buffer is invoked.
 */
class StreamingShuffleServerHandler(
    onTerminationAckReceived: (Int, Long) => Unit,
    shuffleId: Int,
    // One reader per reduce partition, so this equals the writer's numPartitions.
    numReaders: Int,
    val context: TaskContext,
    errorNotifier: ErrorNotifier,
    onTerminationAckReceivedWithClient: (Int, Long, TransportClient) => Unit = (_, _, _) => (),
    onClientConnected: (Int, TransportClient) => Unit = (_, _) => ())
    extends RpcHandler with TaskContextAwareLogging {

  val futureClients: Array[CompletableFuture[TransportClient]] =
    Array.fill(numReaders)(new CompletableFuture[TransportClient]())
  // A pipelined batch can have multiple downstream consumers for one partition.
  // Keep every connection so the writer can fan out the stream instead of
  // silently serving only the first reader that advertises credit.
  private val clientsByReader: Array[CopyOnWriteArrayList[TransportClient]] =
    Array.fill(numReaders)(new CopyOnWriteArrayList[TransportClient]())

  private[streaming] def clientsFor(readerId: Int): Seq[TransportClient] = {
    clientsByReader(readerId).asScala.toSeq
  }

  setShuffleIdForLogging(shuffleId)

  override def receive(
      client: TransportClient,
      message: ByteBuffer,
      callback: RpcResponseCallback): Unit = {
    var buf: ByteBuf = null
    try {
      buf = Unpooled.wrappedBuffer(message)
      val shuffleMessage = StreamingShuffleMessage.decode(buf)
      handleMessage(client, shuffleMessage)
    } catch {
      case (ex: Throwable) =>
        logError(log"Streaming shuffle server handler receive failed", ex)
        errorNotifier.markError(ex)
    } finally {
      if (buf != null) {
        buf.release()
      }
    }
  }

  private[streaming] def handleMessage(
      client: TransportClient,
      shuffleMessage: StreamingShuffleMessage): Unit = {
    shuffleMessage match {
      case creditControlMessage: CreditControlMessage =>
        clientsByReader(creditControlMessage.shuffleReaderId).addIfAbsent(client)
        futureClients(creditControlMessage.shuffleReaderId).complete(client)
        onClientConnected(creditControlMessage.shuffleReaderId, client)
      case terminationAck: TerminationAckMessage =>
        logInfo(
          s"Received termination ack message from shuffle reader " +
            s"${terminationAck.shuffleReaderId}"
        )
        onTerminationAckReceived(terminationAck.shuffleReaderId, terminationAck.getSeqNum)
        onTerminationAckReceivedWithClient(
          terminationAck.shuffleReaderId, terminationAck.getSeqNum, client)
      case _ =>
        throw new IllegalArgumentException(
          s"Unexpected message type in ShuffleServerHandler: " +
            s"${shuffleMessage.messageType()}"
        )
    }
  }

  override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
    logError(log"Streaming shuffle server handler caught exception.", cause)
    errorNotifier.markError(cause)
  }

  // not needed for streaming shuffle
  // cannot throw UnsupportedException because this function will be called
  // even if this feature is not used.
  override def getStreamManager: StreamManager = null
}
