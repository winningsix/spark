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
import java.util.concurrent.ConcurrentHashMap

import io.netty.buffer.{ByteBuf, Unpooled}

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_ID, STREAMING_SHUFFLE_WRITER_SERVER_THREADS}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.{RpcHandler, StreamManager, TransportServer}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, StreamingShuffleMessage,
  TerminationAckMessage}

/** Executor-scoped transport listener that multiplexes reader control messages to map writers. */
private[streaming] class StreamingShuffleExecutorServer extends Logging {
  private val handlers = new ConcurrentHashMap[Long, StreamingShuffleServerHandler]()

  private def key(shuffleId: Int, writerId: Int): Long =
    (shuffleId.toLong << 32) | (writerId.toLong & 0xffffffffL)

  private val rpcHandler = new RpcHandler {
    override def receive(
        client: TransportClient,
        message: ByteBuffer,
        callback: RpcResponseCallback): Unit = {
      var buf: ByteBuf = null
      try {
        buf = Unpooled.wrappedBuffer(message)
        val decoded = StreamingShuffleMessage.decode(buf)
        val route = decoded match {
          case credit: CreditControlMessage => (credit.shuffleId, credit.shuffleWriterId)
          case ack: TerminationAckMessage => (ack.shuffleId, ack.shuffleWriterId)
          case other =>
            throw new IllegalArgumentException(
              s"Unexpected message type in shared shuffle server: ${other.messageType()}")
        }
        val handler = handlers.get(key(route._1, route._2))
        if (handler == null) {
          throw new IllegalStateException(
            s"No active streaming shuffle writer for shuffle ${route._1}, writer ${route._2}")
        }
        handler.handleMessage(client, decoded)
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
    conf.get(STREAMING_SHUFFLE_WRITER_SERVER_THREADS),
    role)
  private val transportContext = new TransportContext(transportConf, rpcHandler)
  private[streaming] val server: TransportServer = transportContext.createServer()

  val port: Int = server.getPort

  def register(
      shuffleId: Int,
      writerId: Int,
      handler: StreamingShuffleServerHandler): Unit = {
    val existing = handlers.putIfAbsent(key(shuffleId, writerId), handler)
    require(existing == null, s"Streaming shuffle $shuffleId writer $writerId is already active")
  }

  def unregister(
      shuffleId: Int,
      writerId: Int,
      handler: StreamingShuffleServerHandler): Unit = {
    handlers.remove(key(shuffleId, writerId), handler)
  }

  def close(): Unit = server.close()
}
