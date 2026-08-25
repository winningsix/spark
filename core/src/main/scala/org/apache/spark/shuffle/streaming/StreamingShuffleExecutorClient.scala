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

import scala.jdk.CollectionConverters._

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES, EXECUTOR_ID}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.buffer.ManagedBuffer
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient, TransportClientFactory}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.{RpcHandler, StreamManager}
import org.apache.spark.network.shuffle.streaming.StreamingShuffleMessageType

/** Executor-scoped client that multiplexes logical reader/writer streams over pooled channels. */
private[streaming] class StreamingShuffleExecutorClient extends Logging {
  private case class Route(shuffleId: Int, writerId: Int, readerId: Int)
  private case class Registration(handler: StreamingShuffleClientHandler, client: TransportClient)

  private val registrations = new ConcurrentHashMap[Route, Registration]()

  private def decodeRoute(message: ByteBuffer): Route = {
    // Both routed writer-to-reader message types start with the same fixed layout:
    // type (4), sequence number (8), shuffle ID (4), writer ID (4), reader ID (4).
    // Read those fields in place instead of fully decoding and retaining the payload here; the
    // target reader handler performs the one authoritative decode after routing.
    val base = message.position()
    if (message.remaining() < 24) {
      throw new IllegalArgumentException(
        s"Streaming shuffle message is too short to route: ${message.remaining()} bytes")
    }
    val messageType = StreamingShuffleMessageType.decode(message.getInt(base))
    messageType match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW |
          StreamingShuffleMessageType.TERMINATION_CONTROL_MESSAGE =>
        Route(message.getInt(base + 12), message.getInt(base + 16), message.getInt(base + 20))
      case other =>
        throw new IllegalArgumentException(
          s"Unexpected message type in shared shuffle client: $other")
    }
  }

  private def registrationFor(message: ByteBuffer): Registration = {
    val route = decodeRoute(message)
    val registration = registrations.get(route)
    if (registration == null) {
      throw new IllegalStateException(
        s"No active streaming shuffle reader for shuffle ${route.shuffleId}, " +
          s"writer ${route.writerId}, reader ${route.readerId}")
    }
    registration
  }

  private val rpcHandler = new RpcHandler {
    override def receive(
        client: TransportClient,
        message: ByteBuffer,
        callback: RpcResponseCallback): Unit = {
      registrationFor(message).handler.receive(client, message, callback)
    }

    override def receive(client: TransportClient, message: ManagedBuffer): Unit = {
      val byteBuffer = message.nioByteBuffer()
      registrationFor(byteBuffer).handler.receiveMultiplexed(client, byteBuffer, message)
    }

    override def channelInactive(client: TransportClient): Unit = {
      registrations.values().asScala
        .filter(_.client eq client)
        .foreach(_.handler.channelInactive(client))
    }

    override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
      registrations.values().asScala
        .filter(_.client eq client)
        .foreach(_.handler.exceptionCaught(cause, client))
    }

    override def getStreamManager: StreamManager = null
  }

  private val conf = SparkEnv.get.conf
  private val role = conf.get(EXECUTOR_ID).map { id =>
    if (SparkContext.isDriver(id)) "driver" else "executor"
  }
  private val clientConf = SparkTransportConf.fromSparkConf(
    conf, "streaming-shuffle-reader-multiplexed", math.max(1, conf.get(EXECUTOR_CORES)), role)
  private val transportContext = new TransportContext(clientConf, rpcHandler, true, true)
  private val clientFactory: TransportClientFactory = transportContext.createClientFactory()

  def register(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      remoteHost: String,
      remotePort: Int,
      handler: StreamingShuffleClientHandler): TransportClient = {
    val route = Route(shuffleId, writerId, readerId)
    val client = clientFactory.createClient(remoteHost, remotePort)
    val registration = Registration(handler, client)
    val existing = registrations.putIfAbsent(route, registration)
    require(existing == null, s"Streaming shuffle route $route is already active")
    try {
      // Transport invokes channelActive once per physical connection. Each logical stream also
      // needs its own discovery credit, so activate its task handler explicitly after routing is
      // installed.
      handler.useMultiplexedChannel()
      handler.channelActive(client)
      client
    } catch {
      case t: Throwable =>
        registrations.remove(route, registration)
        throw t
    }
  }

  def unregister(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      handler: StreamingShuffleClientHandler): Unit = {
    val route = Route(shuffleId, writerId, readerId)
    val registration = registrations.get(route)
    if (registration != null && (registration.handler eq handler)) {
      registrations.remove(route, registration)
    }
  }

  def close(): Unit = {
    registrations.clear()
    clientFactory.close()
  }
}
