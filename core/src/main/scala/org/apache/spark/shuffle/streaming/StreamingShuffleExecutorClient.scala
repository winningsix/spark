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
import java.util.concurrent.{ConcurrentHashMap, CopyOnWriteArrayList, RejectedExecutionException,
  ScheduledExecutorService, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicLong}

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import io.netty.buffer.{ByteBuf, CompositeByteBuf}
import io.netty.util.concurrent.{Future, GenericFutureListener}

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES, EXECUTOR_ID,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.buffer.{ManagedBuffer, NettyManagedBuffer}
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient, TransportClientFactory}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.{RpcHandler, StreamManager}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage, StreamingShuffleMessageType}
import org.apache.spark.util.ThreadUtils

/** Executor-scoped client that multiplexes logical reader/writer streams over pooled channels. */
private[streaming] class StreamingShuffleExecutorClient extends Logging {
  private case class Route(shuffleId: Int, writerId: Int, readerId: Int)
  private case class RouteGroup(route: Route, start: Int, end: Int)
  private case class ConnectionLane(
      shuffleId: Int,
      remoteHost: String,
      remotePort: Int)
  private case class Registration(
      handler: StreamingShuffleClientHandler,
      client: TransportClient,
      laneShared: Boolean)
  private case class InstalledRegistration(
      route: Route,
      registration: Registration,
      routeRegistrations: CopyOnWriteArrayList[Registration])
  private case class PendingCredit(
      handler: StreamingShuffleClientHandler,
      message: CreditControlMessage)

  // A shuffle partition can be consumed by more than one downstream stage. Those logical readers
  // intentionally share one pooled transport connection and therefore have the same wire route.
  // Keep every task-scoped handler so one incoming frame is fanned out locally; a single-handler
  // map loses the prefix for the later consumer and makes its sequence check start at N instead
  // of zero.
  private val registrations =
    new ConcurrentHashMap[Route, CopyOnWriteArrayList[Registration]]()
  // A pooled TransportClient can outlive one logical reader route and be handed back to a later
  // task after the earlier handler unregisters. The writer keys replay cursors by physical
  // client, so reusing that client for a new logical consumer would make the new reader appear to
  // have already consumed the old stream. Keep a route tombstone and use a fresh unmanaged
  // connection on every subsequent registration; only the first consumer gets pooled sharing.
  private val usedRoutes = ConcurrentHashMap.newKeySet[Route]()
  // Pool one physical connection per (remote executor, shuffle), rather than per remote executor.
  // A large sibling shuffle can otherwise fill the shared channel's FIFO and hold an earlier
  // stage's last data/termination frames behind seconds of unrelated traffic. The shuffle lane
  // keeps cross-route batching within one exchange while avoiding a connection per task/inbox.
  private val laneClients = new ConcurrentHashMap[ConnectionLane, TransportClient]()
  private val cumulativeCreditReleases = new AtomicLong(0L)
  private val cumulativeCreditWrites = new AtomicLong(0L)
  private val cumulativeCreditFrames = new AtomicLong(0L)
  private val creditRepairWrites = new AtomicLong(0L)
  private val closed = new AtomicBoolean(false)
  private val cumulativeCreditLock = new Object
  private val pendingCumulativeCredits = new java.util.IdentityHashMap[
    TransportClient, mutable.LinkedHashSet[StreamingShuffleClientHandler]]()
  private val scheduledCumulativeCreditClients = java.util.Collections.newSetFromMap(
    new java.util.IdentityHashMap[TransportClient, java.lang.Boolean]())

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

  private def decodeRoute(message: ByteBuf): Route = {
    val index = message.readerIndex()
    if (message.readableBytes() < 24) {
      throw new IllegalArgumentException(
        s"Streaming shuffle message is too short to route: ${message.readableBytes()} bytes")
    }
    val messageType = StreamingShuffleMessageType.decode(message.getInt(index))
    messageType match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW |
          StreamingShuffleMessageType.TERMINATION_CONTROL_MESSAGE =>
        Route(message.getInt(index + 12), message.getInt(index + 16), message.getInt(index + 20))
      case other =>
        throw new IllegalArgumentException(
          s"Unexpected message type in shared shuffle client: $other")
    }
  }

  private def registrationsFor(message: ByteBuffer, client: TransportClient): Seq[Registration] = {
    val route = decodeRoute(message)
    registrationsFor(route, client)
  }

  private def registrationsFor(message: ByteBuf, client: TransportClient): Seq[Registration] = {
    val route = decodeRoute(message)
    registrationsFor(route, client)
  }

  private def registrationsFor(route: Route, client: TransportClient): Seq[Registration] = {
    val routeRegistrations = registrations.get(route)
    if (routeRegistrations == null || routeRegistrations.isEmpty) {
      Seq.empty
    } else {
      // A duplicate logical consumer gets an unmanaged connection so its writer-side replay is
      // isolated from the first consumer. Pooled connections can still fan out one incoming body
      // to all handlers that share that exact connection.
      routeRegistrations.asScala.filter(_.client eq client).toSeq
    }
  }

  private def nextMessageLength(buf: ByteBuf): Int = {
    val index = buf.readerIndex()
    val readable = buf.readableBytes()
    if (readable < 12) {
      throw new IllegalArgumentException(
        s"Streaming shuffle message is too short: $readable bytes")
    }
    StreamingShuffleMessageType.decode(buf.getInt(index)) match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW =>
        val dataHeaderLength = 40
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

  /**
   * Routes a body containing complete frames, preserving contiguous frame batches for each
   * logical route. A normal one-route body therefore still reaches the reader in one call, while
   * a cross-route body is split with retained zero-copy slices.
   */
  private def receiveMultiplexedBody(
      client: TransportClient,
      body: ByteBuf,
      message: ManagedBuffer): Unit = {
    // Scan once to find contiguous route groups. The old mixed-route path first scanned the whole
    // body to decide whether it was single-route, then scanned it again while making slices. The
    // handler still performs the authoritative frame decode after routing, but the router no
    // longer pays for two indexed scans of every frame.
    val groups = new scala.collection.mutable.ArrayBuffer[RouteGroup]()
    val view = body.duplicate()
    var groupStart = view.readerIndex()
    var currentRoute: Route = null
    while (view.isReadable) {
      val frameStart = view.readerIndex()
      val route = decodeRoute(view)
      val messageLength = nextMessageLength(view)
      view.skipBytes(messageLength)
      if (currentRoute == null) {
        currentRoute = route
        groupStart = frameStart
      } else if (route != currentRoute) {
        groups += RouteGroup(currentRoute, groupStart, frameStart)
        currentRoute = route
        groupStart = frameStart
      }
    }
    if (currentRoute == null || view.readerIndex() <= groupStart) {
      throw new IllegalArgumentException("Streaming shuffle router made no progress")
    }
    groups += RouteGroup(currentRoute, groupStart, view.readerIndex())

    if (groups.length == 1) {
      val routeRegistrations = registrationsFor(groups.head.route, client)
      if (routeRegistrations.isEmpty) {
        logDebug("Dropping late streaming shuffle body for an inactive route")
      } else {
        routeRegistrations.foreach(_.handler.receiveMultiplexed(client, body, message))
      }
    } else {
      groups.foreach { group =>
        val frameGroup = body.retainedSlice(group.start, group.end - group.start)
        val routeBody = new NettyManagedBuffer(frameGroup)
        try {
          val routeRegistrations = registrationsFor(group.route, client)
          if (routeRegistrations.isEmpty) {
            // A task may unregister immediately after consuming termination while a coalesced body
            // is already in flight on the shared channel. The body is still owned by this method;
            // dropping that late frame is safe because no active reader can consume it.
            logDebug(
              s"Dropping late streaming shuffle body for inactive route " +
                s"shuffle=${group.route.shuffleId}, writer=${group.route.writerId}, " +
                s"reader=${group.route.readerId}")
          } else {
            routeRegistrations.foreach { registration =>
              registration.handler.receiveMultiplexed(client, frameGroup, routeBody)
            }
          }
        } finally {
          // Data messages retain routeBody until their queue consumer releases them; controls do
          // not retain it and are released here.
          routeBody.release()
        }
      }
    }
  }

  private val rpcHandler = new RpcHandler {
    override def receive(
        client: TransportClient,
        message: ByteBuffer,
        callback: RpcResponseCallback): Unit = {
        val routeRegistrations = registrationsFor(message, client)
        if (routeRegistrations.isEmpty) {
          logDebug("Dropping late streaming shuffle message for an inactive route")
        } else {
          routeRegistrations.foreach(_.handler.receive(client, message, callback))
        }
    }

    override def receive(client: TransportClient, message: ManagedBuffer): Unit = {
      // A body produced by the cross-route writer batcher can contain frames for several logical
      // readers. The router keeps one-route bodies zero-copy and only slices at route transitions.
      val body = message.convertToNetty().asInstanceOf[ByteBuf]
      try {
        receiveMultiplexedBody(client, body, message)
      } finally {
        body.release()
      }
    }

    override def channelInactive(client: TransportClient): Unit = {
      registrations.values().asScala.flatMap(_.asScala)
        .filter(_.client eq client)
        .foreach(_.handler.channelInactive(client))
    }

    override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
      registrations.values().asScala.flatMap(_.asScala)
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
  private val cumulativeCreditExecutor: ScheduledExecutorService =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor(
      "streaming-shuffle-cumulative-credit-flush")
  private val cumulativeCreditMaxWaitMs = math.max(1L,
    conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS))

  private def installRegistration(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      remoteHost: String,
      remotePort: Int,
      handler: StreamingShuffleClientHandler): InstalledRegistration = {
    val route = Route(shuffleId, writerId, readerId)
    // A second consumer of the same shuffle partition cannot share the pooled connection: the
    // writer may have already sent a prefix to the first consumer, while this consumer needs a
    // fresh sequence starting at zero. Give only duplicate routes an unmanaged connection; the
    // common one-consumer case keeps the pooled connection and its lower connection count.
    val (client, laneShared) = registrations.synchronized {
      val existing = registrations.get(route)
      if ((existing == null || existing.isEmpty) && usedRoutes.add(route)) {
        val lane = ConnectionLane(shuffleId, remoteHost, remotePort)
        (laneClients.computeIfAbsent(
          lane,
          _ => clientFactory.createUnmanagedClient(remoteHost, remotePort, rpcHandler)), true)
      } else {
        (clientFactory.createUnmanagedClient(remoteHost, remotePort, rpcHandler), false)
      }
    }
    val registration = Registration(handler, client, laneShared)
    handler.setMultiplexedCreditSender(scheduleCumulativeCredit)
    val routeRegistrations = registrations.computeIfAbsent(
      route, _ => new CopyOnWriteArrayList[Registration]())
    require(routeRegistrations.addIfAbsent(registration),
      s"Streaming shuffle route $route is already active for this handler")
    InstalledRegistration(route, registration, routeRegistrations)
  }

  private def removeInstalled(installed: InstalledRegistration): Unit = {
    discardPendingCumulativeCredit(installed.registration.handler)
    installed.registration.handler.clearMultiplexedCreditSender()
    installed.routeRegistrations.remove(installed.registration)
    if (installed.routeRegistrations.isEmpty) {
      registrations.remove(installed.route, installed.routeRegistrations)
    }
    if (!installed.registration.laneShared) installed.registration.client.close()
  }

  private def sendInitialCreditBatch(installed: Seq[InstalledRegistration]): Unit = {
    require(installed.nonEmpty, "Initial credit batch must not be empty")
    val client = installed.head.registration.client
    require(installed.forall(_.registration.client eq client),
      "Initial credit batch must use one physical client")
    var buf: CompositeByteBuf = null
    try {
      val messages = installed.zipWithIndex.map { case (entry, index) =>
        entry.registration.handler.prepareMultiplexedInitialCredit(
          client, configureSocket = index == 0)
      }
      val encodedBytes = messages.foldLeft(0)(_ + _.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(encodedBytes)
      messages.foreach(_.encode(buf))
      val handlers = installed.map(_.registration.handler)
      client.send(buf.retain()).addListener(
        new GenericFutureListener[Future[Void]] {
          override def operationComplete(future: Future[Void]): Unit = {
            if (!future.isSuccess) {
              val cause = Option(future.cause()).getOrElse(
                new RuntimeException("Unknown initial credit batch send failure"))
              handlers.foreach(_.initialCreditBatchSendFailed(cause))
            }
          }
        })
    } finally {
      if (buf != null) buf.release()
    }
  }

  /** Send a body containing the latest credit watermark for each selected logical route. */
  private def sendCreditBatch(
      credits: Seq[PendingCredit],
      client: TransportClient): Unit = {
    if (credits.isEmpty) return
    var buf: CompositeByteBuf = null
    try {
      val encodedBytes = credits.foldLeft(0)(_ + _.message.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(encodedBytes)
      credits.foreach(_.message.encode(buf))
      client.send(buf.retain()).addListener(
        new GenericFutureListener[Future[Void]] {
          override def operationComplete(future: Future[Void]): Unit = {
            if (!future.isSuccess) {
              val cause = Option(future.cause()).getOrElse(
                new RuntimeException("Unknown batched credit send failure"))
              credits.foreach(_.handler.creditBatchSendFailed(client, cause))
            }
          }
        })
    } catch {
      case error: Throwable => credits.foreach(_.handler.creditBatchSendFailed(client, error))
    } finally {
      if (buf != null) buf.release()
    }
  }

  /** Collapse hot frame releases to one cumulative watermark per route and physical lane. */
  private def scheduleCumulativeCredit(
      client: TransportClient,
      handler: StreamingShuffleClientHandler): Unit = {
    if (closed.get()) return
    cumulativeCreditReleases.incrementAndGet()
    val schedule = cumulativeCreditLock.synchronized {
      if (closed.get()) return
      var handlers = pendingCumulativeCredits.get(client)
      if (handlers == null) {
        handlers = new mutable.LinkedHashSet[StreamingShuffleClientHandler]()
        pendingCumulativeCredits.put(client, handlers)
      }
      handlers += handler
      scheduledCumulativeCreditClients.add(client)
    }
    if (schedule) {
      try {
        cumulativeCreditExecutor.schedule(
          new Runnable { override def run(): Unit = flushCumulativeCredits(client) },
          cumulativeCreditMaxWaitMs,
          TimeUnit.MILLISECONDS)
      } catch {
        case _: RejectedExecutionException if closed.get() =>
      }
    }
  }

  private def flushCumulativeCredits(client: TransportClient): Unit = {
    val handlers = cumulativeCreditLock.synchronized {
      scheduledCumulativeCreditClients.remove(client)
      Option(pendingCumulativeCredits.remove(client)).map(_.toSeq).getOrElse(Seq.empty)
    }
    val credits = handlers.flatMap { handler =>
      handler.prepareMultiplexedCreditRepair().map(PendingCredit(handler, _))
    }
    if (credits.nonEmpty) {
      cumulativeCreditWrites.incrementAndGet()
      cumulativeCreditFrames.addAndGet(credits.size)
      sendCreditBatch(credits, client)
    }
  }

  private def discardPendingCumulativeCredit(
      handler: StreamingShuffleClientHandler): Unit = cumulativeCreditLock.synchronized {
    val clients = pendingCumulativeCredits.keySet().iterator()
    val empty = new mutable.ArrayBuffer[TransportClient]()
    while (clients.hasNext) {
      val client = clients.next()
      val handlers = pendingCumulativeCredits.get(client)
      handlers -= handler
      if (handlers.isEmpty) empty += client
    }
    empty.foreach(pendingCumulativeCredits.remove)
  }

  /** Coalesce periodic liveness repairs by physical lane. */
  def repairCreditWindows(
      routes: Iterable[(TransportClient, StreamingShuffleClientHandler)]): Unit = {
    val byClient = new java.util.IdentityHashMap[
      TransportClient, mutable.ArrayBuffer[PendingCredit]]()
    routes.foreach { case (client, handler) =>
      val repairs = handler.prepareMultiplexedCreditRepair().toSeq ++
        handler.prepareMultiplexedReplayRepair().toSeq
      repairs.foreach { message =>
        var credits = byClient.get(client)
        if (credits == null) {
          credits = new mutable.ArrayBuffer[PendingCredit]()
          byClient.put(client, credits)
        }
        credits += PendingCredit(handler, message)
      }
    }
    byClient.entrySet().asScala.foreach { entry =>
      creditRepairWrites.incrementAndGet()
      sendCreditBatch(entry.getValue.toSeq, entry.getKey)
    }
  }

  /**
   * Register writer routes to one remote executor and coalesce their initial discovery credits.
   * Route state remains independent; only the physical transport write is shared.
   */
  def registerBatch(
      shuffleId: Int,
      readerId: Int,
      remoteHost: String,
      remotePort: Int,
      handlersByWriter: Seq[(Int, StreamingShuffleClientHandler)]): Map[Int, TransportClient] = {
    if (handlersByWriter.isEmpty) return Map.empty
    val installed = new scala.collection.mutable.ArrayBuffer[InstalledRegistration]()
    try {
      handlersByWriter.foreach { case (writerId, handler) =>
        installed += installRegistration(
          shuffleId, writerId, readerId, remoteHost, remotePort, handler)
      }
      // Duplicate logical consumers deliberately receive unmanaged clients. Grouping keeps the
      // common pooled lane as one body while retaining the isolation required by duplicate routes.
      installed.groupBy(_.registration.client).values.foreach { group =>
        sendInitialCreditBatch(group.toSeq)
      }
      installed.iterator.map { entry =>
        entry.route.writerId -> entry.registration.client
      }.toMap
    } catch {
      case t: Throwable =>
        installed.foreach(removeInstalled)
        throw t
    }
  }

  def register(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      remoteHost: String,
      remotePort: Int,
      handler: StreamingShuffleClientHandler): TransportClient = {
    registerBatch(
      shuffleId,
      readerId,
      remoteHost,
      remotePort,
      Seq(writerId -> handler))(writerId)
  }

  def unregister(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      handler: StreamingShuffleClientHandler): Unit = {
    val route = Route(shuffleId, writerId, readerId)
    val routeRegistrations = registrations.get(route)
    if (routeRegistrations != null) {
      routeRegistrations.asScala.find(_.handler eq handler).foreach { registration =>
        discardPendingCumulativeCredit(handler)
        handler.clearMultiplexedCreditSender()
        routeRegistrations.remove(registration)
        if (!registration.laneShared) registration.client.close()
      }
      if (routeRegistrations.isEmpty) {
        registrations.remove(route, routeRegistrations)
      }
    }
  }

  /** Release the executor-scoped physical lanes after Spark retires one shuffle. */
  def unregisterShuffle(shuffleId: Int): Unit = {
    registrations.entrySet().asScala.foreach { entry =>
      if (entry.getKey.shuffleId == shuffleId &&
          registrations.remove(entry.getKey, entry.getValue)) {
        entry.getValue.asScala.foreach { registration =>
          discardPendingCumulativeCredit(registration.handler)
          registration.handler.clearMultiplexedCreditSender()
        }
        entry.getValue.asScala.filterNot(_.laneShared).map(_.client).distinct.foreach(_.close())
        entry.getValue.clear()
      }
    }
    laneClients.entrySet().asScala.foreach { entry =>
      if (entry.getKey.shuffleId == shuffleId && laneClients.remove(entry.getKey, entry.getValue)) {
        entry.getValue.close()
      }
    }
    usedRoutes.removeIf(_.shuffleId == shuffleId)
  }

  private[streaming] def cumulativeCreditBatchStats: (Long, Long, Long, Long) =
    (cumulativeCreditReleases.get(), cumulativeCreditWrites.get(),
      cumulativeCreditFrames.get(), creditRepairWrites.get())

  def close(): Unit = {
    if (!closed.compareAndSet(false, true)) return
    logInfo(
      s"Closing executor streaming-shuffle client: " +
        s"cumulativeCreditReleases=${cumulativeCreditReleases.get()} " +
        s"cumulativeCreditWrites=${cumulativeCreditWrites.get()} " +
        s"cumulativeCreditFrames=${cumulativeCreditFrames.get()} " +
        s"creditRepairWrites=${creditRepairWrites.get()}")
    val activeRegistrations = registrations.values().asScala.flatMap(_.asScala).toSeq
    activeRegistrations.foreach { registration =>
      discardPendingCumulativeCredit(registration.handler)
      registration.handler.clearMultiplexedCreditSender()
    }
    cumulativeCreditExecutor.shutdownNow()
    cumulativeCreditLock.synchronized {
      pendingCumulativeCredits.clear()
      scheduledCumulativeCreditClients.clear()
    }
    activeRegistrations
      .filterNot(_.laneShared).map(_.client).toSeq.distinct.foreach(_.close())
    registrations.clear()
    laneClients.values().asScala.toSeq.distinct.foreach(_.close())
    laneClients.clear()
    clientFactory.close()
  }
}
