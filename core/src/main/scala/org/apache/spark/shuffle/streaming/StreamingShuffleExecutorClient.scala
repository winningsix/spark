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
  ScheduledExecutorService, TimeoutException, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicLong}

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import io.netty.buffer.{ByteBuf, CompositeByteBuf}
import io.netty.util.concurrent.{Future, GenericFutureListener}

import org.apache.spark.{SparkContext, SparkEnv}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES, EXECUTOR_ID,
  STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS,
  STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.buffer.{ManagedBuffer, NettyManagedBuffer}
import org.apache.spark.network.client.{RpcResponseCallback, TransportClient, TransportClientFactory}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.{RpcHandler, StreamManager}
import org.apache.spark.network.shuffle.streaming.{CreditControlMessage,
  StreamingShuffleMessageType, TerminationAckMessage}
import org.apache.spark.util.ThreadUtils

private[streaming] object StreamingShuffleExecutorClient {
  private case class PendingInitialCredit(
      request: AnyRef,
      owner: StreamingShuffleExecutorClient,
      client: TransportClient,
      handler: StreamingShuffleClientHandler,
      claim: () => Boolean,
      rollback: () => Unit)
  private case class InitialCredit(
      client: TransportClient,
      handler: StreamingShuffleClientHandler,
      claim: () => Boolean,
      rollback: () => Unit)

  private class InitialCreditBatchScope {
    val pending = new mutable.ArrayBuffer[PendingInitialCredit]()
    var currentRequest: AnyRef = _
  }

  private val currentInitialCreditBatch = new ThreadLocal[InitialCreditBatchScope]()

  private def rollback(entries: Seq[PendingInitialCredit], cause: Throwable): Unit = {
    entries.foreach { entry =>
      try entry.rollback()
      catch {
        case rollbackError: Throwable => cause.addSuppressed(rollbackError)
      }
    }
  }

  /**
   * Execute several independent prepared-route registrations on one worker and defer their
   * initial discovery credits until every request has installed its handlers. Credits that share
   * one physical client are then emitted as one transport body. A request that fails before the
   * flush loses only its own deferred routes; a failed physical write fails and rolls back only
   * the requests carried by that client.
   */
  private[streaming] def runBatchedRouteRegistrations(
      requests: Seq[(AnyRef, () => Unit)]): Map[AnyRef, Throwable] = {
    require(currentInitialCreditBatch.get() == null,
      "Nested streaming shuffle initial-credit batches are not supported")
    val scope = new InitialCreditBatchScope
    val failures = new mutable.LinkedHashMap[AnyRef, Throwable]()
    currentInitialCreditBatch.set(scope)
    try {
      requests.foreach { case (request, registration) =>
        scope.currentRequest = request
        try registration()
        catch {
          case error: Throwable =>
            val requestEntries = scope.pending.filter(_.request eq request).toSeq
            rollback(requestEntries, error)
            scope.pending --= requestEntries
            failures.put(request, error)
        }
      }
    } finally {
      scope.currentRequest = null
      currentInitialCreditBatch.remove()
    }

    scope.pending.filter(_.claim()).groupBy { entry =>
      (entry.owner, entry.client)
    }.values.foreach { entries =>
      try {
        entries.head.owner.sendAndAwaitInitialCreditBatch(
          entries.map(_.handler).toSeq, entries.head.client)
      } catch {
        case error: Throwable =>
          rollback(entries.toSeq, error)
          entries.foreach(entry => failures.getOrElseUpdate(entry.request, error))
      }
    }
    failures.toMap
  }

  private def submitInitialCredits(
      owner: StreamingShuffleExecutorClient,
      entries: Seq[InitialCredit]): Unit = {
    val scope = currentInitialCreditBatch.get()
    if (scope == null) {
      entries.filter(_.claim()).groupBy(_.client).values.foreach { clientEntries =>
        owner.sendInitialCreditBatch(
          clientEntries.map(_.handler).toSeq, clientEntries.head.client)
      }
    } else {
      require(scope.currentRequest != null,
        "Streaming shuffle initial credits have no owning route request")
      entries.foreach { entry =>
        scope.pending += PendingInitialCredit(
          scope.currentRequest,
          owner,
          entry.client,
          entry.handler,
          entry.claim,
          entry.rollback)
      }
    }
  }
}

/** Executor-scoped client that multiplexes logical reader/writer streams over pooled channels. */
private[streaming] class StreamingShuffleExecutorClient extends Logging {
  private case class Route(shuffleId: Int, writerId: Int, readerId: Int)
  private case class RouteGroup(route: Route, start: Int, end: Int)
  private case class ConnectionLane(
      shuffleId: Int,
      remoteHost: String,
      remotePort: Int,
      consumerGeneration: Int)
  private case class Registration(
      handler: StreamingShuffleClientHandler,
      client: TransportClient,
      laneShared: Boolean,
      initialCreditPending: AtomicBoolean)
  private case class InstalledRegistration(
      route: Route,
      registration: Registration,
      routeRegistrations: CopyOnWriteArrayList[Registration])
  private case class PendingCreditRepair(
      handler: StreamingShuffleClientHandler,
      message: CreditControlMessage)
  private case class PendingTerminationAck(
      handler: StreamingShuffleClientHandler,
      writerId: Int,
      sequenceNumber: Long)

  // A shuffle partition can be consumed by more than one downstream stage. Those logical readers
  // intentionally share one pooled transport connection and therefore have the same wire route.
  // Keep every task-scoped handler so one incoming frame is fanned out locally; a single-handler
  // map loses the prefix for the later consumer and makes its sequence check start at N instead
  // of zero.
  private val registrations =
    new ConcurrentHashMap[Route, CopyOnWriteArrayList[Registration]]()
  // A TransportClient is also the writer's replay-cursor identity. Reusing the same client for a
  // later lifetime of one route would make the new consumer appear to have already consumed the
  // stream. Assign successive registrations of each route to successive connection generations.
  // Routes in the same consumer wave normally have the same generation and can still share one
  // physical lane; this avoids opening one unmanaged connection per writer x reader route.
  private val routeConsumerGenerations =
    new ConcurrentHashMap[Route, AtomicInteger]()
  // Pool one physical connection per (remote executor, shuffle, consumer generation), rather
  // than per logical route. The generation preserves replay isolation for repeated consumers,
  // while the shuffle dimension prevents a large sibling exchange from blocking an earlier
  // stage's terminal frames behind unrelated traffic.
  private val laneClients = new ConcurrentHashMap[ConnectionLane, TransportClient]()
  private val initialCreditRegistrations = new AtomicLong(0L)
  private val initialCreditWrites = new AtomicLong(0L)
  private val creditRepairWrites = new AtomicLong(0L)
  private val cumulativeCreditReleases = new AtomicLong(0L)
  private val cumulativeCreditWrites = new AtomicLong(0L)
  private val cumulativeCreditFrames = new AtomicLong(0L)
  private val terminationAckFrames = new AtomicLong(0L)
  private val terminationAckWrites = new AtomicLong(0L)
  private val closed = new AtomicBoolean(false)
  private val currentTerminationAckBatch = new ThreadLocal[
    mutable.LinkedHashMap[
      StreamingShuffleClientHandler,
      (TransportClient, PendingTerminationAck)]]()
  private val cumulativeCreditLock = new Object
  private val pendingCumulativeCredits = new java.util.IdentityHashMap[
    TransportClient, mutable.LinkedHashSet[StreamingShuffleClientHandler]]()
  private val scheduledCumulativeCreditClients = java.util.Collections.newSetFromMap(
    new java.util.IdentityHashMap[TransportClient, java.lang.Boolean]())
  private val cumulativeCreditExecutor: ScheduledExecutorService =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor(
      "streaming-shuffle-cumulative-credit-flush")
  private val cumulativeCreditMaxWaitMs = math.max(1L,
    SparkEnv.get.conf.get(STREAMING_SHUFFLE_CROSS_ROUTE_BATCH_MAX_WAIT_TIME_MS))

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
        withTerminationAckBatch {
          receiveMultiplexedBody(client, body, message)
        }
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
  private val routeRegistrationTimeoutMs =
    conf.get(STREAMING_SHUFFLE_PREPARED_ROUTE_REGISTRATION_TIMEOUT)
  private val initialCreditWriteTimeoutMs = Option(clientConf.connectionTimeoutMs().toLong)
    .filter(_ > 0L)
    .map(math.min(_, routeRegistrationTimeoutMs))
    .getOrElse(routeRegistrationTimeoutMs)
  private val transportContext = new TransportContext(clientConf, rpcHandler, true, true)
  private val clientFactory: TransportClientFactory = transportContext.createClientFactory()

  private def installRegistration(
      shuffleId: Int,
      writerId: Int,
      readerId: Int,
      remoteHost: String,
      remotePort: Int,
      handler: StreamingShuffleClientHandler): InstalledRegistration = {
    val route = Route(shuffleId, writerId, readerId)
    // The writer keys replay state by TransportClient, so every lifetime of the same route needs
    // a distinct client. Pool that client with other routes at the same lifetime generation
    // instead of creating one unmanaged connection for each route. Atomic generation assignment
    // also permits prepared inbox registrations to run in parallel without an executor-wide lock.
    val consumerGeneration = routeConsumerGenerations
      .computeIfAbsent(route, _ => new AtomicInteger(0))
      .getAndIncrement()
    if (consumerGeneration > 0) {
      val active = Option(registrations.get(route)).map(_.size()).getOrElse(0)
      logDebug(
        s"Registering consumer generation $consumerGeneration for streaming shuffle route " +
          s"$route: activeRegistrations=$active")
    }
    val lane = ConnectionLane(shuffleId, remoteHost, remotePort, consumerGeneration)
    val client = laneClients.computeIfAbsent(
      lane,
      _ => clientFactory.createUnmanagedClient(remoteHost, remotePort, rpcHandler))
    val laneShared = true
    val registration = Registration(handler, client, laneShared, new AtomicBoolean(true))
    handler.setMultiplexedCreditSender(scheduleCumulativeCredit)
    handler.setMultiplexedTerminationAckSender(scheduleTerminationAck)
    val routeRegistrations = registrations.computeIfAbsent(
      route, _ => new CopyOnWriteArrayList[Registration]())
    require(routeRegistrations.addIfAbsent(registration),
      s"Streaming shuffle route $route is already active for this handler")
    InstalledRegistration(route, registration, routeRegistrations)
  }

  private def removeInstalled(installed: InstalledRegistration): Unit = {
    installed.registration.initialCreditPending.set(false)
    discardPendingCumulativeCredit(installed.registration.handler)
    installed.registration.handler.clearMultiplexedCreditSender()
    installed.registration.handler.clearMultiplexedTerminationAckSender()
    installed.registration.handler.closeReceiveCreditLease()
    installed.routeRegistrations.remove(installed.registration)
    if (installed.routeRegistrations.isEmpty) {
      registrations.remove(installed.route, installed.routeRegistrations)
    }
    if (!installed.registration.laneShared) installed.registration.client.close()
  }

  private def sendInitialCreditBatch(
      handlers: Seq[StreamingShuffleClientHandler],
      client: TransportClient): Future[Void] = {
    require(handlers.nonEmpty, "Initial credit batch must not be empty")
    initialCreditWrites.incrementAndGet()
    var buf: CompositeByteBuf = null
    try {
      val messages = handlers.zipWithIndex.map { case (handler, index) =>
        handler.prepareMultiplexedInitialCredit(client, configureSocket = index == 0)
      }
      val encodedBytes = messages.foldLeft(0)(_ + _.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(encodedBytes)
      messages.foreach(_.encode(buf))
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

  /** Send one control body containing every due repair frame for a physical lane. */
  private def sendCreditRepairBatch(
      repairs: Seq[PendingCreditRepair],
      client: TransportClient): Unit = {
    require(repairs.nonEmpty, "Credit repair batch must not be empty")
    creditRepairWrites.incrementAndGet()
    sendCreditBatch(repairs, client)
  }

  private def sendCumulativeCreditBatch(
      repairs: Seq[PendingCreditRepair],
      client: TransportClient): Unit = {
    if (repairs.isEmpty) return
    cumulativeCreditWrites.incrementAndGet()
    cumulativeCreditFrames.addAndGet(repairs.size)
    sendCreditBatch(repairs, client)
  }

  private def sendCreditBatch(
      repairs: Seq[PendingCreditRepair],
      client: TransportClient): Unit = {
    var buf: CompositeByteBuf = null
    try {
      val encodedBytes = repairs.foldLeft(0)(_ + _.message.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(encodedBytes)
      repairs.foreach(_.message.encode(buf))
      client.send(buf.retain()).addListener(
        new GenericFutureListener[Future[Void]] {
          override def operationComplete(future: Future[Void]): Unit = {
            if (!future.isSuccess) {
              val cause = Option(future.cause()).getOrElse(
                new RuntimeException("Unknown credit repair batch send failure"))
              repairs.foreach(_.handler.creditRepairBatchSendFailed(client, cause))
            }
          }
        })
    } catch {
      case error: Throwable =>
        repairs.foreach(_.handler.creditRepairBatchSendFailed(client, error))
    } finally {
      if (buf != null) buf.release()
    }
  }

  /** Combine terminal ACKs produced while routing one physical inbound body. */
  private def withTerminationAckBatch(body: => Unit): Unit = {
    require(currentTerminationAckBatch.get() == null,
      "Nested streaming shuffle termination-ACK batches are not supported")
    val pending = new mutable.LinkedHashMap[
      StreamingShuffleClientHandler, (TransportClient, PendingTerminationAck)]()
    currentTerminationAckBatch.set(pending)
    try body
    finally {
      currentTerminationAckBatch.remove()
      pending.values.toSeq.groupBy(_._1).foreach { case (client, entries) =>
        sendTerminationAckBatch(client, entries.map(_._2))
      }
    }
  }

  private def scheduleTerminationAck(
      client: TransportClient,
      handler: StreamingShuffleClientHandler,
      writerId: Int,
      sequenceNumber: Long): Unit = {
    val ack = PendingTerminationAck(handler, writerId, sequenceNumber)
    val pending = currentTerminationAckBatch.get()
    if (pending == null) {
      sendTerminationAckBatch(client, Seq(ack))
    } else {
      // A duplicate terminal in the same physical body needs only one idempotent ACK.
      pending.update(handler, client -> ack)
    }
  }

  private def sendTerminationAckBatch(
      client: TransportClient,
      entries: Seq[PendingTerminationAck]): Unit = {
    if (entries.isEmpty) return
    terminationAckWrites.incrementAndGet()
    terminationAckFrames.addAndGet(entries.size)
    var buf: CompositeByteBuf = null
    try {
      val messages: Seq[(PendingTerminationAck, TerminationAckMessage)] = entries.map { entry =>
        entry -> entry.handler.prepareMultiplexedTerminationAck(
          entry.writerId, entry.sequenceNumber)
      }
      val encodedBytes = messages.foldLeft(0)(_ + _._2.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(encodedBytes)
      messages.foreach(_._2.encode(buf))
      val transportRef = buf.retain()
      val sendFuture = try {
        client.send(transportRef)
      } catch {
        case error: Throwable =>
          transportRef.release()
          throw error
      }
      sendFuture.addListener(
        new GenericFutureListener[Future[Void]] {
          override def operationComplete(future: Future[Void]): Unit = {
            if (future.isSuccess) {
              entries.foreach { entry =>
                entry.handler.terminationAckBatchSendSucceeded(entry.writerId)
              }
            } else {
              val cause = Option(future.cause()).getOrElse(
                new RuntimeException("Unknown termination ACK batch send failure"))
              entries.foreach { entry =>
                entry.handler.terminationAckBatchSendFailed(client, entry.writerId, cause)
              }
            }
          }
        })
    } catch {
      case error: Throwable =>
        entries.foreach { entry =>
          entry.handler.terminationAckBatchSendFailed(client, entry.writerId, error)
        }
    } finally {
      if (buf != null) buf.release()
    }
  }

  /**
   * Coalesce hot-path cumulative credit updates by physical lane.
   *
   * Q3 moves roughly 42 GiB in 32 KiB data frames. Sending one 28-byte Spark transport body for
   * every released frame creates about a million control writes and can leave the terminal ACK
   * behind that FIFO. Each control frame carries an absolute released-byte watermark, so keeping
   * only the latest handler entry during this short window is lossless and bounded by the number
   * of active logical routes, not by the number of data frames.
   */
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
          new Runnable {
            override def run(): Unit = flushCumulativeCredits(client)
          },
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
    val repairs = handlers.flatMap { handler =>
      handler.prepareMultiplexedCreditRepair().map(PendingCreditRepair(handler, _))
    }
    sendCumulativeCreditBatch(repairs, client)
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

  /** Coalesce idempotent route repairs by physical connection. */
  def repairCreditWindows(
      routes: Iterable[(TransportClient, StreamingShuffleClientHandler)]): Unit = {
    val byClient = new java.util.IdentityHashMap[
      TransportClient, mutable.ArrayBuffer[PendingCreditRepair]]()
    routes.foreach { case (client, handler) =>
      handler.prepareMultiplexedCreditRepair().foreach { message =>
        var repairs = byClient.get(client)
        if (repairs == null) {
          repairs = new mutable.ArrayBuffer[PendingCreditRepair]()
          byClient.put(client, repairs)
        }
        repairs += PendingCreditRepair(handler, message)
      }
    }
    byClient.entrySet().asScala.foreach { entry =>
      sendCreditRepairBatch(entry.getValue.toSeq, entry.getKey)
    }
  }

  /**
   * A completed prepared-route future means the discovery frame reached Netty, not just its FIFO.
   */
  private def sendAndAwaitInitialCreditBatch(
      handlers: Seq[StreamingShuffleClientHandler],
      client: TransportClient): Unit = {
    val write = sendInitialCreditBatch(handlers, client)
    try {
      if (!write.await(initialCreditWriteTimeoutMs, TimeUnit.MILLISECONDS)) {
        val timeout = new TimeoutException(
          s"Streaming shuffle initial credit batch did not flush within " +
            s"$initialCreditWriteTimeoutMs ms")
        handlers.foreach(_.initialCreditBatchSendFailed(timeout))
        throw timeout
      }
    } catch {
      case interrupted: InterruptedException =>
        Thread.currentThread().interrupt()
        handlers.foreach(_.initialCreditBatchSendFailed(interrupted))
        throw interrupted
    }
    if (!write.isSuccess) {
      throw Option(write.cause()).getOrElse(
        new RuntimeException("Unknown initial credit batch send failure"))
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
      initialCreditRegistrations.addAndGet(installed.size)
      StreamingShuffleExecutorClient.submitInitialCredits(this, installed.map { entry =>
        StreamingShuffleExecutorClient.InitialCredit(
          entry.registration.client,
          entry.registration.handler,
          () => entry.registration.initialCreditPending.compareAndSet(true, false),
          () => removeInstalled(entry))
      }.toSeq)
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
        registration.initialCreditPending.set(false)
        discardPendingCumulativeCredit(handler)
        handler.clearMultiplexedCreditSender()
        handler.clearMultiplexedTerminationAckSender()
        handler.closeReceiveCreditLease()
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
        entry.getValue.asScala.foreach(_.initialCreditPending.set(false))
        entry.getValue.asScala.foreach { registration =>
          discardPendingCumulativeCredit(registration.handler)
          registration.handler.clearMultiplexedCreditSender()
          registration.handler.clearMultiplexedTerminationAckSender()
          registration.handler.closeReceiveCreditLease()
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
    routeConsumerGenerations.keySet().removeIf(_.shuffleId == shuffleId)
  }

  private[streaming] def initialCreditBatchStats: (Long, Long) =
    (initialCreditRegistrations.get(), initialCreditWrites.get())

  private[streaming] def creditRepairBatchWriteCount: Long = creditRepairWrites.get()

  private[streaming] def cumulativeCreditBatchStats: (Long, Long, Long) =
    (cumulativeCreditReleases.get(), cumulativeCreditWrites.get(), cumulativeCreditFrames.get())

  private[streaming] def terminationAckBatchStats: (Long, Long) =
    (terminationAckWrites.get(), terminationAckFrames.get())

  def close(): Unit = {
    if (!closed.compareAndSet(false, true)) return
    val (creditRegistrations, creditWrites) = initialCreditBatchStats
    logInfo(
      s"Closing executor streaming-shuffle client: " +
      s"initialCreditRegistrations=$creditRegistrations " +
      s"initialCreditWrites=$creditWrites " +
      s"creditRepairWrites=${creditRepairWrites.get()} " +
      s"cumulativeCreditReleases=${cumulativeCreditReleases.get()} " +
      s"cumulativeCreditWrites=${cumulativeCreditWrites.get()} " +
      s"cumulativeCreditFrames=${cumulativeCreditFrames.get()} " +
      s"terminationAckWrites=${terminationAckWrites.get()} " +
      s"terminationAckFrames=${terminationAckFrames.get()}")
    val activeRegistrations = registrations.values().asScala.flatMap(_.asScala).toSeq
    activeRegistrations.foreach(_.initialCreditPending.set(false))
    activeRegistrations.foreach { registration =>
      discardPendingCumulativeCredit(registration.handler)
      registration.handler.clearMultiplexedCreditSender()
      registration.handler.clearMultiplexedTerminationAckSender()
    }
    cumulativeCreditExecutor.shutdownNow()
    cumulativeCreditLock.synchronized {
      pendingCumulativeCredits.clear()
      scheduledCumulativeCreditClients.clear()
    }
    activeRegistrations.filterNot(_.laneShared).map(_.client).distinct.foreach(_.close())
    registrations.clear()
    laneClients.values().asScala.toSeq.distinct.foreach(_.close())
    laneClients.clear()
    clientFactory.close()
  }
}
