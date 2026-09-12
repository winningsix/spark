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
import java.util.concurrent.{CompletableFuture, ConcurrentHashMap, CopyOnWriteArrayList}
import java.util.concurrent.atomic.AtomicLong

import scala.jdk.CollectionConverters._

import io.netty.buffer.{ByteBuf, Unpooled}

import org.apache.spark.{SparkEnv, TaskContext}
import org.apache.spark.internal.config.STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED
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
    onClientConnected: (Int, TransportClient) => Unit = (_, _) => (),
    onCreditAvailable: (Int, TransportClient) => Unit = (_, _) => (),
    onReplayRequested: (Int, TransportClient, Long) => Unit = (_, _, _) => (),
    expectedClientsPerReader: Array[Int] = null)
    extends RpcHandler with TaskContextAwareLogging {

  private val expectedClientCounts: Array[Int] = {
    val counts = if (expectedClientsPerReader == null) {
      Array.fill(numReaders)(1)
    } else {
      require(expectedClientsPerReader.length == numReaders,
        s"Expected reader route count has ${expectedClientsPerReader.length} entries, " +
          s"but shuffle $shuffleId has $numReaders readers")
      expectedClientsPerReader.clone()
    }
    require(counts.forall(_ >= 0), "Expected reader route counts must be non-negative")
    counts
  }

  val futureClients: Array[CompletableFuture[TransportClient]] =
    Array.fill(numReaders)(new CompletableFuture[TransportClient]())
  // A relaxed writer may finish its Spark task before every reader task has been scheduled. Keep
  // the endpoint and replay history alive until each expected reader has registered at least one
  // route; otherwise all currently registered readers can ACK, cleanup can close the writer, and
  // a late reader will wait forever for the termination message that was sent before it connected.
  private val allReadersConnected = CompletableFuture.allOf(futureClients: _*)
  // Unlike allReadersConnected, this future includes every physical sibling route expected for
  // each reducer and is already complete for a reducer with no downstream task.
  private val expectedClientsConnected: Array[CompletableFuture[Void]] =
    Array.tabulate(numReaders) { readerId =>
      if (expectedClientCounts(readerId) == 0) {
        CompletableFuture.completedFuture(null.asInstanceOf[Void])
      } else if (expectedClientCounts(readerId) == 1) {
        futureClients(readerId).thenApply(_ => null.asInstanceOf[Void])
      } else {
        new CompletableFuture[Void]()
      }
    }
  private val allExpectedClientsConnected =
    CompletableFuture.allOf(expectedClientsConnected: _*)
  // A pipelined batch can have multiple downstream consumers for one partition.
  // Keep every connection so the writer can fan out the stream instead of
  // silently serving only the first reader that advertises credit.
  private val clientsByReader: Array[CopyOnWriteArrayList[TransportClient]] =
    Array.fill(numReaders)(new CopyOnWriteArrayList[TransportClient]())
  // A reader may close immediately after its termination ACK has been accepted. Keep the physical
  // client in this set so a TCP reset observed on the server side is not mistaken for a failed
  // producer and propagated through the pipelined group.
  private val terminationAckedClients = ConcurrentHashMap.newKeySet[TransportClient]()

  // Credit is tracked per logical reader route, even when several routes share one physical
  // TransportClient.  The old protocol used the integer in CreditControlMessage only as a
  // connection-discovery marker, which meant that shared channels could continue receiving data
  // for a sibling whose operator had stopped consuming.  A byte window gives the writer a
  // transport-level admission boundary without coupling the reader task scheduler to Netty's
  // channel-wide autoRead setting.
  private class RouteCreditState {
    val available = new AtomicLong(0L)
    val window = new AtomicLong(0L)
    val sent = new AtomicLong(0L)
    val released = new AtomicLong(0L)
  }
  private val creditByReaderAndClient =
    Array.fill(numReaders)(new ConcurrentHashMap[TransportClient, RouteCreditState]())
  private val creditFlowControlEnabled = Option(SparkEnv.get).forall { env =>
    env.conf.get(STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED)
  }

  private[streaming] def clientsFor(readerId: Int): Seq[TransportClient] = {
    clientsByReader(readerId).asScala.toSeq
  }

  private[streaming] def isCreditControlled(readerId: Int, client: TransportClient): Boolean = {
    creditFlowControlEnabled && creditState(readerId, client) != null
  }

  private[streaming] def allReadersConnectedFuture: CompletableFuture[Void] = {
    allReadersConnected
  }

  private[streaming] def allExpectedReadersConnectedFuture: CompletableFuture[Void] = {
    allExpectedClientsConnected
  }

  private[streaming] def expectedClientsFor(readerId: Int): Int = {
    expectedClientCounts(readerId)
  }

  private def creditState(readerId: Int, client: TransportClient): RouteCreditState = {
    creditByReaderAndClient(readerId).get(client)
  }

  private def enableCreditControl(
      readerId: Int,
      client: TransportClient): RouteCreditState = {
    creditByReaderAndClient(readerId).computeIfAbsent(client, _ => new RouteCreditState())
  }

  /** True when this logical route may admit a body of the supplied encoded size. */
  private[streaming] def hasDataCredit(
      readerId: Int,
      client: TransportClient,
      bytes: Long): Boolean = {
    val state = creditState(readerId, client)
    state == null || state.available.get() > 0
  }

  /** Current byte credit available to one logical route. */
  private[streaming] def availableDataCredit(
      readerId: Int,
      client: TransportClient): Long = {
    val state = creditState(readerId, client)
    if (state == null) Long.MaxValue else math.max(0L, state.available.get())
  }

  /** Reserve route credit immediately before a writer submits a body to Netty. */
  private[streaming] def consumeDataCredit(
      readerId: Int,
      client: TransportClient,
      bytes: Long): Unit = {
    val state = creditState(readerId, client)
    if (state != null && bytes > 0) {
      var done = false
      while (!done) {
        val current = state.available.get()
        if (current <= 0) {
          throw new IllegalStateException(
            s"Insufficient streaming shuffle credit for reader $readerId: " +
              s"available=$current requested=$bytes")
        }
        // A single encoded frame may be larger than the per-writer quota. Admit that one frame
        // so a small quota cannot deadlock the route; its reader-side release returns the exact
        // frame size before another frame is admitted.
        done = state.available.compareAndSet(current, math.max(0L, current - bytes))
      }
      state.sent.addAndGet(bytes)
    }
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
        val readerId = creditControlMessage.shuffleReaderId
        // A reader partition can have more than one logical consumer.  Every newly observed
        // physical client needs its own replay prefix; notifying only the first client leaves a
        // late sibling with an empty stream once the producer has already emitted its data.
        // addIfAbsent also makes repeated credit messages on the same connection idempotent.
        val encodedCredit = creditControlMessage.numMessages.toLong
        // A zero-credit watermark repairs byte admission. Int.MinValue is reserved for the
        // complementary sequence repair sent by an idle reader: local Netty submission can
        // advance the writer cursor even when a final frame never becomes reader-visible.
        if (creditControlMessage.numMessages == Int.MinValue) {
          onReplayRequested(readerId, client, creditControlMessage.getSeqNum)
          return
        }
        val enablesCreditFlow = creditFlowControlEnabled && encodedCredit < 0
        val credit = if (encodedCredit < 0) -encodedCredit else encodedCredit
        val state = if (enablesCreditFlow) {
          enableCreditControl(readerId, client)
        } else {
          creditState(readerId, client)
        }
        var grantedCredit = 0L
        var repairWakeup = false
        if (state != null && encodedCredit < 0 && credit > 0) {
          state.window.accumulateAndGet(credit, Math.max)
          // An initial absolute window is idempotent. Once data has been submitted, only the
          // cumulative released-byte watermark below may reopen the bounded route.
          if (state.sent.get() == 0L) {
            val before = state.available.get()
            val after = state.available.accumulateAndGet(credit, Math.max)
            grantedCredit = math.max(0L, after - before)
          }
        } else if (state != null && encodedCredit == 0) {
          // A repeated cumulative watermark is both an idempotent credit repair and a dispatcher
          // wakeup. Clamp it to bytes the writer actually submitted on this connection.
          repairWakeup = true
          val acknowledged = math.max(0L, math.min(
            creditControlMessage.getSeqNum, state.sent.get()))
          var previous = state.released.get()
          while (acknowledged > previous &&
              !state.released.compareAndSet(previous, acknowledged)) {
            previous = state.released.get()
          }
          val delta = math.max(0L, acknowledged - previous)
          if (delta > 0L) {
            val limit = state.window.get()
            state.available.updateAndGet(current =>
              math.min(limit, current + math.min(delta, limit)))
            grantedCredit = delta
          }
        } else if (state != null && credit > 0) {
          // Dedicated connections retain their historical additive-credit mode.
          val limit = state.window.get()
          val before = state.available.get()
          val after = if (limit > 0L) {
            state.available.updateAndGet(current => math.min(limit, current + credit))
          } else {
            state.available.addAndGet(credit)
          }
          grantedCredit = math.max(0L, after - before)
        }
        // Fence the route before publishing it in clientsByReader. Otherwise a concurrent writer
        // drain can observe the new client and broadcast a queued termination frame before the
        // writer's replayTo callback has installed its replay fence.
        val newConnectionForReader = clientsByReader(readerId).synchronized {
          if (clientsByReader(readerId).contains(client)) {
            false
          } else {
            onClientConnected(readerId, client)
            clientsByReader(readerId).add(client)
            if (clientsByReader(readerId).size >= expectedClientCounts(readerId)) {
              expectedClientsConnected(readerId).complete(null.asInstanceOf[Void])
            }
            true
          }
        }
        futureClients(readerId).complete(client)
        if (grantedCredit > 0L || repairWakeup) {
          onCreditAvailable(readerId, client)
        }
      case terminationAck: TerminationAckMessage =>
        // This is one message per map x reduce route (for example, Q3 emits more than 100k
        // acknowledgements on each host).  Logging every successful protocol frame at INFO
        // consumes a material fraction of executor CPU and serializes Netty event loops on the
        // log appender.  Failures remain ERRORs; routine per-route acknowledgements are DEBUG.
        logDebug(
          s"Received termination ack message from shuffle reader " +
            s"${terminationAck.shuffleReaderId}"
        )
        onTerminationAckReceived(terminationAck.shuffleReaderId, terminationAck.getSeqNum)
        onTerminationAckReceivedWithClient(
          terminationAck.shuffleReaderId, terminationAck.getSeqNum, client)
        terminationAckedClients.add(client)
      case _ =>
        throw new IllegalArgumentException(
          s"Unexpected message type in ShuffleServerHandler: " +
            s"${shuffleMessage.messageType()}"
        )
    }
  }

  override def exceptionCaught(cause: Throwable, client: TransportClient): Unit = {
    if (isConnectionClose(cause) &&
        (terminationAckedClients.contains(client) || context.isInterrupted() ||
          context.isFailed() || context.isCompleted())) {
      logDebug(log"Ignoring expected streaming shuffle connection close.", cause)
    } else {
      logError(log"Streaming shuffle server handler caught exception.", cause)
      errorNotifier.markError(cause)
    }
  }

  private def isConnectionClose(cause: Throwable): Boolean = {
    val className = cause.getClass.getName
    val message = Option(cause.getMessage).getOrElse("").toLowerCase(java.util.Locale.ROOT)
    className.contains("ClosedChannel") ||
      message.contains("broken pipe") ||
      message.contains("connection reset") ||
      Option(cause.getCause).exists(isConnectionClose)
  }

  // not needed for streaming shuffle
  // cannot throw UnsupportedException because this function will be called
  // even if this feature is not used.
  override def getStreamManager: StreamManager = null
}
