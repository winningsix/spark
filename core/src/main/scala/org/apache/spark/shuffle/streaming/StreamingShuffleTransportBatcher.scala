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

import java.util.concurrent.{ScheduledExecutorService, ScheduledFuture, TimeUnit}

import scala.collection.mutable

import io.netty.buffer.{ByteBuf, ByteBufAllocator, CompositeByteBuf}
import io.netty.channel.ChannelFuture

import org.apache.spark.network.client.TransportClient
import org.apache.spark.util.{ErrorNotifier, ThreadUtils}

/**
 * Batches already-framed shuffle bodies sent to the same physical peer connection.
 *
 * Each input body contains complete streaming-shuffle frames and ownership is transferred to this
 * class.  A batch is only released by the transport completion callback (or by discard()), so
 * this class does not add a second copy or change the per-route sequence numbers.
 */
private[streaming] final class StreamingShuffleTransportBatcher(
    allocator: ByteBufAllocator,
    maxBytes: Int,
    maxWaitTimeMs: Long,
    maxInFlightBytes: Long,
    errorNotifier: ErrorNotifier) {

  /** Compatibility constructor for focused tests and low-level callers. */
  def this(
      allocator: ByteBufAllocator,
      maxBytes: Int,
      maxWaitTimeMs: Long,
      errorNotifier: ErrorNotifier) = {
    this(allocator, maxBytes, maxWaitTimeMs, maxBytes.toLong, errorNotifier)
  }

  require(maxBytes > 0, "maxBytes must be positive")
  require(maxWaitTimeMs >= 0, "maxWaitTimeMs must be non-negative")
  require(maxInFlightBytes >= maxBytes,
    "maxInFlightBytes must be at least maxBytes so one transport batch can be admitted")

  // A reservation remains held until TransportClient's completion callback, not merely until the
  // body is handed to Netty, because the latter can still retain the direct payload in the
  // channel's outbound queue. Admission must not block the executor's shared outbound dispatcher:
  // a connection whose socket is full would otherwise park every dispatcher thread and prevent
  // unrelated connections with ready readers from sending data or end-of-stream controls.
  private val inFlightBytes = new java.util.concurrent.atomic.AtomicLong(0L)
  private val peakInFlightBytes = new java.util.concurrent.atomic.AtomicLong(0L)

  private case class PendingBody(
      body: ByteBuf,
      onComplete: () => Unit,
      owner: AnyRef,
      bodyErrorNotifier: ErrorNotifier)
  private case class PendingBatch(bodies: mutable.ArrayBuffer[PendingBody], var bytes: Int)

  // TransportClient uses object identity for its channel state. IdentityHashMap avoids ever
  // merging two wrappers that happen to compare equal in a future implementation.
  private val pending = new java.util.IdentityHashMap[TransportClient, PendingBatch]()
  // Batches that are complete but waiting for executor-global transport admission. Keep a FIFO
  // per physical connection to preserve the sequence order in which logical route bodies were
  // submitted, and rotate connections globally so one backlogged peer cannot monopolize each
  // newly released byte window.
  private val awaitingAdmission =
    new java.util.IdentityHashMap[TransportClient, java.util.ArrayDeque[PendingBatch]]()
  private val admissionReadyClients = new java.util.ArrayDeque[TransportClient]()
  private val admissionReadySet =
    java.util.Collections.newSetFromMap(
      new java.util.IdentityHashMap[TransportClient, java.lang.Boolean]())
  private val scheduledFlushes =
    new java.util.IdentityHashMap[TransportClient, ScheduledFuture[_]]()
  private val flushExecutor: ScheduledExecutorService =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor("streaming-shuffle-cross-route-flush")
  private var admissionDrainScheduled = false
  private var closed = false

  private def tryAcquire(bytes: Int): Boolean = {
    val requested = bytes.toLong
    var acquired = false
    while (!acquired) {
      val current = inFlightBytes.get()
      // Admit an oversized body only into an empty window. A single encoded record can be larger
      // than maxBytes/maxInFlightBytes and must still make progress without silently weakening the
      // bound for concurrent batches.
      if (current > 0L && current + requested > maxInFlightBytes) return false
      if (current == 0L || current + requested <= maxInFlightBytes) {
        acquired = inFlightBytes.compareAndSet(current, current + requested)
        if (acquired) peakInFlightBytes.accumulateAndGet(current + requested, Math.max)
      }
    }
    true
  }

  private def release(bytes: Int): Unit = {
    inFlightBytes.addAndGet(-bytes.toLong)
    scheduleAdmissionDrain()
  }

  /** Takes ownership of body and queues it for client. */
  def submit(client: TransportClient, body: ByteBuf, onComplete: () => Unit): Unit = {
    submit(client, body, onComplete, this, errorNotifier)
  }

  /**
   * Takes ownership of body and queues it for client on behalf of one writer owner. The owner is
   * used to remove only that writer's unsent bodies when its task is cleaned up; this batcher can
   * therefore be shared by every writer registered on an executor-level server.
   */
  def submit(
      client: TransportClient,
      body: ByteBuf,
      onComplete: () => Unit,
      owner: AnyRef,
      bodyErrorNotifier: ErrorNotifier): Unit = synchronized {
    if (closed) {
      body.release()
      onComplete()
      return
    }
    var batch = pending.get(client)
    if (batch != null && batch.bytes > 0 && batch.bytes + body.readableBytes() > maxBytes) {
      flushLocked(client)
      batch = null
    }
    if (batch == null) {
      batch = PendingBatch(new mutable.ArrayBuffer[PendingBody](), 0)
      pending.put(client, batch)
      if (maxWaitTimeMs > 0) {
        val scheduled = flushExecutor.schedule(
          new Runnable { override def run(): Unit = flush(client) },
          maxWaitTimeMs,
          TimeUnit.MILLISECONDS)
        scheduledFlushes.put(client, scheduled)
      }
    }
    batch.bodies += PendingBody(body, onComplete, owner, bodyErrorNotifier)
    batch.bytes += body.readableBytes()
    if (batch.bytes >= maxBytes) {
      flushLocked(client)
    }
  }

  /** Flushes all bodies queued for one client before a later control frame is sent. */
  def flush(client: TransportClient): Unit = synchronized {
    flushLocked(client)
  }

  /** Remove one writer's unsent bodies without affecting other writers on the channel. */
  def discardOwner(owner: AnyRef): Unit = synchronized {
    def discardOwnedBodies(batch: PendingBatch): Unit = {
      val removed = batch.bodies.filter(_.owner eq owner)
      if (removed.nonEmpty) {
        batch.bodies --= removed
        batch.bytes = batch.bodies.iterator.map(_.body.readableBytes()).sum
        removed.foreach { body =>
          body.body.release()
          try body.onComplete()
          catch { case t: Throwable => body.bodyErrorNotifier.markError(t) }
        }
      }
    }

    val clients = pending.keySet().iterator()
    val emptyClients = new mutable.ArrayBuffer[TransportClient]()
    while (clients.hasNext) {
      val client = clients.next()
      val batch = pending.get(client)
      if (batch != null) {
        discardOwnedBodies(batch)
        if (batch.bodies.isEmpty) emptyClients += client
      }
    }
    emptyClients.foreach { client =>
      pending.remove(client)
      val scheduled = scheduledFlushes.remove(client)
      if (scheduled != null) scheduled.cancel(false)
    }

    val awaitingClients = awaitingAdmission.keySet().iterator()
    val emptyAwaitingClients = new mutable.ArrayBuffer[TransportClient]()
    while (awaitingClients.hasNext) {
      val client = awaitingClients.next()
      val batches = awaitingAdmission.get(client)
      val batchIterator = batches.iterator()
      while (batchIterator.hasNext) {
        val batch = batchIterator.next()
        discardOwnedBodies(batch)
        if (batch.bodies.isEmpty) batchIterator.remove()
      }
      if (batches.isEmpty) emptyAwaitingClients += client
    }
    emptyAwaitingClients.foreach { client =>
      awaitingAdmission.remove(client)
      admissionReadySet.remove(client)
      admissionReadyClients.remove(client)
    }
  }

  /** Drops unsent bodies during writer failure cleanup. */
  def discard(): Unit = synchronized {
    if (closed) return
    closed = true
    val scheduledIterator = scheduledFlushes.values().iterator()
    while (scheduledIterator.hasNext) scheduledIterator.next().cancel(false)
    scheduledFlushes.clear()
    flushExecutor.shutdownNow()
    val iterator = pending.values().iterator()
    while (iterator.hasNext) {
      iterator.next().bodies.foreach { body =>
        body.body.release()
        try body.onComplete()
        catch { case t: Throwable => body.bodyErrorNotifier.markError(t) }
      }
    }
    pending.clear()
    val awaitingIterator = awaitingAdmission.values().iterator()
    while (awaitingIterator.hasNext) {
      val batches = awaitingIterator.next().iterator()
      while (batches.hasNext) {
        batches.next().bodies.foreach { body =>
          body.body.release()
          try body.onComplete()
          catch { case t: Throwable => body.bodyErrorNotifier.markError(t) }
        }
      }
    }
    awaitingAdmission.clear()
    admissionReadyClients.clear()
    admissionReadySet.clear()
  }

  private def flushLocked(client: TransportClient): Unit = {
    val scheduled = scheduledFlushes.remove(client)
    if (scheduled != null) scheduled.cancel(false)
    val batch = pending.remove(client)
    if (batch == null || batch.bodies.isEmpty) return

    var batches = awaitingAdmission.get(client)
    if (batches == null) {
      batches = new java.util.ArrayDeque[PendingBatch]()
      awaitingAdmission.put(client, batches)
    }
    batches.addLast(batch)
    enqueueAdmissionReadyClientLocked(client)
    drainAdmissionsLocked()
  }

  private def enqueueAdmissionReadyClientLocked(client: TransportClient): Unit = {
    if (admissionReadySet.add(client)) admissionReadyClients.addLast(client)
  }

  /** Schedule a retry without running transport admission on a Netty completion thread. */
  private def scheduleAdmissionDrain(): Unit = synchronized {
    if (!closed && !admissionDrainScheduled && !admissionReadyClients.isEmpty) {
      admissionDrainScheduled = true
      flushExecutor.execute(new Runnable {
        override def run(): Unit = StreamingShuffleTransportBatcher.this.synchronized {
          admissionDrainScheduled = false
          drainAdmissionsLocked()
        }
      })
    }
  }

  /** Fill the available window while preserving FIFO order within each physical connection. */
  private def drainAdmissionsLocked(): Unit = {
    var consecutiveBlockedClients = 0
    while (!closed && !admissionReadyClients.isEmpty &&
        consecutiveBlockedClients < admissionReadyClients.size()) {
      val client = admissionReadyClients.removeFirst()
      admissionReadySet.remove(client)
      val batches = awaitingAdmission.get(client)
      if (batches == null || batches.isEmpty) {
        awaitingAdmission.remove(client)
      } else {
        val batch = batches.peekFirst()
        if (tryAcquire(batch.bytes)) {
          batches.removeFirst()
          if (batches.isEmpty) awaitingAdmission.remove(client)
          else enqueueAdmissionReadyClientLocked(client)
          consecutiveBlockedClients = 0
          sendAdmittedBatch(client, batch)
        } else {
          enqueueAdmissionReadyClientLocked(client)
          consecutiveBlockedClients += 1
        }
      }
    }
  }

  /** Submit a batch whose bytes have already been reserved by drainAdmissionsLocked(). */
  private def sendAdmittedBatch(client: TransportClient, batch: PendingBatch): Unit = {
    var outbound: ByteBuf = null
    var addedBodies = 0
    val admittedBytes = batch.bytes
    try {
      if (batch.bodies.length == 1) {
        outbound = batch.bodies.head.body
      } else {
        val composite = allocator.compositeBuffer(batch.bodies.length)
        outbound = composite
        batch.bodies.foreach { body =>
          addBodyComponents(composite, body.body)
          addedBodies += 1
        }
      }
      val future = client.send(outbound)
      // Ownership has transferred to TransportClient. The local reference must not be released
      // by the synchronous-failure path after send() returns.
      outbound = null
      future.addListener((future: ChannelFuture) => {
        release(admittedBytes)
        val error = if (future.isSuccess) null else future.cause()
        complete(batch, if (isExpectedConnectionClose(client, error)) null else error)
      })
    } catch {
      case e: Throwable =>
        if (outbound != null) outbound.release()
        // Components already added to the aggregate were released above. Bodies after the
        // failing component still own their original reference.
        batch.bodies.drop(addedBodies).foreach(_.body.release())
        release(admittedBytes)
        if (!isExpectedConnectionClose(client, e)) {
          errorNotifier.markError(e)
        }
        complete(batch, if (isExpectedConnectionClose(client, e)) null else e)
    }
  }

  private def isExpectedConnectionClose(
      client: TransportClient,
      cause: Throwable): Boolean = {
    if (cause == null || client.getChannel.isActive) return false
    def isConnectionClose(t: Throwable): Boolean = {
      val className = t.getClass.getName
      val message = Option(t.getMessage).getOrElse("").toLowerCase(java.util.Locale.ROOT)
      className.contains("ClosedChannel") ||
        message.contains("broken pipe") ||
        message.contains("connection reset") ||
        Option(t.getCause).exists(isConnectionClose)
    }
    isConnectionClose(cause)
  }

  /**
   * Flatten an already-framed composite without materializing its payload. Keeping component
   * references at the final transport-body level avoids nested CompositeByteBuf traversal and
   * the merge that Netty may perform when a downstream consumer asks for a NIO view.
   */
  private def addBodyComponents(target: CompositeByteBuf, body: ByteBuf): Unit = {
    body match {
      case composite: CompositeByteBuf =>
        var index = 0
        while (index < composite.numComponents()) {
          target.addComponent(true, composite.component(index).retainedDuplicate())
          index += 1
        }
        // The retained component duplicates now belong to target; release the original body.
        body.release()
      case _ =>
        // Transfer the original reference when there is nothing to flatten.
        target.addComponent(true, body)
    }
  }

  private def complete(batch: PendingBatch, error: Throwable): Unit = {
    batch.bodies.foreach { body =>
      if (error != null) body.bodyErrorNotifier.markError(error)
      try body.onComplete()
      catch { case t: Throwable => body.bodyErrorNotifier.markError(t) }
    }
  }

  /** Exposed for executor diagnostics and tests; this is a transport in-flight high-water mark. */
  private[streaming] def peakInFlightBytesForTest: Long = peakInFlightBytes.get()
}
