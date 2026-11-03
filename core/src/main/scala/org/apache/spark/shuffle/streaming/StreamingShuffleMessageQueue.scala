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

import java.io.{File, RandomAccessFile}
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.{AbstractQueue, ArrayList, Collection, Iterator => JIterator}
import java.util.concurrent.{BlockingQueue, LinkedBlockingQueue, TimeUnit}
import java.util.concurrent.atomic.{AtomicInteger, AtomicLong}

import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal

import io.netty.buffer.Unpooled

import org.apache.spark.memory.MemoryManager
import org.apache.spark.network.shuffle.streaming.DataMessage
import org.apache.spark.network.shuffle.streaming.StreamingShuffleMessage

/**
 * A reader queue that preserves message order while amortizing queue operations over one
 * transport body. The network handler decodes all frames in a body and enqueues them with
 * [[putBatch]]. The reader still observes one StreamingShuffleMessage at a time, so no wire or
 * deserialization semantics change.
 *
 * Only one consumer (the shuffle reader task) is expected, but producers may be concurrent because
 * each writer connection can have its own Netty event loop.
 */
private[streaming] final class StreamingShuffleMessageQueue
    (maxInMemoryBytes: Long = 0L,
     spillDirectory: Option[File] = None,
     memoryManager: Option[MemoryManager] = None)
    extends AbstractQueue[StreamingShuffleMessage] with BlockingQueue[StreamingShuffleMessage] {

  require(maxInMemoryBytes >= 0, "maxInMemoryBytes must be non-negative")

  private sealed trait QueueEntry {
    def materialize(): StreamingShuffleMessage
    def release(): Unit
    def inMemoryBytes: Long
  }

  private final class InMemoryEntry(val value: StreamingShuffleMessage) extends QueueEntry {
    override def materialize(): StreamingShuffleMessage = value
    override def release(): Unit = value.release()
    override def inMemoryBytes: Long = value match {
      case data: DataMessage => data.dataSize.toLong
      case _ => 0L
    }
  }

  private final class SpilledDataEntry(
      val shuffleId: Int,
      val shuffleWriterId: Int,
      val shuffleReaderId: Int,
      val dataSize: Int,
      val uncompressedSize: Int,
      val checksum: Long,
      val seqNum: Long,
      val offset: Long,
      private var consumerReleaseCallback: Runnable) extends QueueEntry {
    private var value: DataMessage = _

    override def materialize(): StreamingShuffleMessage = synchronized {
      if (value == null) {
        val bytes = new Array[Byte](dataSize)
        readFully(bytes, offset)
        val buffer = Unpooled.wrappedBuffer(bytes)
        try {
          value = new DataMessage(
            shuffleId, shuffleWriterId, shuffleReaderId, dataSize, uncompressedSize,
            buffer, checksum)
          value.setSeqNum(seqNum)
          value.setReleaseCallback(consumerReleaseCallback)
          consumerReleaseCallback = null
        } finally {
          // DataMessage retains the buffer once for its own lifetime.
          buffer.release()
        }
      }
      value
    }

    override def release(): Unit = synchronized {
      if (value != null) {
        value.release()
        value = null
      } else if (consumerReleaseCallback != null) {
        val callback = consumerReleaseCallback
        consumerReleaseCallback = null
        callback.run()
      }
    }

    override def inMemoryBytes: Long = 0L
  }

  private val batches = new LinkedBlockingQueue[Array[QueueEntry]]()
  // The consumer owns the active batch. Keeping an index avoids copying every entry from the
  // network batch into a second per-message queue before it can be consumed.
  private var currentBatch: Array[QueueEntry] = null
  private var currentIndex = 0
  private val stateLock = new Object
  // Serialize publication with close, including payload reservation and spill-file creation.
  // A network callback already in progress must not publish a new owner after cancellation.
  private val publicationLock = new Object
  private var closed = false
  private val messageCount = new AtomicInteger(0)
  private val queuedMemoryBytes = new AtomicLong(0L)
  private val spillLock = new Object
  private var spillFile: File = _
  private var spillRaf: RandomAccessFile = _
  private var spillChannel: FileChannel = _
  private val spilledBytes = new AtomicLong(0L)
  private val spilledMessages = new AtomicLong(0L)

  private def canSpill: Boolean = maxInMemoryBytes > 0 && spillDirectory.exists(_.isDirectory)

  private def reserveInMemory(bytes: Long): Boolean = {
    if (bytes <= 0) {
      true
    } else if (!canSpill) {
      queuedMemoryBytes.addAndGet(bytes)
      true
    } else {
      var currentBytes = queuedMemoryBytes.get()
      var reserved = false
      while (!reserved && currentBytes + bytes <= maxInMemoryBytes) {
        reserved = queuedMemoryBytes.compareAndSet(currentBytes, currentBytes + bytes)
        if (!reserved) currentBytes = queuedMemoryBytes.get()
      }
      reserved
    }
  }

  private def ensureSpillChannel(): FileChannel = spillLock.synchronized {
    if (spillChannel == null) {
      spillFile = File.createTempFile("streaming-shuffle-reader-", ".spill", spillDirectory.get)
      spillRaf = new RandomAccessFile(spillFile, "rw")
      spillChannel = spillRaf.getChannel
    }
    spillChannel
  }

  private def writeFully(bytes: Array[Byte]): Long = {
    val channel = ensureSpillChannel()
    spillLock.synchronized {
      val offset = channel.size()
      val buffer = ByteBuffer.wrap(bytes)
      var position = offset
      while (buffer.hasRemaining) {
        position += channel.write(buffer, position)
      }
      spilledBytes.addAndGet(bytes.length.toLong)
      spilledMessages.incrementAndGet()
      offset
    }
  }

  private def readFully(bytes: Array[Byte], offset: Long): Unit = spillLock.synchronized {
    if (spillChannel == null) {
      throw new IllegalStateException("Streaming shuffle spill file is closed")
    }
    val buffer = ByteBuffer.wrap(bytes)
    var position = offset
    while (buffer.hasRemaining) {
      val read = spillChannel.read(buffer, position)
      if (read < 0) throw new IllegalStateException("Unexpected EOF in streaming shuffle spill")
      position += read
    }
  }

  private def reserveMessage(data: DataMessage): Boolean = {
    if (!reserveInMemory(data.dataSize.toLong)) return false
    // The executor reservation follows the message through dequeue and reader consumption.
    // Queue occupancy alone would return the budget while the reader still holds the payload.
    if (canSpill && memoryManager.isDefined) {
      val manager = memoryManager.get
      // Charge the configured execution pool even when off-heap execution is disabled. This is
      // a retained-payload budget, not a measurement of Netty's physical allocation or RSS.
      val reservation = manager.tryAcquireExecutionMemoryForExecutor(
        data.dataSize, manager.tungstenMemoryMode)
      reservation match {
        case Some(reservation) =>
          val callback = data.takeReleaseCallback()
          data.setReleaseCallback(() => {
            try reservation.close()
            finally if (callback != null) callback.run()
          })
        case None =>
          queuedMemoryBytes.addAndGet(-data.dataSize.toLong)
          return false
      }
    }
    true
  }

  private def toEntry(message: StreamingShuffleMessage): QueueEntry = message match {
    case data: DataMessage if !reserveMessage(data) =>
      val bytes = new Array[Byte](data.dataSize)
      data.data.getBytes(data.data.readerIndex(), bytes)
      val offset = writeFully(bytes)
      var consumerReleaseCallback = data.takeReleaseCallback()
      try {
        // Free the copied Netty payload now, but keep receive credit outstanding until the
        // downstream task consumes or cancels this entry. Returning credit here turns the
        // bounded queue into an unbounded disk-backed receive window.
        data.releaseOwnedResources()
      } catch {
        case t: Throwable =>
          if (consumerReleaseCallback != null) consumerReleaseCallback.run()
          consumerReleaseCallback = null
          throw t
      }
      new SpilledDataEntry(
        data.shuffleId, data.shuffleWriterId, data.shuffleReaderId, data.dataSize,
        data.uncompressedSize, data.checksum, data.getSeqNum, offset, consumerReleaseCallback)
    case data: DataMessage =>
      new InMemoryEntry(data)
    case other =>
      new InMemoryEntry(other)
  }

  private def consumeEntry(entry: QueueEntry): StreamingShuffleMessage = {
    val memoryBytes = entry.inMemoryBytes
    if (memoryBytes > 0) queuedMemoryBytes.addAndGet(-memoryBytes)
    messageCount.decrementAndGet()
    entry.materialize()
  }

  /** Enqueues all messages atomically with respect to the reader's batch boundary. */
  def putBatch(messages: Array[StreamingShuffleMessage]): Unit = publicationLock.synchronized {
    if (closed) {
      releaseAll(messages.iterator.map(message => () => message.release()))
      return
    }
    if (messages.nonEmpty) {
      val entries = new Array[QueueEntry](messages.length)
      var converted = 0
      var counted = false
      try {
        while (converted < messages.length) {
          entries(converted) = toEntry(messages(converted))
          converted += 1
        }
        messageCount.addAndGet(entries.length)
        counted = true
        batches.put(entries)
      } catch {
        case t: Throwable =>
          val convertedReleases = entries.iterator.take(converted).map { entry =>
            () => {
              queuedMemoryBytes.addAndGet(-entry.inMemoryBytes)
              entry.release()
            }
          }
          val remainingReleases = messages.iterator.drop(converted)
            .map(message => () => message.release())
          try releaseAll(convertedReleases ++ remainingReleases) catch {
            case NonFatal(error) => if (error ne t) t.addSuppressed(error)
          }
          if (counted) messageCount.addAndGet(-messages.length)
          throw t
      }
    }
  }

  private def consumeBatch(batch: Array[QueueEntry]): StreamingShuffleMessage = {
    currentBatch = batch
    currentIndex = 0
    consumeCurrent()
  }

  private def consumeCurrent(): StreamingShuffleMessage = {
    if (currentBatch == null || currentIndex >= currentBatch.length) {
      currentBatch = null
      currentIndex = 0
      null
    } else {
      val entry = currentBatch(currentIndex)
      currentIndex += 1
      consumeEntry(entry)
    }
  }

  override def put(message: StreamingShuffleMessage): Unit = putBatch(Array(message))

  override def offer(message: StreamingShuffleMessage): Boolean = {
    putBatch(Array(message))
    true
  }

  override def offer(
      message: StreamingShuffleMessage,
      timeout: Long,
      unit: TimeUnit): Boolean = offer(message)

  override def take(): StreamingShuffleMessage = stateLock.synchronized {
    val fromCurrent = consumeCurrent()
    if (fromCurrent != null) fromCurrent
    else consumeBatch(batches.take())
  }

  override def poll(): StreamingShuffleMessage = stateLock.synchronized {
    val fromCurrent = consumeCurrent()
    if (fromCurrent != null) fromCurrent
    else {
      val batch = batches.poll()
      if (batch == null) null else consumeBatch(batch)
    }
  }

  override def poll(timeout: Long, unit: TimeUnit): StreamingShuffleMessage =
    stateLock.synchronized {
      val fromCurrent = consumeCurrent()
      if (fromCurrent != null) fromCurrent
      else {
        val batch = batches.poll(timeout, unit)
        if (batch == null) null else consumeBatch(batch)
      }
    }

  override def peek(): StreamingShuffleMessage = stateLock.synchronized {
    if (currentBatch != null && currentIndex < currentBatch.length) {
      currentBatch(currentIndex).materialize()
    }
    else {
      val batch = batches.peek()
      if (batch == null) null else batch(0).materialize()
    }
  }

  override def size(): Int = messageCount.get()

  override def isEmpty: Boolean = messageCount.get() == 0

  override def remainingCapacity(): Int = Int.MaxValue

  override def drainTo(collection: Collection[_ >: StreamingShuffleMessage]): Int =
    drainTo(collection, Int.MaxValue)

  override def drainTo(
      collection: Collection[_ >: StreamingShuffleMessage],
      maxElements: Int): Int = {
    require(collection ne this, "Cannot drain a queue into itself")
    if (maxElements <= 0) return 0

    stateLock.synchronized {
      var drained = 0
      while (drained < maxElements) {
        val fromCurrent = consumeCurrent()
        if (fromCurrent != null) {
          collection.add(fromCurrent)
          drained += 1
        } else {
          val batch = batches.poll()
          if (batch == null) {
            return drained
          }
          val remaining = maxElements - drained
          val take = math.min(remaining, batch.length)
          var i = 0
          while (i < take) {
            collection.add(consumeEntry(batch(i)))
            drained += 1
            i += 1
          }
          if (take < batch.length) {
            // Keep the not-yet-drained tail as the consumer's current batch without copying it.
            currentBatch = batch
            currentIndex = take
          }
        }
      }
      drained
    }
  }

  override def iterator(): JIterator[StreamingShuffleMessage] = {
    val snapshot = new ArrayList[StreamingShuffleMessage]()
    stateLock.synchronized {
      if (currentBatch != null) {
        var i = currentIndex
        while (i < currentBatch.length) {
          snapshot.add(currentBatch(i).materialize())
          i += 1
        }
      }
      val batchIterator = batches.iterator()
      while (batchIterator.hasNext) {
        batchIterator.next().foreach(entry => snapshot.add(entry.materialize()))
      }
    }
    snapshot.iterator()
  }

  private[streaming] def queuedMemoryBytesCount: Long = queuedMemoryBytes.get()

  private[streaming] def spilledBytesCount: Long = spilledBytes.get()

  private[streaming] def spilledMessagesCount: Long = spilledMessages.get()

  /** Discard a quiesced inbox without reading spilled payloads back into memory. */
  private def discardAll(): Unit = {
    val discarded = new ArrayList[QueueEntry]()
    stateLock.synchronized {
      if (currentBatch != null) {
        while (currentIndex < currentBatch.length) {
          discarded.add(currentBatch(currentIndex))
          currentIndex += 1
        }
        currentBatch = null
        currentIndex = 0
      }
      var batch = batches.poll()
      while (batch != null) {
        batch.foreach(discarded.add)
        batch = batches.poll()
      }
      discarded.asScala.foreach { entry =>
        queuedMemoryBytes.addAndGet(-entry.inMemoryBytes)
        messageCount.decrementAndGet()
      }
    }
    releaseAll(discarded.asScala.iterator.map(entry => () => entry.release()))
  }

  private def releaseAll(releases: Iterator[() => Unit]): Unit = {
    var failure: Throwable = null
    releases.foreach { release =>
      try release() catch {
        case NonFatal(error) =>
          if (failure == null) {
            failure = error
          } else if (failure ne error) {
            failure.addSuppressed(error)
          }
      }
    }
    if (failure != null) throw failure
  }

  private[streaming] def close(): Unit = publicationLock.synchronized {
    if (closed) return
    closed = true
    try discardAll() finally {
      spillLock.synchronized {
        if (spillChannel != null) {
          try spillChannel.close() finally {
            spillRaf.close()
            if (spillFile != null && !spillFile.delete()) spillFile.deleteOnExit()
            spillChannel = null
            spillRaf = null
            spillFile = null
          }
        }
      }
    }
  }
}
