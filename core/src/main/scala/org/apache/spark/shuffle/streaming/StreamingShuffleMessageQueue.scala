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

import io.netty.buffer.Unpooled

import org.apache.spark.network.shuffle.streaming.DataMessage
import org.apache.spark.network.shuffle.streaming.StreamingShuffleMessage

/** Executor-scoped memory reservation shared by all prepared streaming-shuffle inboxes. */
private[streaming] final class StreamingShuffleReaderMemoryBudget(val maxBytes: Long) {
  require(maxBytes > 0, "maxBytes must be positive")

  private val usedBytes = new AtomicLong(0L)

  def tryAcquire(bytes: Long): Boolean = {
    if (bytes <= 0) return true
    var current = usedBytes.get()
    var reserved = false
    while (!reserved && current <= maxBytes - bytes) {
      reserved = usedBytes.compareAndSet(current, current + bytes)
      if (!reserved) current = usedBytes.get()
    }
    reserved
  }

  def release(bytes: Long): Unit = {
    if (bytes > 0) {
      val remaining = usedBytes.addAndGet(-bytes)
      require(remaining >= 0, s"Released $bytes bytes from a $remaining-byte reservation")
    }
  }

  private[streaming] def usedBytesCount: Long = usedBytes.get()
}

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
     sharedMemoryBudget: Option[StreamingShuffleReaderMemoryBudget] = None)
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
  private val messageCount = new AtomicInteger(0)
  private val queuedMemoryBytes = new AtomicLong(0L)
  private val peakQueuedMemoryBytes = new AtomicLong(0L)
  private val maxDataMessageBytes = new AtomicLong(0L)
  private val spillLock = new Object
  private var spillFile: File = _
  private var spillRaf: RandomAccessFile = _
  private var spillChannel: FileChannel = _
  private val spilledBytes = new AtomicLong(0L)
  private val spilledMessages = new AtomicLong(0L)

  private def updateMaximum(maximum: AtomicLong, candidate: Long): Unit = {
    var current = maximum.get()
    while (candidate > current && !maximum.compareAndSet(current, candidate)) {
      current = maximum.get()
    }
  }

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
      if (reserved && !sharedMemoryBudget.forall(_.tryAcquire(bytes))) {
        queuedMemoryBytes.addAndGet(-bytes)
        false
      } else {
        if (reserved) updateMaximum(peakQueuedMemoryBytes, queuedMemoryBytes.get())
        reserved
      }
    }
  }

  private def releaseInMemory(bytes: Long): Unit = {
    if (bytes > 0) {
      queuedMemoryBytes.addAndGet(-bytes)
      sharedMemoryBudget.foreach(_.release(bytes))
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

  private def toEntry(message: StreamingShuffleMessage): QueueEntry = message match {
    case data: DataMessage if canSpill && !reserveInMemory(data.dataSize.toLong) =>
      updateMaximum(maxDataMessageBytes, data.dataSize.toLong)
      val bytes = new Array[Byte](data.dataSize)
      data.data.getBytes(data.data.readerIndex(), bytes)
      val offset = writeFully(bytes)
      // Free the copied payload now, but keep receive credit outstanding until the downstream
      // task consumes or cancels this entry. Returning credit at spill time turns a bounded inbox
      // into an unbounded disk sink because its producer immediately refills every spilled frame.
      val consumerReleaseCallback = data.takeReleaseCallback()
      try {
        data.releaseOwnedResources()
      } catch {
        case t: Throwable =>
          if (consumerReleaseCallback != null) consumerReleaseCallback.run()
          throw t
      }
      val entry = new SpilledDataEntry(
        data.shuffleId, data.shuffleWriterId, data.shuffleReaderId, data.dataSize,
        data.uncompressedSize, data.checksum, data.getSeqNum, offset, consumerReleaseCallback)
      entry
    case data: DataMessage if canSpill =>
      updateMaximum(maxDataMessageBytes, data.dataSize.toLong)
      new InMemoryEntry(data)
    case data: DataMessage =>
      updateMaximum(maxDataMessageBytes, data.dataSize.toLong)
      reserveInMemory(data.dataSize.toLong)
      new InMemoryEntry(data)
    case other =>
      new InMemoryEntry(other)
  }

  private def consumeEntry(entry: QueueEntry): StreamingShuffleMessage = {
    val memoryBytes = entry.inMemoryBytes
    releaseInMemory(memoryBytes)
    messageCount.decrementAndGet()
    entry.materialize()
  }

  /** Enqueues all messages atomically with respect to the reader's batch boundary. */
  def putBatch(messages: Array[StreamingShuffleMessage]): Unit = {
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
          if (converted > 0) {
            var i = 0
            while (i < converted) {
              if (entries(i) != null) {
                releaseInMemory(entries(i).inMemoryBytes)
                entries(i).release()
              }
              i += 1
            }
          }
          while (converted < messages.length) {
            messages(converted).release()
            converted += 1
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

  /** Visible to focused tests to verify that body batching is actually used. */
  private[streaming] def numQueuedBatches: Int = batches.size()

  private[streaming] def queuedMemoryBytesCount: Long = queuedMemoryBytes.get()

  private[streaming] def peakQueuedMemoryBytesCount: Long = peakQueuedMemoryBytes.get()

  private[streaming] def maxDataMessageBytesCount: Long = maxDataMessageBytes.get()

  private[streaming] def spilledBytesCount: Long = spilledBytes.get()

  private[streaming] def spilledMessagesCount: Long = spilledMessages.get()

  private[streaming] def close(): Unit = spillLock.synchronized {
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
