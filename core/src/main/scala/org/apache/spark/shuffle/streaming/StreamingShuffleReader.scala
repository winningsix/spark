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

import java.io.File
import java.util.concurrent.{BlockingQueue, CompletableFuture, ConcurrentHashMap, ConcurrentLinkedQueue, LinkedBlockingQueue, Semaphore, TimeUnit}
import java.util.concurrent.atomic.AtomicInteger

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import io.netty.buffer.ByteBufInputStream

import org.apache.spark.{ShuffleLocationResponse, SparkContext, SparkEnv, SparkRuntimeException, TaskContext}
import org.apache.spark.internal.LogKeys
import org.apache.spark.internal.config.{EXECUTOR_ID, SHUFFLE_COMPRESS,
  STREAMING_SHUFFLE_CHECKSUM_ENABLED, STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED,
  STREAMING_SHUFFLE_READER_CLIENT_CREATION_THREADS, STREAMING_SHUFFLE_READER_MAX_MEMORY,
  STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED,
  STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY,
  STREAMING_SHUFFLE_READER_WAIT_FOR_TERMINATION_ACKS}
import org.apache.spark.memory.{MemoryConsumer, MemoryMode}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.client.{TransportClient, TransportClientFactory}
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.shuffle.streaming.{DataMessage, ShuffleChecksum, StreamingShuffleMessage, TerminationControlMessage}
import org.apache.spark.shuffle.{ShuffleHandle, ShuffleReader, ShuffleReadMetricsReporter}
import org.apache.spark.util.{ErrorNotifier, NextIterator, ThreadUtils, Utils}

/**
 * Default factory used by `StreamingShuffleReader` to create its output iterator.
 */
class StreamingShuffleReaderIteratorFactory {
  def create[K, C](
      messageQueue: BlockingQueue[StreamingShuffleMessage],
      handleTerminationMessage: TerminationControlMessage => Boolean,
      handleDataMessage: DataMessage => Iterator[(K, C)],
      checkTaskFailure: () => Unit,
      inputExhausted: () => Boolean = () => false,
      repairIdleCreditWindows: () => Unit = () => (),
      recordQueueWaitNanos: Long => Unit = _ => ()
    ): Iterator[Product2[K, C]] = {
    new NextIterator[Product2[K, C]] {
      // Iterator that iterates through multiple rows in data message buffer. When the iterator
      // does not have any more rows, we should fetch another message from message queue.
      private var rowIterator: Iterator[(K, C)] = Iterator.empty
      private var idleSinceNanos = 0L
      private var lastRepairNanos = 0L
      private val repairIntervalNanos = TimeUnit.MILLISECONDS.toNanos(500L)

      def getNext(): Product2[K, C] = {
        while (!rowIterator.hasNext) {
          checkTaskFailure()
          // A shuffle with zero map partitions never publishes a data or termination frame.
          // Discovery is therefore the only end-of-input signal for this case.
          if (inputExhausted()) {
            finished = true
            return null.asInstanceOf[Product2[K, C]]
          }
          val immediate = messageQueue.poll()
          val message = if (immediate != null) {
            immediate
          } else {
            val waitStartNanos = System.nanoTime()
            val awaited = messageQueue.poll(10, TimeUnit.MILLISECONDS)
            recordQueueWaitNanos(System.nanoTime() - waitStartNanos)
            awaited
          }
          message match {
            case msg: TerminationControlMessage =>
              idleSinceNanos = 0L
              if (handleTerminationMessage(msg)) {
                finished = true
                return null.asInstanceOf[Product2[K, C]]
              }
            case dataMessage: DataMessage =>
              idleSinceNanos = 0L
              rowIterator = handleDataMessage(dataMessage)
            case null =>
              val now = System.nanoTime()
              if (idleSinceNanos == 0L) idleSinceNanos = now
              if (now - idleSinceNanos >= repairIntervalNanos &&
                  now - lastRepairNanos >= repairIntervalNanos) {
                repairIdleCreditWindows()
                lastRepairNanos = now
              }
            case other =>
              throw new IllegalArgumentException(
                s"Unexpected message type in reader queue: ${other.getClass.getName}")
          }
        }
        rowIterator.next()
      }

      override def close(): Unit = {
        // no-op. handleTerminationMessage will take care of final cleanup.
      }
    }
  }
}

class StreamingShuffleReader[K, C](
    handle: ShuffleHandle,
    val context: TaskContext,
    clientHandler: Option[StreamingShuffleClientHandler] = None,
    private[streaming] val errorNotifier: ErrorNotifier = new ErrorNotifier(),
    sharedClientFactory: Option[TransportClientFactory] = None,
    sharedExecutorClient: Option[StreamingShuffleExecutorClient] = None,
    receiveInbox: Option[StreamingShuffleReceiveInboxLease] = None,
    readMetrics: Option[ShuffleReadMetricsReporter] = None)
    extends ShuffleReader[K, C] with TaskContextAwareLogging {
  assert(SparkEnv.get.streamingShuffleOutputTracker.isDefined)
  private val conf = SparkEnv.get.conf

  private val streamingShuffleHandle = handle.asInstanceOf[StreamingShuffleHandle[K, _, C]]
  setShuffleIdForLogging(streamingShuffleHandle.shuffleId)
  // a mapping of mapId and client
  private[spark] val clientMap = new ConcurrentHashMap[Long, TransportClient]()
  private val logicalClientHandlers =
    new ConcurrentHashMap[Long, StreamingShuffleClientHandler]()
  // Standalone readers used by low-level tests own their factories. Readers constructed by the
  // shuffle manager use its executor-scoped shared factory instead, so this queue stays empty.
  private val clientFactories = new ConcurrentLinkedQueue[TransportClientFactory]()
  private val tracker = SparkEnv.get.streamingShuffleOutputTracker.get

  private val role = conf.get(EXECUTOR_ID).map { id =>
    if (SparkContext.isDriver(id)) "driver" else "executor"
  }

  private val clientConf = SparkTransportConf.fromSparkConf(
    conf,
    s"streaming-shuffle-reader-${streamingShuffleHandle.shuffleId}-${context.partitionId()}",
    1, // a client should only need to use 1 thread
    role)

  private[spark] val taskDiscoveryExecutor =
    ThreadUtils.newDaemonSingleThreadExecutor(
      s"streaming-shuffle-task-discovery-thread-" +
        s"${streamingShuffleHandle.shuffleId}-${context.partitionId()}")

  private val preparedSession = receiveInbox.flatMap(_.preparedSession)
  private val activeErrorNotifier = preparedSession.map(_.errorNotifier).getOrElse(errorNotifier)
  private val totalNumShuffleWriters: AtomicInteger = preparedSession
    .map(_.totalNumShuffleWriters)
    .getOrElse(new AtomicInteger(-1))
  private var perWriterByteLimit: Long = 1

  // We might need to revisit if the size limit is enough. If not, there should be a way to tie it
  // to the per-task memory limit from the task context.
  private val MAX_MEMORY = conf.get(STREAMING_SHUFFLE_READER_MAX_MEMORY)
  private val READER_BACKPRESSURE_ENABLED =
    conf.get(STREAMING_SHUFFLE_READER_BACKPRESSURE_ENABLED)
  private val READER_QUEUE_MAX_MEMORY = conf.get(STREAMING_SHUFFLE_READER_QUEUE_MAX_MEMORY)
  // Data and termination messages from all writers are put into this queue.
  private[spark] val messageQueue: BlockingQueue[StreamingShuffleMessage] =
    receiveInbox.map(_.queue).getOrElse(if (
      conf.get(STREAMING_SHUFFLE_READER_MESSAGE_BATCHING_ENABLED)) {
      new StreamingShuffleMessageQueue(
        READER_QUEUE_MAX_MEMORY,
        Some(new File(Utils.getLocalDir(conf))))
    } else {
      // Keep the disabled setting as the original one-message-per-queue-operation path for
      // apples-to-apples performance comparisons.
      new LinkedBlockingQueue[StreamingShuffleMessage]()
    })

  private val memoryConsumer =
    new MemoryConsumer(context.taskMemoryManager(), MemoryMode.OFF_HEAP) {
      override def spill(size: Long, trigger: MemoryConsumer): Long = 0
    }

  private val shuffleChecksum = if (conf.get(STREAMING_SHUFFLE_CHECKSUM_ENABLED)) {
    new ShuffleChecksum()
  } else {
    null
  }
  private val compressionCodec = if (conf.get(SHUFFLE_COMPRESS)) {
    Some(StreamingShuffleCompression.decompressor)
  } else {
    None
  }

  // The set of shuffle writers that this reader has successfully received
  // termination ack messages from.  This is used to make sure all term ack messages
  // are successfully sent before exiting.
  private[spark] val terminationAckControlMessageSet = preparedSession
    .map(_.terminationAckControlMessageSet)
    .getOrElse(ConcurrentHashMap.newKeySet[Long]())

  private val allTermAcksSentNotice = preparedSession
    .map(_.allTermAcksSentNotice)
    .getOrElse(new Semaphore(0))

  // thread pool used to perform client creation in parallel
  private[spark] val clientCreationExecutor = ThreadUtils.newDaemonFixedThreadPool(
    conf.get(STREAMING_SHUFFLE_READER_CLIENT_CREATION_THREADS),
    s"streaming-shuffle-async-client-creation-${context.partitionId()}")

  // Signals to other threads that task discovery should stop. For example, we may receive all
  // the termination messages before we actually put the clients in the client map. In that
  // scenario we can just exit without checking the client map for whether all the clients were
  // created.
  @volatile private var taskDiscoveryShouldStop = false

  private var currentDataMessage: StreamingShuffleMessage = _
  private var queueWaitNanosRemainder = 0L

  private def recordQueueWaitNanos(waitNanos: Long): Unit = {
    val totalNanos = queueWaitNanosRemainder + waitNanos
    val waitMillis = TimeUnit.NANOSECONDS.toMillis(totalNanos)
    queueWaitNanosRemainder = totalNanos - TimeUnit.MILLISECONDS.toNanos(waitMillis)
    if (waitMillis > 0L) {
      readMetrics.foreach(_.incFetchWaitTime(waitMillis))
    }
  }

  private def shutdownExecutorService(
      executor: java.util.concurrent.ExecutorService,
      name: String): Unit = {
    executor.shutdownNow()
    try {
      if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
        logWarning(log"${MDC(LogKeys.NAME, name)} did not shut down within the timeout.")
      } else {
        logDebug(log"${MDC(LogKeys.NAME, name)} shut down successfully.")
      }
    } catch {
      case _: InterruptedException =>
        // make sure we clean up even if the task thread is interrupted during shutdown
        shutdownExecutorService(executor, name)
        // Restore the interrupt flag so downstream code knows we were interrupted
        Thread.currentThread().interrupt()
    }
  }

  /**
   * Cleans up all reader resources. This method should be idempotent and
   * can be called multiple times without issue.
   */
  private[streaming] def cleanupResources(): Unit = {
    val cleanupStartTime = System.currentTimeMillis()

    Utils.tryLogNonFatalError {
      stopTaskDiscovery()
    }
    Utils.tryLogNonFatalError {
      shutdownExecutorService(clientCreationExecutor, "Client Creation Executor")
    }
    sharedExecutorClient match {
      case Some(executorClient) =>
        Utils.tryLogNonFatalError {
          logicalClientHandlers.forEach((writerId, handler) =>
            executorClient.unregister(
              streamingShuffleHandle.shuffleId,
              Math.toIntExact(writerId),
              context.partitionId(),
              handler))
        }
      case None =>
        Utils.tryLogNonFatalError {
          clientMap.forEach((_, client) => client.close())
        }
    }
    logicalClientHandlers.clear()
    Utils.tryLogNonFatalError {
      clientFactories.forEach(factory => factory.close())
    }
    Utils.tryLogNonFatalError {
      if (currentDataMessage != null) {
        currentDataMessage.release()
        currentDataMessage = null
      }
    }
    val inboxStats = receiveInbox.map(_.close()).getOrElse {
      val list = new java.util.ArrayList[StreamingShuffleMessage]()
      messageQueue.drainTo(list)
      list.forEach(_.release())
      messageQueue match {
        case queue: StreamingShuffleMessageQueue =>
          val stats = StreamingShuffleReceiveInboxStats(
            queue.spilledBytesCount, queue.spilledMessagesCount)
          queue.close()
          stats
        case _ =>
          StreamingShuffleReceiveInboxStats(0L, 0L)
      }
    }
    logDebug(
      log"Streaming reader queue spilled ${MDC(LogKeys.NUM_BYTES, inboxStats.spilledBytes)} " +
        log"bytes in ${MDC(LogKeys.COUNT, inboxStats.spilledMessages)} messages")
    Utils.tryLogNonFatalError {
      memoryConsumer.freeMemory(memoryConsumer.getUsed())
    }
    logDebug(log"Resource cleanup took ${MDC(LogKeys.DURATION,
      System.currentTimeMillis() - cleanupStartTime)} ms")
  }

  // Register a task completion listener to make sure we clean up resources
  // when the task is completed.  Without this, threads, client connections/factories,
  // message buffers, and memory allocations could be leaked.
  context.addTaskCompletionListener[Unit] { _ =>
    cleanupResources()
  }

  if (preparedSession.isEmpty) {
    taskDiscoveryExecutor.execute(() => {
    val startTime = System.currentTimeMillis()
    try {
      logDebug(log"Task discovery thread started.")
      // a mapping of mapId and client creation future.  Used for parallel client creation
      val clientFutureMap = new ConcurrentHashMap[Long, CompletableFuture[Void]]()
      // A replayable/internal-consumer shuffle can publish another writer task for the same
      // logical map index while locations are discovered incrementally. The logical map index,
      // rather than the transient map task id, is the stable identity for a reader; otherwise a
      // second publication is counted as an extra writer and discovery fails.
      val clientMapIndexes = mutable.HashMap.empty[Long, Int]

      var isDone = false

      def shouldStop(): Boolean = {
        (
          // Got all locations for shuffle writers
          // and started creating the clients to communicate with them.
          isDone
          // signal from main thread that task discovery should terminate.
          // For example, we got all the term messages from all clients
          || taskDiscoveryShouldStop
          // task has failed or been interrupted.
          || context.isFailed()
          || context.isInterrupted()
          )
      }

      while (!shouldStop()) {
        val shuffleLocationResponseOption =
          tracker.getAvailableShuffleWriterTaskLocations(streamingShuffleHandle.shuffleId)

        var retryCount = 0
        shuffleLocationResponseOption.foreach {
          case ShuffleLocationResponse(shuffleWriterLocations, numShuffleWriters) =>
            if (!totalNumShuffleWriters.compareAndSet(-1, numShuffleWriters)) {
              val expected = totalNumShuffleWriters.get()
              require(expected == numShuffleWriters,
                s"Streaming shuffle writer count changed while discovering locations: " +
                  s"first=$expected current=$numShuffleWriters " +
                  s"locations=${shuffleWriterLocations.toSeq.sortBy(_._1)}")
            } else {
              perWriterByteLimit = Math.max(MAX_MEMORY / math.max(1, numShuffleWriters), 1)
              if (READER_BACKPRESSURE_ENABLED) {
                memoryConsumer.acquireMemory(MAX_MEMORY)
              }
            }
            shuffleWriterLocations
              .foreach {
                case (mapId, location) =>
                  val duplicateLogicalWriter = location.mapIndex >= 0 && clientMapIndexes.values
                    .exists(_ == location.mapIndex)
                  if (!clientFutureMap.containsKey(mapId) && !duplicateLogicalWriter) {
                    clientMapIndexes.put(mapId, location.mapIndex)
                    val future = createClientAsync(mapId.toInt, location.host, location.port)
                      .thenAccept((shuffleClient: TransportClient) => {
                        clientMap.put(mapId, shuffleClient)
                        logDebug(
                          log"Created shuffle client to shuffle " +
                            log"writer with id ${MDC(LogKeys.MAP_ID, mapId)} and location ${MDC(
                              LogKeys.TASK_LOCATION, location)}. ${MDC(
                              LogKeys.NUM_CONNECTED_SHUFFLE_WRITERS, clientMap.size)} / ${MDC(
                              LogKeys.NUM_SHUFFLE_WRITERS, numShuffleWriters)} shuffle writer " +
                            log"tasks connected.")
                      }).exceptionally(th => {
                        val errorMsg = s"Error creating transport client to shuffle writer" +
                          s" with id ${mapId} and location ${location}."
                        // The real exception is likely wrapped in CompletionException
                        logError(errorMsg, th.getCause)
                        activeErrorNotifier.markError(th.getCause)
                        throw new RuntimeException(errorMsg)
                      })
                    clientFutureMap.put(mapId, future)
                  }
              }

            val numClients = clientFutureMap.size()
            // A location response may be an incremental snapshot.  Its writer count describes
            // that snapshot, while clientFutureMap retains map ids discovered in earlier
            // snapshots; compare against the stable total captured above instead of the current
            // response count.
            val expectedNumShuffleWriters = totalNumShuffleWriters.get()
            if (numClients > expectedNumShuffleWriters) {
              val discoveredMapIds = clientFutureMap.keySet().asScala.toSeq.sorted
              val discoveredMapIndexes = shuffleWriterLocations.toSeq.sortBy(_._1).map {
                case (id, location) => s"$id:${location.mapIndex}"
              }.mkString("[", ",", "]")
              logWarning(log"Streaming shuffle discovered more writer locations than expected: " +
                log"${MDC(LogKeys.NUM_CONNECTED_SHUFFLE_WRITERS, numClients)} / " +
                log"${MDC(LogKeys.NUM_SHUFFLE_WRITERS, expectedNumShuffleWriters)}; " +
                log"map ids=${MDC(LogKeys.MAP_ID, discoveredMapIds)}" +
                log" map indexes=${MDC(LogKeys.MAP_ID, discoveredMapIndexes)}")
            }
            require(numClients <= expectedNumShuffleWriters,
              s"Streaming shuffle discovered too many writer locations: " +
                s"actual=$numClients expected=$expectedNumShuffleWriters " +
                s"clientMapIds=${clientFutureMap.keySet().asScala.toSeq.sorted} " +
                s"locations=${shuffleWriterLocations.toSeq.sortBy(_._1)}")
            if (numClients != expectedNumShuffleWriters) {
              // TODO also implement timeout
              Thread.sleep(10)
              retryCount += 1
              if (retryCount % 100 == 0) {
                logDebug(log"Still attempting to get shuffle writer locations." +
                  log" Got the location of ${MDC(LogKeys.NUM_CONNECTED_SHUFFLE_WRITERS,
                    clientFutureMap.size)} / ${MDC(LogKeys.NUM_SHUFFLE_WRITERS,
                    numShuffleWriters)} shuffle writers")
              }
            } else {
              // we have received all shuffle writer locations
              // and are in the process of creating clients to connect to them
              isDone = true
            }
        }
      }

      if (isDone && !taskDiscoveryShouldStop && !context.isFailed() && !context.isInterrupted()) {
        // wait for all futures to finish
        CompletableFuture.allOf(clientFutureMap.values().asScala.toSeq: _*).get()
        require(
          clientMap.size() == totalNumShuffleWriters.get(),
          s"actual num of clients: ${clientMap.size()} " +
            s"expected num clients: ${totalNumShuffleWriters.get()} " +
            s"clientMapIds=${clientMap.keySet().asScala.toSeq.sorted} " +
            s"clientFutureMapIds=${clientFutureMap.keySet().asScala.toSeq.sorted}"
        )
      }
    } catch {
      case th: Throwable =>
        logError(log"Task discovery thread failed.", th)
        activeErrorNotifier.markError(th)
    } finally {
      clientCreationExecutor.shutdown()
      logDebug(log"Task discovery thread exited. Took ${MDC(LogKeys.DURATION,
        System.currentTimeMillis() - startTime)} ms")
    }
    })
  } else {
    taskDiscoveryExecutor.shutdown()
    clientCreationExecutor.shutdown()
  }

  private def stopTaskDiscovery(): Unit = {
    taskDiscoveryShouldStop = true
    shutdownExecutorService(taskDiscoveryExecutor, "Task Discovery Executor")
  }

  private def createClientAsync(
      mapId: Int,
      remoteHost: String,
      remotePort: Int): CompletableFuture[TransportClient] = {
    val future = new CompletableFuture[TransportClient]()
    clientCreationExecutor.execute(() => {
      try {
        val shuffleClient = createClient(mapId, remoteHost, remotePort)
        future.complete(shuffleClient)
      } catch {
        case th: Throwable =>
          future.completeExceptionally(th)
      }
    })
    future
  }

  protected def onTermAckResponse(shuffleWriterId: Int): Unit = {
    terminationAckControlMessageSet.add(shuffleWriterId.toLong)
    val curSent = terminationAckControlMessageSet.size()
    val totalSentNeeded = totalNumShuffleWriters.get()
    logDebug(log"Termination ack message sent successfully to shuffle writer " +
      log"${MDC(LogKeys.SHUFFLE_WRITER_ID, shuffleWriterId)}." +
      log" ${MDC(LogKeys.NUM_TERMINATION_ACKS, curSent)} / " +
      log"${MDC(LogKeys.NUM_SHUFFLE_WRITERS, totalSentNeeded)} sent successfully.")

    // if we have sent all term acks successfully
    if (totalSentNeeded > 0 && curSent == totalSentNeeded) {
      allTermAcksSentNotice.release()
    }
  }

  /**
   * Verifies the checksum of a DataMessage if checksum is enabled.
   * @throws SparkRuntimeException if checksum verification fails
   */
  private def verifyDataMessageChecksum(dataMessage: DataMessage, data: io.netty.buffer.ByteBuf)
      : Unit = {
    if (shuffleChecksum != null) {
      shuffleChecksum.reset()
      shuffleChecksum.updateChecksum(data, data.readerIndex(), data.readableBytes())
      val calculatedChecksum = shuffleChecksum.getValue()
      if (dataMessage.checksum != calculatedChecksum) {
        throw new SparkRuntimeException(
          errorClass = "STREAMING_SHUFFLE_CHECKSUM_VERIFICATION_FAILED",
          messageParameters = Map(
            "writerId" -> dataMessage.shuffleWriterId.toString,
            "expectedChecksum" -> dataMessage.checksum.toString,
            "calculatedChecksum" -> calculatedChecksum.toString,
            "dataLength" -> data.readableBytes().toString
          )
        )
      }
    }
  }

  // visible for test
  protected def createClient(mapId: Int, remoteHost: String, remotePort: Int): TransportClient = {
    val handler = clientHandler.getOrElse(new StreamingShuffleClientHandler(
      mapId,
      context.partitionId(),
      messageQueue,
      streamingShuffleHandle.shuffleId,
      perWriterByteLimit,
      context,
      activeErrorNotifier
    ))
    handler.setOnTermAckResponseHandler(onTermAckResponse)
    sharedExecutorClient match {
      case Some(executorClient) =>
        val client = executorClient.register(
          streamingShuffleHandle.shuffleId,
          mapId,
          context.partitionId(),
          remoteHost,
          remotePort,
          handler)
        logicalClientHandlers.put(mapId.toLong, handler)
        client
      case None =>
        sharedClientFactory match {
          case Some(factory) =>
            factory.createUnmanagedClient(remoteHost, remotePort, handler)
          case None =>
            val clientContext = new TransportContext(clientConf, handler)
            val factory = clientContext.createClientFactory()
            clientFactories.add(factory)
            factory.createClient(remoteHost, remotePort)
        }
    }
  }

  private def checkTaskFailure(): Unit = {
    context.getTaskFailure.foreach(throw _)
    // Surface any background error on the task thread so that markTaskFailed and
    // markTaskCompleted are called from this thread, ensuring completion listeners
    // (including cleanupResources) run without contention.
    activeErrorNotifier.throwErrorIfExists()
    if (context.isInterrupted()) {
      throw new InterruptedException("Task interrupted. Exiting read loop.")
    }
  }

  override def read(): Iterator[Product2[K, C]] = {
    val serializerInstance = streamingShuffleHandle.dependency.serializer.newInstance()
    val byteBufSerializer = serializerInstance match {
      case serializer: StreamingShuffleSerializerInstance => Some(serializer)
      case _ => None
    }
    // Termination messages are added to a set that contains the shuffle writer ids that have sent
    // termination messages. When the set size reaches the number of shuffle writers, we know
    // that we will not receive any future messages, and the reader can be closed. When a data
    // message is read, the actual data (UnsafeRow) is extracted and emitted through the iterator.
    val terminationControlMessageSet = collection.mutable.Set[Long]()
    var lastIdleDiagnosticsNanos = 0L

    /**
     * Returns true if the reader should stop after handling the termination message, which means
     * we have received termination messages from all shuffle writers.
     */
    def handleTerminationMessage(msg: TerminationControlMessage): Boolean = {
      val finishedId = msg.shuffleWriterId
      terminationControlMessageSet += finishedId
      val logMsg = if (totalNumShuffleWriters.get() > 0) {
        log"Got termination message from ${MDC(LogKeys.SHUFFLE_WRITER_ID, finishedId)}." +
          log" ${MDC(LogKeys.NUM_TERMINATION_ACKS, terminationControlMessageSet.size)} / ${
            MDC(LogKeys.NUM_SHUFFLE_WRITERS, totalNumShuffleWriters.get())}" +
          log" termination messages received."
      } else {
        log"Got termination message from ${MDC(LogKeys.SHUFFLE_WRITER_ID, finishedId)}." +
          log" ${MDC(LogKeys.NUM_TERMINATION_ACKS, terminationControlMessageSet.size)}" +
          log" termination messages received."
      }
      logDebug(logMsg)
      if (totalNumShuffleWriters.get() > 0
        && totalNumShuffleWriters.get() == terminationControlMessageSet.size) {
        logDebug(log"Got termination messages from all shuffle writers. Shutting down.")

        // The writer-side ACK callbacks are asynchronous. Waiting for every callback here can
        // deadlock a chained pipelined shuffle: the downstream reader is waiting for upstream
        // termination while the upstream writer is waiting for this reader's ACK. Keep the
        // strict behavior as the default for compatibility, but allow the chained path to finish
        // after all ACKs have been submitted.
        if (conf.get(STREAMING_SHUFFLE_READER_WAIT_FOR_TERMINATION_ACKS)) {
          while (!allTermAcksSentNotice.tryAcquire(100, TimeUnit.MILLISECONDS)) {
            checkTaskFailure()
          }
        }
        true
      } else {
        false
      }
    }

    def handleDataMessage(dataMessage: DataMessage): Iterator[(K, C)] = {
      currentDataMessage = dataMessage
      var decompressedBuffer: io.netty.buffer.ByteBuf = null
      val recordData = if (dataMessage.uncompressedSize == dataMessage.dataSize) {
        dataMessage.getRecordData()
      } else {
        val decompressor = compressionCodec.getOrElse(throw new IllegalStateException(
          "Received a compressed streaming shuffle message while spark.shuffle.compress=false"))
        decompressedBuffer = dataMessage.data.alloc().directBuffer(
          dataMessage.uncompressedSize, dataMessage.uncompressedSize)
        try {
          val compressed = dataMessage.getRecordData()
          val source = compressed.nioBuffer(compressed.readerIndex(), dataMessage.dataSize)
          val destination = decompressedBuffer.nioBuffer(0, dataMessage.uncompressedSize)
          val uncompressedBytes = decompressor.decompress(
            source, source.position(), dataMessage.dataSize,
            destination, destination.position(), dataMessage.uncompressedSize)
          if (uncompressedBytes != dataMessage.uncompressedSize) {
            throw new IllegalArgumentException(
              s"Compressed streaming shuffle message produced $uncompressedBytes bytes, " +
                s"expected ${dataMessage.uncompressedSize}")
          }
          decompressedBuffer.writerIndex(dataMessage.uncompressedSize)
          decompressedBuffer
        } catch {
          case t: Throwable =>
            decompressedBuffer.release()
            decompressedBuffer = null
            throw t
        }
      }
      verifyDataMessageChecksum(dataMessage, recordData)
      val deserializedIterator = byteBufSerializer match {
        case Some(serializer) =>
          serializer.keyValueIteratorFromByteBuf(recordData).asInstanceOf[Iterator[(K, C)]]
        case None =>
          serializerInstance
            .deserializeStream(new ByteBufInputStream(recordData))
            .asKeyValueIterator
            .asInstanceOf[Iterator[(K, C)]]
      }
      assert(
        deserializedIterator.hasNext,
        formatMessage(
          s"data message that had no data to deserialize:" +
            s" ${dataMessage.data}. Readable bytes: " +
            s"${dataMessage.data.readableBytes()}"
        )
      )
      new NextIterator[(K, C)] {
        override def getNext(): (K, C) = {
          if (!deserializedIterator.hasNext) {
            finished = true
            null.asInstanceOf[(K, C)]
          } else {
            deserializedIterator.next()
          }
        }
        override def close(): Unit = {
          if (decompressedBuffer != null) {
            decompressedBuffer.release()
            decompressedBuffer = null
          }
          dataMessage.release()
          currentDataMessage = null
        }
      }
    }

    new StreamingShuffleReaderIteratorFactory().create(
      messageQueue,
      handleTerminationMessage,
      handleDataMessage,
      checkTaskFailure,
      () => totalNumShuffleWriters.get() == 0,
      () => preparedSession match {
        case Some(session) =>
          session.repairIdleCreditWindows()
          val now = System.nanoTime()
          if (now - lastIdleDiagnosticsNanos >= TimeUnit.SECONDS.toNanos(30L)) {
            logWarning(s"Streaming shuffle reader remains idle: " +
              session.idleDiagnostics(terminationControlMessageSet.toSet))
            lastIdleDiagnosticsNanos = now
          }
        case None =>
          logicalClientHandlers.forEach { (writerId, handler) =>
            val client = clientMap.get(writerId)
            if (client != null) handler.repairCreditWindow(client)
          }
      },
      recordQueueWaitNanos
    )
  }
}
