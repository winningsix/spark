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

import org.apache.spark.{ShuffleDependency, SparkContext, SparkEnv, SparkException, SparkRuntimeException, TaskContext}
import org.apache.spark.internal.Logging
import org.apache.spark.internal.config.{EXECUTOR_CORES, EXECUTOR_ID,
  STREAMING_SHUFFLE_ELASTIC_PRODUCERS_ENABLED, STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED,
  STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED}
import org.apache.spark.network.TransportContext
import org.apache.spark.network.client.TransportClientFactory
import org.apache.spark.network.netty.SparkTransportConf
import org.apache.spark.network.server.NoOpRpcHandler
import org.apache.spark.network.shuffle.streaming.{DataMessage, StreamingShuffleMessage, StreamingShuffleMessageType, TerminationControlMessage}
import org.apache.spark.shuffle._

class StreamingShuffleHandle[K, V, C](shuffleId: Int, dependency: ShuffleDependency[K, V, C])
  extends BaseShuffleHandle[K, V, C](shuffleId, dependency)

object StreamingShuffleManager extends Logging {
  // Exposed for testing
  private[spark] val QUERY_ID_PROPERTY_KEY = "sql.streaming.queryId"
  // Since above is not applicable for batch query, we use below id to track error for batch
  // query with streaming shuffle
  private val QUERY_EXECUTION_ID_PROPERTY_KEY = "spark.sql.execution.id"

  def getQueryId(context: TaskContext): String = {
    Option(context.getLocalProperty(QUERY_ID_PROPERTY_KEY))
      .orElse(Option(context.getLocalProperty(QUERY_EXECUTION_ID_PROPERTY_KEY)))
      .getOrElse(throw SparkException.internalError(
        "Streaming shuffle requires the query id or SQL execution id local property to be set"))
  }

  /* Called from the reader side to get the writerId associated with a message */
  def getWriterId(message: StreamingShuffleMessage): Int = {
    message.messageType() match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW =>
        message.asInstanceOf[DataMessage].shuffleWriterId
      case StreamingShuffleMessageType.TERMINATION_CONTROL_MESSAGE =>
        message.asInstanceOf[TerminationControlMessage].shuffleWriterId
      case _ =>
        // Should not reach here
        throw streamingShuffleUnexpectedMessageType(message.messageType());
    }
  }

  def streamingShuffleIncorrectSequenceNumber(
      messageType: StreamingShuffleMessageType,
      writerId: Int,
      readerId: Int,
      expSeqNum: Long,
      actSeqNum: Long): RuntimeException = {
    new SparkRuntimeException(
      errorClass = "STREAMING_SHUFFLE_INCORRECT_SEQUENCE_NUMBER",
      messageParameters = Map(
        "messageType" -> messageType.toString,
        "writerId" -> writerId.toString,
        "readerId" -> readerId.toString,
        "expSeqNum" -> expSeqNum.toString,
        "actSeqNum" -> actSeqNum.toString))
  }

  def streamingShuffleUnexpectedMessageType(
      messageType: StreamingShuffleMessageType): RuntimeException = {
    new SparkRuntimeException(
      errorClass = "STREAMING_SHUFFLE_UNEXPECTED_MESSAGE_TYPE",
      messageParameters = Map("messageType" -> messageType.toString))
  }
}

private[spark] class StreamingShuffleManager
  extends PipelinedShuffleManager
  with PipelinedShuffleSchedulingProvider
  with Logging {

  logInfo(log"Using StreamingShuffleManager")

  override def schedulingRequirements(
      group: PipelinedShuffleGroupMetadata): PipelinedGroupSchedulingRequirements = {
    if (SparkEnv.get.conf.get(STREAMING_SHUFFLE_ELASTIC_PRODUCERS_ENABLED)) {
      PipelinedGroupSchedulingRequirements(
        residencyPolicy = ReaderResidencyWithElasticProducers())
    } else {
      PipelinedGroupSchedulingRequirements()
    }
  }

  @volatile private var readerClientFactory: TransportClientFactory = _
  @volatile private var sharedExecutorClient: StreamingShuffleExecutorClient = _
  @volatile private var sharedWriterServer: StreamingShuffleExecutorServer = _

  private def getSharedWriterServer: StreamingShuffleExecutorServer = {
    var server = sharedWriterServer
    if (server == null) synchronized {
      server = sharedWriterServer
      if (server == null) {
        server = new StreamingShuffleExecutorServer()
        sharedWriterServer = server
      }
    }
    server
  }

  /**
   * A single client factory is shared by all streaming-shuffle readers in this executor. Each
   * reader still creates an unmanaged connection with its own task-scoped RPC handler, but those
   * connections share the factory's Netty event loop and allocator instead of creating one event
   * loop per reader-writer pair.
   */
  private def getReaderClientFactory: TransportClientFactory = {
    var factory = readerClientFactory
    if (factory == null) synchronized {
      factory = readerClientFactory
      if (factory == null) {
        val conf = SparkEnv.get.conf
        val role = conf.get(EXECUTOR_ID).map { id =>
          if (SparkContext.isDriver(id)) "driver" else "executor"
        }
        val clientConf = SparkTransportConf.fromSparkConf(
          conf,
          "streaming-shuffle-reader-shared",
          math.max(1, conf.get(EXECUTOR_CORES)),
          role)
        val clientContext = new TransportContext(
          clientConf, new NoOpRpcHandler(), true, true)
        factory = clientContext.createClientFactory()
        readerClientFactory = factory
      }
    }
    factory
  }

  private def getSharedExecutorClient: StreamingShuffleExecutorClient = {
    var client = sharedExecutorClient
    if (client == null) synchronized {
      client = sharedExecutorClient
      if (client == null) {
        client = new StreamingShuffleExecutorClient()
        sharedExecutorClient = client
      }
    }
    client
  }

  override def registerShuffle[K, V, C](
      shuffleId: Int,
      dependency: ShuffleDependency[K, V, C]): ShuffleHandle = {
    new StreamingShuffleHandle(shuffleId, dependency)
  }

  override def getWriter[K, V](
      handle: ShuffleHandle,
      mapId: Long,
      context: TaskContext,
      metrics: ShuffleWriteMetricsReporter): ShuffleWriter[K, V] = {
    val streamingShuffleHandle = handle.asInstanceOf[StreamingShuffleHandle[K, V, _]]
    val sharedServer = if (SparkEnv.get.conf.get(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED)) {
      Some(getSharedWriterServer)
    } else {
      None
    }
    new StreamingShuffleWriter[K, V](
      streamingShuffleHandle, mapId, context, sharedExecutorServer = sharedServer)
  }

  /**
   * For the streaming shuffle, the startMapIndex, endMapIndex, startPartition, and endPartition
   * arguments are not relevant.
   */
  override def getReader[K, C](
      handle: ShuffleHandle,
      startMapIndex: Int,
      endMapIndex: Int,
      startPartition: Int,
      endPartition: Int,
      context: TaskContext,
      metrics: ShuffleReadMetricsReporter): ShuffleReader[K, C] = {
    val streamingShuffleHandle = handle.asInstanceOf[StreamingShuffleHandle[K, _, C]]
    val conf = SparkEnv.get.conf
    val useSharedConnections = conf.get(STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED)
    require(!useSharedConnections || conf.get(STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED),
      s"${STREAMING_SHUFFLE_SHARED_CONNECTIONS_ENABLED.key} requires " +
        s"${STREAMING_SHUFFLE_SHARED_WRITER_SERVER_ENABLED.key}")
    if (useSharedConnections) {
      new StreamingShuffleReader[K, C](
        streamingShuffleHandle, context, sharedExecutorClient = Some(getSharedExecutorClient))
    } else {
      new StreamingShuffleReader[K, C](
        streamingShuffleHandle, context, sharedClientFactory = Some(getReaderClientFactory))
    }
  }

  override def unregisterShuffle(shuffleId: Int): Boolean = {
    // No manager-side state to release here: the driver's StreamingShuffleOutputTracker is
    // unregistered in ContextCleaner.doCleanupShuffle (its state is driver-only), and per-task
    // writer and reader resources are released via task completion listeners.
    true
  }

  override def stop(): Unit = synchronized {
    if (readerClientFactory != null) {
      readerClientFactory.close()
      readerClientFactory = null
    }
    if (sharedExecutorClient != null) {
      sharedExecutorClient.close()
      sharedExecutorClient = null
    }
    if (sharedWriterServer != null) {
      sharedWriterServer.close()
      sharedWriterServer = null
    }
  }
}
