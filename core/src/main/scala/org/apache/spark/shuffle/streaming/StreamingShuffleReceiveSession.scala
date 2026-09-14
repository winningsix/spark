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

import java.util.concurrent.{CompletableFuture, ConcurrentHashMap, Semaphore}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger}

import scala.collection.mutable
import scala.jdk.CollectionConverters._

import org.apache.spark.{ShuffleLocationResponse, StreamingShuffleTaskLocation}
import org.apache.spark.internal.Logging
import org.apache.spark.network.client.TransportClient
import org.apache.spark.util.{ErrorNotifier, Utils}

/**
 * One receive lifecycle, independent of who polls locations or supplies connection threads.
 * Task readers and prepared inboxes retain their own scheduling and memory-budget policies.
 */
private[streaming] final class StreamingShuffleReceiveSession(
    shuffleId: Int,
    val errorNotifier: ErrorNotifier,
    closeRoute: (Long, TransportClient, StreamingShuffleClientHandler) => Unit,
    onDiscoveryFinished: () => Unit = () => (),
    onDrainReady: () => Unit = () => ()) extends Logging {
  val clients = new ConcurrentHashMap[Long, TransportClient]()
  private val handlers = new ConcurrentHashMap[Long, StreamingShuffleClientHandler]()
  private val clientFutures = new ConcurrentHashMap[Long, CompletableFuture[Void]]()
  private val mapIndexes = mutable.HashSet.empty[Int]
  private val closed = new AtomicBoolean(false)
  private val discoveryFinished = new AtomicBoolean(false)
  private val routeLifecycleLock = new Object

  val totalNumShuffleWriters = new AtomicInteger(-1)
  val terminationAckControlMessageSet = ConcurrentHashMap.newKeySet[Long]()
  val allTermAcksSentNotice = new Semaphore(0)

  def isClosed: Boolean = closed.get()
  def isDiscoveryFinished: Boolean = discoveryFinished.get()

  private def finishDiscovery(): Unit = {
    if (discoveryFinished.compareAndSet(false, true)) onDiscoveryFinished()
  }

  def onWriterSnapshot(
      snapshot: ShuffleLocationResponse,
      initialize: Int => Unit)(
      connect: Map[Long, StreamingShuffleTaskLocation] =>
        Map[Long, CompletableFuture[Void]]): Unit = synchronized {
    if (isClosed || isDiscoveryFinished) return
    val ShuffleLocationResponse(locations, numWriters) = snapshot
    if (totalNumShuffleWriters.compareAndSet(-1, numWriters)) initialize(numWriters)
    require(totalNumShuffleWriters.get() == numWriters,
      s"Writer count changed for shuffle $shuffleId: " +
        s"expected=${totalNumShuffleWriters.get()} actual=$numWriters")
    // Empty input has no terminal frame to make a prepared inbox drain-ready.
    if (numWriters == 0) onDrainReady()
    // A new physical writer attempt for an already discovered logical map is not another input.
    val fresh = locations.filter { case (mapId, location) =>
      val duplicate = location.mapIndex >= 0 && mapIndexes.contains(location.mapIndex)
      if (!duplicate && !clientFutures.containsKey(mapId)) {
        if (location.mapIndex >= 0) mapIndexes += location.mapIndex
        true
      } else {
        false
      }
    }
    require(clientFutures.size() + fresh.size <= numWriters,
      s"Streaming shuffle discovered too many writer locations for $shuffleId: " +
        s"known=${clientFutures.keySet()} fresh=${fresh.keys} expected=$numWriters")
    val pending = connect(fresh)
    clientFutures.putAll(pending.asJava)
    pending.values.toSeq.distinct.foreach(_.whenComplete { (_, error) =>
      if (error != null) failDiscovery(Option(error.getCause).getOrElse(error))
    })
    if (clientFutures.size() == numWriters) finishDiscovery()
  }

  def awaitConnections(): Unit = {
    CompletableFuture.allOf(clientFutures.values().asScala.toSeq: _*).get()
    require(clients.size() == totalNumShuffleWriters.get(),
      s"Shuffle $shuffleId connected ${clients.size()} / ${totalNumShuffleWriters.get()} " +
        s"writers: connected=${clients.keySet()} discovered=${clientFutures.keySet()}")
  }

  /** Closing and installing a completed connection share one ownership boundary. */
  def registerRoute(
      writerId: Long,
      client: TransportClient,
      handler: StreamingShuffleClientHandler): Unit = routeLifecycleLock.synchronized {
    if (isClosed) {
      closeRoute(writerId, client, handler)
    } else {
      handlers.put(writerId, handler)
      clients.put(writerId, client)
    }
  }

  def onTerminationAck(writerId: Int): Unit = {
    if (terminationAckControlMessageSet.add(writerId.toLong) &&
        terminationAckControlMessageSet.size() == totalNumShuffleWriters.get()) {
      allTermAcksSentNotice.release()
      onDrainReady()
    }
  }

  def routes: Seq[(TransportClient, StreamingShuffleClientHandler)] = {
    handlers.entrySet().asScala.flatMap { entry =>
      Option(clients.get(entry.getKey)).map(_ -> entry.getValue)
    }.toSeq
  }

  def idleDiagnostics(readerTerminations: Set[Long]): String = {
    val snapshot = handlers.entrySet().asScala.toSeq
    val missing = snapshot.iterator.collect {
      case entry if !entry.getValue.terminationReceivedForDiagnostics =>
        s"${entry.getKey}:${entry.getValue.lastSequenceNumberForDiagnostics}"
    }.take(16).mkString(",")
    s"expectedWriters=${totalNumShuffleWriters.get()}, discovered=${clientFutures.size()}, " +
      s"connected=${clients.size()}, handlers=${handlers.size()}, handlerTerminations=" +
      s"${snapshot.count(_.getValue.terminationReceivedForDiagnostics)}, " +
      s"queuedTerminations=${readerTerminations.size}, ackedTerminations=" +
      s"${terminationAckControlMessageSet.size()}, missingHandlerWriter:lastSeq=[$missing]"
  }

  def failDiscovery(error: Throwable): Unit = {
    finishDiscovery()
    if (!isClosed) {
      logError(s"Receive discovery failed for shuffle $shuffleId", error)
      errorNotifier.markError(error)
      onDrainReady()
    }
  }

  def close(): Unit = {
    if (closed.compareAndSet(false, true)) {
      finishDiscovery()
      routeLifecycleLock.synchronized {
        clients.forEach { (writerId, client) =>
          Utils.tryLogNonFatalError { closeRoute(writerId, client, handlers.get(writerId)) }
        }
        handlers.clear()
        clients.clear()
      }
    }
  }
}
