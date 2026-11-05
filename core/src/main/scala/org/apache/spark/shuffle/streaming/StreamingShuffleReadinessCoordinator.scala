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

import scala.collection.mutable
import scala.util.{Failure, Success, Try}
import scala.util.control.NonFatal

import org.apache.spark.rpc.RpcEndpointRef
import org.apache.spark.util.{ThreadUtils, Utils}

private[spark] case class StreamingShuffleReaderKey(
    stageId: Int,
    stageAttemptId: Int,
    taskIndex: Int)

private[spark] case class StreamingShuffleReaderPreparation(
    key: StreamingShuffleReaderKey,
    executorId: String,
    partitionId: Int,
    shuffleIds: Seq[Int])

private[spark] case class StreamingShuffleReaderReadiness(
    executorId: String,
    ready: Boolean,
    failure: Option[String],
    prepared: Boolean = false)

/**
 * Driver-side control plane for the streaming shuffle's executor-owned receive buffers.
 * The scheduler supplies placements, reads readiness snapshots, and retires stage attempts. It
 * does not construct inboxes or wait for their RPCs. All state is protected by this monitor;
 * RPCs are asynchronous, with at most one preparation batch outstanding per executor.
 *
 * The notification callback must only enqueue a scheduling wakeup, never acquire the scheduler
 * lock: resource offers enter this coordinator while holding that lock. RPC callbacks never
 * access a TaskSetManager. Preparation failure is retained until the scheduler retires the stage,
 * so a subsequent offer cannot silently replace an inbox containing the only copy of live data.
 */
private[spark] class StreamingShuffleReadinessCoordinator {
  private class Entry(
      val request: StreamingShuffleReaderPreparation,
      val endpoint: RpcEndpointRef) {
    private val ordinals = mutable.HashMap.empty[Int, Int]
    val inboxes: Seq[StreamingShuffleReceiveInboxId] = request.shuffleIds.map { shuffleId =>
      val ordinal = ordinals.getOrElse(shuffleId, 0)
      ordinals.update(shuffleId, ordinal + 1)
      StreamingShuffleReceiveInboxId(shuffleId, request.key.stageId,
        request.key.stageAttemptId, request.partitionId, -1L, ordinal)
    }
    val drainReady = mutable.HashSet.empty[StreamingShuffleReceiveInboxId]
    var sent = false
    var acknowledged = false
    var failure: Option[String] = None
  }

  private val endpoints = mutable.HashMap.empty[String, RpcEndpointRef]
  private val entries = mutable.HashMap.empty[StreamingShuffleReaderKey, Entry]
  private val inboxOwners =
    mutable.HashMap.empty[(String, StreamingShuffleReceiveInboxId), Entry]
  private val inFlight = mutable.HashMap.empty[String, Seq[Entry]]
  private var closed = false
  private var onUpdate: () => Unit = () => ()

  def setOnUpdate(callback: () => Unit): Unit = synchronized {
    if (!closed) onUpdate = callback
  }

  def registerExecutor(executorId: String, endpoint: RpcEndpointRef): Boolean = synchronized {
    if (closed) return false
    endpoints.get(executorId).filter(_ != endpoint).foreach { _ => removeExecutor(executorId) }
    endpoints.put(executorId, endpoint)
    onUpdate()
    true
  }

  def executorIds: Seq[String] = synchronized { endpoints.keys.toSeq }

  def snapshot: Map[StreamingShuffleReaderKey, StreamingShuffleReaderReadiness] = synchronized {
    entries.iterator.map { case (key, entry) =>
      key -> StreamingShuffleReaderReadiness(entry.request.executorId,
        entry.failure.isEmpty && entry.acknowledged &&
          entry.inboxes.forall(entry.drainReady.contains), entry.failure,
        prepared = entry.acknowledged && entry.failure.isEmpty)
    }.toMap
  }

  def prepare(requests: Seq[StreamingShuffleReaderPreparation]): Unit = synchronized {
    if (closed) return
    requests.foreach { request =>
      if (!entries.contains(request.key)) {
        endpoints.get(request.executorId).foreach { endpoint =>
          val entry = new Entry(request, endpoint)
          entries.put(request.key, entry)
          entry.inboxes.foreach(id => inboxOwners.put((request.executorId, id), entry))
        }
      }
    }
    requests.iterator.map(_.executorId).toSet.foreach(dispatch)
  }

  private def dispatch(executorId: String): Unit = {
    if (closed || inFlight.contains(executorId)) return
    val batch = entries.valuesIterator.filter { entry =>
      entry.request.executorId == executorId && !entry.sent && entry.failure.isEmpty
    }.toSeq
    if (batch.nonEmpty) {
      batch.foreach(_.sent = true)
      inFlight.put(executorId, batch)
      // Enqueue while holding the monitor so cancellation cannot overtake request publication.
      // ask() uses the normal RPC timeout and does not wait for the executor's reply.
      try {
        batch.head.endpoint.ask[Boolean](
          PrepareStreamingShuffleReceiveInboxes(batch.flatMap(_.inboxes))).onComplete { result =>
          complete(executorId, batch, result)
        }(ThreadUtils.sameThread)
      } catch {
        case NonFatal(error) => complete(executorId, batch, Failure(error))
      }
    }
  }

  private def complete(executorId: String, batch: Seq[Entry], result: Try[Boolean]): Unit =
    synchronized {
      if (inFlight.get(executorId).exists(_ eq batch)) inFlight.remove(executorId)
      batch.foreach { entry =>
        if (!closed && entries.get(entry.request.key).exists(_ eq entry) &&
            entry.failure.isEmpty) {
          result match {
            case Success(true) => entry.acknowledged = true
            case _ =>
              val detail = result.failed.toOption.map(_.toString)
                .getOrElse("executor rejected receive preparation")
              entry.failure = Some(s"Streaming shuffle receive preparation failed on " +
                s"executor $executorId: $detail")
              release(entry)
          }
        } else {
          // A cancelled batch may have been prepared remotely after cancellation. Release again
          // on completion, using its captured endpoint, never a replacement executor's endpoint.
          release(entry)
        }
      }
      dispatch(executorId)
      if (!closed) onUpdate()
    }

  def markDrainReady(executorId: String, id: StreamingShuffleReceiveInboxId): Unit = synchronized {
    inboxOwners.get((executorId, id)).foreach { entry =>
      if (entry.failure.isEmpty && entry.drainReady.add(id)) onUpdate()
    }
  }

  private def release(entry: Entry): Unit = {
    entry.inboxes.foreach { id =>
      val address = (entry.request.executorId, id)
      if (inboxOwners.get(address).exists(_ eq entry)) inboxOwners.remove(address)
      if (entry.sent) {
        Utils.tryLogNonFatalError { entry.endpoint.send(ReleaseStreamingShuffleReceiveInbox(id)) }
      }
    }
    entry.drainReady.clear()
  }

  private def retire(predicate: Entry => Boolean): Unit = {
    entries.valuesIterator.filter(predicate).toSeq.foreach { entry =>
      entries.remove(entry.request.key)
      release(entry)
    }
  }

  def releaseStage(stageId: Int, stageAttemptId: Int): Unit = synchronized {
    retire(entry => entry.request.key.stageId == stageId &&
      entry.request.key.stageAttemptId == stageAttemptId)
  }

  def unregisterShuffle(shuffleId: Int): Unit = synchronized {
    retire(_.request.shuffleIds.contains(shuffleId))
  }

  def removeExecutor(executorId: String): Unit = synchronized {
    endpoints.remove(executorId)
    inFlight.remove(executorId)
    entries.valuesIterator.filter(_.request.executorId == executorId).foreach { entry =>
      entry.failure = Some(s"Prepared streaming shuffle reader lost executor $executorId")
      release(entry)
    }
    if (!closed) onUpdate()
  }

  def close(): Unit = synchronized {
    closed = true
    onUpdate = () => ()
    retire(_ => true)
    endpoints.clear()
    inFlight.clear()
  }
}
