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

import java.util.concurrent.TimeoutException

import scala.collection.mutable.ArrayBuffer
import scala.concurrent.{Future, Promise}
import scala.reflect.ClassTag

import org.apache.spark.{SparkConf, SparkFunSuite}
import org.apache.spark.rpc.{RpcAddress, RpcEndpointRef, RpcTimeout}

class StreamingShuffleReadinessCoordinatorSuite extends SparkFunSuite {
  private class Endpoint extends RpcEndpointRef(new SparkConf(false)) {
    val batches = ArrayBuffer.empty[Seq[StreamingShuffleReceiveInboxId]]
    val replies = ArrayBuffer.empty[Promise[Boolean]]
    val releases = ArrayBuffer.empty[StreamingShuffleReceiveInboxId]
    override def address: RpcAddress = RpcAddress("localhost", 1)
    override def name: String = "receive-test"
    override def send(message: Any): Unit = message match {
      case ReleaseStreamingShuffleReceiveInbox(id) => releases += id
    }
    override def ask[T: ClassTag](message: Any, timeout: RpcTimeout): Future[T] = {
      val PrepareStreamingShuffleReceiveInboxes(ids) = message: @unchecked
      batches += ids
      val reply = Promise[Boolean]()
      replies += reply
      reply.future.asInstanceOf[Future[T]]
    }
  }

  private def request(index: Int = 0, attempt: Int = 0, executor: String = "e1") = {
    StreamingShuffleReaderPreparation(
      StreamingShuffleReaderKey(1, attempt, index), executor, index, Seq(7, 8, 7))
  }

  test("readiness requires the prepare ACK and every input, including reused inputs") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    val reader = request()
    coordinator.prepare(Seq(reader))
    val ids = endpoint.batches.head
    assert(ids.map(_.readerOrdinal) === Seq(0, 0, 1))
    ids.foreach(coordinator.markDrainReady("e1", _))
    assert(!coordinator.snapshot(reader.key).ready)
    endpoint.replies.head.success(true)
    assert(coordinator.snapshot(reader.key).ready)
    coordinator.close()
  }

  test("an ACK alone and a partially ready input set cannot launch a reader") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    val reader = request()
    coordinator.prepare(Seq(reader))
    endpoint.replies.head.success(true)
    assert(!coordinator.snapshot(reader.key).ready)
    endpoint.batches.head.init.foreach(coordinator.markDrainReady("e1", _))
    assert(!coordinator.snapshot(reader.key).ready)
    coordinator.markDrainReady("e1", endpoint.batches.head.last)
    assert(coordinator.snapshot(reader.key).ready)
    coordinator.close()
  }

  test("offers coalesce behind one in-flight batch without blocking other executors") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val first = new Endpoint
    val second = new Endpoint
    coordinator.registerExecutor("e1", first)
    coordinator.registerExecutor("e2", second)
    coordinator.prepare(Seq(request()))
    val queued = (1 to 10).map(i => request(index = i))
    (1 to 5).foreach { _ => coordinator.prepare(queued) }
    coordinator.prepare(Seq(request(index = 11, executor = "e2")))
    assert(first.batches.size === 1)
    assert(second.batches.size === 1)
    first.replies.head.success(true)
    assert(first.batches.size === 2)
    assert(first.batches(1).size === 30)
    coordinator.close()
    first.replies(1).success(true)
    second.replies.head.success(true)
  }

  test("cancel during prepare fences late readiness and ACK without touching a new attempt") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    val oldReader = request()
    coordinator.prepare(Seq(oldReader))
    val oldIds = endpoint.batches.head
    coordinator.releaseStage(1, 0)
    coordinator.releaseStage(1, 0)
    assert(endpoint.releases.toSeq === oldIds)
    val newReader = request(attempt = 1)
    coordinator.prepare(Seq(newReader))
    oldIds.foreach(coordinator.markDrainReady("e1", _))
    endpoint.replies.head.success(true)
    assert(coordinator.snapshot.keySet === Set(newReader.key))
    assert(!coordinator.snapshot(newReader.key).ready)
    assert(endpoint.releases.toSeq === oldIds ++ oldIds)
    val newIds = endpoint.batches(1)
    newIds.foreach(coordinator.markDrainReady("e1", _))
    endpoint.replies(1).success(true)
    assert(coordinator.snapshot(newReader.key).ready)
    coordinator.close()
  }

  test("cancelling queued readers never sends their prepare or release RPCs") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    val active = request()
    coordinator.prepare(Seq(active))
    coordinator.prepare(Seq(request(attempt = 1)))
    coordinator.releaseStage(1, 1)
    endpoint.replies.head.success(true)
    assert(endpoint.batches.size === 1)
    assert(endpoint.releases.isEmpty)
    assert(coordinator.snapshot.keySet === Set(active.key))
    coordinator.close()
  }

  Seq(false, true).foreach { timeout =>
    test(s"prepare failure releases the batch without silently retrying: timeout=$timeout") {
      val coordinator = new StreamingShuffleReadinessCoordinator
      val endpoint = new Endpoint
      coordinator.registerExecutor("e1", endpoint)
      val readers = Seq(request(), request(index = 1))
      coordinator.prepare(readers)
      val ids = endpoint.batches.head
      ids.foreach(coordinator.markDrainReady("e1", _))
      if (timeout) endpoint.replies.head.failure(new TimeoutException("test timeout"))
      else endpoint.replies.head.success(false)
      assert(coordinator.snapshot.values.forall(s => !s.ready && s.failure.isDefined))
      assert(endpoint.releases.toSeq === ids)
      coordinator.prepare(readers)
      assert(endpoint.batches.size === 1)
      ids.foreach(coordinator.markDrainReady("e1", _))
      assert(coordinator.snapshot.values.forall(!_.ready))
      coordinator.close()
    }
  }

  test("executor loss retains failure and a late ACK cleans only the original endpoint") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val oldEndpoint = new Endpoint
    val replacement = new Endpoint
    coordinator.registerExecutor("e1", oldEndpoint)
    val oldReader = request()
    coordinator.prepare(Seq(oldReader))
    coordinator.removeExecutor("e1")
    assert(coordinator.snapshot(oldReader.key).failure.isDefined)
    coordinator.registerExecutor("e1", replacement)
    val newReader = request(attempt = 1)
    coordinator.prepare(Seq(newReader))
    oldEndpoint.replies.head.success(true)
    assert(replacement.releases.isEmpty)
    assert(!coordinator.snapshot(newReader.key).ready)
    replacement.batches.head.foreach(coordinator.markDrainReady("e1", _))
    replacement.replies.head.success(true)
    assert(coordinator.snapshot(newReader.key).ready)
    coordinator.close()
  }

  test("shuffle cleanup preserves unrelated receive state and ignores late notifications") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    val first = request().copy(shuffleIds = Seq(7))
    val other = request(index = 1).copy(shuffleIds = Seq(9))
    coordinator.prepare(Seq(first, other))
    endpoint.replies.head.success(true)
    coordinator.unregisterShuffle(7)
    endpoint.batches.head.foreach(coordinator.markDrainReady("e1", _))
    assert(coordinator.snapshot.keySet === Set(other.key))
    assert(coordinator.snapshot(other.key).ready)
    assert(endpoint.releases.map(_.shuffleId).toSeq === Seq(7))
    coordinator.close()
  }

  test("closing with an outstanding prepare cannot revive scheduling or recreate state") {
    val coordinator = new StreamingShuffleReadinessCoordinator
    val endpoint = new Endpoint
    coordinator.registerExecutor("e1", endpoint)
    var updates = 0
    coordinator.setOnUpdate(() => updates += 1)
    coordinator.prepare(Seq(request()))
    coordinator.close()
    coordinator.close()
    endpoint.batches.head.foreach(coordinator.markDrainReady("e1", _))
    endpoint.replies.head.success(true)
    coordinator.prepare(Seq(request(attempt = 1)))
    assert(!coordinator.registerExecutor("e2", new Endpoint))
    assert(updates === 0)
    assert(coordinator.snapshot.isEmpty)
    assert(coordinator.executorIds.isEmpty)
    assert(endpoint.batches.size === 1)
  }
}
