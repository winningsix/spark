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

import java.util.concurrent.{ArrayBlockingQueue, CountDownLatch, TimeUnit}
import java.util.concurrent.atomic.AtomicBoolean

import scala.collection.mutable

import org.apache.spark.internal.Logging

/**
 * One permit per executor core. A synchronous task keeps its thread, stack, and Spark resources
 * while waiting on shuffle I/O. Only its ability to run another task body is lent. Threads
 * created by a native operator or by the network service are outside this pool.
 */
private[spark] final class StreamingTaskPermitPool(cores: Int, trace: Boolean) extends Logging {
  require(cores > 0)
  private val firstTask = new AtomicBoolean(true)
  private val firstUnmanagedWait = new AtomicBoolean(true)

  // A fresh stamp per observed wait prevents a late reuse from counting as a live transfer.
  private class Stamp(val stage: Int, val reason: String) {
    @volatile var waiting = true
  }
  private class Permit {
    var donor: Stamp = _
  }
  private class Lease(val stage: Int, val taskId: Long) {
    var permit: Permit = _
    var waits = 0
    var yields = 0
    var handoffs = 0
    var resumeDelayNanos = 0L
    val reclaims = mutable.Map.empty[Int, Int]
    val transfers = mutable.Map.empty[(Int, String, Boolean), Int]
  }
  private val free = new ArrayBlockingQueue[Permit](cores, true)
  (0 until cores).foreach(_ => free.add(new Permit))
  private val current = new ThreadLocal[Lease]

  private class Resume {
    val wake = new CountDownLatch(1)
    var permit: Permit = _
    var checkpointStage = -1
  }
  private val resumptions = mutable.ArrayDeque.empty[Resume]
  @volatile private var requested = false
  @volatile var readyQuota = false
  @volatile var parkedReporter: StreamingParkedTaskReporter = _
  def hasIdleQuota: Boolean = !free.isEmpty
  private[streaming] def hasReadyWaiter: Boolean = requested

  private def deliver(permit: Permit, checkpointStage: Int = -1): Boolean = {
    if (resumptions.isEmpty) return false
    val resume = resumptions.removeHead()
    requested = resumptions.nonEmpty
    resume.permit = permit
    resume.checkpointStage = checkpointStage
    resume.wake.countDown()
    true
  }

  private def release(permit: Permit): Unit = {
    if (readyQuota) synchronized {
      if (!deliver(permit)) free.add(permit)
    } else free.add(permit)
  }

  // An interrupted reader may already own a dequeued frame. Restore the permit and the
  // interrupt bit before returning control to its normal frame cleanup path.
  private def uninterrupted[T](f: => T): T = {
    var interrupted = false
    try {
      while (true) {
        try return f catch {
          case _: InterruptedException => interrupted = true
        }
      }
      throw new IllegalStateException("unreachable")
    } finally {
      if (interrupted) Thread.currentThread().interrupt()
    }
  }

  private def resume(lease: Lease): Unit = {
    var permit = free.poll()
    val queued = permit == null
    if (queued && readyQuota) {
      // Check and publish under the same lock used to return a permit. A release between
      // the first poll and registration must never leave an idle permit and a sleeping reader.
      val ticket = synchronized {
        permit = free.poll()
        if (permit != null) null else {
          val waiter = new Resume
          resumptions.append(waiter)
          requested = true
          waiter
        }
      }
      if (ticket != null) {
        val start = if (trace) System.nanoTime() else 0L
        uninterrupted(ticket.wake.await())
        if (trace) {
          lease.resumeDelayNanos += System.nanoTime() - start
          val from = ticket.checkpointStage
          if (from >= 0) lease.reclaims.update(from, lease.reclaims.getOrElse(from, 0) + 1)
        }
        permit = ticket.permit
      }
    } else if (queued) {
      permit = uninterrupted(free.take())
    }
    attach(lease, permit, queued)
  }

  /** A task between shuffle frames can give a newly runnable peer its core immediately. */
  def checkpoint(): Unit = {
    if (!requested) return
    val lease = current.get()
    if (lease != null && lease.permit != null && synchronized { deliver(lease.permit, lease.stage) }) {
      lease.permit = null
      lease.handoffs += 1
      attach(lease, uninterrupted(free.take()), queued = true)
    }
  }

  private def attach(lease: Lease, permit: Permit, queued: Boolean): Unit = {
    lease.permit = permit
    val donor = permit.donor
    permit.donor = null
    if (donor != null && donor.waiting) {
      val key = (donor.stage, donor.reason, queued)
      lease.transfers.update(key, lease.transfers.getOrElse(key, 0) + 1)
    }
    if (queued) lease.waits += 1
  }

  def run[T](stage: Int, taskId: Long, checkKilled: () => Unit)(body: => T): T = {
    if (trace && firstTask.compareAndSet(true, false)) {
      logInfo(s"ShufflePermitPool cores=$cores firstStage=$stage")
    }
    val lease = new Lease(stage, taskId)
    var permit = free.poll()
    val queued = permit == null
    while (permit == null) {
      checkKilled()
      permit = free.poll(50, TimeUnit.MILLISECONDS)
    }
    attach(lease, permit, queued)
    current.set(lease)
    try {
      checkKilled()
      body
    } finally {
      current.remove()
      release(lease.permit)
      if (trace && (lease.waits > 0 || lease.yields > 0 || lease.transfers.nonEmpty)) {
        val moves = lease.transfers.iterator.map { case ((from, why, queued), n) =>
          s"$from/$why/$queued/$n"
        }.mkString(",")
        val reclaims = lease.reclaims.iterator.map { case (from, n) => s"$from/$n" }.mkString(",")
        logInfo(s"ShufflePermit task=$taskId stage=$stage yields=${lease.yields} " +
          s"waits=${lease.waits} transfers=$moves handoffs=${lease.handoffs} " +
          s"reclaims=$reclaims resumeDelayNs=${lease.resumeDelayNanos}")
      }
    }
  }

  def transportWait[T](reason: String)(body: => T): T = {
    val lease = current.get()
    if (lease == null || lease.permit == null) {
      if (lease == null && trace && firstUnmanagedWait.compareAndSet(true, false)) {
        logInfo(s"ShufflePermitUnmanaged reason=$reason thread=${Thread.currentThread().getName}")
      }
      return body
    }
    val stamp = if (trace) new Stamp(lease.stage, reason) else null
    val held = lease.permit
    held.donor = stamp
    lease.permit = null
    lease.yields += 1
    release(held)
    val reporter = parkedReporter
    if (reporter != null) reporter.park(lease.taskId)
    try body finally {
      if (reporter != null) reporter.wake(lease.taskId)
      if (stamp != null) stamp.waiting = false
      resume(lease)
    }
  }
}
