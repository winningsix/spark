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

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock

/**
 * Executor-wide CPU tokens that let compute capacity flow from pipelined readers to whoever has
 * work.
 *
 * With pipelined shuffle a resident reader holds a scheduler slot for its whole producer phase
 * although it mostly waits for data. Charging readers a fraction of a CPU lets the driver keep
 * nearly all slots for producers; this gate then bounds how many tasks actually compute:
 *
 *  - A task scheduled with a full CPU (producers, regular tasks) is already bounded by slot
 *    accounting. It takes its token without waiting, so the gate never delays it; the token count
 *    may go negative while such tasks hold more tokens than there are permits.
 *  - A task scheduled with a fraction of a CPU (resident readers) only computes on leftover
 *    capacity: it waits for a free token and returns it whenever it blocks on the streaming
 *    transport (a reader waiting for data, a writer waiting for credit).
 *
 * Threads that never entered the gate (Netty, flush threads, non-task code) are unaffected.
 */
private[spark] object StreamingCpuGate {
  @volatile private[spark] var sharedPool: StreamingTaskPermitPool = _

  def configureShared(cores: Int, trace: Boolean): Unit = synchronized {
    if (sharedPool == null) sharedPool = new StreamingTaskPermitPool(cores, trace)
  }

  def readyPool: StreamingTaskPermitPool = {
    val pool = sharedPool
    if (pool != null && pool.readyQuota) pool else null
  }

  def transportWait[T](reason: String)(body: => T): T = {
    val pool = sharedPool
    if (pool == null) blocking(body) else pool.transportWait(reason)(body)
  }

  @volatile private var configured = false
  private val lock = new ReentrantLock()
  private val freed = lock.newCondition()
  private var available = 0

  /** 0 = not entered, 1 = holds a token as a full task, 2 = holds a token as a fractional task. */
  private val state = new ThreadLocal[Integer] {
    override def initialValue(): Integer = 0
  }
  private val waitNanos = new AtomicLong(0L)

  /** Enable the gate with `permits` tokens (no-op when `permits` <= 0 or already configured). */
  def configure(permits: Int): Unit = synchronized {
    if (permits > 0 && !configured) {
      available = permits
      configured = true
    }
  }

  def enabled: Boolean = configured

  /** Nanoseconds fractional tasks spent waiting for a token (diagnostics). */
  def totalWaitNanos: Long = waitNanos.get()

  private def take(fullTask: Boolean): Unit = {
    lock.lock()
    try {
      if (!fullTask && available <= 0) {
        val start = System.nanoTime()
        while (available <= 0) {
          // interruptible: a killed task must not stay parked here
          freed.await(10, TimeUnit.MILLISECONDS)
        }
        waitNanos.addAndGet(System.nanoTime() - start)
      }
      available -= 1
    } finally {
      lock.unlock()
    }
    state.set(if (fullTask) 1 else 2)
  }

  private def give(): Unit = {
    state.set(0)
    lock.lock()
    try {
      available += 1
      freed.signal()
    } finally {
      lock.unlock()
    }
  }

  /**
   * Take a token for the current task thread. `fullTask` is true for tasks scheduled with at
   * least one CPU; they never wait.
   */
  def enter(fullTask: Boolean): Unit = {
    if (configured && state.get() == 0) {
      take(fullTask)
    }
  }

  /** Return the current task thread's token, if it holds one. */
  def exit(): Unit = {
    if (configured && state.get() != 0) give()
  }

  /** Run a blocking wait without holding a token, then take one back before returning. */
  def blocking[T](body: => T): T = {
    if (!configured || state.get() == 0) {
      body
    } else {
      val full = state.get() == 1
      give()
      try body finally take(full)
    }
  }
}
