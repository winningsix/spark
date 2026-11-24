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

import scala.collection.mutable

import org.apache.spark.util.{ThreadUtils, Utils}

private[spark] case class ParkedShuffleTasks(executorId: String, tasks: Seq[Long])

/**
 * Coalesces transport waits. Short local queue misses normally finish before the first
 * observation. The executor remains the owner of the compute limit even when a notice is stale.
 */
private[spark] final class StreamingParkedTaskReporter(
    send: Seq[Long] => Unit,
    needsTasks: () => Boolean) {
  private val timer = ThreadUtils.newDaemonSingleThreadScheduledExecutor("shuffle-parked-offers")
  private val parked = mutable.HashSet.empty[Long]
  private var scheduled = false
  private var stopped = false

  def park(id: Long): Unit = synchronized {
    if (!stopped) {
      parked += id
      if (!scheduled) schedule(4L)
    }
  }

  def wake(id: Long): Unit = synchronized { parked -= id }

  private def schedule(delayMs: Long): Unit = {
    scheduled = true
    timer.schedule(new Runnable {
      override def run(): Unit = {
        val snapshot = StreamingParkedTaskReporter.this.synchronized {
          scheduled = false
          if (!stopped && parked.nonEmpty) {
            schedule(24L)
            if (needsTasks()) parked.toVector else Vector.empty
          } else Vector.empty
        }
        if (snapshot.nonEmpty) Utils.tryLogNonFatalError { send(snapshot) }
      }
    }, delayMs, TimeUnit.MILLISECONDS)
  }

  def close(): Unit = synchronized {
    stopped = true
    parked.clear()
    timer.shutdownNow()
  }
}
