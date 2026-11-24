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

package org.apache.spark.sql.execution

import java.nio.ByteBuffer
import java.util.{Collections, IdentityHashMap, UUID}
import java.util.concurrent.{ConcurrentLinkedQueue, Executors, ThreadFactory}

import org.apache.spark.SparkEnv
import org.apache.spark.internal.Logging
import org.apache.spark.sql.catalyst.expressions.{BloomFilterMightContain, Expression}
import org.apache.spark.storage.{StorageLevel, TestBlockId}
import org.apache.spark.util.io.ChunkedByteBuffer

/**
 * Late binding for runtime bloom filters.
 *
 * A runtime bloom filter (`might_contain(scalar-subquery(bloom_filter_agg), hash(key))`) only
 * prunes rows that a join would drop anyway, so the probe side does not have to wait for it.
 * Normally `waitForSubqueries` blocks the whole probe stage until every filter is built, which
 * serializes the filter-building jobs in front of the main scan. With late binding:
 *
 *  - Driver: an unfinished filter subquery is not waited for. Its result is published (as raw
 *    bytes, through the driver block manager) once it completes. The backend writes a
 *    placeholder for it in the task plan.
 *  - Executor: before running a task, the backend replaces the placeholder with the published
 *    filter, or with an all-pass filter if it is not ready yet. Early tasks scan unfiltered; later
 *    tasks are pruned as before. Results are unchanged.
 *
 * Only plans executed by a backend that declares support (by class-name prefix) are eligible,
 * because vanilla Spark operators evaluate the subquery value eagerly.
 */
object LateRuntimeFilter extends Logging {
  val ENABLED_KEY = "spark.sql.execution.lateRuntimeFilter.enabled"
  val BACKEND_PREFIX_KEY = "spark.sql.execution.lateRuntimeFilter.backendPrefix"
  val PLACEHOLDER_PREFIX = "LATEBF:"

  private def conf = SparkEnv.get.conf

  private val ids = Collections.synchronizedMap(new IdentityHashMap[ScalarSubquery, String]())
  private val deferredOrder = new ConcurrentLinkedQueue[ScalarSubquery]()
  private val maxDeferred = 1024
  private val published = new ConcurrentLinkedQueue[String]()
  private val maxPublished = 256
  private lazy val publisher = Executors.newCachedThreadPool(new ThreadFactory {
    override def newThread(r: Runnable): Thread = {
      val t = new Thread(r, "late-runtime-filter")
      t.setDaemon(true)
      t
    }
  })

  // Executor side: recently resolved filter bytes, by placeholder id (small LRU: a filter can be
  // several MB). Negative lookups are not cached.
  private val resolved = Collections.synchronizedMap(
    new java.util.LinkedHashMap[String, Array[Byte]](16, 0.75f, true) {
      override def removeEldestEntry(e: java.util.Map.Entry[String, Array[Byte]]): Boolean =
        size() > 32
    })

  private def isMightContain(e: Expression): Boolean =
    e.isInstanceOf[BloomFilterMightContain] || e.prettyName.contains("might_contain")

  /** Scalar subqueries in `plan`'s own expressions that feed a might_contain filter argument. */
  def lateBindableSubqueries(plan: SparkPlan): java.util.Set[ScalarSubquery] = {
    val out = Collections.newSetFromMap(new IdentityHashMap[ScalarSubquery, java.lang.Boolean]())
    val env = SparkEnv.get
    if (env == null || !env.conf.getBoolean(ENABLED_KEY, false)) return out
    val prefix = env.conf.get(BACKEND_PREFIX_KEY, "org.apache.gluten.")
    if (!plan.getClass.getName.startsWith(prefix)) return out
    plan.expressions.foreach(_.foreach {
      case m if isMightContain(m) && m.children.nonEmpty =>
        m.children.head match {
          case s: ScalarSubquery => out.add(s)
          case _ =>
        }
      case _ =>
    })
    // Partition filters are evaluated on the driver while listing files, so a filter that also
    // prunes partitions needs its value before the scan starts: keep waiting for those.
    plan match {
      case scan: FileSourceScanLike =>
        scan.partitionFilters.foreach(_.foreach {
          case s: ScalarSubquery => out.remove(s)
          case _ =>
        })
      case _ =>
    }
    out
  }

  // Wait this long for a filter before binding it late: a filter that is almost done is worth
  // waiting for (the first task wave would otherwise run unpruned), a slow one is not.
  private def maxWaitMs: Long =
    Option(SparkEnv.get).map(_.conf.getLong("spark.sql.execution.lateRuntimeFilter.maxWaitMs", 0L))
      .getOrElse(0L)

  private def subqueryReady(s: ScalarSubquery): Boolean = s.plan match {
    case q: SubqueryExec => q.awaitReady(maxWaitMs)
    case r: ReusedSubqueryExec => r.child match {
      case q: SubqueryExec => q.awaitReady(maxWaitMs)
      case _ => false
    }
    case _ => false
  }

  /** Fill in the result if it is already available; true when the subquery holds its value. */
  def readyNow(s: ScalarSubquery): Boolean = {
    if (s.isResultUpdated) return true
    if (subqueryReady(s)) {
      s.updateResult()
      true
    } else {
      false
    }
  }

  /** Placeholder id for a deferred subquery, if this subquery was deferred and is not ready. */
  def placeholderFor(s: ScalarSubquery): Option[String] = {
    if (s.isResultUpdated) None else Option(ids.get(s))
  }

  /** Stop waiting for `s`; publish its result for executors once it completes. */
  def defer(s: ScalarSubquery): Unit = {
    val id = ids.synchronized {
      Option(ids.get(s)).getOrElse {
        val fresh = UUID.randomUUID().toString
        ids.put(s, fresh)
        deferredOrder.add(s)
        while (deferredOrder.size() > maxDeferred) {
          Option(deferredOrder.poll()).foreach(ids.remove)
        }
        fresh
      }
    }
    publisher.submit(new Runnable {
      override def run(): Unit = {
        try {
          s.updateResult()
          val bytes = s.eval(null) match {
            case b: Array[Byte] => b
            case _ => Array.emptyByteArray // no filter: executors use the all-pass filter
          }
          publish(id, bytes)
        } catch {
          case t: Throwable =>
            // The filter is optional; the query's own join still enforces correctness.
            logWarning(s"Late runtime filter $id failed; tasks run unfiltered", t)
            publish(id, Array.emptyByteArray)
        }
      }
    })
  }

  private def blockId(id: String) = TestBlockId("latebf_" + id)

  private def publish(id: String, bytes: Array[Byte]): Unit = {
    val bm = SparkEnv.get.blockManager
    bm.putBytes(blockId(id), new ChunkedByteBuffer(ByteBuffer.wrap(bytes)),
      StorageLevel.MEMORY_ONLY_SER, tellMaster = true)
    published.add(id)
    while (published.size() > maxPublished) {
      Option(published.poll()).foreach { old =>
        try bm.removeBlock(blockId(old), tellMaster = true) catch { case _: Throwable => }
      }
    }
  }

  /**
   * Executor side: the published filter bytes for `id`, or None when not published yet. An empty
   * array means "no filter".
   */
  def fetch(id: String): Option[Array[Byte]] = {
    Option(resolved.get(id)).orElse {
      val env = SparkEnv.get
      env.blockManager.getRemoteBytes(blockId(id)).map { chunked =>
        val bytes = chunked.toArray
        resolved.put(id, bytes)
        bytes
      }
    }
  }
}
