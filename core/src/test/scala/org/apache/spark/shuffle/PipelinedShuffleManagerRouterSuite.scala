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

package org.apache.spark.shuffle

import scala.collection.mutable

import org.mockito.Mockito.mock

import org.apache.spark._
import org.apache.spark.internal.config.{SHUFFLE_MANAGER, SHUFFLE_MANAGER_INCREMENTAL}
import org.apache.spark.rdd.RDD
import org.apache.spark.serializer.JavaSerializer
import org.apache.spark.shuffle.streaming.StreamingShuffleManager

/**
 * A recording ShuffleManager test double: it records which calls it received so a test can assert
 * that the router routed to the correct underlying manager. Every instance registers itself in a
 * process-wide registry keyed by class, because the router keeps its delegates in private fields
 * and a test otherwise has no reference to them. Constructor takes (SparkConf, Boolean) to match
 * how the router instantiates managers.
 */
private class RecordingShuffleManager(conf: SparkConf, isDriver: Boolean) extends ShuffleManager {
  RecordingShuffleManager.register(this)
  val registered = mutable.ArrayBuffer[Int]()
  val writerCalls = mutable.ArrayBuffer[Int]()
  val readerCalls = mutable.ArrayBuffer[Int]()
  val unregistered = mutable.ArrayBuffer[Int]()
  @volatile var stopped = false
  // Configurable so tests can drive the router's unregister OR-semantics and stop() error handling.
  @volatile var unregisterResult = true
  @volatile var stopError: Option[Throwable] = None

  override def registerShuffle[K, V, C](
      shuffleId: Int, dependency: ShuffleDependency[K, V, C]): ShuffleHandle = {
    registered += shuffleId
    new RecordingShuffleManager.RecordingHandle(shuffleId)
  }
  override def getWriter[K, V](
      handle: ShuffleHandle, mapId: Long, context: TaskContext,
      metrics: ShuffleWriteMetricsReporter): ShuffleWriter[K, V] = {
    require(handle.isInstanceOf[RecordingShuffleManager.RecordingHandle],
      s"expected an unwrapped RecordingHandle, got $handle")
    writerCalls += handle.shuffleId
    null
  }
  override def getReader[K, C](
      handle: ShuffleHandle, startMapIndex: Int, endMapIndex: Int, startPartition: Int,
      endPartition: Int, context: TaskContext, metrics: ShuffleReadMetricsReporter)
      : ShuffleReader[K, C] = {
    require(handle.isInstanceOf[RecordingShuffleManager.RecordingHandle],
      s"expected an unwrapped RecordingHandle, got $handle")
    readerCalls += handle.shuffleId
    null
  }
  override def unregisterShuffle(shuffleId: Int): Boolean = {
    unregistered += shuffleId
    unregisterResult
  }
  override def shuffleBlockResolver: ShuffleBlockResolver = mock(classOf[ShuffleBlockResolver])
  override def stop(): Unit = {
    stopped = true
    stopError.foreach(throw _)
  }
}

private object RecordingShuffleManager {
  class RecordingHandle(shuffleId: Int) extends ShuffleHandle(shuffleId)

  // Registry so tests can reach the instances the router built. Cleared per test.
  private val instances = mutable.ArrayBuffer[RecordingShuffleManager]()
  def register(m: RecordingShuffleManager): Unit = synchronized { instances += m }
  def clear(): Unit = synchronized { instances.clear() }
  def of[T <: RecordingShuffleManager](cls: Class[T]): T = synchronized {
    instances.find(cls.isInstance).getOrElse(
      throw new NoSuchElementException(s"no ${cls.getSimpleName} was instantiated")).asInstanceOf[T]
  }
}

// Distinct subclasses so the router instantiates two different classes (default vs incremental)
// and tests can tell which one handled a shuffle.
private class DefaultRecordingManager(conf: SparkConf, isDriver: Boolean)
  extends RecordingShuffleManager(conf, isDriver)
private class IncrementalRecordingManager(conf: SparkConf, isDriver: Boolean)
  extends RecordingShuffleManager(conf, isDriver)

class PipelinedShuffleManagerRouterSuite extends SparkFunSuite with LocalSparkContext {

  override def beforeEach(): Unit = {
    super.beforeEach()
    // Genuinely reset the process-wide recording registry per test (tests that build a router via
    // ShuffleManager.create rather than startWithRouter otherwise see instances from prior tests).
    RecordingShuffleManager.clear()
  }

  private def newConf(): SparkConf = new SparkConf(loadDefaults = false)
    .set(SHUFFLE_MANAGER, classOf[DefaultRecordingManager].getName)
    .set(SHUFFLE_MANAGER_INCREMENTAL, classOf[IncrementalRecordingManager].getName)

  /**
   * Start a SparkContext with the given conf, then return the live router SparkEnv built (so we
   * test the real installed instance, not a second hand-built one). The registry is cleared right
   * after startup so `defaultMgr`/`incrementalMgr` resolve to the router's own delegates and not
   * to any managers instantiated during SparkContext bring-up.
   */
  private def startWithRouter(conf: SparkConf = newConf()): PipelinedShuffleManagerRouter = {
    sc = new SparkContext("local", "test", conf)
    val router = SparkEnv.get.shuffleManager.asInstanceOf[PipelinedShuffleManagerRouter]
    RecordingShuffleManager.clear()
    // Re-register the live router's two delegates so the registry points at exactly them.
    RecordingShuffleManager.register(
      router.regularShuffleManager.asInstanceOf[RecordingShuffleManager])
    RecordingShuffleManager.register(
      router.incrementalShuffleManager.asInstanceOf[RecordingShuffleManager])
    router
  }

  private def defaultMgr = RecordingShuffleManager.of(classOf[DefaultRecordingManager])
  private def incrementalMgr = RecordingShuffleManager.of(classOf[IncrementalRecordingManager])

  private def pipelinedDep(sc: SparkContext): PipelinedShuffleDependency[Int, Int, Int] = {
    val rdd: RDD[(Int, Int)] = sc.parallelize(1 to 4, 2).map(x => (x, x))
    new PipelinedShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(2))
  }
  private def regularDep(sc: SparkContext): ShuffleDependency[Int, Int, Int] = {
    val rdd: RDD[(Int, Int)] = sc.parallelize(1 to 4, 2).map(x => (x, x))
    new ShuffleDependency[Int, Int, Int](rdd, new HashPartitioner(2))
  }

  test("ShuffleManager.create installs the router only when the incremental config is set") {
    val without = new SparkConf(loadDefaults = false)
      .set(SHUFFLE_MANAGER, classOf[DefaultRecordingManager].getName)
    assert(!ShuffleManager.create(without, isDriver = true)
      .isInstanceOf[PipelinedShuffleManagerRouter])

    assert(ShuffleManager.create(newConf(), isDriver = true)
      .isInstanceOf[PipelinedShuffleManagerRouter])
  }

  test("a PipelinedShuffleDependency registers with the incremental manager, wrapped") {
    val router = startWithRouter()
    val handle = router.registerShuffle(10, pipelinedDep(sc))
    assert(handle.isInstanceOf[IncrementalShuffleHandle])
    assert(handle.shuffleId === 10)
    // The incremental manager saw the register; the default manager did not.
    assert(incrementalMgr.registered.contains(10))
    assert(!defaultMgr.registered.contains(10))
  }

  test("a regular ShuffleDependency registers with the default manager, not wrapped") {
    val router = startWithRouter()
    val handle = router.registerShuffle(11, regularDep(sc))
    assert(!handle.isInstanceOf[IncrementalShuffleHandle])
    assert(defaultMgr.registered.contains(11))
    assert(!incrementalMgr.registered.contains(11))
  }

  test("getWriter/getReader route to the correct underlying manager and unwrap the handle") {
    val router = startWithRouter()
    val incrementalHandle = router.registerShuffle(20, pipelinedDep(sc))
    val regularHandle = router.registerShuffle(21, regularDep(sc))

    router.getWriter(incrementalHandle, 0L, mock(classOf[TaskContext]),
      mock(classOf[ShuffleWriteMetricsReporter]))
    router.getReader(regularHandle, 0, 1, 0, 1, mock(classOf[TaskContext]),
      mock(classOf[ShuffleReadMetricsReporter]))

    // The incremental writer call reached the incremental manager (with an unwrapped handle, as the
    // require() inside the double enforces), and NOT the default manager -- and vice versa.
    assert(incrementalMgr.writerCalls === Seq(20))
    assert(defaultMgr.writerCalls.isEmpty)
    assert(defaultMgr.readerCalls === Seq(21))
    assert(incrementalMgr.readerCalls.isEmpty)
  }

  test("IncrementalShuffleHandle survives Java serialization (the driver->executor path)") {
    val router = startWithRouter()
    val handle = router.registerShuffle(40, pipelinedDep(sc))
    val ser = new JavaSerializer(sc.conf).newInstance()
    val roundTripped = ser.deserialize[ShuffleHandle](ser.serialize(handle))
    assert(roundTripped.isInstanceOf[IncrementalShuffleHandle])
    assert(roundTripped.shuffleId === 40)
    // The wrapped delegate must survive too, so executor-side unwrapping works.
    assert(roundTripped.asInstanceOf[IncrementalShuffleHandle].delegate.shuffleId === 40)
  }

  test("unregisterShuffle is attempted on both managers and succeeds") {
    val router = startWithRouter()
    router.registerShuffle(30, pipelinedDep(sc))
    assert(router.unregisterShuffle(30))
    assert(incrementalMgr.unregistered.contains(30))
    assert(defaultMgr.unregistered.contains(30))
  }

  test("stop stops both underlying managers") {
    val router = startWithRouter()
    router.stop()
    assert(incrementalMgr.stopped)
    assert(defaultMgr.stopped)
  }

  test("SparkEnv initializes the streaming shuffle tracker when the incremental manager is " +
      "StreamingShuffleManager") {
    val conf = new SparkConf(loadDefaults = false)
      .set(SHUFFLE_MANAGER, classOf[DefaultRecordingManager].getName)
      .set(SHUFFLE_MANAGER_INCREMENTAL, classOf[StreamingShuffleManager].getName)
    sc = new SparkContext("local", "test", conf)
    assert(SparkEnv.get.streamingShuffleOutputTracker.isDefined)
  }

  test("SparkEnv does not initialize the tracker when the incremental manager is not streaming") {
    sc = new SparkContext("local", "test", newConf())
    assert(SparkEnv.get.streamingShuffleOutputTracker.isEmpty)
  }

  test("regularShuffleManager exposes the default manager (for ShuffleExchangeExec sort detection)") {
    // ShuffleExchangeExec.needToCopyObjectsBeforeShuffle unwraps the router to this manager and
    // checks isInstanceOf[SortShuffleManager]; assert the unwrap returns the real default manager.
    val router = startWithRouter()
    assert(router.regularShuffleManager eq defaultMgr,
      "regularShuffleManager must be the configured default (spark.shuffle.manager) manager")
    // And with a real sort default, it is actually a SortShuffleManager.
    val sortConf = new SparkConf(loadDefaults = false)
      .set(SHUFFLE_MANAGER, "sort")
      .set(SHUFFLE_MANAGER_INCREMENTAL, classOf[IncrementalRecordingManager].getName)
    val sortRouter = ShuffleManager.create(sortConf, isDriver = true)
      .asInstanceOf[PipelinedShuffleManagerRouter]
    assert(sortRouter.regularShuffleManager
      .isInstanceOf[org.apache.spark.shuffle.sort.SortShuffleManager])
    sortRouter.stop()
  }

  test("unregisterShuffle ORs the two managers: succeeds when only the owning manager returns true") {
    val router = startWithRouter()
    router.registerShuffle(30, pipelinedDep(sc))
    // The non-owning (default) manager returns false for this unknown shuffle; the owning
    // (incremental) manager returns true. OR-semantics must yield true (AND would wrongly fail).
    defaultMgr.unregisterResult = false
    incrementalMgr.unregisterResult = true
    assert(router.unregisterShuffle(30), "OR-semantics: owner's true must not be vetoed")
    assert(incrementalMgr.unregistered.contains(30))
    assert(defaultMgr.unregistered.contains(30))
    // And false only when BOTH return false.
    defaultMgr.unregisterResult = false
    incrementalMgr.unregisterResult = false
    assert(!router.unregisterShuffle(31))
  }

  test("stop runs both managers even if the first throws, preserving the first error") {
    // Build the router directly (no SparkContext), so its stop() is only called by this test and
    // not again during context teardown (which would re-throw the injected error).
    val router = ShuffleManager.create(newConf(), isDriver = true)
      .asInstanceOf[PipelinedShuffleManagerRouter]
    val incMgr = router.incrementalShuffleManager.asInstanceOf[RecordingShuffleManager]
    val defMgr = router.regularShuffleManager.asInstanceOf[RecordingShuffleManager]
    val incErr = new RuntimeException("incremental stop failed")
    val defErr = new RuntimeException("default stop failed")
    incMgr.stopError = Some(incErr)
    defMgr.stopError = Some(defErr)
    val thrown = intercept[RuntimeException](router.stop())
    // Both stop() were attempted...
    assert(incMgr.stopped && defMgr.stopped)
    // ...the first (incremental) error is thrown, with the second attached as suppressed.
    assert(thrown eq incErr)
    assert(thrown.getSuppressed.contains(defErr))
  }

  test("ShuffleManager.create surfaces a clear error for a bad incremental manager class name") {
    val badConf = new SparkConf(loadDefaults = false)
      .set(SHUFFLE_MANAGER, "sort")
      .set(SHUFFLE_MANAGER_INCREMENTAL, "org.apache.spark.NotAShuffleManager")
    // The router constructor instantiates the incremental manager eagerly, so a bad class name
    // fails at creation rather than silently.
    intercept[Exception](ShuffleManager.create(badConf, isDriver = true))
  }
}
