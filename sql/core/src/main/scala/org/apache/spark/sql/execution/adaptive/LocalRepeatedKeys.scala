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

package org.apache.spark.sql.execution.adaptive

import org.apache.spark.TaskContext
import org.apache.spark.memory.{MemoryConsumer,SparkOutOfMemoryError,TooLargePageException}
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.expressions.codegen.UnsafeRowWriter
import org.apache.spark.sql.catalyst.optimizer.BuildRight
import org.apache.spark.sql.catalyst.plans.{Inner,LeftOuter}
import org.apache.spark.sql.catalyst.plans.physical.{ClusteredDistribution,Partitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{ProjectExec,SparkPlan,UnaryExecNode}
import org.apache.spark.sql.execution.joins.ShuffledHashJoinExec
import org.apache.spark.sql.execution.metric.SQLMetrics
import org.apache.spark.sql.types.LongType
import org.apache.spark.unsafe.array.LongArray
import org.apache.spark.unsafe.hash.Murmur3_x86_32

private[adaptive] case class RepeatedLookupKeys(child: org.apache.spark.sql.catalyst.plans.logical.LogicalPlan)
    extends org.apache.spark.sql.catalyst.plans.logical.UnaryNode {
  override def output: Seq[Attribute] = child.output
  override protected def withNewChildInternal(c: org.apache.spark.sql.catalyst.plans.logical.LogicalPlan): RepeatedLookupKeys =
    copy(child=c)
}
private[adaptive] object PlanExactLookupSummary extends org.apache.spark.sql.execution.SparkStrategy {
  override def apply(plan: org.apache.spark.sql.catalyst.plans.logical.LogicalPlan): Seq[SparkPlan] = plan match {
    case RepeatedLookupKeys(child) => Seq(LocalRepeatedKeysExec(planLater(child)))
    case _ => Nil
  }
}

/** A left outer join that only observes preserved columns produces one copy for either zero
  * or one match. Within a complete key partition only repeated right keys can add copies. */
private[sql] case class LocalRepeatedKeysExec(child: SparkPlan) extends UnaryExecNode {
  override def output: Seq[Attribute] = child.output
  override def outputPartitioning: Partitioning = child.outputPartitioning
  override def requiredChildDistribution = Seq(ClusteredDistribution(Seq(child.output.head)))
  override lazy val metrics=Map(
    "fallback" -> SQLMetrics.createMetric(sparkContext,"partitions using external key counts"),
    "outputRows" -> SQLMetrics.createMetric(sparkContext,"lookup rows after singleton elimination"))
  override protected def withNewChildInternal(c: SparkPlan): LocalRepeatedKeysExec = copy(child=c)
  override protected def doExecute(): RDD[InternalRow] = {
    val limit=conf.getConfString("spark.sql.shuffle.localRepeatedLookup.maxTaskBytes","67108864").toLong
    val fallback=longMetric("fallback")
    val emitted=longMetric("outputRows")
    child.execute().mapPartitions { source =>
      val table=new LocalMultiplicityTable(limit)
      TaskContext.get().addTaskCompletionListener[Unit](_ => table.close())
      var rejected: Option[Long]=None
      while (rejected.isEmpty && source.hasNext) {
        val row=source.next()
        if (!row.isNullAt(0)) {
          val key=row.getLong(0)
          if (!table.add(key)) rejected=Some(key)
        }
      }
      if (rejected.isDefined) fallback += 1
      val writer=new UnsafeRowWriter(1)
      val outputKeys: Iterator[Long] = rejected match {
        case None => table.keys(keepSingles=false)
        case Some(first) =>
          // Keep the same exact relation even when the task runs out of table memory.
          // The spillable aggregation merges the consumed prefix and remaining records.
          val counts=new org.apache.spark.util.collection.ExternalAppendOnlyMap[Long,Long,Long](
            identity, (a,b)=>a+b, (a,b)=>a+b)
          table.keys(keepSingles=true).foreach(k=>counts.insert(k,1L))
          table.close()
          counts.insert(first,1L)
          source.foreach(r=>if (!r.isNullAt(0)) counts.insert(r.getLong(0),1L))
          counts.iterator.filter(_._2>1L).flatMap { case (k,n) =>
            Iterator.iterate(0L)(_+1L).takeWhile(_<n).map(_=>k)
          }
      }
      val rows=outputKeys.map { key =>
        emitted+=1L
        writer.reset();writer.zeroOutNullBytes();writer.write(0,key);writer.getRow: InternalRow
      }
      org.apache.spark.util.CompletionIterator[InternalRow, Iterator[InternalRow]](rows,table.close())
    }
  }
}

private final class LocalMultiplicityTable(limit: Long) extends MemoryConsumer(
    TaskContext.get().taskMemoryManager(),TaskContext.get().taskMemoryManager().getTungstenMemoryMode) {
  private var values: LongArray=null
  private var extra: LongArray=null
  private var slots=0
  private var usedSlots=0
  private var zeros=0L
  override def spill(size: Long, trigger: MemoryConsumer): Long = 0L
  def close(): Unit = {
    if (values!=null) freeArray(values)
    if (extra!=null) freeArray(extra)
    values=null;extra=null
  }
  private def allocate(slots: Int): LongArray = {
    if (slots.toLong*8+getUsed>limit) return null
    val a=try allocateArray(slots) catch {
      case _: SparkOutOfMemoryError | _: TooLargePageException => return null
    }
    a.zeroOut();a
  }
  private def find(a: LongArray, size: Int, k: Long): Int = {
    val mask=size-1
    var i=Murmur3_x86_32.hashLong(k,0)&mask
    while (a.get(i)!=0L && a.get(i)!=k) i=(i+1)&mask
    i
  }
  private def grow(): Boolean = {
    if (slots>=(1<<29)) return false
    val n=if (slots==0) 1024 else slots*2
    val a=allocate(n)
    if (a==null) return false
    val b=if (extra==null) null else allocate(n)
    if (extra!=null && b==null) { freeArray(a);return false }
    var i=0
    while (i<slots) {
      val k=values.get(i)
      if (k!=0L) {
        val next=find(a,n,k);a.set(next,k)
        if (b!=null) b.set(next,extra.get(i))
      }
      i+=1
    }
    close();values=a;extra=b;slots=n;true
  }
  def add(k: Long): Boolean = {
    if (k==0L) { zeros+=1;return true }
    if (slots==0 && !grow()) return false
    var i=find(values,slots,k)
    if (values.get(i)!=0L) {
      if (extra==null) extra=allocate(slots)
      if (extra==null) return false
      extra.set(i,extra.get(i)+1L)
    } else {
      if (usedSlots>=slots-slots/3) {
        if (!grow()) return false
        i=find(values,slots,k)
      }
      values.set(i,k);usedSlots+=1
    }
    true
  }
  def keys(keepSingles: Boolean): Iterator[Long] = new Iterator[Long] {
    private var i=0
    private var remaining=if (keepSingles || zeros>1) zeros else 0L
    private var current=0L
    override def hasNext: Boolean = {
      if (extra==null && !keepSingles) i=slots
      while (remaining==0 && i<slots) {
        current=values.get(i)
        if (current!=0L) {
          val count=if (extra==null) 1L else extra.get(i)+1L
          if (keepSingles || count>1) remaining=count
        }
        i+=1
      }
      remaining>0L
    }
    override def next(): Long = {
      if (!hasNext) throw new NoSuchElementException("exhausted lookup keys")
      remaining-=1;current
    }
  }
}
