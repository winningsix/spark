package org.apache.spark.sql.execution.window

import java.util.{HashMap, PriorityQueue}
import org.apache.spark.TaskContext
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.physical.Partitioning
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{SortExec, SparkPlan, UnaryExecNode}
import org.apache.spark.sql.execution.metric.SQLMetrics
import org.apache.spark.sql.types._

class RankCandidatesExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectQueryStagePrepRule(_ => RankCandidates)
}

private[window] object RankCandidates extends Rule[SparkPlan] {
  override def apply(plan: SparkPlan): SparkPlan = {
    if (!conf.getConfString("spark.sql.execution.preFilterPartialRank.enabled","false").toBoolean)
      return plan
    plan.transformUp {
      case w @ WindowGroupLimitExec(part, order, _: Rank, n, Partial, s: SortExec)
          if !s.global && part.nonEmpty && n > 0 && part.forall(_.isInstanceOf[Attribute]) &&
            order.nonEmpty && order.forall(k => k.child.isInstanceOf[Attribute] &&
              k.child.dataType.isInstanceOf[NumericType]) &&
            !s.child.isInstanceOf[RankCandidateFilterExec] =>
        w.copy(child = s.copy(child = RankCandidateFilterExec(part,order,n,s.child)))
    }
  }
}

/** A row with at least K strictly better predecessors in this partition cannot have rank <= K. */
private[window] case class RankCandidateFilterExec(part: Seq[Expression],
    order: Seq[SortOrder], limit: Int, child: SparkPlan) extends UnaryExecNode {
  override def output: Seq[Attribute] = child.output
  override def outputOrdering: Seq[SortOrder] = child.outputOrdering
  override def outputPartitioning: Partitioning = child.outputPartitioning
  override lazy val metrics = Map(
    "numInputRows" -> SQLMetrics.createMetric(sparkContext, "input candidates"),
    "rejectedRows" -> SQLMetrics.createMetric(sparkContext, "rows excluded before sort"),
    "trackedGroups" -> SQLMetrics.createMetric(sparkContext, "tracked partition keys"))
  override protected def doExecute(): RDD[InternalRow] = {
    val in = child.output
    val partitionKeys=part
    val orderKeys=order.map(_.child)
    val keyOrdering=order.zipWithIndex.map { case (o,i) =>
      o.copy(child=BoundReference(i,o.child.dataType,o.child.nullable),sameOrderExpressions=Nil)
    }
    val k=limit
    val inputRows=longMetric("numInputRows")
    val droppedRows=longMetric("rejectedRows")
    val trackedGroups=longMetric("trackedGroups")
    child.execute().mapPartitions({ rows =>
      val pg=UnsafeProjection.create(partitionKeys,in)
      val score=UnsafeProjection.create(orderKeys,in)
      val ord=RowOrdering.create(keyOrdering,Nil)
      val worstFirst: java.util.Comparator[UnsafeRow]=(a,b)=>ord.compare(b,a)
      val groups=new HashMap[UnsafeRow,PriorityQueue[UnsafeRow]]()
      // Stop admitting new groups at this budget. Untracked rows proceed through the original
      // sort and exact rank. Only fixed-width numeric order keys are retained in the heaps.
      var remaining=1024L * 1024
      var seen=0L
      var dropped=0L
      TaskContext.get().addTaskCompletionListener[Unit] { _ =>
        inputRows += seen; droppedRows += dropped; trackedGroups += groups.size()
      }
      rows.filter { row =>
        seen+=1
        val key=pg(row)
        val v=score(row)
        var heap=groups.get(key)
        if (heap==null) {
          val bytes=128L+key.getSizeInBytes+k.toLong*(80L+v.getSizeInBytes)
          if (bytes<=remaining) {
            remaining-=bytes
            heap=new PriorityQueue[UnsafeRow](k,worstFirst)
            groups.put(key.copy(),heap)
          }
        }
        if (heap==null) true
        else if (heap.size()<k) {heap.add(v.copy());true}
        else {
          val cmp=ord.compare(v,heap.peek())
          if (cmp<0) {heap.poll();heap.add(v.copy())}
          if (cmp>0) dropped+=1
          cmp<=0
        }
      }
    }, preservesPartitioning=true)
  }
  override protected def withNewChildInternal(next: SparkPlan): RankCandidateFilterExec =
    copy(child=next)
}
