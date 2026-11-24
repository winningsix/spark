package org.apache.spark.sql.execution.adaptive

import scala.collection.mutable
import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal
import org.apache.parquet.hadoop.ParquetFileReader
import org.apache.parquet.hadoop.util.HadoopInputFile
import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation,LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat

class MeasuredLookupExtension extends SparkSessionExtensionsProvider {
  override def apply(ext:SparkSessionExtensions):Unit = ext.injectPreCBORule(_ => MeasuredLookup)
}

private[adaptive] object MeasuredLookup extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.sizeRepeatedLookupFromFooters"
  private case class Scan(relation:HadoopFsRelation, nonNull:Set[String])

  private def unfiltered(p:LogicalPlan):Option[Scan] = p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute]) => unfiltered(c)
    case Filter(cond,c) =>
      val terms=splitConjunctivePredicates(cond)
      val keys=terms.collect { case IsNotNull(a:Attribute) => a.name }
      if(keys.size!=terms.size) None else unfiltered(c).map(v=>v.copy(nonNull=v.nonNull++keys))
    case r:LogicalRelation => r.relation match {
      case h:HadoopFsRelation if h.fileFormat.isInstanceOf[ParquetFileFormat] && h.partitionSchema.isEmpty =>
        Some(Scan(h,Set.empty))
      case _=>None
    }
    case _=>None
  }

  private def exceeds(s:Scan,width:Int,limit:Long):Boolean = try {
    val conf=s.relation.sparkSession.sessionState.newHadoopConfWithOptions(s.relation.options)
    val files=s.relation.location.listFiles(Nil,Nil).iterator.flatMap(_.files.iterator)
    val fixedBytes=BigInt(8)*((width+63)/64+width)
    var rows=BigInt(0)
    while(files.hasNext && rows*fixedBytes<=limit) {
      val f=files.next()
      val reader=ParquetFileReader.open(HadoopInputFile.fromPath(f.getPath,conf))
      try for(block<-reader.getFooter.getBlocks.asScala) {
        val fields=block.getColumns.asScala.map(c=>c.getPath.toDotString->c.getStatistics).toMap
        val nullCounts=s.nonNull.toSeq.map(n=>fields.get(n).filter(v=>v!=null && v.isNumNullsSet).map(_.getNumNulls))
        if(nullCounts.forall(_.isDefined))
          rows+=(BigInt(block.getRowCount)-nullCounts.flatten.map(BigInt(_)).sum).max(0)
      } finally reader.close()
    }
    rows*fixedBytes>limit
  } catch {case NonFatal(_) => false}

  override def apply(plan:LogicalPlan):LogicalPlan={
    val budget=conf.autoBroadcastJoinThreshold
    if(plan.isStreaming || budget<=0 || !conf.getConfString(setting,"false").toBoolean ||
        conf.getConfString("spark.sql.parquet.fieldId.read.enabled","false").toBoolean) return plan
    val costs=mutable.Map.empty[(Scan,Int),Boolean]
    plan.transformUp {
      case parent @ Join(grouped, Join(_,filtered,Inner,Some(_:EqualTo),JoinHint.NONE),Inner,Some(_:EqualTo),JoinHint.NONE)
          if filtered.output.size==1 && grouped.exists(_.isInstanceOf[Aggregate]) =>
        val sources=filtered.collect {case r:LogicalRelation => r.relation}.toSet
        val candidates=grouped.collect {
          case j @ Join(l,r,Inner,Some(EqualTo(a:Attribute,b:Attribute)),JoinHint.NONE)
              if ((l.outputSet.contains(a)&&r.outputSet.contains(b))||(l.outputSet.contains(b)&&r.outputSet.contains(a))) &&
              r.output.size>1 => (j,unfiltered(r))
        }.collect {case(j,Some(s)) if sources.contains(s.relation) => (j,s)}
        val costly=candidates.filter {case(j,s)=> candidates.count(_._2==s)>1 &&
          costs.getOrElseUpdate((s,j.right.output.size),exceeds(s,j.right.output.size,budget))}
        if(costly.isEmpty) parent else {
          val rewritten=grouped.transformUp {
            case j:Join if costly.exists(x=>x._1 eq j) =>
              j.copy(hint=JoinHint(None,Some(HintInfo(Some(SHUFFLE_HASH)))))
          }
          parent.copy(left=rewritten)
        }
    }
  }
}
