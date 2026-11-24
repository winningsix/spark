package org.apache.spark.sql.execution.adaptive

import java.nio.ByteOrder
import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal
import org.apache.parquet.hadoop.ParquetFileReader
import org.apache.parquet.hadoop.util.HadoopInputFile
import org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.INT32
import org.apache.spark.sql.{SparkSessionExtensions,SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{FilePartition,HadoopFsRelation,LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.types.IntegerType

class PagedLookupExtension extends SparkSessionExtensionsProvider {
  def apply(ext:SparkSessionExtensions):Unit=ext.injectPreCBORule(_=>PagedLookup)
}

private[adaptive] object PagedLookup extends Rule[LogicalPlan] {
  val setting="spark.sql.optimizer.splitRepeatedLookupAtIndexedKeys"

  private def source(p:LogicalPlan):Option[HadoopFsRelation]=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>source(c)
    case Filter(cond,c) if cond.deterministic=>source(c)
    case l:LogicalRelation=>l.relation match {
      case r:HadoopFsRelation if r.partitionSchema.isEmpty && r.fileFormat.isInstanceOf[ParquetFileFormat]=>Some(r)
      case _=>None
    }
    case _=>None
  }

  private def boundaries(r:HadoopFsRelation,key:Attribute):Seq[Int]=try {
    val dirs=r.location.listFiles(Nil,Nil)
    val files=dirs.flatMap(_.files)
    if(files.size!=1 || key.dataType!=IntegerType) return Nil
    val f=files.head
    val step=FilePartition.maxSplitBytes(r.sparkSession,dirs)
    if(step<=0 || f.getLen<=step) return Nil
    val parts=1+(f.getLen-1)/step
    val s=r.sparkSession
    val reader=ParquetFileReader.open(HadoopInputFile.fromPath(f.getPath,s.sessionState.newHadoopConfWithOptions(r.options)))
    try {
      val blocks=reader.getFooter.getBlocks.asScala
      if(blocks.size!=1) return Nil
      val col=blocks.head.getColumns.asScala.find(_.getPath.toDotString==key.name)
      if(!col.exists(c=>c.getPrimitiveType.getPrimitiveTypeName==INT32 && c.getColumnIndexReference!=null && c.getOffsetIndexReference!=null)) return Nil
      val c=col.get;val idx=reader.readColumnIndex(c);val offset=reader.readOffsetIndex(c)
      if(idx==null || offset==null) return Nil
      val n=offset.getPageCount
      if(parts>n || parts>s.sparkContext.defaultParallelism) return Nil
      // Physical page order can be arbitrary even when each page spans a narrow key range.
      val bounds=(0 until n).flatMap {i=>
        val lo=idx.getMinValues.get(i);val hi=idx.getMaxValues.get(i)
        if(idx.getNullPages.get(i) || lo.remaining()!=4 || hi.remaining()!=4) None
        else Some((lo.duplicate().order(ByteOrder.LITTLE_ENDIAN).getInt(),
          hi.duplicate().order(ByteOrder.LITTLE_ENDIAN).getInt()))
      }
      if(bounds.size<parts) return Nil
      val minima=bounds.map(_._1).sorted
      val cuts=(1 until parts.toInt).map(i=>minima((i.toLong*minima.size/parts).toInt)).distinct
      val edges=Seq(Long.MinValue)++cuts.map(_.toLong)++Seq(Long.MaxValue)
      if(edges.sliding(2).exists { pair=>bounds.forall {case (a,b)=>b>=pair.head && a<pair.last} }) Nil
      else cuts
    } finally reader.close()
  } catch {case NonFatal(_) => Nil}

  private[adaptive] def striped(p:LogicalPlan,k:Attribute,cuts:Seq[Int]):LogicalPlan = {
    if(cuts.isEmpty) return p
    val branches=(0 to cuts.size).map {i=>
      val lo=if(i==0) None else Some(GreaterThanOrEqual(k,Literal(cuts(i-1))))
      val hi=if(i==cuts.size) None else Some(LessThan(k,Literal(cuts(i))))
      val predicate=(lo,hi) match {
        case (None,Some(u))=>Or(IsNull(k),u)
        case (Some(l),None)=>l
        case (Some(l),Some(u))=>And(l,u)
        case _=>throw new IllegalStateException("expected at least one page boundary")
      }
      val rows=Filter(predicate,p)
      if(i==0) rows else Project(p.output.map(a=>Alias(a,a.name)()),rows)
    }
    Union(branches)
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    if(p.isStreaming || !conf.getConfString(setting,"false").toBoolean ||
        conf.getConfString("spark.sql.parquet.fieldId.read.enabled","false").toBoolean) return p
    p.transformUp {
      case outer @ Join(grouped,Join(_,lookup,Inner,Some(_:EqualTo),_),Inner,Some(_:EqualTo),_)
          if grouped.exists(_.isInstanceOf[Aggregate]) && lookup.output.size==1 =>
        val original=source(lookup)
        val children=grouped.collect {
          case j @ Join(_,rhs,Inner,Some(EqualTo(a:Attribute,b:Attribute)),_)
              if rhs.output.size==2 && original.isDefined && source(rhs)==original =>
            val k=if(rhs.outputSet.contains(a)) a else b
            (j,k)
        }.filter {case(j,k)=>j.right.outputSet.contains(k)}
        if(children.size!=2 || children.map(_._2.name).distinct.size!=1) outer else {
          val cuts=boundaries(original.get,children.head._2)
          if(cuts.isEmpty) outer else outer.copy(left=grouped.transformUp {
            case j:Join if children.exists(_._1 eq j) =>
              j.copy(right=striped(j.right,children.find(_._1 eq j).get._2,cuts))
          })
        }
    }
  }
}
