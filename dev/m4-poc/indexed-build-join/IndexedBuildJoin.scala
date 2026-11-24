package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.optimizer.{BuildLeft,JoinSelectionHelper}
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

class IndexedBuildJoinExtension extends SparkSessionExtensionsProvider {
  def apply(ext:SparkSessionExtensions):Unit=ext.injectPreCBORule(_=>IndexedBuildJoin)
}

private[adaptive] object IndexedBuildJoin extends Rule[LogicalPlan] with PredicateHelper with JoinSelectionHelper {
  val setting="spark.sql.optimizer.distributeSingleGroupBuild"

  private def source(p:LogicalPlan):Option[HadoopFsRelation]=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>source(c)
    case Filter(cond,c) if cond.deterministic=>source(c)
    case l:LogicalRelation=>l.relation match {
      case r:HadoopFsRelation if r.partitionSchema.isEmpty && r.fileFormat.isInstanceOf[ParquetFileFormat]=>Some(r)
      case _=>None
    }
    case _=>None
  }

  private def boundaries(r:HadoopFsRelation,key:Attribute,cols:Int,nonNull:Seq[String],budget:Long):Seq[Int]=try {
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
      val block=blocks.head
      val stat=block.getColumns.asScala.map(c=>c.getPath.toDotString->c.getStatistics).toMap
      val dropped=nonNull.distinct.map(n=>stat.get(n).filter(v=>v!=null && v.isNumNullsSet).map(_.getNumNulls))
      if(!dropped.forall(_.isDefined) || (BigInt(block.getRowCount)-dropped.flatten.map(BigInt(_)).sum)*
          (8L*(cols+(cols+63)/64))<=budget) return Nil
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

  private def filters(p:LogicalPlan):Option[Seq[String]]=p match {
    case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute])=>filters(c)
    case Filter(cond,c)=>
      val parts=splitConjunctivePredicates(cond)
      val cols=parts.collect {case IsNotNull(a:Attribute)=>a.name}
      if(cols.size==parts.size) filters(c).map(_++cols) else None
    case _:LogicalRelation=>Some(Nil)
    case _=>None
  }

  private def rewrite(j:Join,mode:String,budget:Long):Option[Join]=for {
    side<-getBroadcastBuildSide(j,false,conf)
    left=side==BuildLeft
    build=if(left) j.left else j.right
    probe=if(left) j.right else j.left
    if build.output.size>=2
    cond<-j.condition
    keys=splitConjunctivePredicates(cond).collect {
      case EqualTo(a:Attribute,b:Attribute) if build.outputSet.contains(a) && probe.outputSet.contains(b)=>a
      case EqualTo(a:Attribute,b:Attribute) if build.outputSet.contains(b) && probe.outputSet.contains(a)=>b
    }
    if keys.size==1
    key=keys.head if key.dataType==IntegerType
    r<-source(build)
    nn<-filters(build)
    cuts=boundaries(r,key,build.output.size,nn,budget) if cuts.nonEmpty
  } yield {
    val rows=if(mode=="striped" || mode=="scan") striped(build,key,cuts) else build
    val hint=Some(HintInfo(Some(SHUFFLE_HASH)))
    val selected=if(mode=="scan") JoinHint.NONE else if(left) JoinHint(hint,None) else JoinHint(None,hint)
    if(left) j.copy(left=rows,hint=selected) else j.copy(right=rows,hint=selected)
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"off")
    val budget=conf.autoBroadcastJoinThreshold
    if(budget<=0 || p.isStreaming || !Set("shuffle","striped","scan").contains(mode) ||
        conf.getConfString("spark.sql.parquet.fieldId.read.enabled","false").toBoolean) p
    else p.transformDown {case j @ Join(_,_,Inner,_,JoinHint.NONE)=>rewrite(j,mode,budget).getOrElse(j)}
  }
}
