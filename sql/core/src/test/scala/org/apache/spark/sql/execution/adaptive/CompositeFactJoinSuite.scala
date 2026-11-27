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

import org.apache.spark.SparkFunSuite
import org.apache.spark.sql.classic.SparkSession
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._

class CompositeFactJoinSuite extends SparkFunSuite {
  test("two connected dimensions contribute a second fact join key without changing row multiplicity") {
    val s=SparkSession.builder().master("local[3]").appName("composite join")
      .config("spark.ui.enabled","false").config("spark.sql.autoBroadcastJoinThreshold","-1")
      .config("spark.sql.extensions",classOf[LookupMultiplicityExtension].getName).getOrCreate()
    try withTempDir { dir =>
      import s.implicits._
      Seq((1,10,2),(1,10,2),(2,11,3),(3,12,4),(1,15,4)).toDF("i","da","x").write.parquet(dir+"/a")
      Seq((1,11,1),(1,12,1),(1,14,2),(2,10,7),(3,10,1)).toDF("j","db","y").write.parquet(dir+"/b")
      Seq((10,Some(8)),(10,Some(8)),(11,Some(8)),(12,Some(9)),(14,None)).toDF("day","week").write.parquet(dir+"/d")
      for (n<-Seq("a","b","d")) s.read.parquet(dir+"/"+n).createOrReplaceTempView(n)
      val sql="select a.i,a.x,b.y,d1.week from a join b on a.i=b.j and b.y<a.x "+
        "join d d1 on a.da=d1.day join d d2 on b.db=d2.day and d1.week=d2.week"
      def planned(text:String,mode:String)={
        s.conf.set(CompositeFactJoin.setting,mode)
        val df=s.sql(text);(df.queryExecution.optimizedPlan,df.collect().map(_.toString).sorted.toList)
      }
      def composite(p:LogicalPlan)=p.exists {
        case Join(_,_,Inner,Some(c),_)=>c.exists(_.isInstanceOf[LessThan]) && c.collect {case e:EqualTo=>e}.size>=2
        case _=>false
      }
      val (parent,rows)=planned(sql,"off");assert(rows.size==4 && !composite(parent))
      for (mode<-Seq("keys","filters")){
        val (next,actual)=planned(sql,mode);assert(actual==rows && composite(next),next.treeString)
        val outer=sql.replace("from a join b","from a left outer join b")
        val keep=planned(outer,mode);assert(keep._2==planned(outer,"off")._2)
      }
      s.conf.set("spark.sql.optimizer.compositeFactJoin.buildSide", "left")
      val (hinted, withHint) = planned(sql, "filters")
      assert(withHint == rows)
      assert(hinted.exists {
        case j: Join => j.hint.leftHint.exists(_.strategy.contains(SHUFFLE_HASH))
        case _ => false
      })

      val indicators = "sum(case when week is null then 1 else 0 end) n, " +
        "sum(case when week is not null then 1 else 0 end) p, count(*) c, count(week) cw"
      for (filter <- Seq("", " where day=-1")) {
        val query = "select " + indicators + " from d" + filter
        s.conf.set("spark.sql.optimizer.countComplementarySums", false)
        val reference = s.sql(query)
        val expected = reference.collect().toList
        s.conf.set("spark.sql.optimizer.countComplementarySums", true)
        val rewritten = s.sql(query)
        assert(rewritten.schema == reference.schema && rewritten.collect().toList == expected)
        if (filter.isEmpty) {
          val tree = rewritten.queryExecution.optimizedPlan.treeString
          assert(!tree.contains("count(1)") && tree.contains("count(week"), tree)
        }
      }
    } finally s.stop()
  }
  test("derived range scans preserve upper-bound overflow, nulls and empty inputs") {
    val session = SparkSession.builder().master("local[3]").appName("derived range bound")
      .config("spark.ui.enabled", false)
      .config("spark.sql.shuffle.partitions", 4)
      .config("spark.sql.extensions", classOf[LookupMultiplicityExtension].getName)
      .getOrCreate()
    try withTempDir { dir =>
      val sources = Map(
        "sales" -> "select * from values (1,1,3),(1,2,8),(1,2,null),(2,1,1) as t(item,day,qty)",
        "stock" -> "select * from values (1,1,2),(1,2,6),(1,1,8),(1,1,null) as t(item,day,n)",
        "cal" -> "select * from values (1,4,0),(1,4,0),(2,4,0),(3,5,1) as t(day,wk,yr)")
      sources.foreach { case (name, query) =>
        val path = new java.io.File(dir, name).toString
        session.sql(query).write.parquet(path)
        session.read.parquet(path).createOrReplaceTempView(name)
      }
      val query = """with a as (select s.item,s.qty,c.wk from sales s join cal c
                    |on s.day=c.day where c.yr=0), b as (select t.item,t.n,c.wk from stock t
                    |join cal c on t.day=c.day)
                    |select a.qty,b.n from a join b on a.item=b.item and a.wk=b.wk
                    |and b.n<a.qty order by a.qty,b.n""".stripMargin
      session.conf.set("spark.sql.optimizer.pruneRelatedLookup", false)
      val expected = session.sql(query).collect().toList
      assert(expected.exists(_.getInt(1) == 6))
      session.conf.set("spark.sql.optimizer.pruneRelatedLookup", true)
      session.conf.set("spark.sql.optimizer.rangeMaxScanTasks", 2)
      session.conf.set("spark.sql.optimizer.joinRangeCutoff", 4)
      session.conf.set("spark.sql.adaptive.prepareDerivedRange", true)
      val range = session.sql(query)
      assert(range.queryExecution.optimizedPlan.collectWithSubqueries {
        case a: Aggregate if a.getTagValue(PruneRelatedLookup.DERIVED_RANGE_BOUND).contains(true) => a
      }.nonEmpty)
      assert(range.collect().toList == expected)
      assert(session.sql(query.replace("c.yr=0", "c.yr=99")).collect().isEmpty)
    } finally {
      session.stop()
    }
  }

}
