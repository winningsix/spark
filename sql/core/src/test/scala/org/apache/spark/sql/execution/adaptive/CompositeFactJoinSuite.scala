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
    } finally s.stop()
  }
}
