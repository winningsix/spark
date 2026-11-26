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

import org.apache.spark.SparkConf
import org.apache.spark.SparkFunSuite
import org.apache.spark.sql.test.SharedSparkSession
import org.apache.spark.util.Utils

class LookupMultiplicitySuite extends SparkFunSuite with SharedSparkSession {
  override protected def sparkConf: SparkConf = super.sparkConf
    .set("spark.sql.extensions", classOf[LookupMultiplicityExtension].getName)
    .set("spark.sql.shuffle.partitions", "4")
    .set("spark.sql.adaptive.enabled", "true")

  test("outer lookup summary preserves ordered rows and schema with spill and reuse") {
    val s = spark
    val dir = Utils.createTempDir()
    try {
      val inputs = Seq(
        "f" -> "select * from values (1,100,1),(1,100,1),(2,200,1),(3,300,0),(4,400,1),(null,500,1),(1,null,0),(5,500,0),(-1,-1,1),(-2147483648,2147483647,1),(2147483647,-2147483648,0),(-1,0,1) t(item,ord,flag)",
        "dim" -> "select * from values (1,'a'),(1,'a'),(1,'b'),(2,'a'),(3,null),(null,'a'),(5,'c'),(-1,'d'),(-2147483648,'e'),(2147483647,'f') t(k,label)",
        "r" -> "select * from values (1,100),(1,100),(2,200),(4,400),(null,500),(1,null),(1,null),(-1,-1),(-1,-1),(-2147483648,2147483647),(-2147483648,2147483647),(2147483647,-2147483648),(-1,0) t(ri,ro)")
      for ((name, query) <- inputs) {
        val path = new java.io.File(dir,name).getPath
        s.sql(query).write.parquet(path)
        s.read.parquet(path).createOrReplaceTempView(name)
      }
      def run(sql:String, mode:String, budget:Long) = {
        s.conf.set("spark.sql.optimizer.exactRepeatSummary",mode)
        s.conf.set("spark.sql.shuffle.localRepeatedLookup.maxTaskBytes",budget)
        val df=s.sql(sql)
        val optimized=df.queryExecution.optimizedPlan.treeString
        val rows=df.collect().toList
        (df.schema,rows,optimized)
      }
      val joined="select label, count(*) n,sum(flag) p from f join dim on item=k left outer join r on item=ri and ord=ro group by label"
      val extra="select 'raw' label,count(*) n,sum(cast(ri as bigint)) p from r"
      val queries=Seq(joined+" order by label nulls first",
        "select * from ("+joined+" union all "+extra+") whole order by label nulls first",
        joined.replace("left outer join r","left outer join (select * from r where ri=10000) r")+" order by label nulls first")
      for (q<-queries) {
        val (schema,expected,_)=run(q,"off",0)
        for (mode<-Seq("sealed","direct"); budget<-Seq(0L,67108864L)) {
          val (actual,rows,logical)=run(q,mode,budget)
          require(schema==actual && rows==expected,s"$mode $budget $expected != $rows")
          require(logical.contains("RepeatedLookupKeys"),logical)

        }
      }
    } finally {
      Seq("f", "dim", "r").foreach(s.catalog.dropTempView)
      Utils.deleteRecursively(dir)
    }
  }
}
