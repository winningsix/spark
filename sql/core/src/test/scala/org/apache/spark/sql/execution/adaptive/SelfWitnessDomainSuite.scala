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

import org.apache.spark.{SparkConf, SparkFunSuite}
import org.apache.spark.sql.test.SharedSparkSession
import org.apache.spark.util.Utils

class SelfWitnessDomainSuite extends SparkFunSuite with SharedSparkSession {
  override protected def sparkConf: SparkConf = super.sparkConf
    .set("spark.sql.extensions", classOf[SelfWitnessDomainExtension].getName + "," +
      classOf[SelfWitnessDomainAfterExtension].getName)
    .set("spark.sql.optimizer.selfWitnessDomain.expectedNumItems", "2")
    .set("spark.sql.shuffle.partitions", "4")

  test("order membership preserves duplicate and nullable rows across joins") {
    val tmp=Utils.createTempDir()
    try {
      val rows="values (1,1),(1,1),(1,2),(1,null),(2,5),(2,5),(3,null),(null,2),(null,3),(4,9),(4,null),(5,1),(5,7)"
      spark.sql("select * from "+rows+" as t(k,v)").write.parquet(tmp+"/a")
      spark.sql("select * from values (1,3),(1,3),(2,6),(null,1),(9,null) as t(k,v)").write.parquet(tmp+"/b")
      for(t<-Seq("a","b"))spark.read.parquet(tmp+"/"+t).createOrReplaceTempView(t)
      def check(sql:String, expected:Boolean): Unit = {
        def run(enabled:Boolean) = {
          spark.conf.set("spark.sql.optimizer.selfWitnessDomain.enabled",enabled)
          spark.conf.set("spark.sql.optimizer.mergeWitnessExclusion.enabled",enabled)
          spark.conf.set("spark.sql.optimizer.filterOrderUpdates.enabled",enabled)
          spark.conf.set("spark.sql.optimizer.sharedCandidateOrders.enabled",enabled)
          spark.conf.set("spark.sql.optimizer.filterMembershipInputs.enabled",enabled)
          spark.conf.set("spark.sql.optimizer.mergePositiveOrderDomains.enabled",enabled)
          val df=spark.sql(sql)
          (df.schema, df.collect().toList, df.queryExecution.optimizedPlan.treeString)
        }
        val off=run(false); val on=run(true)
        require(off._1==on._1 && off._2==on._2,(sql, off._2,on._2).toString)
        require(on._3.contains("witness_min")==expected,sql+"\n"+on._3)
      }
      for(op<-Seq("exists","not exists")) {
        check(s"select * from a l where l.k<5 and $op (select 1 from a r where r.k=l.k and r.v<>l.v) order by k,v",true)
        check(s"select * from a l where $op (select 1 from a r where r.k=l.k and r.v<>l.v and r.v=1) order by k,v",false)
        check(s"select * from a l where $op (select 1 from b r where r.k=l.k and r.v<>l.v) order by k,v",false)
      }
      check("select l.* from a l left semi join a r on l.k=r.k and l.v<>r.v order by k,v",true)
      val pairs = "select l.k,l.v from a l where exists (select 1 from a w where w.k=l.k and w.v<>l.v) and not exists (select 1 from b e where e.k=l.k) order by k,v"
      check(pairs,true)
      require(spark.sql(pairs).queryExecution.optimizedPlan.treeString.contains("has_exclusion"))
      val extra=pairs.replace("e.k=l.k)", "e.k=l.k and e.v<>l.v)")
      check(extra,true)
      require(!spark.sql(extra).queryExecution.optimizedPlan.treeString.contains("has_exclusion"))
      val grouped = "select count(*),sum(l.v) from a l join (select * from b where v=3) d on l.k=d.k " +
        "where exists (select 1 from a w where w.k=l.k and w.v<>l.v) and " +
        "not exists (select 1 from b e where e.k=l.k and e.v=7)"
      check(grouped,true)
      require(spark.sql(grouped).queryExecution.optimizedPlan.treeString.contains("candidate_order_filter"))
      check(grouped.replace("v=3","v=99"),true)
      val both = "select count(distinct l.k),sum(l.v) from a l join (select * from b where v=3) d on l.v=d.k " +
        "where l.k in (select k from a group by k having min(v)<max(v)) " +
        "and l.k in (select k from b)"
      check(both,true)
      val shape=spark.sql(both).queryExecution.optimizedPlan.treeString
      require(shape.contains("candidate_order_filter") && shape.contains("has_returned_order"),shape)
      check(both.replace("v=3","v=99"),true)
      val cte = "with pairs as (select x.k from a x join a y on x.k=y.k and x.v<>y.v) "
      val raw = cte + "select l.k,l.v from a l where l.k in (select k from pairs) " +
        "and l.k in (select b.k from b join pairs p on b.k=p.k) order by l.k,l.v"
      check(raw, true)
      check(raw.replace("a y on", "b y on"), false)
      check(raw.replace("b.k=p.k", "b.v=p.k"), false)
    } finally {
      Seq("a","b").foreach(spark.catalog.dropTempView)
      Utils.deleteRecursively(tmp)
    }
  }
}
