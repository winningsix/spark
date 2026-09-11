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

package org.apache.spark.shuffle.streaming

import org.apache.spark.SparkConf
import org.apache.spark.resource.CpuAmount
import org.apache.spark.scheduler.TaskSet

private[spark] object StreamingShuffleTaskResources {
  private val ReaderTaskCpus = "spark.shuffle.streaming.reader.taskCpus"
  private val ReaderProducerTaskCpus = "spark.shuffle.streaming.readerProducer.taskCpus"

  def taskCpus(conf: SparkConf, taskSet: TaskSet, default: BigDecimal): BigDecimal = {
    val key = if (taskSet.isPipelinedShuffleReader && taskSet.isPipelinedShuffleProducer) {
      Some(ReaderProducerTaskCpus)
    } else if (taskSet.isPipelinedShuffleReader) {
      Some(ReaderTaskCpus)
    } else {
      None
    }
    key.flatMap { name =>
      conf.getOption(name).map { value =>
        CpuAmount.parseUntrusted(value).getOrElse {
          throw new IllegalArgumentException(s"$name must be a positive CPU amount")
        }
      }
    }.getOrElse(default)
  }
}
