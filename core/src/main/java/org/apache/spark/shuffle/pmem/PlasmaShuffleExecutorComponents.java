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

package org.apache.spark.shuffle.pmem;

import org.apache.spark.SparkEnv;
import org.apache.spark.SparkConf;
import org.apache.spark.storage.BlockManager;
import com.google.common.annotations.VisibleForTesting;
import org.apache.spark.shuffle.api.ShuffleExecutorComponents;
import org.apache.spark.shuffle.api.ShuffleMapOutputWriter;
import org.apache.spark.shuffle.api.SingleSpillShuffleMapOutputWriter;

import java.util.Map;
import java.util.Optional;

public class PlasmaShuffleExecutorComponents implements ShuffleExecutorComponents {
    private final SparkConf sparkConf;
    private BlockManager blockManager;
    private PlasmaShuffleBlockResolver blockResolver;
    public PlasmaShuffleExecutorComponents(SparkConf sparkConf) {
        this.sparkConf = sparkConf;
    }

    @VisibleForTesting
    public PlasmaShuffleExecutorComponents(
            SparkConf sparkConf,
            BlockManager blockManager,
            PlasmaShuffleBlockResolver blockResolver
            ) {
        this.sparkConf = sparkConf;
        this.blockManager = blockManager;
        this.blockResolver = blockResolver;
    }

    @Override
    public void initializeExecutor(String appId, String execId, Map<String, String> extraConfigs) {
        blockManager = SparkEnv.get().blockManager();
        if (blockManager == null) {
            throw new IllegalStateException("No blockManager available from the SparkEnv.");
        }
        blockResolver = new PlasmaShuffleBlockResolver(sparkConf, blockManager);
    }

    @Override
    public ShuffleMapOutputWriter createMapOutputWriter(
            int shuffleId,
            long mapTaskId,
            int numPartitions) {
        if (blockResolver == null) {
            throw new IllegalStateException(
                    "Executor components must be initialized before getting writers.");
        }
        return new PlasmaShuffleMapOutputWriter(shuffleId, mapTaskId, numPartitions, blockResolver, sparkConf);
    }

    @Override
    public Optional<SingleSpillShuffleMapOutputWriter> createSingleFileMapOutputWriter(
            int shuffleId,
            long mapId) {
        return Optional.empty();
    }
}
