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

import net.jpountz.lz4.LZ4Factory

/** Executor-JVM-wide stateless LZ4 primitives for independent streaming-shuffle blocks. */
private[streaming] object StreamingShuffleCompression {
  // Cache fastestInstance() once: repeated JNI discovery can serialize on LZ4Factory and retry a
  // failed native load. The compressor and decompressor implementations are stateless.
  private lazy val factory = LZ4Factory.fastestInstance()
  lazy val compressor = factory.fastCompressor()
  // The factory's fastDecompressor is a Java implementation for ByteBuffer input in lz4-java
  // 1.11.1, while safeDecompressor is JNI-backed and can validate the compressed input length.
  lazy val decompressor = factory.safeDecompressor()
}
