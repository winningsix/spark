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

import io.netty.buffer.ByteBuf

import org.apache.spark.serializer.SerializerInstance

/**
 * Optional serializer fast path for streaming shuffle's native network buffers.
 *
 * Implementations must use the same record format as their regular SerializationStream so that
 * either side can fall back independently without changing the wire protocol. Returned rows may
 * reference `input`; the streaming reader keeps the corresponding DataMessage alive until the
 * iterator is exhausted.
 */
private[spark] trait StreamingShuffleSerializerInstance { self: SerializerInstance =>

  def writeValueToByteBuf(value: Any, output: ByteBuf): Unit

  def keyValueIteratorFromByteBuf(input: ByteBuf): Iterator[(Any, Any)]
}
