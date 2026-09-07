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
package org.apache.spark.network.util;

import io.netty.buffer.PooledByteBufAllocator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NettyUtilsSuite {

  @Test
  public void sharedAllocatorsPreserveDirectAndCachePolicies() {
    for (boolean allowCache : new boolean[] {false, true}) {
      PooledByteBufAllocator direct =
        NettyUtils.getSharedPooledByteBufAllocator(true, allowCache);
      PooledByteBufAllocator heap =
        NettyUtils.getSharedPooledByteBufAllocator(false, allowCache);

      assertNotSame(direct, heap);
      assertSame(direct, NettyUtils.getSharedPooledByteBufAllocator(true, allowCache));
      assertSame(heap, NettyUtils.getSharedPooledByteBufAllocator(false, allowCache));
      var directBuffer = direct.ioBuffer(64);
      var heapBuffer = heap.ioBuffer(64);
      try {
        assertTrue(directBuffer.isDirect());
        assertFalse(heapBuffer.isDirect());
      } finally {
        directBuffer.release();
        heapBuffer.release();
      }
    }
  }
}
