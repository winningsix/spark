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

package org.apache.spark.util.sketch

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, DataInputStream, DataOutputStream}

import scala.util.Random

import org.scalatest.funsuite.AnyFunSuite // scalastyle:ignore funsuite

class BitArraySuite extends AnyFunSuite { // scalastyle:ignore funsuite

  test("error case when create BitArray") {
    intercept[IllegalArgumentException](new BitArray(0))
    intercept[IllegalArgumentException](new BitArray(64L * Integer.MAX_VALUE + 1))
  }

  test("bitSize") {
    assert(new BitArray(64).bitSize() == 64)
    // BitArray is word-aligned, so 65~128 bits need 2 long to store, which is 128 bits.
    assert(new BitArray(65).bitSize() == 128)
    assert(new BitArray(127).bitSize() == 128)
    assert(new BitArray(128).bitSize() == 128)
  }

  test("set") {
    val bitArray = new BitArray(64)
    assert(bitArray.set(1))
    // Only returns true if the bit changed.
    assert(!bitArray.set(1))
    assert(bitArray.set(2))
  }

  test("normal operation") {
    // use a fixed seed to make the test predictable.
    val r = new Random(37)

    val bitArray = new BitArray(320)
    val indexes = (1 to 100).map(_ => r.nextInt(320).toLong).distinct

    indexes.foreach(bitArray.set)
    indexes.foreach(i => assert(bitArray.get(i)))
    assert(bitArray.cardinality() == indexes.length)
  }

  test("serialization keeps the per-word big-endian format across buffer chunks") {
    val r = new Random(37)
    // Spans several I/O chunks plus a partial one.
    for (numWords <- Seq(1, 8191, 8192, 8193, 3 * 8192 + 17)) {
      val bitArray = new BitArray(64L * numWords)
      (1 to 2000).foreach(_ => bitArray.set((r.nextLong() & Long.MaxValue) % (64L * numWords)))
      val bytes = new ByteArrayOutputStream()
      bitArray.writeTo(new DataOutputStream(bytes))

      // Decode word by word as the previous per-word DataOutput format.
      val in = new DataInputStream(new ByteArrayInputStream(bytes.toByteArray))
      assert(in.readInt() == numWords)
      val decoded = new BitArray(64L * numWords)
      for (w <- 0 until numWords) {
        val word = in.readLong()
        (0 until 64).filter(b => ((word >>> b) & 1L) == 1L).foreach(b => decoded.set(64L * w + b))
      }
      assert(in.read() == -1)
      assert(decoded == bitArray)

      val roundTrip = BitArray.readFrom(new DataInputStream(
        new ByteArrayInputStream(bytes.toByteArray)))
      assert(roundTrip == bitArray)
      assert(roundTrip.cardinality() == bitArray.cardinality())
    }
  }

  test("merge") {
    // use a fixed seed to make the test predictable.
    val r = new Random(37)

    val bitArray1 = new BitArray(64 * 6)
    val bitArray2 = new BitArray(64 * 6)

    val indexes1 = (1 to 100).map(_ => r.nextInt(64 * 6).toLong).distinct
    val indexes2 = (1 to 100).map(_ => r.nextInt(64 * 6).toLong).distinct

    indexes1.foreach(bitArray1.set)
    indexes2.foreach(bitArray2.set)

    bitArray1.putAll(bitArray2)
    indexes1.foreach(i => assert(bitArray1.get(i)))
    indexes2.foreach(i => assert(bitArray1.get(i)))
    assert(bitArray1.cardinality() == (indexes1 ++ indexes2).distinct.length)
  }
}
