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

package org.apache.spark.sql.execution

import java.io._
import java.nio.ByteBuffer

import scala.reflect.ClassTag

import io.netty.buffer.{ByteBuf, ByteBufInputStream}

import org.apache.spark.{SparkEnv, SparkUnsupportedOperationException}
import org.apache.spark.serializer.{DeserializationStream, SerializationStream, Serializer, SerializerInstance}
import org.apache.spark.shuffle.streaming.StreamingShuffleSerializerInstance
import org.apache.spark.sql.catalyst.expressions.UnsafeRow
import org.apache.spark.sql.execution.metric.SQLMetric
import org.apache.spark.unsafe.Platform
import org.apache.spark.util.Utils

/**
 * Serializer for serializing [[UnsafeRow]]s during shuffle. Since UnsafeRows are already stored as
 * bytes, this serializer simply copies those bytes to the underlying output stream. When
 * deserializing a stream of rows, instances of this serializer mutate and return a single UnsafeRow
 * instance that is backed by an on-heap byte array.
 *
 * Note that this serializer implements only the [[Serializer]] methods that are used during
 * shuffle, so certain [[SerializerInstance]] methods will throw SparkUnsupportedOperationException.
 *
 * @param numFields the number of fields in the row being serialized.
 */
class UnsafeRowSerializer(
    numFields: Int,
    dataSize: SQLMetric = null) extends Serializer with Serializable {
  // Capture the setting on the driver for every writer of this dependency.
  private val compactPairs = numFields == 2 && Option(SparkEnv.get).exists(_.conf.getBoolean(
    "spark.shuffle.unsafeRow.compactWordPairs.enabled", false))

  private val compactTriples = numFields == 3 && Option(SparkEnv.get).exists(_.conf.getBoolean(
    "spark.shuffle.unsafeRow.compactTriples.enabled", false))

  private val compactSingles = numFields == 1 && Option(SparkEnv.get).exists(_.conf.getBoolean(
    "spark.shuffle.unsafeRow.compactSingleWord.enabled", false))

  private val compactFlags = compactTriples && SparkEnv.get.conf.getBoolean(
    "spark.sql.shuffle.distributedPipelined.enabled", false)

  override def newInstance(): SerializerInstance =
    new UnsafeRowSerializerInstance(numFields, dataSize, compactPairs, compactTriples, compactSingles, compactFlags)
  override def supportsRelocationOfSerializedObjects: Boolean = true
}

private class UnsafeRowSerializerInstance(
    numFields: Int,
    dataSize: SQLMetric,
    compactPairs: Boolean,
    compactTriples: Boolean,
    compactSingles: Boolean,
    compactFlags: Boolean)
    extends SerializerInstance with StreamingShuffleSerializerInstance {

  def this(numFields: Int, dataSize: SQLMetric, compactPairs: Boolean,
      compactTriples: Boolean, compactSingles: Boolean) =
    this(numFields, dataSize, compactPairs, compactTriples, compactSingles, false)

  def this(numFields: Int, dataSize: SQLMetric, compactPairs: Boolean, compactTriples: Boolean) =
    this(numFields, dataSize, compactPairs, compactTriples, false)

  def this(numFields: Int, dataSize: SQLMetric, compactPairs: Boolean) =
    this(numFields, dataSize, compactPairs, false)

  // A non-null, one-field UnsafeRow with no variable payload occupies two words. Pack
  // a 38-bit unsigned value into a tagged 30-bit prefix and one trailing byte.
  private def singleWord(row: UnsafeRow): Long = {
    if (row.getSizeInBytes == 16 && Platform.getLong(row.getBaseObject, row.getBaseOffset) == 0L) {
      val value = row.getLong(0)
      if ((value >>> 38) == 0L) return value
    }
    -1L
  }

  private def restoreSingle(header: Int, tail: Int, buffer: Array[Byte], row: UnsafeRow): Unit = {
    row.pointTo(buffer, Platform.BYTE_ARRAY_OFFSET, 16)
    Platform.putLong(buffer, Platform.BYTE_ARRAY_OFFSET, 0L)
    row.setLong(0, ((header & 0x3fffffff).toLong << 8) | tail.toLong)
  }

  // Keep the first word verbatim. Two bits select how the remaining 29 header bits
  // are shared by the other words. The fourth mode is reserved (including the EOF value).
  // Prefix 1110 is outside the existing triple modes and leaves 60 payload bits.
  // Inspect all three raw words so nulls, padding and out-of-range values retain
  // their original encoding. No column statistics are needed for correctness.
  private def packedFlag(row: UnsafeRow): Long = {
    if (!compactFlags || row.getSizeInBytes != 32 ||
        Platform.getLong(row.getBaseObject, row.getBaseOffset) != 0L) return 0L
    val key = row.getLong(0)
    val value = row.getLong(1)
    val flag = row.getLong(2)
    if ((key >>> 35) != 0 || (value >>> 24) != 0 || (flag >>> 1) != 0) return 0L
    0xe000000000000000L | (key << 25) | (value << 1) | flag
  }

  private def unpackFlag(header: Int, tail: Int, buffer: Array[Byte], row: UnsafeRow): Unit = {
    val packed = (header.toLong << 32) | Integer.toUnsignedLong(tail)
    row.pointTo(buffer, Platform.BYTE_ARRAY_OFFSET, 32)
    Platform.putLong(buffer, Platform.BYTE_ARRAY_OFFSET, 0L)
    row.setLong(0, (packed >>> 25) & 0x7ffffffffL)
    row.setLong(1, (packed >>> 1) & 0xffffffL)
    row.setLong(2, packed & 1L)
  }

  private def tripleHeader(row: UnsafeRow): Int = {
    if (row.getSizeInBytes != 32 || Platform.getLong(row.getBaseObject, row.getBaseOffset) != 0L) {
      return 0
    }
    val b = row.getLong(1)
    val c = row.getLong(2)
    if ((b >>> 24) == 0 && (c >>> 5) == 0) {
      0x80000000 | (b.toInt << 5) | c.toInt
    } else if ((b >>> 16) == 0 && (c >>> 13) == 0) {
      0xa0000000 | (b.toInt << 13) | c.toInt
    } else if ((b >>> 8) == 0 && (c >>> 21) == 0) {
      0xc0000000 | (b.toInt << 21) | c.toInt
    } else {
      0
    }
  }

  private def unpackTriple(header: Int, first: Long, buffer: Array[Byte], row: UnsafeRow): Unit = {
    val width = 5 + 8 * ((header >>> 29) & 3)
    row.pointTo(buffer, Platform.BYTE_ARRAY_OFFSET, 32)
    Platform.putLong(buffer, Platform.BYTE_ARRAY_OFFSET, 0L)
    row.setLong(0, first)
    row.setLong(1, (header & 0x1fffffff) >>> width)
    row.setLong(2, header & ((1 << width) - 1))
  }

  // A negative header distinguishes this eight-byte record from an ordinary length and payload.
  // The two words may trade places so either can carry the wider value. Preserve all 24 raw
  // bytes, including the null word, by escaping anything outside this representation.
  private def pack(row: UnsafeRow): Long = {
    if (!compactPairs || row.getSizeInBytes != 24 ||
        Platform.getLong(row.getBaseObject, row.getBaseOffset) != 0L) return 0L
    val a = row.getLong(0)
    val b = row.getLong(1)
    if ((a >>> 36) == 0 && (b >>> 26) == 0) {
      Long.MinValue | (a << 26) | b
    } else if ((b >>> 36) == 0 && (a >>> 26) == 0) {
      val packed = Long.MinValue | (1L << 62) | (b << 26) | a
      if ((packed >> 32).toInt == -1) 0L else packed
    } else {
      0L
    }
  }

  private def unpack(header: Int, tail: Int, buffer: Array[Byte], row: UnsafeRow): Unit = {
    val bits = (header.toLong << 32) | Integer.toUnsignedLong(tail)
    val wide = (bits >>> 26) & ((1L << 36) - 1)
    val narrow = bits & ((1L << 26) - 1)
    val swapped = (header & (1 << 30)) != 0
    row.pointTo(buffer, Platform.BYTE_ARRAY_OFFSET, 24)
    Platform.putLong(buffer, Platform.BYTE_ARRAY_OFFSET, 0L)
    row.setLong(0, if (swapped) narrow else wide)
    row.setLong(1, if (swapped) wide else narrow)
  }

  override def writeValueToByteBuf(value: Any, output: ByteBuf): Unit = {
    val row = value.asInstanceOf[UnsafeRow]
    val rowSize = row.getSizeInBytes
    if (dataSize != null) dataSize.add(rowSize)
    if (compactSingles) {
      val value = singleWord(row)
      if (value >= 0L) {
        output.writeInt(0x80000000 | (value >>> 8).toInt)
        output.writeByte(value.toInt)
        return
      }
    }
    val flagged = packedFlag(row)
    if (flagged != 0L) {
      output.writeInt((flagged >>> 32).toInt)
      output.writeInt(flagged.toInt)
      return
    }
    val triple = if (compactTriples) tripleHeader(row) else 0
    if (triple != 0) {
      output.writeInt(triple)
      output.writeLong(row.getLong(0))
      return
    }
    val packed = pack(row)
    if (packed != 0L) {
      output.writeInt((packed >>> 32).toInt)
      output.writeInt(packed.toInt)
      return
    }
    output.ensureWritable(Integer.BYTES + rowSize)
    output.writeInt(rowSize)
    val targetIndex = output.writerIndex()
    if (output.hasMemoryAddress) {
      row.writeToMemory(null, output.memoryAddress() + targetIndex)
      output.writerIndex(targetIndex + rowSize)
    } else if (output.hasArray) {
      row.writeToMemory(
        output.array(), Platform.BYTE_ARRAY_OFFSET + output.arrayOffset() + targetIndex)
      output.writerIndex(targetIndex + rowSize)
    } else {
      output.writeBytes(row.getBytes)
    }
  }

  override def keyValueIteratorFromByteBuf(input: ByteBuf): Iterator[(Any, Any)] = {
    if (numFields != 3 && numFields != 1 && !input.hasMemoryAddress && !input.hasArray) {
      return deserializeStream(new ByteBufInputStream(input)).asKeyValueIterator
        .asInstanceOf[Iterator[(Any, Any)]]
    }
    new Iterator[(Any, Any)] {
      private val row = new UnsafeRow(numFields)
      private lazy val expandedRow = new Array[Byte](if (numFields == 3) 32 else 24)
      private var copiedRow: Array[Byte] = _
      private val rowTuple: (Int, UnsafeRow) = (0, row)

      override def hasNext: Boolean = input.isReadable

      override def next(): (Any, Any) = {
        if (input.readableBytes() < Integer.BYTES) {
          throw new EOFException("Incomplete UnsafeRow length in streaming shuffle buffer")
        }
        val rowSize = input.readInt()
        if (numFields == 1 && (rowSize >>> 30) == 2 && input.isReadable) {
          restoreSingle(rowSize, input.readUnsignedByte().toInt, expandedRow, row)
          return rowTuple
        }
        if (numFields == 3 && (rowSize >>> 28) == 14) {
          if (input.readableBytes() < Integer.BYTES) throw new EOFException("Incomplete compact triple")
          unpackFlag(rowSize, input.readInt(), expandedRow, row)
          return rowTuple
        }
        if (numFields == 3 && rowSize < 0 && (rowSize >>> 29) < 7 &&
            input.readableBytes() >= java.lang.Long.BYTES) {
          unpackTriple(rowSize, input.readLong(), expandedRow, row)
          return rowTuple
        }
        if (numFields == 2 && rowSize < -1 && input.readableBytes() >= Integer.BYTES) {
          unpack(rowSize, input.readInt(), expandedRow, row)
          return rowTuple
        }
        if (rowSize < 0 || rowSize > input.readableBytes()) {
          throw new EOFException(
            s"Invalid UnsafeRow size $rowSize with ${input.readableBytes()} readable bytes")
        }
        val rowIndex = input.readerIndex()
        if (input.hasMemoryAddress) {
          row.pointTo(null, input.memoryAddress() + rowIndex, rowSize)
        } else if (input.hasArray) {
          row.pointTo(
            input.array(), Platform.BYTE_ARRAY_OFFSET + input.arrayOffset() + rowIndex, rowSize)
        } else {
          if (copiedRow == null || copiedRow.length < rowSize) copiedRow = new Array[Byte](rowSize)
          input.getBytes(rowIndex, copiedRow, 0, rowSize)
          row.pointTo(copiedRow, rowSize)
        }
        input.skipBytes(rowSize)
        rowTuple
      }
    }
  }

  /**
   * Serializes a stream of UnsafeRows. Within the stream, each record consists of a record
   * length and payload or a tagged one-, two-, or three-field representation.
   */
  override def serializeStream(out: OutputStream): SerializationStream = new SerializationStream {
    private[this] var writeBuffer: Array[Byte] = new Array[Byte](4096)
    private[this] val dOut: DataOutputStream =
      new DataOutputStream(new BufferedOutputStream(out))

    override def writeValue[T: ClassTag](value: T): SerializationStream = {
      val row = value.asInstanceOf[UnsafeRow]
      if (dataSize != null) {
        dataSize.add(row.getSizeInBytes)
      }
      if (compactSingles) {
        val value = singleWord(row)
        if (value >= 0L) {
          dOut.writeInt(0x80000000 | (value >>> 8).toInt)
          dOut.writeByte(value.toInt)
          return this
        }
      }
      val flagged = packedFlag(row)
      if (flagged != 0L) {
        dOut.writeInt((flagged >>> 32).toInt)
        dOut.writeInt(flagged.toInt)
        return this
      }
      val triple = if (compactTriples) tripleHeader(row) else 0
      if (triple != 0) {
        dOut.writeInt(triple)
        dOut.writeLong(row.getLong(0))
        return this
      }
      val packed = pack(row)
      if (packed == 0L) {
        dOut.writeInt(row.getSizeInBytes)
        row.writeToStream(dOut, writeBuffer)
      } else {
        dOut.writeLong(packed)
      }
      this
    }

    override def writeKey[T: ClassTag](key: T): SerializationStream = {
      // The key is only needed on the map side when computing partition ids. It does not need to
      // be shuffled.
      assert(null == key || key.isInstanceOf[Int])
      this
    }

    override def writeAll[T: ClassTag](iter: Iterator[T]): SerializationStream = {
      // This method is never called by shuffle code.
      throw SparkUnsupportedOperationException()
    }

    override def writeObject[T: ClassTag](t: T): SerializationStream = {
      // This method is never called by shuffle code.
      throw SparkUnsupportedOperationException()
    }

    override def flush(): Unit = {
      dOut.flush()
    }

    override def close(): Unit = {
      writeBuffer = null
      dOut.close()
    }
  }

  override def deserializeStream(in: InputStream): DeserializationStream = {
    new DeserializationStream {
      private[this] val dIn: DataInputStream = new DataInputStream(new BufferedInputStream(in))
      // 1024 is a default buffer size; this buffer will grow to accommodate larger rows
      private[this] var rowBuffer: Array[Byte] = new Array[Byte](1024)
      private[this] var row: UnsafeRow = new UnsafeRow(numFields)
      private[this] var rowTuple: (Int, UnsafeRow) = (0, row)
      private[this] val EOF: Int = -1

      private def readRow(header: Int): Unit = {
        if (header >= 0) {
          if (rowBuffer.length < header) rowBuffer = new Array[Byte](header)
          Utils.readFully(dIn, rowBuffer, 0, header)
          row.pointTo(rowBuffer, Platform.BYTE_ARRAY_OFFSET, header)
        } else if (numFields == 1 && (header >>> 30) == 2) {
          restoreSingle(header, dIn.readUnsignedByte(), rowBuffer, row)
        } else if (numFields == 3 && (header >>> 28) == 14) {
          unpackFlag(header, dIn.readInt(), rowBuffer, row)
        } else if (numFields == 3 && (header >>> 29) < 7) {
          unpackTriple(header, dIn.readLong(), rowBuffer, row)
        } else if (numFields == 2 && header < -1) {
          unpack(header, dIn.readInt(), rowBuffer, row)
        } else {
          throw new IOException(s"Invalid UnsafeRow size $header")
        }
      }

      override def asKeyValueIterator: Iterator[(Int, UnsafeRow)] = {
        new Iterator[(Int, UnsafeRow)] {

          private[this] def readSize(): Int = try {
            dIn.readInt()
          } catch {
            case e: EOFException =>
              dIn.close()
              EOF
          }

          private[this] var rowSize: Int = readSize()
          override def hasNext: Boolean = rowSize != EOF

          override def next(): (Int, UnsafeRow) = {
            readRow(rowSize)
            rowSize = readSize()
            if (rowSize == EOF) { // We are returning the last row in this stream
              dIn.close()
              val _rowTuple = rowTuple
              // Null these out so that the byte array can be garbage collected once the entire
              // iterator has been consumed
              row = null
              rowBuffer = null
              rowTuple = null
              _rowTuple
            } else {
              rowTuple
            }
          }
        }
      }

      override def asIterator: Iterator[Any] = {
        // This method is never called by shuffle code.
        throw SparkUnsupportedOperationException()
      }

      override def readKey[T: ClassTag](): T = {
        // We skipped serialization of the key in writeKey(), so just return a dummy value since
        // this is going to be discarded anyways.
        null.asInstanceOf[T]
      }

      override def readValue[T: ClassTag](): T = {
        val rowSize = dIn.readInt()
        readRow(rowSize)
        row.asInstanceOf[T]
      }

      override def readObject[T: ClassTag](): T = {
        // This method is never called by shuffle code.
        throw SparkUnsupportedOperationException()
      }

      override def close(): Unit = {
        dIn.close()
      }
    }
  }

  // These methods are never called by shuffle code.
  override def serialize[T: ClassTag](t: T): ByteBuffer = throw SparkUnsupportedOperationException()
  override def deserialize[T: ClassTag](bytes: ByteBuffer): T =
    throw SparkUnsupportedOperationException()
  override def deserialize[T: ClassTag](bytes: ByteBuffer, loader: ClassLoader): T =
    throw SparkUnsupportedOperationException()
}
