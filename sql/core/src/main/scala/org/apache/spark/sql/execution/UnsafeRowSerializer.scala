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

import io.netty.buffer.{ByteBuf, ByteBufOutputStream}

import org.apache.spark.SparkUnsupportedOperationException
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
  override def newInstance(): SerializerInstance =
    new UnsafeRowSerializerInstance(numFields, dataSize)
  override def supportsRelocationOfSerializedObjects: Boolean = true
}

private class UnsafeRowSerializerInstance(
    numFields: Int,
    dataSize: SQLMetric) extends SerializerInstance with StreamingShuffleSerializerInstance {

  private[this] val byteBufWriteBuffer: Array[Byte] = new Array[Byte](4096)

  override def serializedValueSize(value: Any): Option[Int] = {
    // The streaming representation is one four-byte length followed by the UnsafeRow bytes.
    Some(Math.addExact(Integer.BYTES, value.asInstanceOf[UnsafeRow].getSizeInBytes))
  }

  private def byteBufBaseObject(buffer: ByteBuf): Object = {
    if (buffer.hasArray) buffer.array() else null
  }

  private def byteBufBaseOffset(buffer: ByteBuf, index: Int): Long = {
    if (buffer.hasArray) {
      Platform.BYTE_ARRAY_OFFSET + buffer.arrayOffset() + index
    } else {
      buffer.memoryAddress() + index
    }
  }

  /**
   * Writes the same length-prefixed format as serializeStream directly into streaming shuffle's
   * native buffer. UnsafeRow data is already in its wire representation, so the common direct or
   * array-backed ByteBuf paths need one memory copy and no OutputStream layers.
   */
  override def writeValueToByteBuf(value: Any, output: ByteBuf): Unit = {
    val row = value.asInstanceOf[UnsafeRow]
    val rowSize = row.getSizeInBytes
    if (dataSize != null) dataSize.add(rowSize)
    output.writeInt(rowSize)
    output.ensureWritable(rowSize)
    if (output.hasArray || output.hasMemoryAddress) {
      val writerIndex = output.writerIndex()
      Platform.copyMemory(
        row.getBaseObject,
        row.getBaseOffset,
        byteBufBaseObject(output),
        byteBufBaseOffset(output, writerIndex),
        rowSize)
      output.writerIndex(writerIndex + rowSize)
    } else {
      // Composite/custom ByteBuf implementations need not expose a contiguous address. Preserve
      // compatibility without penalizing the pooled direct buffers used by streaming shuffle.
      row.writeToStream(new ByteBufOutputStream(output), byteBufWriteBuffer)
    }
  }

  /**
   * Reads length-prefixed rows directly from a retained streaming-shuffle ByteBuf. The returned
   * UnsafeRow is mutable and reused, matching deserializeStream. On common contiguous buffers it
   * points at the message memory, which remains retained until this iterator is exhausted.
   */
  override def keyValueIteratorFromByteBuf(input: ByteBuf): Iterator[(Any, Any)] = {
    new Iterator[(Any, Any)] {
      private[this] val row = new UnsafeRow(numFields)
      private[this] val rowTuple: (Int, UnsafeRow) = (0, row)
      private[this] var fallbackRowBuffer: Array[Byte] = new Array[Byte](1024)

      override def hasNext: Boolean = input.isReadable

      override def next(): (Any, Any) = {
        if (!hasNext) throw new NoSuchElementException("End of UnsafeRow ByteBuf")
        if (input.readableBytes() < Integer.BYTES) {
          throw new EOFException("Truncated UnsafeRow length in streaming shuffle buffer")
        }
        val rowSize = input.readInt()
        if (rowSize < 0 || input.readableBytes() < rowSize) {
          throw new EOFException(
            s"Invalid UnsafeRow size $rowSize with ${input.readableBytes()} readable bytes")
        }
        if (input.hasArray || input.hasMemoryAddress) {
          val readerIndex = input.readerIndex()
          row.pointTo(
            byteBufBaseObject(input), byteBufBaseOffset(input, readerIndex), rowSize)
          input.skipBytes(rowSize)
        } else {
          if (fallbackRowBuffer.length < rowSize) {
            fallbackRowBuffer = new Array[Byte](rowSize)
          }
          input.readBytes(fallbackRowBuffer, 0, rowSize)
          row.pointTo(fallbackRowBuffer, Platform.BYTE_ARRAY_OFFSET, rowSize)
        }
        rowTuple
      }
    }
  }

  /**
   * Serializes a stream of UnsafeRows. Within the stream, each record consists of a record
   * length (stored as a 4-byte integer, written high byte first), followed by the record's bytes.
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
      dOut.writeInt(row.getSizeInBytes)
      row.writeToStream(dOut, writeBuffer)
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
            if (rowBuffer.length < rowSize) {
              rowBuffer = new Array[Byte](rowSize)
            }
            Utils.readFully(dIn, rowBuffer, 0, rowSize)
            row.pointTo(rowBuffer, Platform.BYTE_ARRAY_OFFSET, rowSize)
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
        if (rowBuffer.length < rowSize) {
          rowBuffer = new Array[Byte](rowSize)
        }
        Utils.readFully(dIn, rowBuffer, 0, rowSize)
        row.pointTo(rowBuffer, Platform.BYTE_ARRAY_OFFSET, rowSize)
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
