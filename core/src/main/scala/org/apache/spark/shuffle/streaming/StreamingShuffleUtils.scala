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

import java.util.Locale

import io.netty.buffer.{ByteBuf, CompositeByteBuf}
import io.netty.channel.ChannelFuture

import org.apache.spark.network.client.TransportClient
import org.apache.spark.network.shuffle.streaming.{StreamingShuffleMessage, StreamingShuffleMessageType}

private[streaming] object StreamingShuffleUtils {
  private val CommonHeaderLength = Integer.BYTES + java.lang.Long.BYTES
  private val RoutedHeaderLength = CommonHeaderLength + 3 * Integer.BYTES
  private val DataHeaderLength = RoutedHeaderLength + 2 * Integer.BYTES + java.lang.Long.BYTES
  private val ReaderControlHeaderLength = RoutedHeaderLength + Integer.BYTES
  private val DataSizeOffset = RoutedHeaderLength

  /** Own the encoded control body until transport accepts its retained reference. */
  def sendControlMessages(
      client: TransportClient,
      messages: Seq[StreamingShuffleMessage]): ChannelFuture = {
    var buf: CompositeByteBuf = null
    try {
      val bytes = messages.foldLeft(0)(_ + _.headerLength())
      buf = client.getChannel.alloc().compositeBuffer().capacity(bytes)
      messages.foreach(_.encode(buf))
      client.send(buf.retain())
    } finally {
      if (buf != null) buf.release()
    }
  }

  /**
   * Return the length of the next streaming-shuffle frame in a transport body. Writers may
   * concatenate frames, while message decoding requires an exact frame slice.
   */
  def frameLength(buf: ByteBuf): Int = {
    val index = buf.readerIndex()
    val readable = buf.readableBytes()
    if (readable < CommonHeaderLength) {
      throw new IllegalArgumentException(
        s"Streaming shuffle message is too short: $readable bytes")
    }
    StreamingShuffleMessageType.decode(buf.getInt(index)) match {
      case StreamingShuffleMessageType.DATA_MESSAGE_UNSAFE_ROW =>
        if (readable < DataHeaderLength) {
          throw new IllegalArgumentException(
            s"Truncated streaming DataMessage header: $readable bytes")
        }
        val dataSize = buf.getInt(index + DataSizeOffset)
        if (dataSize < 0 || dataSize > readable - DataHeaderLength) {
          throw new IllegalArgumentException(
            s"Invalid streaming DataMessage size $dataSize with $readable bytes available")
        }
        DataHeaderLength + dataSize
      case StreamingShuffleMessageType.TERMINATION_CONTROL_MESSAGE => RoutedHeaderLength
      case StreamingShuffleMessageType.CREDIT_CONTROL_MESSAGE |
          StreamingShuffleMessageType.TERMINATION_ACK_MESSAGE => ReaderControlHeaderLength
    }
  }

  def isConnectionClose(cause: Throwable): Boolean = cause != null && {
    val className = cause.getClass.getName
    val message = Option(cause.getMessage).getOrElse("").toLowerCase(Locale.ROOT)
    className.contains("ClosedChannel") ||
      message.contains("broken pipe") ||
      message.contains("connection reset") ||
      isConnectionClose(cause.getCause)
  }
}
