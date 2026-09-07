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

package org.apache.spark.network.shuffle.streaming;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;

/**
 * Reader-to-writer control message.
 *
 * Besides connection establishment, distributed multiplexed routes use this message for
 * byte-based flow control. A negative {@link #numMessages} advertises the initial absolute byte
 * window; {@link Integer#MIN_VALUE} discovers a bounded route with a zero-byte window. Zero means
 * that {@link #getSeqNum()} carries the cumulative number of encoded data bytes released by the
 * reader on this connection. Positive values retain the legacy additive grant.
 */
public final class CreditControlMessage extends StreamingShuffleMessage {
  public final int shuffleId;
  public final int shuffleWriterId;
  public final int shuffleReaderId;

  /**
   * Negative values establish an absolute byte window, {@link Integer#MIN_VALUE} establishes a
   * zero-byte window, zero selects a cumulative release acknowledgement in the inherited sequence
   * field, and positive values are additive grants.
   */
  public final int numMessages;

  public CreditControlMessage(int shuffleWriterId, int shuffleReaderId, int numMessages) {
    this(-1, shuffleWriterId, shuffleReaderId, numMessages);
  }

  public CreditControlMessage(
      int shuffleId, int shuffleWriterId, int shuffleReaderId, int numMessages) {
    this.shuffleId = shuffleId;
    this.shuffleWriterId = shuffleWriterId;
    this.shuffleReaderId = shuffleReaderId;
    this.numMessages = numMessages;
  }

  @Override
  public StreamingShuffleMessageType messageType() {
    return StreamingShuffleMessageType.CREDIT_CONTROL_MESSAGE;
  }

  @Override
  public int headerLength() {
    // 4 bytes each for shuffle, writer, and reader IDs, plus 4 bytes for message credit.
    return super.headerLength() + 16;
  }

  @Override
  public void encode(CompositeByteBuf buf) {
    super.encode(buf);

    buf.writeInt(shuffleId);
    // Write the shuffle writer ID
    buf.writeInt(shuffleWriterId);
    // Write the shuffle reader ID
    buf.writeInt(shuffleReaderId);
    // Write the number of messages
    buf.writeInt(numMessages);
  }

  public static CreditControlMessage decode(ByteBuf buf) {
    int shuffleId = buf.readInt();
    // Read the shuffle writer ID
    int shuffleWriterId = buf.readInt();
    // Read the shuffle reader ID
    int shuffleReaderId = buf.readInt();
    // Read the number of messages
    int numMessages = buf.readInt();

    return new CreditControlMessage(shuffleId, shuffleWriterId, shuffleReaderId, numMessages);
  }
}
