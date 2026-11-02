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

package org.apache.spark.network.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.WritableByteChannel;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.spark.network.util.AbstractFileRegion;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.spark.network.TestManagedBuffer;
import org.apache.spark.network.buffer.ManagedBuffer;
import org.apache.spark.network.buffer.NettyManagedBuffer;
import org.apache.spark.network.util.ByteArrayWritableChannel;

public class MessageWithHeaderSuite {

  @Test
  public void testSingleWrite() throws Exception {
    testFileRegionBody(8, 8);
  }

  @Test
  public void testShortWrite() throws Exception {
    testFileRegionBody(8, 1);
  }

  @Test
  public void testByteBufBody() throws Exception {
    testByteBufBody(Unpooled.copyLong(42));
  }

  @Test
  public void testCompositeByteBufBodySingleBuffer() throws Exception {
    ByteBuf header = Unpooled.copyLong(42);
    CompositeByteBuf compositeByteBuf = Unpooled.compositeBuffer();
    compositeByteBuf.addComponent(true, header);
    assertEquals(1, compositeByteBuf.nioBufferCount());
    testByteBufBody(compositeByteBuf);
  }

  @Test
  public void testCompositeByteBufBodyMultipleBuffers() throws Exception {
    ByteBuf header = Unpooled.copyLong(42);
    CompositeByteBuf compositeByteBuf = Unpooled.compositeBuffer();
    compositeByteBuf.addComponent(true, header.retainedSlice(0, 4));
    compositeByteBuf.addComponent(true, header.slice(4, 4));
    assertEquals(2, compositeByteBuf.nioBufferCount());
    testByteBufBody(compositeByteBuf);
  }

  @Test
  public void testGatheringWriteResumesAcrossHeaderAndBody() throws Exception {
    ByteBuf header = Unpooled.copyLong(42);
    CompositeByteBuf body = Unpooled.compositeBuffer();
    for (long value = 1; value <= 3; value++) {
      body.addComponent(true, Unpooled.copyLong(value));
    }
    ManagedBuffer managed = new NettyManagedBuffer(body);
    MessageWithHeader msg = new MessageWithHeader(
      managed, header, managed.convertToNetty(), managed.size());
    TestGatheringChannel channel = new TestGatheringChannel((int) msg.count());
    try {
      int[] quotas = {0, 5, 13, 0, 100};
      int[] expectedWrites = {0, 5, 13, 0, 14};
      for (int i = 0; i < quotas.length; i++) {
        channel.quota = quotas[i];
        assertEquals(expectedWrites[i], msg.transferTo(channel, msg.transferred()));
        assertEquals(channel.length(), msg.transferred());
      }
      assertEquals(msg.count(), msg.transferred());
      assertEquals(3, channel.gatherWrites);
      // Header short writes remain scalar; the composite body uses one syscall per attempt.
      assertEquals(3, channel.scalarWrites);
      ByteBuffer result = ByteBuffer.wrap(channel.getData());
      assertEquals(42L, result.getLong());
      for (long value = 1; value <= 3; value++) {
        assertEquals(value, result.getLong());
      }
    } finally {
      msg.release();
    }
    assertEquals(0, header.refCnt());
    assertEquals(0, body.refCnt());
  }

  @Test
  public void testGatheringWriteKeepsTransferSizeBounded() throws Exception {
    CompositeByteBuf body = Unpooled.compositeBuffer();
    for (int i = 0; i < 3; i++) {
      body.addComponent(true, Unpooled.buffer(128 * 1024).writeZero(128 * 1024));
    }
    ManagedBuffer managed = new NettyManagedBuffer(body);
    MessageWithHeader msg = new MessageWithHeader(
      managed, Unpooled.EMPTY_BUFFER, managed.convertToNetty(), managed.size());
    TestGatheringChannel channel = new TestGatheringChannel((int) msg.count());
    try {
      channel.quota = Integer.MAX_VALUE;
      assertEquals(256 * 1024, msg.transferTo(channel, msg.transferred()));
      assertEquals(128 * 1024, msg.transferTo(channel, msg.transferred()));
      assertEquals(msg.count(), msg.transferred());
      assertEquals(2, channel.gatherWrites);
      assertEquals(0, channel.scalarWrites);
      assertEquals(256 * 1024, channel.maxGatherBytes);
    } finally {
      msg.release();
    }
    assertEquals(0, body.refCnt());
  }

  private static class TestGatheringChannel extends ByteArrayWritableChannel
      implements GatheringByteChannel {
    private int quota;
    private int scalarWrites;
    private int gatherWrites;
    private long maxGatherBytes;

    TestGatheringChannel(int size) {
      super(size);
    }

    private int writeLimited(ByteBuffer src) {
      int limit = src.limit();
      src.limit(src.position() + Math.min(src.remaining(), quota));
      int written = super.write(src);
      src.limit(limit);
      quota -= written;
      return written;
    }

    @Override
    public int write(ByteBuffer src) {
      scalarWrites++;
      return writeLimited(src);
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) {
      gatherWrites++;
      long offered = 0;
      for (int i = offset; i < offset + length; i++) {
        offered += srcs[i].remaining();
      }
      maxGatherBytes = Math.max(maxGatherBytes, offered);
      long written = 0;
      for (int i = offset; i < offset + length; i++) {
        written += writeLimited(srcs[i]);
        if (srcs[i].hasRemaining()) {
          break;
        }
      }
      return written;
    }

    @Override
    public long write(ByteBuffer[] srcs) {
      return write(srcs, 0, srcs.length);
    }
  }

  /**
   * Test writing a {@link MessageWithHeader} using the given {@link ByteBuf} as header.
   *
   * @param header the header to use.
   * @throws Exception thrown on error.
   */
  private void testByteBufBody(ByteBuf header) throws Exception {
    long expectedHeaderValue = header.getLong(header.readerIndex());
    ByteBuf bodyPassedToNettyManagedBuffer = Unpooled.copyLong(84);
    assertEquals(1, header.refCnt());
    assertEquals(1, bodyPassedToNettyManagedBuffer.refCnt());
    ManagedBuffer managedBuf = new NettyManagedBuffer(bodyPassedToNettyManagedBuffer);

    Object body = managedBuf.convertToNetty();
    assertEquals(2, bodyPassedToNettyManagedBuffer.refCnt());
    assertEquals(1, header.refCnt());

    MessageWithHeader msg = new MessageWithHeader(managedBuf, header, body, managedBuf.size());
    ByteBuf result = doWrite(msg, 1);
    assertEquals(msg.count(), result.readableBytes());
    assertEquals(expectedHeaderValue, result.readLong());
    assertEquals(84, result.readLong());

    assertTrue(msg.release());
    assertEquals(0, bodyPassedToNettyManagedBuffer.refCnt());
    assertEquals(0, header.refCnt());
  }

  @Test
  public void testDeallocateReleasesManagedBuffer() throws Exception {
    ByteBuf header = Unpooled.copyLong(42);
    ManagedBuffer managedBuf = Mockito.spy(new TestManagedBuffer(84));
    ByteBuf body = (ByteBuf) managedBuf.convertToNetty();
    assertEquals(2, body.refCnt());
    MessageWithHeader msg = new MessageWithHeader(managedBuf, header, body, body.readableBytes());
    assertTrue(msg.release());
    Mockito.verify(managedBuf, Mockito.times(1)).release();
    assertEquals(0, body.refCnt());
  }

  private void testFileRegionBody(int totalWrites, int writesPerCall) throws Exception {
    ByteBuf header = Unpooled.copyLong(42);
    int headerLength = header.readableBytes();
    TestFileRegion region = new TestFileRegion(totalWrites, writesPerCall);
    MessageWithHeader msg = new MessageWithHeader(null, header, region, region.count());

    ByteBuf result = doWrite(msg, totalWrites / writesPerCall);
    assertEquals(headerLength + region.count(), result.readableBytes());
    assertEquals(42, result.readLong());
    for (long i = 0; i < 8; i++) {
      assertEquals(i, result.readLong());
    }
    assertTrue(msg.release());
  }

  private ByteBuf doWrite(MessageWithHeader msg, int minExpectedWrites) throws Exception {
    int writes = 0;
    ByteArrayWritableChannel channel = new ByteArrayWritableChannel((int) msg.count());
    while (msg.transferred() < msg.count()) {
      msg.transferTo(channel, msg.transferred());
      writes++;
    }
    assertTrue(minExpectedWrites <= writes, "Not enough writes!");
    return Unpooled.wrappedBuffer(channel.getData());
  }

  private static class TestFileRegion extends AbstractFileRegion {

    private final int writeCount;
    private final int writesPerCall;
    private int written;

    TestFileRegion(int totalWrites, int writesPerCall) {
      this.writeCount = totalWrites;
      this.writesPerCall = writesPerCall;
    }

    @Override
    public long count() {
      return 8L * writeCount;
    }

    @Override
    public long position() {
      return 0;
    }

    @Override
    public long transferred() {
      return 8L * written;
    }

    @Override
    public long transferTo(WritableByteChannel target, long position) throws IOException {
      for (int i = 0; i < writesPerCall; i++) {
        ByteBuf buf = Unpooled.copyLong((position / 8) + i);
        ByteBuffer nio = buf.nioBuffer();
        while (nio.remaining() > 0) {
          target.write(nio);
        }
        buf.release();
        written++;
      }
      return 8L * writesPerCall;
    }

    @Override
    protected void deallocate() {
    }

  }

}
