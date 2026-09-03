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

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit.{MILLISECONDS, SECONDS}
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration.Duration

import io.netty.buffer.{ByteBuf, CompositeByteBuf, UnpooledByteBufAllocator}
import io.netty.channel.ChannelFuture
import io.netty.util.concurrent.GenericFutureListener
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.when
import org.scalatest.concurrent.Eventually.eventually
import org.scalatest.concurrent.PatienceConfiguration.Timeout
import org.scalatest.matchers.should.Matchers
import org.scalatest.time.{Seconds, Span}
import org.scalatestplus.mockito.MockitoSugar

import org.apache.spark.SparkFunSuite
import org.apache.spark.network.client.TransportClient
import org.apache.spark.util.{ErrorNotifier, ThreadUtils}

class StreamingShuffleTransportBatcherSuite
  extends SparkFunSuite
  with Matchers
  with MockitoSugar {

  test("flattened transport batches do not consolidate framed body components") {
    val bodyCount = 20
    val batcher = new StreamingShuffleTransportBatcher(
      UnpooledByteBufAllocator.DEFAULT,
      maxBytes = bodyCount * 2,
      maxWaitTimeMs = 0,
      maxInFlightBytes = bodyCount * 2,
      new ErrorNotifier())
    val client = mock[TransportClient]
    val future = mock[ChannelFuture]
    val listener = new AtomicReference[GenericFutureListener[ChannelFuture]]()
    val outbound = new AtomicReference[ByteBuf]()

    when(future.isSuccess).thenReturn(true)
    when(future.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        listener.set(invocation.getArgument[GenericFutureListener[ChannelFuture]](0))
        future
      }
    when(client.send(any[ByteBuf])).thenAnswer { invocation =>
      outbound.set(invocation.getArgument[ByteBuf](0))
      future
    }

    try {
      (0 until bodyCount).foreach { value =>
        val framed = UnpooledByteBufAllocator.DEFAULT.compositeBuffer(2)
        framed.addComponent(true,
          UnpooledByteBufAllocator.DEFAULT.buffer(1).writeByte(value))
        framed.addComponent(true,
          UnpooledByteBufAllocator.DEFAULT.buffer(1).writeByte(255 - value))
        batcher.submit(client, framed, () => ())
      }

      eventually(Timeout(Span(5, Seconds))) {
        listener.get() should not be null
      }
      val sent = outbound.get().asInstanceOf[CompositeByteBuf]
      // The old body-count limit consolidated the 40 input components into a small number of
      // copied buffers. Keeping every component proves that no addComponent call crossed the
      // composite's maxNumComponents threshold and allocated a hidden direct copy.
      sent.numComponents() shouldBe bodyCount * 2
      sent.readableBytes() shouldBe bodyCount * 2
      (0 until bodyCount).foreach { value =>
        sent.getUnsignedByte(value * 2) shouldBe value
        sent.getUnsignedByte(value * 2 + 1) shouldBe 255 - value
      }

      outbound.getAndSet(null).release()
      listener.get().operationComplete(future)
    } finally {
      Option(outbound.getAndSet(null)).foreach(_.release())
      batcher.discard()
    }
  }

  test("a full transport window does not block an unrelated connection") {
    implicit val executionContext: ExecutionContext = ExecutionContext.global
    val batcher = new StreamingShuffleTransportBatcher(
      UnpooledByteBufAllocator.DEFAULT,
      maxBytes = 16,
      maxWaitTimeMs = 0,
      maxInFlightBytes = 16,
      new ErrorNotifier())
    val firstClient = mock[TransportClient]
    val secondClient = mock[TransportClient]
    val firstFuture = mock[ChannelFuture]
    val secondFuture = mock[ChannelFuture]
    val firstListener = new AtomicReference[GenericFutureListener[ChannelFuture]]()
    val secondListener = new AtomicReference[GenericFutureListener[ChannelFuture]]()
    val firstOutbound = new AtomicReference[ByteBuf]()
    val secondOutbound = new AtomicReference[ByteBuf]()
    val secondSends = new AtomicInteger(0)

    when(firstFuture.isSuccess).thenReturn(true)
    when(secondFuture.isSuccess).thenReturn(true)
    when(firstFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        firstListener.set(invocation.getArgument[GenericFutureListener[ChannelFuture]](0))
        firstFuture
      }
    when(secondFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        secondListener.set(invocation.getArgument[GenericFutureListener[ChannelFuture]](0))
        secondFuture
      }
    when(firstClient.send(any[ByteBuf])).thenAnswer { invocation =>
      firstOutbound.set(invocation.getArgument[ByteBuf](0))
      firstFuture
    }
    when(secondClient.send(any[ByteBuf])).thenAnswer { invocation =>
      secondOutbound.set(invocation.getArgument[ByteBuf](0))
      secondSends.incrementAndGet()
      secondFuture
    }

    try {
      batcher.submit(
        firstClient,
        UnpooledByteBufAllocator.DEFAULT.buffer(16).writeZero(16),
        () => ())
      eventually(Timeout(Span(5, Seconds))) {
        firstListener.get() should not be null
      }

      // The first connection owns the complete transport window and its future is deliberately
      // unfinished. Enqueuing a body for another connection must return instead of parking the
      // caller (the shared outbound dispatcher in production).
      ThreadUtils.awaitResult(Future {
        batcher.submit(
          secondClient,
          UnpooledByteBufAllocator.DEFAULT.buffer(16).writeZero(16),
          () => ())
      }, Duration(5, SECONDS))
      secondSends.get() shouldBe 0

      firstOutbound.getAndSet(null).release()
      firstListener.get().operationComplete(firstFuture)
      eventually(Timeout(Span(5, Seconds))) {
        secondSends.get() shouldBe 1
        secondListener.get() should not be null
      }

      secondOutbound.getAndSet(null).release()
      secondListener.get().operationComplete(secondFuture)
      eventually(Timeout(Span(5, Seconds))) {
        batcher.peakInFlightBytesForTest shouldBe 16L
      }
    } finally {
      batcher.discard()
    }
  }

  test("asynchronous admission drain uses the batcher monitor") {
    val batcher = new StreamingShuffleTransportBatcher(
      UnpooledByteBufAllocator.DEFAULT,
      maxBytes = 1,
      maxWaitTimeMs = 0,
      maxInFlightBytes = 1,
      new ErrorNotifier())
    val client = mock[TransportClient]
    val firstFuture = mock[ChannelFuture]
    val secondFuture = mock[ChannelFuture]
    val firstListener = new AtomicReference[GenericFutureListener[ChannelFuture]]()
    val secondListener = new AtomicReference[GenericFutureListener[ChannelFuture]]()
    val sends = new AtomicInteger(0)
    val secondSendStarted = new CountDownLatch(1)

    when(firstFuture.isSuccess).thenReturn(true)
    when(secondFuture.isSuccess).thenReturn(true)
    when(firstFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        firstListener.set(invocation.getArgument[GenericFutureListener[ChannelFuture]](0))
        firstFuture
      }
    when(secondFuture.addListener(any[GenericFutureListener[ChannelFuture]]))
      .thenAnswer { invocation =>
        secondListener.set(invocation.getArgument[GenericFutureListener[ChannelFuture]](0))
        secondFuture
      }
    when(client.send(any[ByteBuf])).thenAnswer { invocation =>
      val outbound = invocation.getArgument[ByteBuf](0)
      outbound.release()
      sends.incrementAndGet() match {
        case 1 => firstFuture
        case 2 =>
          secondSendStarted.countDown()
          secondFuture
      }
    }

    try {
      batcher.submit(
        client,
        UnpooledByteBufAllocator.DEFAULT.buffer(1).writeZero(1),
        () => ())
      batcher.submit(
        client,
        UnpooledByteBufAllocator.DEFAULT.buffer(1).writeZero(1),
        () => ())
      eventually(Timeout(Span(5, Seconds))) {
        firstListener.get() should not be null
        sends.get() shouldBe 1
      }

      // Completing the first send schedules an admission drain. While this thread owns the
      // batcher monitor, that drain must not enter the shared FIFO. A bare synchronized block in
      // the anonymous Runnable locks the Runnable itself and violates this exclusion.
      batcher.synchronized {
        firstListener.get().operationComplete(firstFuture)
        secondSendStarted.await(250, MILLISECONDS) shouldBe false
      }
      eventually(Timeout(Span(5, Seconds))) {
        secondSendStarted.getCount shouldBe 0L
        secondListener.get() should not be null
      }
      secondListener.get().operationComplete(secondFuture)
    } finally {
      batcher.discard()
    }
  }
}
