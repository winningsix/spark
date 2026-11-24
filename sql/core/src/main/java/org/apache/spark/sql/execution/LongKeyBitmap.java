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

package org.apache.spark.sql.execution;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/** Bounded, mergeable filter for integral keys clustered in a limited range. */
public final class LongKeyBitmap {
  private static final int PAGE_SHIFT = 15;
  private static final int PAGE_BYTES = 1 << (PAGE_SHIFT - 3);
  private final int maxPages;
  private final Map<Long, byte[]> pages = new HashMap<>();
  private long first = Long.MAX_VALUE;
  private long last = Long.MIN_VALUE;
  private long currentPage;
  private byte[] currentBits;
  private boolean disabled;

  public LongKeyBitmap(int budget) {
    // A serialized partial also carries an eight-byte page ID per allocated page.
    maxPages = (budget - Long.BYTES) / (PAGE_BYTES + Long.BYTES);
    if (maxPages <= 0) throw new IllegalArgumentException("Bitmap budget is too small");
  }

  private void disable() {
    disabled = true;
    pages.clear();
    currentBits = null;
  }

  private byte[] page(long id) {
    if (currentBits != null && currentPage == id) return currentBits;
    first = Math.min(first, id);
    last = Math.max(last, id);
    // Shifting LONG_MIN and LONG_MAX by 15 leaves room for the subtraction.
    if (last - first >= maxPages) {
      disable();
      return null;
    }
    currentPage = id;
    currentBits = pages.computeIfAbsent(id, ignored -> new byte[PAGE_BYTES]);
    return currentBits;
  }

  public void add(long key) {
    if (disabled) return;
    byte[] bits = page(key >> PAGE_SHIFT);
    if (bits != null) bits[(int) (key >>> 3) & (PAGE_BYTES - 1)] |= (byte) (1 << (key & 7));
  }

  public void merge(LongKeyBitmap other) {
    if (disabled) return;
    if (other.disabled) { disable(); return; }
    for (Map.Entry<Long, byte[]> entry : other.pages.entrySet()) {
      byte[] into = page(entry.getKey());
      if (into == null) return;
      byte[] from = entry.getValue();
      for (int i = 0; i < PAGE_BYTES; ++i) into[i] |= from[i];
    }
  }

  public byte[] partial() {
    int n = pages.size();
    ByteBuffer out = ByteBuffer.allocate(Integer.BYTES + n * (Long.BYTES + PAGE_BYTES));
    out.putInt(disabled ? -1 : n);
    for (Map.Entry<Long, byte[]> entry : pages.entrySet()) {
      out.putLong(entry.getKey()).put(entry.getValue());
    }
    return out.array();
  }

  public static LongKeyBitmap restore(byte[] data, int budget) {
    LongKeyBitmap result = new LongKeyBitmap(budget);
    ByteBuffer in = ByteBuffer.wrap(data);
    int n = in.getInt();
    if (n == -1 && !in.hasRemaining()) { result.disable(); return result; }
    if (n < 0 || n > result.maxPages || in.remaining() != n * (Long.BYTES + PAGE_BYTES)) {
      throw new IllegalArgumentException("Invalid partial bitmap length");
    }
    for (int i = 0; i < n; ++i) {
      byte[] bits = result.page(in.getLong());
      if (bits == null) throw new IllegalArgumentException("Invalid partial bitmap range");
      in.get(bits);
    }
    return result;
  }

  public byte[] finish() {
    if (disabled || pages.isEmpty()) return null;
    byte[] out = new byte[Long.BYTES + (int) (last - first + 1) * PAGE_BYTES];
    ByteBuffer.wrap(out).putLong(first << (PAGE_SHIFT - 3));
    for (Map.Entry<Long, byte[]> entry : pages.entrySet()) {
      int offset = Long.BYTES + (int) (entry.getKey() - first) * PAGE_BYTES;
      System.arraycopy(entry.getValue(), 0, out, offset, PAGE_BYTES);
    }
    return out;
  }

  /** The input byte array belongs to a materialized scalar subquery and is immutable. */
  public static final class Probe implements java.io.Serializable {
    private final long firstByte;
    private final byte[] bits;
    public Probe(byte[] data) {
      bits = data;
      firstByte = ByteBuffer.wrap(data).getLong();
    }
    public boolean contains(long key) {
      long offset = (key >> 3) - firstByte;
      return offset >= 0 && offset < bits.length - Long.BYTES &&
          (bits[Long.BYTES + (int) offset] & (1 << (key & 7))) != 0;
    }
  }
}
