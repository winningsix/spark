package org.apache.spark.sql.execution;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Sparse mapper partials go over the shuffle as keys. Large partials use a bounded bitmap. */
public final class CompactKeyBuffer {
  private static final int SPARSE = -2;
  private final int budget;
  private final int limit;
  private long[] keys = new long[16];
  private int size;
  private LongKeyBitmap bitmap;

  public CompactKeyBuffer(int byteBudget) {
    if (byteBudget < 8192) throw new IllegalArgumentException("Invalid bitmap budget");
    budget = byteBudget;
    // Cap sparse storage at 512 KiB per task. Promotion also bounds duplicate-heavy inputs.
    limit = Math.min(65536, (byteBudget - 8) / Long.BYTES);
  }

  private LongKeyBitmap materialize() {
    if (bitmap == null) {
      bitmap = new LongKeyBitmap(budget);
      for (int i = 0; i < size; ++i) bitmap.add(keys[i]);
      keys = null;
      size = 0;
    }
    return bitmap;
  }

  public void add(long key) {
    if (bitmap != null || size == limit) {
      materialize().add(key);
      return;
    }
    if (size == keys.length) keys = Arrays.copyOf(keys, Math.min(limit, size * 2));
    keys[size++] = key;
  }

  public void merge(CompactKeyBuffer other) {
    if (other.bitmap != null) materialize().merge(other.bitmap);
    else for (int i = 0; i < other.size; ++i) add(other.keys[i]);
  }

  public byte[] partial() {
    if (bitmap != null) return bitmap.partial();
    ByteBuffer out = ByteBuffer.allocate(8 + size * Long.BYTES);
    out.putInt(SPARSE).putInt(size);
    out.asLongBuffer().put(keys, 0, size);
    return out.array();
  }

  public static CompactKeyBuffer restore(byte[] data, int byteBudget) {
    CompactKeyBuffer result = new CompactKeyBuffer(byteBudget);
    if (data.length < 4) throw new IllegalArgumentException("Missing partial header");
    ByteBuffer in = ByteBuffer.wrap(data);
    if (in.getInt() == SPARSE) {
      if (in.remaining() < 4) throw new IllegalArgumentException("Missing sparse count");
      int n = in.getInt();
      if (n < 0 || n > result.limit || in.remaining() != n * Long.BYTES) {
        throw new IllegalArgumentException("Invalid sparse key count");
      }
      result.keys = new long[Math.max(16, n)];
      in.asLongBuffer().get(result.keys, 0, n);
      result.size = n;
    } else {
      result.bitmap = LongKeyBitmap.restore(data, byteBudget);
      result.keys = null;
    }
    return result;
  }

  public byte[] finish() {
    return materialize().finish();
  }
}
