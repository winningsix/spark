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

package org.apache.spark.util.collection.unsafe.sort;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

import org.apache.spark.unsafe.Platform;

import static org.junit.jupiter.api.Assertions.*;

public class UnsafeSorterSpillMergerSuite {
  private static final RecordComparator RECORD_COMPARATOR = new RecordComparator() {
    @Override
    public int compare(Object left, long leftOffset, int leftLength,
        Object right, long rightOffset, int rightLength) {
      return Long.compare(Platform.getLong(left, leftOffset), Platform.getLong(right, rightOffset));
    }
  };

  private static class ArrayIterator extends UnsafeSorterIterator {
    private final long[] values;
    private final boolean constantPrefix;
    private final long[] current = new long[1];
    private int position = -1;

    ArrayIterator(long[] values, boolean constantPrefix) {
      this.values = values;
      this.constantPrefix = constantPrefix;
    }

    @Override public boolean hasNext() { return position + 1 < values.length; }
    @Override public void loadNext() throws IOException { current[0] = values[++position]; }
    @Override public Object getBaseObject() { return current; }
    @Override public long getBaseOffset() { return Platform.LONG_ARRAY_OFFSET; }
    @Override public int getRecordLength() { return Long.BYTES; }
    @Override public long getKeyPrefix() { return constantPrefix ? 0 : current[0]; }
    @Override public int getNumRecords() { return values.length; }
    @Override public long getCurrentPageNumber() { throw new UnsupportedOperationException(); }
  }

  @Test
  public void mergeInterleavedInputsAndEqualPrefixes() throws Exception {
    for (boolean constantPrefix : new boolean[] {false, true}) {
      Random random = new Random(42);
      for (int inputs : new int[] {1, 2, 7, 32}) {
        UnsafeSorterSpillMerger merger = new UnsafeSorterSpillMerger(
          RECORD_COMPARATOR, PrefixComparators.LONG, inputs);
        long[][] values = new long[inputs][];
        for (int i = 0; i < inputs; i++) {
          values[i] = random.longs(i * 13, -100, 100).sorted().toArray();
          merger.addSpillIfNotEmpty(new ArrayIterator(values[i], constantPrefix));
        }
        long[] expected = Arrays.stream(values).flatMapToLong(Arrays::stream).sorted().toArray();
        UnsafeSorterIterator merged = merger.getSortedIterator();
        assertEquals(expected.length, merged.getNumRecords());
        for (long value : expected) {
          assertTrue(merged.hasNext());
          merged.loadNext();
          assertEquals(value, Platform.getLong(merged.getBaseObject(), merged.getBaseOffset()));
        }
        assertFalse(merged.hasNext());
      }
    }
  }

  @Test
  public void consecutiveRunUsesLinearComparisons() throws Exception {
    int inputs = 32;
    int recordsPerInput = 128;
    int[] comparisons = {0};
    PrefixComparator counting = new PrefixComparator() {
      @Override public int compare(long left, long right) {
        comparisons[0]++;
        return Long.compare(left, right);
      }
    };
    UnsafeSorterSpillMerger merger = new UnsafeSorterSpillMerger(
      RECORD_COMPARATOR, counting, inputs);
    for (int i = 0; i < inputs; i++) {
      long[] values = new long[recordsPerInput];
      for (int j = 0; j < recordsPerInput; j++) values[j] = (long) i * recordsPerInput + j;
      merger.addSpillIfNotEmpty(new ArrayIterator(values, false));
    }
    UnsafeSorterIterator merged = merger.getSortedIterator();
    int total = inputs * recordsPerInput;
    for (int i = 0; i < total; i++) {
      assertTrue(merged.hasNext());
      merged.loadNext();
      assertEquals(i, merged.getKeyPrefix());
    }
    assertFalse(merged.hasNext());
    // Switching runs may need heap work; advancing within a run should only compare the head.
    assertTrue(comparisons[0] < 2 * total, "comparisons=" + comparisons[0]);
  }

  @Test
  public void singleInputRetainsCurrentRecordAndPropagatesReadFailure() throws Exception {
    UnsafeSorterSpillMerger merger = new UnsafeSorterSpillMerger(
      RECORD_COMPARATOR, PrefixComparators.LONG, 1);
    merger.addSpillIfNotEmpty(new ArrayIterator(new long[] {7, 9}, false) {
      private int reads;
      @Override public void loadNext() throws IOException {
        if (++reads == 2) throw new IOException("injected read failure");
        super.loadNext();
      }
    });
    UnsafeSorterIterator merged = merger.getSortedIterator();
    merged.loadNext();
    assertEquals(7, merged.getKeyPrefix());
    assertEquals(7, Platform.getLong(merged.getBaseObject(), merged.getBaseOffset()));
    assertTrue(merged.hasNext());
    IOException failure = assertThrows(IOException.class, merged::loadNext);
    assertEquals("injected read failure", failure.getMessage());
  }
}
