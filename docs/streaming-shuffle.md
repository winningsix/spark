---
layout: global
title: Experimental Pipelined Shuffle
license: |
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
---

This page describes the experimental pipelined-shuffle changes carried by the
`codex/rtm-flush-close-fence` branch. They are not part of an Apache Spark release and are disabled
unless the incremental streaming shuffle manager and SQL pipelining are explicitly enabled.

* This will become a table of contents (this text will be scraped).
{:toc}

# Current change set

The implementation lets a reduce task consume shuffle frames while its map stage is still running.
The current stabilization series adds the following behavior:

* Reader-queue spill and writer-replay spill have independent task accumulators. Both counters are
  serialized into Spark event logs in addition to contributing to total task disk spill.
* Prepared readers share an executor-wide receive-credit budget. Credit turns are limited to one
  frame and rotate across ready routes so a blocked input cannot consume every receive window.
* Relaxed writers use bounded executor-wide raw and wire-buffer pools. A compression allocation
  can fall back to the already-accounted raw buffer instead of blocking a chained pipeline.
* An uncompressed raw buffer is returned only after both replay ownership and network ownership
  complete. Buffers are returned to the executor pool rather than retained in per-writer caches.
* Raw-pool exhaustion performs selective cross-writer reclamation. The waiting writer asks a
  sibling writer to move one queued frame from a dormant route into replay storage, then reuses the
  released raw lease. This avoids both an all-writer `awaitBorrow` cycle and unconditional replay
  spill on the normal path.
* Submitted replay frames are indexed in a FIFO reclamation queue. Pool-pressure recovery no
  longer rescans the complete retained replay history for every buffer request, avoiding
  quadratic final-flush work on large shuffles.

# Relevant configuration

The AWS W06 validation profile uses the following non-default settings:

```
spark.shuffle.streaming.readerBackpressure.enabled true
spark.shuffle.streaming.writerBackpressure.enabled false
spark.shuffle.streaming.readerTotalQueueMaxMemory 2g
spark.shuffle.streaming.rawBufferPoolMaxMemory 2g
spark.shuffle.streaming.wireBufferMaxMemory 1g
spark.shuffle.streaming.crossRouteMaxInFlightBytes 256m
spark.shuffle.streaming.networkBufferMaxWaitTimeMs 0
spark.task.cpus 0.5
spark.shuffle.streaming.reader.taskCpus 1
spark.shuffle.streaming.readerProducer.taskCpus 1
```

The role-specific CPU values affect scheduler accounting, not physical CPU affinity. Charging a
reader or reader-producer one CPU while charging a pure producer half a CPU preserves overlap but
prevents too many memory-retaining fan-in tasks from occupying one executor.

# Metrics

The event log exposes these task metric fields:

* `Streaming Shuffle Reader Queue Bytes Spilled`
* `Streaming Shuffle Writer Replay Bytes Spilled`

They are subsets of `Disk Bytes Spilled`; they must not be added to that total. A zero reader-queue
value does not imply zero RTM spill because blocked writer routes may still use replay storage.

# Validation status

The focused core suites for the writer, reader, and manager pass 77 tests at source commit
`b420106d1fe`. Two-node AWS W06 stress probes showed that writer progress reservation breaks the
raw-buffer wait: all 14 upstream writers completed in the constrained-reader probe. That probe was
still incomplete after 1633 seconds and had accumulated approximately 625.48 GiB of stage disk
spill. An unrestricted-reader probe with a 2 GiB raw pool was still incomplete after 1151 seconds.
These interrupted probes are liveness diagnostics, not benchmark results; they do not demonstrate
a new performance benefit over the 1265.831-second BSP reference. The evidence bundle and the
published 1.109x exploratory RTM result are maintained in the
[rtm-workloads W06 reader-flow report](https://github.com/HighPerfDataAccelerator/rtm-workloads/blob/main/results/aws-w06-reader-flow-b420106d1fe-500g-20260908/REPORT.md).

This feature remains experimental. A single clean exploratory pair is not a formal acceptance
result; formal qualification requires a warm-up and three alternating measured runs per mode.
