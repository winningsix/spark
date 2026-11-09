<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Pipelined (RTM) vs. regular (BSP) shuffle: TPC-H SF1000 on one host

Results of sweep M (2026-11-07) for the code in this branch.

## Setup

- Host: 1-socket Xeon 6741P with 48 cores and 288 MB L3. The SMT siblings of the measured CPUs stay idle during runs.
- Cluster: `local-cluster[2,16,40960]`.
  - Executor 0 is pinned to CPUs 0-15 and executor 1 to CPUs 16-31.
  - The driver runs on CPUs 32-35.
- Data: TPC-H SF1000 parquet, with float decimals.
- Queries: 21 TPC-H queries. Q18 is excluded because BSP also runs out of memory on it.
- Runs: each query runs in its own application.
  - Every mode gets one warmup run and then three measured runs.
  - The order of modes is rotated on every iteration.
  - The table reports the median of the three measured runs.
- Results: query results match BSP, except Q15. Q15 returns 0 or 1 rows nondeterministically in every mode, because it compares floats for equality.

Settings common to all modes:

| Setting | Value |
| --- | --- |
| `spark.task.cpus` | 0.25 (128 slots) |
| `spark.sql.shuffle.partitions` | 32 |
| `spark.sql.adaptive.enabled` | false |
| `spark.sql.autoBroadcastJoinThreshold` | -1 |
| `spark.sql.join.preferSortMergeJoin` | false |
| `spark.sql.files.maxPartitionNum` | 32 |
| `spark.sql.execution.aggregate.adaptivePartialAggregation.enabled` | true |
| `spark.cleaner.periodicGC.interval` | 30s |
| `spark.sql.shuffle.distributedPipelined.hashJoinPolicy.enabled` | true |
| `spark.sql.shuffle.distributedPipelined.groupSlotFraction` | 0.75 |
| Executor JVM options | `-XX:+UseTransparentHugePages`, `-XX:GCLockerRetryAllocationCount=100` |
| Shuffle local dirs | one on each of two disks |

Modes:

| Mode | Description |
| --- | --- |
| bsp | Regular shuffle. |
| bspx | bsp plus `hashJoinPolicy.applyToRegular=true`: BSP with the same join and bloom-filter plan policy as RTM. |
| rtms | Distributed pipelined shuffle with `spark.sql.shuffle.pipelined.simpleBuildInputs.enabled=true`. |
| rtmp | rtms plus 64 shuffle partitions and `hashJoinPolicy.maxLocalMapThreshold=32m`. This threshold keeps the policy's join choices identical to 32 partitions. |

Fairness rule: every generic setting was screened on both modes, and each mode uses its own best global setting. Settings are never chosen per query.
- Transparent huge pages help both modes.
- 64 partitions are worse for BSP (724 s vs 693 s on Q21, Q5, Q10 and Q7), so BSP stays at 32.
- Turning off shuffle compression hurts RTM, so compression stays on.

## Results

Speedups are relative to bsp. "rtmp busy cores" is the average number of busy cores out of 32.

| Query | bsp (s) | bspx (s) | rtms (s) | rtmp (s) | bspx | rtms | rtmp | rtmp busy cores |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Q1 | 21.8 | 22.3 | 21.4 | 21.9 | 0.98 | 1.02 | 1.00 | 30.7 |
| Q2 | 106.3 | 8.7 | 9.2 | 8.7 | 12.19 | 11.52 | 12.17 | 26.2 |
| Q3 | 87.1 | 66.2 | 61.2 | 61.5 | 1.32 | 1.42 | 1.41 | 28.1 |
| Q4 | 85.1 | 55.8 | 52.1 | 45.3 | 1.52 | 1.64 | 1.88 | 30.8 |
| Q5 | 182.9 | 203.5 | 167.4 | 165.8 | 0.90 | 1.09 | 1.10 | 29.3 |
| Q6 | 3.9 | 3.9 | 3.9 | 3.9 | 0.99 | 0.99 | 0.99 | 30.9 |
| Q7 | 71.0 | 71.4 | 67.1 | 59.6 | 0.99 | 1.06 | 1.19 | 29.3 |
| Q8 | 125.5 | 44.1 | 41.0 | 40.4 | 2.85 | 3.06 | 3.11 | 28.8 |
| Q9 | 258.7 | 130.2 | 119.6 | 117.5 | 1.99 | 2.16 | 2.20 | 29.6 |
| Q10 | 81.3 | 65.2 | 60.7 | 61.0 | 1.25 | 1.34 | 1.33 | 29.2 |
| Q11 | 35.1 | 21.6 | 18.0 | 19.0 | 1.63 | 1.95 | 1.84 | 25.3 |
| Q12 | 42.9 | 31.8 | 30.4 | 29.8 | 1.35 | 1.41 | 1.44 | 30.4 |
| Q13 | 75.8 | 69.2 | 63.0 | 58.5 | 1.09 | 1.20 | 1.30 | 30.2 |
| Q14 | 12.3 | 12.3 | 12.3 | 12.1 | 1.00 | 1.01 | 1.02 | 29.1 |
| Q15 | 24.1 | 23.8 | 23.0 | 22.4 | 1.01 | 1.05 | 1.08 | 30.2 |
| Q16 | 22.7 | 18.9 | 15.9 | 21.4 | 1.20 | 1.43 | 1.06 | 31.2 |
| Q17 | 188.6 | 34.3 | 29.0 | 28.9 | 5.49 | 6.51 | 6.53 | 29.7 |
| Q19 | 14.7 | 14.2 | 13.1 | 13.5 | 1.04 | 1.12 | 1.09 | 30.6 |
| Q20 | 29.0 | 19.7 | 20.3 | 19.4 | 1.47 | 1.43 | 1.50 | 28.1 |
| Q21 | 331.1 | 334.6 | 293.0 | 280.9 | 0.99 | 1.13 | 1.18 | 30.9 |
| Q22 | 29.0 | 23.6 | 19.2 | 17.7 | 1.23 | 1.51 | 1.64 | 30.5 |

Summary. "Busy" is the time-weighted average share of the 32 cores in use.

| Mode | Total (s) | Speedup, total time | Speedup, geomean | Worker CPU (s) | Busy |
| --- | ---: | ---: | ---: | ---: | ---: |
| bsp | 1829 | 1.00X | 1.00X | 48614 | 84% |
| bspx | 1275 | 1.43X | 1.49X | 36450 | 91% |
| rtms | 1141 | 1.60X | 1.62X | 32649 | 91% |
| rtmp | 1109 | 1.65X | 1.64X | 32283 | 93% |

## Interpretation

- Where the gain comes from: of rtmp's 1.64X geomean speedup over bsp, about 1.49X comes from the plan policy alone (bspx). Pipelining adds about 1.10X on top.
- Upper bound: rtmp needs 32283 worker CPU-seconds. Even at 100% use of the 32 cores, the total would be at least 1009 s, so the total-time speedup over bsp cannot exceed about 1.81X. Getting beyond that needs less CPU work, not more overlap.
- Parity queries: Q1 and Q6 are a single scan of 6 billion rows plus a tiny shuffle. Their physical work is identical in every mode, so parity with BSP is expected.
- Q16 is slower in rtmp than in rtms.
  - The planner gives each pipelined group a budget of 128 × 0.75 = 96 reader slots.
  - At 64 partitions, the join stage plus the next aggregation stage need more than 96 slots.
  - So the planner keeps the 118.7M-row distinct-aggregation exchange as a regular shuffle.
- Q11 has the lowest utilization: 25.3 of 32 cores (79%) in rtmp. At 64 partitions, a supplier exchange that is reused by the main query and by its subquery overflows the 96-slot budget and stays a regular shuffle.
