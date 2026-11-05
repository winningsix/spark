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

# Pipelined group admission: SF1000 performance qualification

## Conclusion

The initial admission implementation exposed two functional defects on SF1000. Both were fixed
and covered by regression tests. The fixed producer window remains a performance limitation:
Q1's 33 scan tasks acquire a second wave with window 32, despite spare scheduling capacity.
A larger-window diagnostic removes that regression. The tested policy should remain opt-in;
these measurements do not justify enabling it by default.

## Protocol

* Code: `98e2739491f`, including reader-startup and replay-admission fixes.
* SF1000 float Parquet, unchanged dataset and SQL. No GPU acceleration.
* Two executor JVMs on one host, 16 pinned physical cores and 32 GiB heap per executor.
* `spark.task.cpus=0.25`: 128 nominal task slots across 32 physical cores.
* AQE disabled; unchanged join strategies, shuffle partitions, and normalized physical plans.
* Main comparison: one artifact, admission disabled versus enabled with producer window 32.
  The baseline retains its existing elastic producer cap of 64. Enabling the new policy replaces
  that with a fixed reservation window; this is a comparison of scheduling policies, not merely
  the cost of running admission code.
* One warmup and three alternating measured executions per configuration and query. Page cache
  is retained. Query time excludes JVM startup. All measured samples are retained.
* Additional Q1 window-64 cohort uses the same baseline and another warmup plus three alternating
  measured pairs. It is a diagnostic, not a query-specific production recommendation.

## Warm-run results

| Query / configuration | Admission off | Admission on | Change |
| --- | ---: | ---: | ---: |
| Q3, window 32 | 77.830 s | 80.678 s | +3.66% |
| Q1, window 32 | 23.531 s | 27.229 s | +15.72% |
| Q1, window 64 diagnostic | 23.935 s | 23.319 s | -2.57% |

Q3's three on samples are 80.678, 81.481, and 75.696 seconds; its off samples are 77.830,
76.960, and 79.418 seconds. A separate local Spark process briefly overlapped the second on
sample. An earlier code cohort had the opposite direction. Therefore the final median exceeds
the regression threshold, but a stable causal Q3 regression is not established. Do not claim
that Q3 passes performance qualification; repeat on dedicated workers before accepting it.

| Main comparison metric | Q1 off | Q1 on | Q3 off | Q3 on |
| --- | ---: | ---: | ---: | ---: |
| OS busy physical cores | 29.320 | 25.033 | 29.325 | 28.365 |
| Useful task CPU parallelism | 27.683 | 24.224 | 22.521 | 22.056 |
| Physical device writes, GiB | 0.006 | 0.011 | 88.542 | 95.456 |
| Peak executor RSS, GiB | 18.139 | 23.588 | 91.473 | 94.862 |

Device counters include host activity and delayed writeback. Loopback traffic is retained in
raw telemetry, but does not qualify a multi-host network. RSS is observed process residency,
not a measurement of the shuffle memory cap alone.

## Fixed-window tail

Spark's configured scan partition target of 32 produces 33 actual lineitem scan tasks here.
With admission off, all 33 launch within milliseconds. With window 32, the last task waits
about 21 seconds for a reserved producer slot, then runs for roughly six more seconds. Reader
reservations remain resident while that final scan task runs. Q1's main median increases 15.7%.

The window-64 diagnostic lets all 33 scan tasks start and returns Q1 to the baseline range.
However, choosing 64 globally is insufficient: Q3 has 64 reader tasks and two 33-task producer
branches. Fully reserving those demands 130 task slots, exceeding the tested capacity of 128.

The next policy change should separate the minimum producer reservation needed for progress
from the number of producer tasks allowed to use otherwise available capacity. Expansion must
respect reader reservations, other groups, and pool entitlement. Extra capacity should return
as tasks finish; ordinary tasks remain non-preemptible. This expansion is not implemented in
the measured code and requires separate mixed BSP/pipeline qualification.

## Small-window exploration

Two additional fresh-JVM Q1 executions, without query warmup, completed with correct results:

| Fixed window per producer | Single SQL execution |
| --- | ---: |
| 1 (current opt-in policy default) | 673.519 s |
| 8 | 90.465 s |

These are exploratory timings, not paired steady-state medians. Window 1 sustained about
1.1 executor CPU cores in sampled 30-second windows; a thread snapshot showed one active
scan task and waiting readers. The query continued to make progress and completed. The
minimum resource needed for liveness is not sufficient for throughput on this workload.

## Functional defects found and fixed

1. Reader startup was computed from running plus completed tasks. Spark removes a finished
   task from the running count before asynchronously processing its result. The gap could
   rearm startup checks and abort a query after the admission timeout. Startup now checks
   each partition's launch history. The regression test fails before the fix and passes after.
2. Range partitioning samples pipelined output, then uses retained replay output in another
   job. Admission incorrectly waited for the completed producer to submit another task set.
   Registration now stops at available output and reserves only stages that need execution.
   The SQL regression timed out before the fix and completed in about five seconds afterward.

Final validation passed 255 tests: 172 core scheduler/pool/readiness tests, 73 selected DAG
scheduler tests, and ten selected SQL tests. Core production/test and SQL test scalastyle passed.
All completed paired benchmark queries passed result and event-log checks: matching output
keys and non-floating fields, floating aggregates within the stated tolerance, all submitted
stages completed, no task failures/retries/speculation, and two executors without query-time loss.

Executor logs in both admission modes contain `CancellationException` reports from
`StreamingShuffleWriter.cleanupResourcesNow`, logged by `ErrorNotifier`. The corresponding
accepted event logs contain no failed/retried tasks or queries. These cleanup-path reports
are retained for follow-up; this qualification does not claim error-free executor logs or
that the reports have been fixed.

## Evidence

Local evidence root: `/disk0/tmp/ferdinandx/rtm-admission-perf-20261105/`.

The `final/` directory contains manifests, exact runtime hashes, SQL, plans, result rows,
per-second worker telemetry, event logs, driver/executor logs, stage summaries, and
`FINAL_SUMMARY.json`. The `final/window64/` directory contains the larger-window diagnostic.
The parent directory retains the first failed Q3 run, red/green regression logs, and test
reports. `qualified/` retains the Q1 replay failure and the preceding Q3 cohort. Failed or
interrupted queries are excluded from performance medians.

No AWS resources were created. This is a local two-executor qualification of Q1/Q3, not an
AWS, multi-host, mixed-workload throughput, cold-start, or full Q1-Q22 qualification.
