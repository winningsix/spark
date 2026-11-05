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


# Elastic producer admission: SF1000 regression qualification

## Outcome

The fixed producer window is now a minimum liveness reservation, not a concurrency ceiling. Pure producers may use compatible, unreserved CPU offers after all required readers have launched. Extra tasks acquire no lasting reservation and return capacity to normal FIFO/FAIR scheduling when they finish. Reader reservations and each input branch's minimum remain protected.

This cohort found no median wall-time regression against the existing RTM scheduling path. This is an admission-policy comparison, not a new BSP-versus-RTM result or proof of zero overhead for arbitrary queries.

| Query | Legacy RTM median | Elastic admission median | Time change | Legacy samples | Elastic samples |
| --- | ---: | ---: | ---: | --- | --- |
| Q1 | 23.197 s | 22.743 s | -1.96% | 23.197, 23.070, 23.263 | 22.743, 22.723, 24.284 |
| Q3 | 85.855 s | 79.403 s | -7.51% | 86.016, 79.465, 85.855 | 82.172, 79.403, 76.983 |

Q1 launched all 33 scan tasks within 2-5 ms in each measured elastic run while retaining a configured producer minimum of 1. The fixed-window tail observed in the previous report is absent. Q1's small median improvement is best interpreted as restored baseline performance. Q3 improves in this paired cohort, with overlapping sample ranges; it is not a universal speedup claim.

## Protocol and identity

- Source commit: `b70c7699f3c3ada424e6a5f8fef59e849f76633a`.
- Core artifact SHA-256: `4348d644e0d27826b478e47f0a66524b10cff829b24402934576c8c338096b2f`.
- Same core artifact for both modes; group admission disabled for legacy and enabled for candidate. Producer minimum is 1 in both configurations and inactive in the legacy path.
- SF1000 float Parquet at `/disk3/tmp/parquet_float_sf1k_spark2a`: 3,204 files, 376,772,841,750 bytes. Sizes and modification times match the retained inventory.
- One host, two active executor JVMs, 32 physical worker cores, 32 GiB heap per executor. Fractional task charge 0.25 gives 128 task slots, not 128 CPU cores. Driver uses four separate cores.
- Retained page cache. Both applications remain resident, but only one query executes at a time. Per query: one warm-up per mode, then three measured pairs in alternating order.
- SQL, scan sizing, shuffle partition count 32, join settings, AQE disabled, and transport/memory settings unchanged. Normalized physical plans match in every paired iteration.
- First Q3 warm-ups were 165.561 s for legacy and 86.076 s for candidate. Both are retained and excluded under the predeclared warm-up rule. Legacy's warm-up tail consumed substantial task CPU; the captured GC total was under one second. No measured sample was discarded.

## Resource evidence

All values below are medians of the three measured runs. OS utilization covers 32 physical worker cores. Task parallelism is summed task CPU seconds divided by query wall time.

| Query / mode | OS busy cores | Task CPU parallelism | Task CPU seconds | Physical writes GiB | Logical disk spill GiB | Peak combined executor RSS GiB | Loopback TX GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Q1 / baseline | 29.82 | 28.78 | 669.58 | 0.008 | 0.000 | 21.46 | 0.009 |
| Q1 / candidate | 29.77 | 28.96 | 663.31 | 0.007 | 0.000 | 20.42 | 0.008 |
| Q3 / baseline | 28.09 | 21.71 | 1835.66 | 93.566 | 49.252 | 92.28 | 56.563 |
| Q3 / candidate | 29.30 | 22.93 | 1820.98 | 92.489 | 49.282 | 93.75 | 56.562 |

Q1 retains about 93% OS CPU utilization. Q3 improves useful task parallelism without increasing total task CPU work. Physical writes and logical spill are essentially unchanged for Q3; this scheduling change does not remove its materialized build input or operator spill. Device counters include host activity and delayed writeback. RX and TX are retained separately in `summary.json`; loopback cannot qualify multi-host network capacity.

## Correctness and scheduler validation

- 262 tests passed: 175 task-scheduler/pool/policy/readiness tests, 73 selected DAG-scheduler tests, and 14 selected SQL tests. Core source and test scalastyle checks passed.
- New regressions cover first-wave launch of 33 producers with minimum 1, protection of another input branch's minimum, returning extra capacity to an underallocated FAIR BSP pool, and executor loss after extra producers have completed.
- Two-executor SQL tests cover a wide source with two reader stages, materialized build prerequisites, concurrent BSP backlog, completed-producer replay, and Q3 correctness.
- All 16 benchmark executions match independent retained reference results. Keys and non-floating fields match exactly; floating aggregates use absolute tolerance 1e-8 and relative tolerance 1e-12.
- Every application ended and every submitted stage completed. No failed, retried, or speculative tasks; no executor losses; exactly two executors per application. Runtime hashes remained unchanged and executor class origins identify the intended core artifact.
- Existing writer-cleanup `CancellationException` messages remain in both modes; counts and raw logs are retained. They caused no query/task failures. This change does not claim to resolve those cleanup log messages. The SQL suite also emitted a possible daemon-thread-leak warning at teardown; its fork exited.
- All benchmark applications and their executors exited. No AWS resources were created.

## Design limits

The scheduler still uses ordinary non-preemptible tasks. Extra producers follow the existing FIFO/FAIR task-set ordering, including its resource-offer granularity; this does not add strict per-launch fairness or thread suspension. A running extra producer can retain its slot while blocked by backpressure. Other branches' and groups' reserved capacity is protected, but arbitrary waiting BSP work has no immediate preemption guarantee.

Loss or decommissioning of an executor that launched extra producers fails the group even if those producers have completed: their shuffle state may still be needed. CPU reservations do not replace the shuffle memory manager, credit limits, or spill policy. Large plans, multi-host behavior, long-running queries, and concurrent throughput remain separate qualifications.

## Evidence

Full evidence root: `/disk0/tmp/ferdinandx/rtm-elastic-admission-20261105`.

- `manifest.json`, `runtime-hashes.json`, `dataset-verification.json`: artifact, configuration, dataset identity.
- `FINAL_SUMMARY.json`, `summary.json`, `q1-tail-evidence.json`: all samples, telemetry, correctness gates, and scan launch times.
- `final-validation.log`, `dag-registration.log`: successful validation; earlier failed build attempts remain in the evidence directory.
- `q1-baseline`, `q1-candidate`, `q3-baseline`, `q3-candidate`: results, physical plans, event logs, driver/executor logs, and one-second telemetry.
- `cleanup-log-observations.json`: retained cleanup log observations.

See [the admission design](rtm_pipelined_group_admission_design.md) and [the earlier fixed-window measurements](rtm_group_admission_performance_20261105.md).
