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

# Resource admission for finite pipelined batch groups

## Scope and example

This prototype keeps Spark's task execution model. It reserves resources for every required
reader task and a minimum rolling window of tasks from each pure producer stage. Additional
producers can use unreserved CPU offers in the scheduler's FIFO/FAIR order. It does not
suspend running tasks or multiplex operators on a smaller thread pool.

Consider a read-only query with an independently materialized hash-join build input:

| Work | Tasks | Scheduling treatment |
| --- | ---: | --- |
| Build-side scan and materialized shuffle | Plan-dependent | Finish the prerequisite before admitting the dependent pipeline |
| Stage 1: probe-side scan/filter | 100 | Pure producer; four guaranteed slots, with expansion into unreserved capacity |
| Stage 2: join | 8 | Reader and producer; eight resident tasks, counted once |
| Stage 3: aggregation | 8 | Reader; eight resident tasks |

The group needs at least 20 task slots when every task costs one CPU core. With 32 application
slots, 12 are unreserved: other work or additional scan tasks can use them in scheduler order.
If no other work takes those slots, up to 16 scan tasks can run alongside the 16 readers.
When one scan task completes, another can use its reserved producer slot. There is no barrier
between successive waves of scan tasks. Each join task still
builds its local hash table from the completed build-side shuffle before processing probe rows.

For multiple pure producer branches, each branch has its own window. A busy branch cannot take
the slots reserved for another input required by the readers. The implementation uses each task
set's actual CPU charge, including supported fractional CPU charges; a task count is not always
a physical core count. Exchange partition counts still come from the physical plan. Automatic
resource-based partition sizing is not implemented.

## Stage identification and registration

DAGScheduler constructs connected components using pipelined shuffle dependencies between stages.
The graph walk lives in `PipelinedStageGroup.admissionGroups`, which returns descriptors without
submitting tasks or reserving resources. DAGScheduler registers those descriptors before stage
submission; `StreamingShuffleGroupAdmission` owns mutable reservation and launch state.
A stage that reads any pipelined shuffle is a reader, including an intermediate stage that also
writes a pipelined shuffle. Only a stage that writes a pipelined shuffle without reading one is a
pure producer. Narrow dependencies remain within their existing stages.

Registration walks only the stages that still need execution. A completed shuffle output stops
the walk, including a pipelined output retained under an existing internal replay lease. Range
partitioning, for example, first samples a hash-shuffle output and then reads it again. The second
job reserves slots for its new readers without waiting for the completed producer to submit tasks
again. A group reading only replayed inputs can therefore contain readers and no pure producer.
This reuses the existing replay contract; it does not enable arbitrary cross-job exchange reuse.

A materialized shuffle edge separates components. Its producing stage runs as a prerequisite,
using normal scheduling when it does not itself read a pipelined shuffle. An internal materialized
edge whose endpoints also belong to the same pipelined component is rejected by this prototype:
its dependency would prevent all component task sets from becoming ready together.

Before submitting any member task set, DAGScheduler registers every component with its job ID,
stage IDs, expected attempts, task counts, and reader/producer roles. Task sets can still be
submitted in normal dependency order. Submission does not grant permission to launch.

A task set marked as requiring reservation cannot launch without its registered descriptor.
Registration mismatches and simultaneous jobs sharing the same live reserved stage fail explicitly.
A group cannot reserve resources until all its nonempty member task sets have been submitted.
Consequently, a producer submitted before a reader cannot run early or hold the CPU resources that
a materialized prerequisite needs.

## CPU reservation and startup

The shuffle-owned admission policy receives resource offers from TaskSchedulerImpl. It reserves
specific executor placements for reader partitions and producer windows, respecting CPU amounts,
resource profiles, registered receive services, and executor/task exclusions. The first version
supports CPU-only tasks and the existing default-resource-profile eligibility restrictions.

Reservations accumulate from currently free CPU offers. Existing BSP tasks are not preempted.
Unreserved capacity remains available to ordinary work; the same free CPU cannot be counted both
as a group reservation and as capacity for another task. Reader reservations become fixed receive
placements, rather than preparing an inbox on an executor that cannot subsequently run its reader.

After all placements are reserved, the receive coordinator asynchronously prepares the readers'
input endpoints. Preparation acknowledgement and data readiness are separate states:

* Acknowledgement means the executor has established the receive endpoints.
* Data readiness means the inputs have reached the existing drain/readiness condition.

Reserved reader tasks may launch after preparation acknowledgement even with empty inputs.
Requiring input data here would deadlock startup because pure producers are held until all reader
tasks have been launched or have completed. Task launch is the scheduler's criterion; it is not a
separate executor-side acknowledgement that every reader has attached. Prepared endpoints exist
before launch, and reserved compute allows those readers to run and attach. Startup is checked
against each reader partition's launch history. A finished task can leave the running count before
its result is processed asynchronously; that interval must not rearm the startup timeout or stop
new producer tasks from launching.

Once the reader requirement is satisfied, pure producers may use their own reserved placements
or unreserved compatible CPU offers. Expansion never consumes another branch's or group's idle
reservation. Additional producers require a registered receive service and remain subject to normal
resource-profile, exclusion, and locality checks. Reader tasks may also produce data while starting;
their required downstream receive endpoints are prepared asynchronously and their compute capacity is reserved.
Successful reader partitions release their reservations. Producer slots are reused until that
producer stage finishes. Extra producer tasks acquire no lasting reservation: when they finish,
their CPUs return to normal scheduling. Loss of an executor that launched extra producers fails
the group even if those producers have finished, since shuffle state may still be needed.
Successful stages return their reserved capacity, and job cleanup removes the group descriptor.

## Sharing the application with BSP

New reservation targets follow the scheduler's FIFO/FAIR task-set order. A complete group behind
other pending work becomes eligible to reserve after a configurable aging delay. A partially
reserved target keeps accumulating capacity rather than allowing BSP refill to take it back.
Only one new or partial reservation target is processed per offer pass, and the total number of
admitted or partially reserved groups is capped.

Idle reservations have a separate pool counter. FAIR comparisons include running tasks plus
reservations, while the actual running-task count remains unchanged. Launch converts an idle
reservation into a running task for accounting purposes; it does not count the capacity twice.
Within a group, readers receive launch priority without globally moving all pipelined readers ahead
of other pools. Extra producers retain ordinary running-task accounting. At the next offer, an
underallocated FAIR pool can take CPUs released by extra producers; FIFO retains its existing
priority behavior. This does not add preemption or per-task rebalancing within a resource-offer
pass. The existing scheduler may launch multiple tasks from one task set before re-sorting pools.

This is a conservative starvation-mitigation policy, not a bounded-wait or strict CPU-share
guarantee. Ordinary tasks are non-preemptible. Reservations can temporarily leave CPUs idle while
capacity accumulates. A group large enough to consume the application can delay BSP until tasks
finish. The aging delay, admission timeout, group size, and concurrent-group cap are explicit
trade-offs that need mixed-workload performance qualification.

## Failure, cancellation, and limits

Admission and reader startup have a timeout measured from complete task-set submission. Timeout,
preparation failure, a failed or cancelled member, and loss or decommissioning of a reserved
executor fail the affected group and release its reservation accounting. Existing job-abort and
receive-coordinator cleanup retire the task and transport state, including late preparation replies.
No task suspension, automatic whole-query retry, or mid-query switch to BSP is added. An admission
failure is reported to the caller; it is not automatically replanned as BSP.

These are compute reservations. They do not establish a new whole-query memory reservation or
prove that arbitrary operators can progress under memory pressure. Existing credit, shuffle buffer
accounting through MemoryManager, and supported spill paths remain responsible for data retention.
Blocked tasks still occupy their slots. General exchange-reuse, replay, skew, and large-plan
qualification with the new policy remains follow-up work; the opt-in is not a production support
claim for every plan accepted by the existing planner.

Streaming task sets identified by the existing streaming-query property do not opt into the new
batch reservation path. The default configuration leaves the previous scheduling path in place.

## Configuration

All settings below are internal and application-scoped.

| Setting | Default | Meaning |
| --- | --- | --- |
| `spark.shuffle.streaming.groupAdmission.enabled` | `false` | Enable finite batch group reservations |
| `spark.shuffle.streaming.groupAdmission.producerWindow` | `1` | Minimum reserved tasks per pure producer stage; extra tasks may use unreserved CPUs |
| `spark.shuffle.streaming.groupAdmission.maxConcurrentGroups` | `1` | Maximum admitted or partially reserved groups |
| `spark.shuffle.streaming.groupAdmission.reservationDelay` | `5s` | Aging delay before reserving ahead of earlier pending work |
| `spark.shuffle.streaming.groupAdmission.timeout` | `60s` | Wait limit after complete submission, including reader startup |

The prepared receive service, positive reader queue memory, shared writer server, and shared
connections must also be enabled. The group window supersedes the legacy elastic producer caps
for registered groups. The configured minimum stays reserved on its original placements; extra
producer execution does not enlarge that reservation. This separates admission feasibility from
runtime parallelism without adding another hard producer cap.

## Validation and next phase

Scheduler tests cover producer-first submission, complete graph registration, empty-input startup,
rolling producer replacement, separate producer branches, accumulation alongside BSP, pool
accounting and aging, concurrent-group limits, cancellation, timeout, executor loss, successful
release, missing descriptors, and preservation of the streaming submission path.

Local-cluster SQL tests use two executor processes. They verify exact results against BSP for a
wide source with two reader stages and for a join with a materialized build prerequisite. A mixed
workload test uses a conventional RDD aggregation with a materialized shuffle. It verifies that
pipeline tasks start while BSP backlog tasks are still running, that both workloads return exact
results, and that no tasks fail. These are functional tests, not a throughput or
latency benchmark. They do not establish multi-host network behavior or SF1000 performance.

Validation on 2026-11-05 passed 249 tests: 144 task-scheduler tests, 13 pool tests, four shuffle
scheduling-policy tests, ten receive-readiness tests, 72 selected DAG-scheduler tests, and six
SQL tests. Of the six SQL tests, three enable the new reservation policy; the other three preserve
coverage of the legacy spill-readiness path and Q3 correctness with AQE disabled and enabled.
The Q3 checks are not evidence that the new admission policy has been qualified for Q3 performance.

Subsequent SF1000 qualification found and fixed two admission defects: asynchronous reader
result processing could rearm startup timeout, and range-sampling replay could wait for a
completed producer that would never submit tasks again. The fixes passed 255 focused tests.
The measurements also exposed a remaining performance limitation of a fixed producer window:
Q1's 33 scan tasks form a second wave at window 32, increasing median time by 15.7%. A larger
window removes that regression, but cannot be a universal setting for multi-branch groups.
The subsequent elastic-producer change separates minimum reservation from runtime parallelism
and permits expansion into available unreserved capacity. These fixed-window results remain
historical evidence, not measurements of the elastic policy. Q3 also did not pass that performance
check,
with substantial sample variation and brief unrelated host activity.
See [the SF1000 performance report](rtm_group_admission_performance_20261105.md) for the full
protocol, retained samples, functional fixes, and qualification limits.

Elastic-producer qualification subsequently passed 262 related tests and 16 SF1000 query
executions. With producer minimum 1, all 33 Q1 scan tasks launched within 2-5 ms. Q1 median
was 22.743 s versus 23.197 s for legacy RTM; Q3 was 79.403 s versus 85.855 s. Both modes used
the same artifact and physical plans, with one warm-up and three alternating measured pairs.
These are single-host, two-executor results, not multi-host or general zero-overhead claims.
See [the elastic-producer performance report](rtm_elastic_admission_performance_20261105.md)
for samples, CPU and I/O evidence, correctness, and remaining limitations.

The subsequent code cleanup separates graph-to-admission descriptor construction from
DAGScheduler event handling, separates reservation placement from policy selection, shares
planner consumer checks, and moves the shared compression primitives into their own file.
It follows the community review emphasis on
[shared correctness checks](https://github.com/apache/spark/pull/58097#discussion_r3874738592),
[preserving disabled-feature behavior](https://github.com/apache/spark/pull/58097#discussion_r3816785113),
and [stage identity in admission accounting](https://github.com/apache/spark/pull/57341#discussion_r3655488036).
The cleanup passed 462 tests (302 core/transport, 73 DAG, 87 SQL), all four core/SQL main/test
scalastyle checks, and 24 SF1000 query executions with matching results and clean event logs.
Floating aggregates use absolute tolerance 1e-8 and relative tolerance 1e-12; keys and other
fields are exact. Both executors loaded the frozen core and SQL artifacts for each version.

Performance qualification compares pre-cleanup `dc64852fad8` with source `eb6b8735abb`.
Both enable elastic admission with producer minimum 1. This is not a BSP comparison or an
admission-disabled comparison. Physical plans match. Each cohort has one warm-up per version
and three alternating measured pairs. After the first Q3 cohort exceeded the 2% regression
tolerance, a fixed second cohort was declared and run with unchanged artifacts and settings.
All measured samples are retained:

| Query/cohort | Before, seconds | After, seconds | Median change |
| --- | --- | --- | --- |
| Q1 | 24.059, 22.628, 23.352 | 23.046, 22.266, 28.461 | -1.31% |
| Q3 initial | 79.330, 85.317, 75.702 | 81.062, 77.948, 85.450 | +2.18% |
| Q3 repeat | 76.376, 75.864, 75.155 | 93.768, 90.603, 79.877 | +19.43% |

Pooling all six measured Q3 samples gives 76.120 s before and 83.256 s after (+9.37%).
Median task CPU parallelism falls from 23.17 to 22.00; physical device writes are similar
(96.25 versus 96.03 GiB, including host activity and delayed writeback). Q3 remains at 164
successful tasks per query, with unchanged logical shuffle-write bytes. Writer and compression
instruction-bytecode comparisons show no hot-path change, but this does not establish the
cause of the timing difference. The cleanup therefore fails the Q3 performance gate and is
kept on `codex/rtm-code-cleanup-20261105`; the remote qualified POC branch is not advanced.
The results are from one host with two executors and do not qualify multi-host networking.
Evidence, artifact hashes, per-run metrics, and retained warm-ups are under
`/disk0/tmp/ferdinandx/rtm-code-cleanup-20261105/`, with the combined benchmark record at
`perf/FINAL_ALL_SUMMARY.json`. The remaining performance difference requires attribution
before promoting the cleanup to the qualified POC.

A later phase may separate operator state residency from compute threads. Blocked execution
instances could yield threads and resume when input or output capacity becomes available. That
requires operator-level cooperative execution and memory management; it cannot be achieved merely
by changing FIFO to FAIR. Lending that compute capacity to ordinary BSP tasks also needs an
explicit reclamation strategy because those tasks are not inherently preemptible.
