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
reader task and a fixed rolling window of tasks from each pure producer stage. It does not
suspend running tasks or multiplex operators on a smaller thread pool.

Consider a read-only query with an independently materialized hash-join build input:

| Work | Tasks | Scheduling treatment |
| --- | ---: | --- |
| Build-side scan and materialized shuffle | Plan-dependent | Finish the prerequisite before admitting the dependent pipeline |
| Stage 1: probe-side scan/filter | 100 | Pure producer; four tasks at a time in this example |
| Stage 2: join | 8 | Reader and producer; eight resident tasks, counted once |
| Stage 3: aggregation | 8 | Reader; eight resident tasks |

The group needs 20 task slots when every task costs one CPU core. With 32 application slots,
12 remain available for other work. When one scan task completes, another can use its reserved
producer slot. There is no barrier between successive waves of scan tasks. Each join task still
builds its local hash table from the completed build-side shuffle before processing probe rows.

For multiple pure producer branches, each branch has its own window. A busy branch cannot take
the slots reserved for another input required by the readers. The implementation uses each task
set's actual CPU charge, including supported fractional CPU charges; a task count is not always
a physical core count. Exchange partition counts still come from the physical plan. Automatic
resource-based partition sizing is not implemented.

## Stage identification and registration

DAGScheduler constructs connected components using pipelined shuffle dependencies between stages.
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

Once the reader requirement is satisfied, pure producers may launch only within their own reserved
windows and executor placements. Reader tasks may also produce data while starting; their required
downstream receive endpoints are prepared asynchronously and their compute capacity is reserved.
Successful reader partitions release their reservations. Producer slots are reused until that
producer stage finishes. Successful stages return their reserved capacity, and job cleanup removes
the complete group descriptor.

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
of other pools.

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
| `spark.shuffle.streaming.groupAdmission.producerWindow` | `1` | Fixed reserved task window per pure producer stage |
| `spark.shuffle.streaming.groupAdmission.maxConcurrentGroups` | `1` | Maximum admitted or partially reserved groups |
| `spark.shuffle.streaming.groupAdmission.reservationDelay` | `5s` | Aging delay before reserving ahead of earlier pending work |
| `spark.shuffle.streaming.groupAdmission.timeout` | `60s` | Wait limit after complete submission, including reader startup |

The prepared receive service, positive reader queue memory, shared writer server, and shared
connections must also be enabled. The group window supersedes the legacy elastic producer caps
for registered groups. It is a fixed window, not a minimum that automatically grows into spare
capacity. Enlarging or moving an admitted group's window is deferred.

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

A later phase may separate operator state residency from compute threads. Blocked execution
instances could yield threads and resume when input or output capacity becomes available. That
requires operator-level cooperative execution and memory management; it cannot be achieved merely
by changing FIFO to FAIR. Lending that compute capacity to ordinary BSP tasks also needs an
explicit reclamation strategy because those tasks are not inherently preemptible.
