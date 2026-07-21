# Spark 5 Pipelined UCX Shuffle POC Status - 2026-07-21

## Code Branches

- Spark: `poc/tpch4gpu-spark5-20260717`
- Gluten: `poc/tpch4gpu-gluten-20260717`
- Velox: `poc/tpch4gpu-velox-20260717`

The current POC target is a fully streaming shuffle path for Spark 5 TPC-H 1TB on 4 GPUs, using Gluten as the Spark/Velox integration layer and Velox UCX exchange as the data plane.

## Current Architecture

The shuffle path is no longer the old Gluten MPP plan-collapse workaround when running the native UCX template. The current path is:

1. Spark physical planning marks supported columnar shuffle dependencies as pipelined.
2. `PipelinedShuffleManagerRouter` delegates regular shuffles to the standard columnar shuffle manager and pipelined shuffles to `UcxColumnarShuffleManager`.
3. Gluten creates UCX shuffle handles, registers writer endpoints, and exposes reader metadata through `NativeUcxShuffleReadMetadataIterator`.
4. `VeloxIteratorApi` captures native UCX reader specs and writer context while building Velox tasks.
5. `SubstraitToVeloxPlan` creates Velox UCX `ExchangeNode`s for native shuffle inputs.
6. `VeloxRuntime` wraps shuffle writer tasks with native UCX `PartitionedOutput`.
7. Velox cuDF operator adapters replace those nodes with `UcxExchange` and `UcxPartitionedOutput`.

Representative evidence from the latest Q7 validation:

- `spark.gluten.mpp.enabled=false`
- `spark.sql.shuffle.pipelined.enabled=true`
- `spark.shuffle.manager.incremental=org.apache.spark.shuffle.UcxColumnarShuffleManager`
- `dataPlane=velox-native-ucx-exchange`
- `Created Velox UCX ExchangeNode`
- `replacing Exchange with UcxExchange`
- `Wrapped Velox plan with native UCX PartitionedOutput`
- `replacing PartitionedOutput with UcxPartitionedOutput`

## Control Plane And Backpressure

There are three layers of control:

- Spark driver scheduler control: pipelined shuffle groups, concurrent stage scheduling, group admission, deferred consumer completion, reader residency checks, per-stage/per-executor caps, and producer fairness.
- Gluten UCX coordinator: shuffle/group state, writer endpoint registration, reader coverage, reader readiness gates, reader endpoint polling, and group completion/abort messages.
- Velox UCX exchange: native UCX exchange and partitioned output operators with UCX output queues and backpressure on the device-buffer data path.

The most recent Spark scheduler fix keeps live task sets in a pipelined group registry instead of relying only on `Pool.getSortedTaskSetQueue`. That matters because a downstream reader task set can have zero pending tasks while its tasks are still running and resident. Without the live registry, Spark could lose visibility of resident readers and block producer refill indefinitely with `waiting-for-reader-residency`.

## Validation

Latest focused validation after the live task-set registry fix:

- Q7 on GPUs `0,1,6,7`, runtime bloom enabled:
  - Run root: `/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/tpch-4gpu-gpu03/runs/native-velox-plan-q7-4gpu0167-livegroup-20260721-094942`
  - Time: `17.227s`
  - Functional: pass
  - MPP evidence: `0`
  - Velox native UCX exchange nodes: `29`
  - Velox native UCX partitioned outputs: `253`
  - cuDF fallback: `122`

- Q7 on GPUs `0,1,3,4`, runtime bloom disabled:
  - Run root: `/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/tpch-4gpu-gpu03/runs/native-velox-q7-4gpu0134-querybloomoff-20260721-095737`
  - Time: `32.801s`
  - Functional: pass
  - Strict fully GPU: pass, `cudf_fallbacks=0`
  - MPP evidence: `0`
  - Velox native UCX exchange nodes: `28`
  - Velox native UCX partitioned outputs: `252`

Spark scheduler unit validation:

- `org.apache.spark.scheduler.TaskSchedulerImplSuite`
- Result: `123` tests passed

## Historical 22-Query Result

The best completed 22-query 4GPU strict run from the previous working profile is:

- Run root: `/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/runs/full22-queryconf-q14-cap12-20260720-0640`
- Complete: true
- Functional complete: true
- Strict cuDF complete: true
- Sum of query times: `250.436s`
- Power test time: `251.000s`
- Total wall time including table setup: `263.295s`
- MPP evidence: `0`
- cuDF fallback: `0`
- UCX writer endpoints: `3156`
- UCX reader endpoints: `8161`
- Native UCX shuffle handles: `3437`

Per-query times from that run:

| Query | Time ms |
| --- | ---: |
| 1 | 5512 |
| 2 | 6583 |
| 3 | 14404 |
| 4 | 2852 |
| 5 | 31957 |
| 6 | 852 |
| 7 | 19572 |
| 8 | 13300 |
| 9 | 12540 |
| 10 | 19502 |
| 11 | 4763 |
| 12 | 15425 |
| 13 | 4625 |
| 14 | 2892 |
| 15 | 6210 |
| 16 | 5310 |
| 17 | 18440 |
| 18 | 28332 |
| 19 | 2819 |
| 20 | 6067 |
| 21 | 25667 |
| 22 | 2812 |

Important caveat: this 22-query run was before the latest Spark live task-set registry fix. The latest code has not yet been rerun for a full 22/22 pass.

## Current Known Issue

Runtime bloom filter is the main known performance and fully-GPU blocker.

With runtime bloom enabled, Q7 is much faster, but Velox reports cuDF replacement failures around `velox_might_contain` and `velox_bloom_filter_agg`, causing local CPU fallback inside Velox. With runtime bloom disabled, Q7 becomes strict fully GPU, but runtime increases from roughly `17-18s` to `32.8s`.

The next optimization target is to keep the bloom-filter pruning benefit without causing Velox cuDF fallback. That likely requires adding or routing GPU support for the bloom-filter expressions/aggregation path, or replacing that runtime bloom filter path with an equivalent GPU-compatible implementation.
