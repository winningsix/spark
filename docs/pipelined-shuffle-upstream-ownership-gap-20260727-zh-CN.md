# Pipelined Shuffle 调度能力与 Upstream 职责边界 - 2026-07-27

## 目的

本文梳理以下五项 pipelined shuffle 调度能力目前分别处于什么状态，
以及它们应该由 upstream Spark、Query Coordinator 还是 Structured
Streaming backpressure 负责：

1. pipelined group 构造；
2. slot feasibility 和 group admission；
3. stage co-residency；
4. deferred completion；
5. group-atomic failure 和 rerun。

本文关于 Gluten Query Coordinator 去留的判断只针对 **Spark-visible**
路径：scan、exchange、join、aggregate 等执行单元继续体现为 Spark stages
和 tasks，而不是隐藏在一个 `MppNativeQuery` 内部。

本文基于以下代码快照：

- upstream `master`：`d2693b5baf5c`，日期为 2026-07-26；
- 已合入的基础提交：
  [`c15aa124de8`](https://github.com/apache/spark/commit/c15aa124de83584cdb652df637acf8d96506e6ed)，
  `[SPARK-58185][CORE] Define PipelinedShuffleDependency and route shuffles
  to a ShuffleManager by dependency type`；
- 尚未合入的 upstream 调度
  [PR #57341](https://github.com/apache/spark/pull/57341)，
  `[SPARK-58263][CORE] Concurrently schedule pipelined-shuffle stage groups
  in the DAGScheduler`；
- POC fork commit：
  [`718ea6cb55d`](https://github.com/winningsix/spark/commit/718ea6cb55d73d172be24edfdba2677957142c09)，
  branch `poc/tpch4gpu-spark5-20260717`；
- 配套 Gluten/native POC commit：
  [`90301a721578`](https://github.com/winningsix/gluten/commit/90301a721578f948d3ec7ce70d0239639f749c94)，
  branch `poc/tpch4gpu-gluten-cleanup-perf-20260724`。

本文末尾还记录了基于上述性能 tag 继续开发的本地 shared MVP：

- Spark branch `poc/pipelined-shuffle-shared-mvp-20260727`；
- Gluten branch `poc/ucx-transport-control-mvp-20260727`；
- 最终候选 artifact `pipelined-transport-drain-v3-20260727`。

## 结论

截至 2026-07-27，这五项 group 调度能力都还没有正式合入 upstream
Spark `master`。

Upstream `master` 目前已有的是基础设施：

- `PipelinedShuffleDependency`；
- 按 dependency 类型选择对应的 `ShuffleManager`；
- 相关 shuffle API 和 manager routing。

开放的 PR #57341 已经实现前四项的第一版：

- 简化的 whole-job group 模型；
- fail-fast slot feasibility 和 gang admission；
- producer/consumer stages 并发提交；
- deferred consumer completion。

PR #57341 尚未实现 group-atomic failure，并明确把它留给后续 PR。

POC fork 已经实现更通用的 mixed-DAG group 构造和 group-wide failure
propagation，但仍然没有真正的 scheduler-side atomic slot reservation。
它也没有在 `DAGScheduler` 内部自动重跑整个 group，而是把完整 query
或 micro-batch 的 rerun 留给上层执行框架。

对于 Spark-visible 路径，如果 Spark 最终补齐 Flink 式 pipelined-region
scheduling，Gluten 不再需要维护第二套 query-level scheduling
coordinator。Gluten 仍需保留 UCX/native shuffle control plane，负责
endpoint、credit、attempt fencing、transport backpressure 和 native
资源清理。

本地 shared MVP 已进一步验证：在当前受控的 AQE-off、all-pipelined、
静态单 workload 范围内，不必等待全部 production-general Flink 能力到位，
也可以删除 Gluten 的 query-level scheduling authority。Spark 保留 group
构造、admission、co-residency、deferred completion 和 group terminal
outcome；Gluten 只执行 Spark 下发的 group lifecycle，并维护 UCX transport
状态以及 native drain barrier。原始 TPC-H 22Q 三对 A/B 的逐 query
中位数总和变化为 `+0.63%`；补齐 transport-local deferred cleanup 后，
在恢复完整 qualified profile 后，3 次计时的同序号 22Q 样本中位数变化
为 `+0.19%`，逐 query 中位数之和为 `-0.65%`。两轮都未观察到不可解释的
整体性能回退。此前 `B-C-C-B` 的 `-2.17%` 使用了空 per-query overrides
和 `python_collect`，已经从正式性能统计中排除。

## 状态矩阵

| 能力 | Upstream `master` | PR #57341 | POC fork `718ea6cb55d` |
| --- | --- | --- | --- |
| Pipelined group 构造 | 没有 | 当前 POC 足够：all-pipelined job 整体作为一个 group；通用场景受限：mixed job 暂不支持 | 已实现 pipelined edge connected component，可支持 mixed DAG |
| Slot feasibility 和 group admission | 没有 | 已有第一版：检查当前 free slots，不满足则 fail fast | 已有 manager-aware admission 和 reader-residency 检查，但不是 atomic reservation |
| Stage co-residency | 没有 | 已实现 group 内 stages 并发提交 | 已实现，并增加 reader residency、producer refill/cap |
| Deferred completion | 没有 | 已实现 | 已实现 |
| Group-atomic failure | 没有 | 没有，留给后续 PR | 已实现主要的 group-wide fail-fast 和 abort propagation |
| Automatic group rerun | 没有 | 没有 | `DAGScheduler` 内没有；由 query 或 micro-batch caller 负责 |

## 五项能力不全是当前 POC 的刚需

上面的五项首先是一张 capability 和 ownership checklist，不表示当前
Spark-visible TPC-H POC 必须一次性交付五套完整、通用的机制。

需要区分：

- **语义不变量**：为了保证当前 POC 不死锁、不提前完成和不产生错误结果，
  必须满足；
- **具体实现机制**：可以由 Spark Scheduler、shuffle transport 或静态
  部署约束以不同方式实现；
- **通用化能力**：面向 mixed DAG、AQE、dynamic allocation、多 workload
  和生产 fault tolerance，当前 POC 不一定需要。

当前 POC 有以下受控条件：

```text
单 query 顺序运行
专用静态 4-GPU 集群
spark.sql.adaptive.enabled=false
spark.dynamicAllocation.enabled=false
所有 SQL shuffle 都是 pipelined
一个 Spark job 对应一个 pipelined group
UCX shuffle 不支持局部 replay
```

在这些条件下，五项能力应按下面方式分级：

| 项目 | 当前 POC 刚需程度 | 当前真正需要的部分 | 当前不要求的通用化 |
| --- | --- | --- | --- |
| Pipelined group 构造 | 部分需要 | 把 all-pipelined job 识别为一个 group | 任意 mixed-DAG connected components |
| Slot feasibility/group admission | 条件性需要 | 保证 readers 和最小 producer frontier 有共同推进容量 | Admission wait queue、多 workload 公平性、严格 slot lease |
| Stage co-residency | 刚需 | Producer 和 consumer stages 同时 active | 跨 workload 的全局 gang scheduler |
| Deferred completion | 正确性不变量是刚需 | Producer final 前不能让 consumer/job completion 生效 | 必须使用 Driver 缓存整个 `CompletionEvent` 这一特定实现 |
| Group-atomic failure | 刚需 | 当前 non-replayable generation 任意真实失败后整体 abort | 更小 region 的局部 replay/recovery |
| Automatic group rerun | 当前 batch POC 不需要 | Query 失败并交给调用方决定是否重提即可 | `DAGScheduler` 内自动重建整个 group |

### 三个不能省略的语义不变量

当前 POC 最终必须保证的是：

```text
Progress
  producer 和 consumer 有足够资源共同推进

Completion
  producer final 前不能暴露 consumer success

Failure
  non-replayable stream 不能局部 retry
```

只要这三个不变量得到满足，具体代码不一定必须分别表现为五个独立的
subsystem。

例如，deferred completion 的正确性不变量也可以由更强的 transport/task
protocol 保证：

```text
Consumer 收到所有 producers 的 EndOfData
并完成 termination acknowledgement
            |
            v
Consumer task 才允许返回 Success
```

如果这个协议足够严格，Driver 就不一定需要永久保留显式的 deferred
`CompletionEvent` buffer。当前 POC 使用 Driver-side deferral，是因为
现有 task/transport lifecycle 还没有独立提供完整保证。

### 当前 POC 的最小 Upstream 闭环

当前受控 POC 所需的最小 upstream 能力可以收敛成：

1. 将 all-pipelined job 识别为一个 group。
2. 启动前保证全部 required readers 加最小 producer frontier 有推进容量。
3. 并发提交 producer 和 consumer stages。
4. Producer final 前禁止 consumer/job completion 对外生效。
5. 任意真实失败都 abort 整个 group；不要求 scheduler 自动 rerun。

因此当前最短 upstream 路径是：

```text
PR #57341
  whole-job group
  + admission/co-scheduling
  + completion handling
        |
        v
补充 group-atomic abort
        |
        v
形成当前 POC 的最小 scheduler 闭环
```

Mixed-DAG connected components、admission wait queue、dynamic-resource
reconsideration、strict slot reservation、多 workload fairness 和
scheduler-internal automatic rerun 都可以作为后续通用化工作。

## 1. Pipelined Group 构造

普通 Spark 会按 shuffle dependency 切分 stage，并等待 producer stage
完成后再运行 consumer stage。

Pipelined shuffle 的 producer 和 consumer 必须同时运行。因此 Spark
首先需要确定：

> 哪几个 stage 属于同一个必须共同调度、共同结束和共同失败的
> pipelined group？

### PR #57341 的语义

PR #57341 采用一个有意简化的第一版模型：

- 一个 job 要么全部使用 regular shuffle，要么全部使用 pipelined
  shuffle；
- all-pipelined job 的整个 DAG 作为一个 group；
- 同一个 job 混合 regular 和 pipelined shuffle 时暂时拒绝执行。

这个模型对当前 Spark-visible TPC-H POC 是正确且足够的，不应把 mixed
DAG support 当成第一阶段 upstream integration 的 blocker。

当前 POC 的受控执行条件是：

```text
spark.sql.adaptive.enabled=false
spark.sql.shuffle.pipelined.enabled=true
```

启用 pipelined shuffle 后，当前
[`ShuffleExchangeExec`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/sql/core/src/main/scala/org/apache/spark/sql/execution/exchange/ShuffleExchangeExec.scala#L545)
会为每个 SQL shuffle exchange 创建 `PipelinedShuffleDependency`。AQE
关闭后，中间也不会引入额外的 materialized query-stage 边界。因此对
当前 22 个 TPC-H query：

```text
all SQL shuffle edges 都是 pipelined
                 |
                 v
whole job 正好是一个 pipelined connected component
                 |
                 v
PR #57341 的 whole-job group 就是当前 POC 需要的 group
```

所以这里的评价应该拆成两个范围：

| 目标范围 | PR #57341 的 group 模型 |
| --- | --- |
| 当前 AQE-off、all-pipelined TPC-H POC | 足够 |
| 第一阶段 upstream scheduler integration | 足够 |
| 当前 workload 替代 POC connected-component 构造 | 可以 |
| Mixed regular/pipelined DAG | 不支持 |
| 一个 job 中存在多个 blocking-separated regions | 不支持 |
| Flink 式通用 pipelined-region semantics | 尚不完整 |

“尚不完整”只针对未来的 production-general 场景，不表示当前实现不能
支撑 POC。

### POC fork 的语义

POC fork 沿 pipelined dependency 向 producer 和 consumer 两个方向
搜索 connected component：

```text
regular input
     |
     v
 producer A ===pipelined===> consumer B ===pipelined===> consumer C

另一条 regular dependency -------------------------------> C
```

这里 `A/B/C` 构成一个 pipelined group，regular dependency 可以作为
group 的外部输入。因此：

- 同一个 job 可以同时包含 regular stages 和 pipelined stages；
- 同一个 job 可以包含多个互不相连的 pipelined groups。

实现位置：
[`DAGScheduler.pipelinedGroupOf`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L1639)。

### 还需要交给 upstream 的内容

如果 upstream 最终需要支持 mixed DAG，而不只是 whole-job
pipelining，就仍然需要引入 connected-component group semantics。这是
后续 generalization，不是当前 POC 或第一阶段 PR 的合入前置条件。

## 2. Slot Feasibility 和 Group Admission

Pipelined group 不能像普通 Spark stages 一样先启动一部分，再等待剩余
stages 获得资源。

例如：

```text
Producer：需要 4 个 slots
Consumer：需要 4 个 slots
集群当前可用：4 个 slots
```

如果 Spark 先启动 4 个 producer，而 producer 又需要等待 consumer
消费数据，那么 consumer 永远拿不到 slot，整个 group 就会死锁。

因此 group 启动前必须回答：

> 当前是否有足够的 producer 和 consumer 执行容量，保证这个 group
> 启动后能够向前推进？

### PR #57341 的 admission

PR #57341 已经实现第一版 up-front gang admission：

- 计算同一 resource profile 下当前可用的 slots；
- 扣除其他 running 和 enqueued work 的需求；
- group 能整体放下才提交；
- 放不下时立即 fail fast。

这里的“资源不足”特指 Spark Scheduler 当前可分配的 task slots 无法满足
group admission demand，不是 UCX queue 满、native queued bytes 过高、
GPU 显存不足或 source 输入过快。

可以简化为：

```text
当前可用 slots
  = 当前 ResourceProfile 支持的最大并发 task 数
  - 已经 running 的 tasks
  - 已经 enqueued 的其他 work demand

如果：
当前可用 slots < group admission demand

则：
group admission 失败
```

ResourceProfile 可以同时包含 CPU 和 GPU 约束。例如：

```text
4 个 executors
每个 executor：8 CPU cores、1 GPU
spark.task.cpus=1
spark.task.resource.gpu.amount=0.25

CPU capacity = 4 * 8 = 32 tasks
GPU capacity = 4 * (1 / 0.25) = 16 tasks
实际最大并发 = min(32, 16) = 16 tasks
```

如果 group 需要同时 admission 20 个 GPU tasks，就会被判定为资源不足。

资源不足需要区分两种情况：

| 类型 | 示例 | 是否可能自行恢复 |
| --- | --- | --- |
| 永久不足 | 集群总容量为 8 slots，group 最小需求为 12 | 不扩容或不降低 parallelism 就无法运行 |
| 暂时不足 | 集群总容量为 16 slots，其他 workload 正占用 8，group 需要 12 | 其他 work 结束后可能恢复 |

PR #57341 当前没有 admission wait queue，也不会把 group 放入
`WAITING_FOR_RESOURCES` 状态。因此它不区分上述两种情况：首次检查不满足
时直接失败，不会等待其他 tasks 结束、新 executor 加入或 dynamic
allocation 扩容后自动重新 admission。

如果后续增加 wait queue，预期流程应该是：

```text
当前 free slots 不足
          |
          v
group 进入 WAITING_FOR_RESOURCES
          |
          | task 完成、executor 加入或资源释放
          v
重新计算 slot feasibility
          |
          v
满足后 admission 并共同 deploy
```

### POC fork 的 admission

POC fork 根据 shuffle manager 类型计算需求：

- pull-style manager 可能要求整个 group 的所有 tasks；
- push/streaming manager 至少要求全部 readers，以及每个 pure producer
  stage 的部分 producers；
- 如果 manager 要求 readers 常驻，还会增加 reader-residency 检查和
  capacity change 后的 reconsideration。

实现位置：
[`DAGScheduler.pipelinedGroupExceedsCapacity`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L1695)。

### 当前共同的限制

目前的 admission 都不等同于真正的 atomic slot reservation：

```text
检查时有 8 个 free slots
          |
          | 其他 workload 可能同时抢占资源
          v
实际 launch 时不一定还有 8 个 slots
```

所以当前更准确的描述是 best-effort gang admission，而不是严格的
资源 reservation。

## 3. Stage Co-residency

Admission 解决的是 group 在理论上是否能放得下；co-residency 解决的是
producer 和 consumer 是否能同时处于 active 状态。

普通 Spark 会等待 shuffle map stage 完成后再提交 consumer。
Pipelined shuffle 必须改变这条规则：

```text
普通 shuffle：
producer 完成 -> consumer 启动

pipelined shuffle：
producer active <-> consumer active
```

PR #57341 已经在 admission 成功后并发提交 group 内的 producer 和
consumer stages。

POC fork 在此基础上还增加了：

- reader residency；
- producer refill；
- producer task cap；
- shuffle control-plane 状态反馈。

需要区分两种保证：

- 逻辑 co-residency：group 内 stages 被同时提交和激活，已经具备；
- 严格物理 co-residency：slots 被持久保留，不会被其他 workload 抢走，
  目前还不具备。

如果需要在高竞争集群中提供严格保证，后续仍可能需要
TaskScheduler/SchedulerBackend 层面的 reservation 或 lease。

## 4. Deferred Completion

Streaming consumer task 可能在 producer 进入 final 状态前报告成功。

如果按普通 Spark completion path 立即处理这个成功事件，可能出现：

```text
Consumer 报告成功
        |
        v
Consumer stage 被标记完成
        |
        v
Job 被标记完成
        |
        v
Producer 实际仍未结束，甚至随后失败
```

### 当前 POC 采用“两层结束”

当前 POC 不是让已经读完数据的 consumer task 继续占着 Executor slot
等待 producer，而是区分：

1. **Executor 上的物理 task 结束**：iterator 返回，task thread 退出，
   Executor 上报 `Task Success`，对应的 task slot 可以释放；
2. **DAGScheduler 中的语义完成**：accumulator、`TaskEnd`、stage completion
   和 job completion 是否可以正式生效。

如果 consumer 的相关 producer stages 还没有进入 final 状态，POC
只延迟第二层：DAGScheduler 缓存 consumer 的整个 `CompletionEvent`，
不会让该 event 推进 stage 或 job completion。Consumer task 本身已经
正常返回，不会为了 deferred completion 继续占用 Executor task thread。

当前时序可以概括为：

```text
Producer native task
    注册 endpoint
    持续发送数据
    noMoreData / EOS
    native UCX 可能继续 drain
          |
          +-------------------+
          |                   |
Consumer native task          Producer Spark task
    发现全部 endpoints         writer.stop(true)
    noMoreSplits               返回 MapStatus
    继续读取数据和 EOS          Executor 上报 Task Success
    iterator 结束                     |
    Executor 上报 Task Success         |
          |                            |
          +------ CompletionEvent -----+
                         |
                    DAGScheduler
                         |
             producer stage 仍未 final？
                    |             |
                   是            否
                    |             |
           缓存 consumer event    正常结算
                    |
             producer 最终成功/失败
                    |
             成功：replay event
             失败：drop result bookkeeping
```

### 数据面和 Spark Scheduler 的结束信号

当前路径中有多个不同层级的“结束”，不能互相替代：

| 信号或状态 | 准确含义 | 是否代表 Spark task 已结束 |
| --- | --- | --- |
| Reader `noMoreSplits` / `noMoreReaderEndpoints` | 所有预期 producer 都已有 endpoint，或者已被 accounted，不会再出现新的输入源 | 否 |
| Writer `noMoreData` | 该 native producer 不会再产生新记录 | 否 |
| Native writer `finished` | UCX/native writer 已进入 transport final/drained 状态 | 否 |
| Reader 收到所有数据和 EOS | 该 consumer 已经 drain 已知 inputs，iterator 可以结束 | 尚未；随后 task 才返回 |
| Spark `Task Success` | task 函数已经返回，Executor 已报告成功 | 是，task 级 |
| Producer stage final | 该 producer stage 的全部 Spark tasks 已得到最终结果 | 是，stage 级 |
| Deferred event replay | Consumer success 正式计入 accumulator、stage 和 job | 是，group/job 可见 |

特别需要注意，`noMoreSplits` 并不表示所有 producers 都已完成。当前
`completedMapCount` 的计算是：

```text
已经发现 endpoint 的 maps
    +
已经 finished、因此不会再出现 endpoint 的 maps
```

达到 `expectedMaps` 只说明 producer 集合已经封口。调用
`noMoreSplits()` 后，Velox reader 仍会继续从现有 endpoints 读取，直到
收到数据流的 EOS。

实现位置：

- native Velox Exchange split poller：
  [`NativeUcxShuffleExecution.startVeloxExchangeSplitPoller`](https://github.com/winningsix/gluten/blob/90301a721578f948d3ec7ce70d0239639f749c94/gluten-substrait/src/main/scala/org/apache/spark/shuffle/NativeUcxShuffleExecution.scala#L326)；
- streaming reader endpoint poller：
  [`UcxColumnarShuffleManager.startEndpointPoller`](https://github.com/winningsix/gluten/blob/90301a721578f948d3ec7ce70d0239639f749c94/gluten-substrait/src/main/scala/org/apache/spark/shuffle/UcxColumnarShuffleManager.scala#L1244)。

### Producer task 当前如何结束

Native producer task 的主要步骤是：

1. 获取 writer credit；
2. 注册 UCX endpoint；
3. 启动 native writer `noMoreData` 状态 poller；
4. 驱动 Velox pipeline 并持续发送 shuffle 数据；
5. native runtime 不再产生数据后报告 `noMoreData`；
6. Spark 调用 `ShuffleWriter.stop(true)`，writer 返回零长度的
   `MapStatus`；
7. `ShuffleMapTask` 返回，Executor 上报 `Task Success`。

Coordinator 当前把 `noMoreData || finished` 视为 `writerDone`，据此把
writer 加入 finished coverage 并释放 writer credit。这个较弱条件只用于
progress/credit bookkeeping，不是 transport runtime 的物理清理条件，也
不等于 Spark `ShuffleMapTask` 已经进入 final 状态。

另外，native producer 可以在 Spark task 返回后保持 detached 状态，由
后台 poller 继续报告 queued bytes、`noMoreData` 和 `finished`，直到 UCX
输出队列 drain。因此也不能把 producer 的 Spark `Task Success` 简单解释
成所有 native buffer 已经完成 drain。

2026-07-27 的回退调查进一步确认，Spark authoritative group complete
也不能直接解释成 UCX transport 已经 drain。当前本地 MVP 因此增加一层
transport-local completion：

1. Spark group complete 到达时，transport group 先进入 `Draining`；
2. 保留 writer/reader endpoint、native state 和 unregister 所需映射；
3. 对每个已注册 writer，必须是同一个当前 attempt，并且同时观察到
   `noMoreData=true` 和 `finished=true`；
4. 满足上述条件后才进入 `Finished`，再 reset transport runtime；
5. 如果 Spark 的 shuffle unregister 更早到达，只记录 pending
   unregister，等 drain 完成后再执行清理。

这里仍然不需要 query-level coordinator。Spark 拥有 group 的
authoritative scheduler outcome；Gluten 只拥有 UCX/native 物理资源何时
可以安全释放这一 transport-local 事实。

实现位置：

- writer 执行和 `stop`：
  [`UcxColumnarShuffleWriter`](https://github.com/winningsix/gluten/blob/90301a721578f948d3ec7ce70d0239639f749c94/gluten-substrait/src/main/scala/org/apache/spark/shuffle/UcxColumnarShuffleManager.scala#L234)；
- detached writer 状态 poller：
  [`startNativeWriterNoMoreDataPoller`](https://github.com/winningsix/gluten/blob/90301a721578f948d3ec7ce70d0239639f749c94/gluten-substrait/src/main/scala/org/apache/spark/shuffle/UcxColumnarShuffleManager.scala#L550)；
- Coordinator 对 writer state 的处理：
  [`reportNativeWriterState`](https://github.com/winningsix/gluten/blob/90301a721578f948d3ec7ce70d0239639f749c94/gluten-substrait/src/main/scala/org/apache/spark/shuffle/UcxShuffleCoordinator.scala#L1189)。

### Consumer task 当前如何结束

Native consumer task 的主要步骤是：

1. 注册 reader endpoint；
2. 获取当前可见的 writers 和 `expectedMaps`；
3. 随着 producers 启动，动态向 Velox ExchangeNode 增加 splits；
4. 所有预期 producers 都被 accounted 后调用 `noMoreSplits()`；
5. Velox reader 继续读取现有 splits，直到所有输入数据和 EOS 被消费；
6. iterator 结束，task completion listener 报告 reader
   `noMoreSplits=true, finished=true`；
7. task 返回，Executor 向 Spark 上报 consumer `Task Success`。

因此 consumer 的物理结束条件不是看到 `noMoreSplits`，而是
`noMoreSplits` 之后继续 drain，并最终从 native reader 得到 EOS/空结果。

### Driver 如何延迟并最终结算

Consumer 的成功 `CompletionEvent` 到达
`DAGScheduler.handleTaskCompletion` 后，如果
`pipelinedConsumerDeferrals(stage).pendingProducers` 仍然非空，
DAGScheduler 会：

1. 缓存整个 `CompletionEvent`；
2. 在 accumulator 更新、`SparkListenerTaskEnd`、stage completion 和
   job completion 之前直接返回；
3. 等待相关 producer stage 的最终结果。

等相关 producers 都进入 final 状态后：

- producer/group 成功：把缓存的 events 重新投递到 DAGScheduler event
  loop，按普通路径 exactly once 地执行全部 side effects；
- producer/group 失败：不采用这些 consumer success，不更新
  accumulator/stage/job result bookkeeping；仍补发 `TaskEnd`，避免
  Spark UI 和 listener 永久认为 task 还在运行，然后由 group abort
  终止当前 generation。

实现位置：

- 注册 consumer 对 producer 的 deferral 关系：
  [`DAGScheduler.submitStage`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L2446)；
- 缓存整个成功 `CompletionEvent`：
  [`DAGScheduler.handleTaskCompletion`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L3307)；
- producer final 后 replay 或 drop：
  [`DAGScheduler.releaseDeferredPipelinedConsumers`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L4451)。

### 为什么当前协议仍需要 Driver-side deferral

Reader drain 到 EOS 能证明该 consumer 已经收完当前 generation 的输入，
但不能证明 producer 的 Spark task/stage 随后一定成功。Producer 仍可能
在 task teardown、completion handling 或其他 Spark lifecycle 路径中
失败。

如果 consumer 是 ResultStage，立即采用它的成功结果可能先结束 job，
然后 Spark 会取消仍被认为 active 的 producer stage。Deferred
completion 补的是这一段 Scheduler lifecycle 缺口：

```text
数据面完整：
  consumer 已收到全部 EndOfData/EOS

还不等于

Scheduler outcome 已确定：
  producer Spark stages 已全部 final-success
```

所以当前 POC 的保证是一个双 barrier：

- **Data-plane barrier**：`noMoreSplits` 后继续 drain 到 EOS，保证数据
  完整；
- **Scheduler-plane barrier**：producer stages final 后才 replay
  consumer completion，保证 stage/job 不提前结束。

PR #57341 和 POC fork 都已经实现 Driver-side deferred completion。
未来如果 transport/task 协议能够严格保证 consumer 只有在所有 producer
Spark outcomes 都已确定、并完成 termination acknowledgement 后才返回，
可以用该协议替代显式的 `CompletionEvent` buffer；当前实现尚未提供这个
等价保证。

Deferred completion 是 scheduler lifecycle 和 correctness 规则，与
source backpressure 是两个不同问题。

## 5. Group-Atomic Failure 和 Rerun

这里必须把 failure 和 rerun 拆成两个不同职责。

### Group-atomic failure

Group-atomic failure 的含义是：

> 如果 group 内任意 producer、consumer 或中间 stage 发生真实失败，
> 当前 generation 的整个 group 都作为一个不可分割的失败单元终止，
> 不能只重试其中一个 task 或 stage。

这里的 atomic 是状态和恢复语义上的原子性，并不是要求所有 executor
进程在同一时刻物理停止。Scheduler 必须只产生一个 group terminal
outcome，并把异步到达的 task、endpoint 和 completion event 收敛到这个
outcome。

例如：

```text
Producer Stage A
       |
       | streaming UCX shuffle
       v
Consumer Stage B
       |
       | streaming UCX shuffle
       v
Consumer Stage C
```

如果 B 的一个 task 失败，A 可能已经发送了部分数据，B 可能已经消费并
处理了部分数据，C 也可能已经消费了 B 的部分输出。只启动一个新的 B
task 时，它无法从一个稳定、可寻址的 offset 或 shuffle file 继续读取，
也无法撤回旧 B 已经发给 C 的结果。

普通 materialized shuffle 和当前 pipelined UCX shuffle 的恢复边界不同：

| Shuffle 类型 | 稳定恢复边界 | 合理的 retry 单元 |
| --- | --- | --- |
| 普通 materialized shuffle | 已注册、可寻址的 map output/shuffle file | 单个 task 或 stage |
| 当前 pipelined UCX shuffle | executor/GPU/UCX 中的 transient stream 和 queue | 整个 pipelined group generation |

### 为什么当前 POC 必须这样处理

当前 Spark-visible UCX POC 需要 group-atomic failure，不是因为未来可能
出现少见 corner case，而是当前 data path 没有支持局部 replay 的稳定
边界。

具体原因包括：

1. **Pipelined map output 是 transient 的。** Producer 完成后，POC 不把
   结果注册为 `MapOutputTracker` 中可持久寻址的 map output。Incremental
   reader 通过 UCX transport 发现和消费 producer，而不是稍后重新读取
   shuffle file。
2. **UCX destination queue 是消耗式读取。** Consumer 已取走的数据不能
   由一个新的 task attempt 从同一 sequence space 任意重放。当前实现也
   因此禁止把一个 native streaming exchange 直接复用给多个 consumer。
3. **Producer 和 consumer 同时推进。** Consumer 失败前可能已经把部分
   结果发送给下一层 consumer，局部重试无法回滚这些下游副作用。
4. **Transport 状态绑定到具体 attempt 和 executor。** Endpoint、native
   task ID、queue、reader coverage 和 termination acknowledgement 都与
   当前 generation 绑定。Executor loss 后，孤立地重建一个 task 会把新旧
   attempt 的 transport state 混在一起。
5. **Consumer success 可能早于 producer final。** POC 会 deferred
   consumer completion。如果 producer 随后失败，这些 success event
   必须全部 drop；不能让一部分 stage 保持成功并只重跑 producer。
6. **Spark 默认 `FetchFailed` 路径不适用。** 普通 Spark 会单独 resubmit
   map stage；但 transient pipelined stream 不能被独立 re-read，单独启动
   producer 也可能因为没有共同运行的 readers 而永久等待 termination
   acknowledgements。

当前实现注释记录了两个对应的实际错误模式：

- `SC-233883`：`FetchFailed` 后孤立重提 map stage，破坏 co-scheduling
  并导致 group deadlock；
- `SC-235532`：executor loss 后单独重提已经成功或部分成功的 producer，
  streaming writer 在等待 termination acknowledgements 时挂住。

因此失败时必须执行：

```text
任意真实 task/stage/transport failure
                   |
                   v
把当前 group generation 标记为 FAILED
                   |
                   +--> cancel 全部 active group tasks
                   +--> drop deferred consumer completions
                   +--> reject 旧 attempt/generation 消息
                   +--> abort UCX queues、streams 和 endpoints
                   +--> release scheduler/native resources
                   |
                   v
向 Spark SQL/Structured Streaming execution 报告一次 group failure
```

一个正确的 group-atomic failure contract 至少需要保证：

1. group 内不能一部分 stages 保持成功、另一部分局部重跑；
2. 失败 generation 的 endpoint、native state 和 completion 不再生效；
3. deferred consumer completion 在 producer failure 后只能 drop；
4. 当前 generation 只有一个最终状态：`SUCCEEDED` 或 `FAILED`；
5. 如果上层决定 rerun，必须创建干净的新 generation。

只有在 shuffle 提供 durable per-partition replay、consumer consumption
offset、downstream rollback 或幂等提交、以及跨 attempt 的一致性协议后，
才可能把恢复范围缩小到单个 task 或部分 region。当前 POC 不具备这些
条件，因此 group generation 是最小的安全 failure boundary。

PR #57341 尚未实现这项能力，并明确留给后续 PR。

POC fork 已经实现主要的 group-wide failure propagation：

- pipelined `TaskSet` 的 effective `maxFailures` 为 1；
- `FetchFailed` 不再触发孤立的 map stage retry；
- executor loss 和 terminal task failure 会传播到整个 group；
- group 内所有 active stages 一起 abort。

实现位置：

- [`TaskSetManager.effectiveMaxTaskFailures`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/TaskSetManager.scala#L79)；
- [pipelined `FetchFailed` handling](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L3503)；
- [`DAGScheduler.abortPipelinedShuffleGroup`](https://github.com/winningsix/spark/blob/718ea6cb55d73d172be24edfdba2677957142c09/core/src/main/scala/org/apache/spark/scheduler/DAGScheduler.scala#L2009)。

### Automatic rerun

POC fork 没有在 `DAGScheduler` 内部原地重跑整个 group。

原地重跑需要把 producer/consumer streams、native queues、endpoints 和
group generation state 作为一个事务完整重建。这不应由普通的 stage
retry 逻辑隐式完成。

推荐的职责边界是：

```text
DAGScheduler
  原子终止失败的 pipelined group
          |
          v
Spark SQL / Structured Streaming execution
  根据 checkpoint 和 query 状态决定是否重跑完整 query 或 micro-batch
```

Structured Streaming 已经有 micro-batch 和 checkpoint 边界，适合拥有
checkpoint-aware rerun 策略。

普通 batch SQL 没有相同的 checkpoint 语义，通常应该让整个 query
失败，再由调用者决定是否重新提交。

因此：

- group-atomic termination 应该由 upstream Spark Scheduler 负责；
- automatic whole-query 或 whole-batch rerun 应该由上层 execution
  framework 负责。

## Spark Execution、Scheduler 和 Backpressure 的关系

Spark execution layer、Spark Scheduler 和 streaming backpressure 解决
的是三个相关但不同的问题。下表中的 Query/Streaming Coordinator 指
Spark SQL 或 Structured Streaming execution layer，不是 Gluten 内部的
第二套 query scheduler。

| 能力 | 推荐 owner |
| --- | --- |
| 确定哪些 stages 构成 pipelined group | Spark `DAGScheduler` |
| 判断 group 是否有足够 slots 安全启动 | Spark Scheduler |
| 保持 producer 和 consumer stages 同时 active | Spark Scheduler |
| 延迟处理过早到达的 consumer completion | Spark `DAGScheduler` |
| group 失败时原子终止所有成员 | Spark Scheduler |
| 是否以及何时重提完整 query 或 micro-batch | Spark Query/Streaming execution |
| 根据 checkpoint 恢复 query | Structured Streaming execution |
| 在持续压力下降低 source 输入速率 | Streaming backpressure |
| 报告 native transport readiness、demand 和 failure | Shuffle-manager control-plane adapter |

### Backpressure 不能代替 group admission

Backpressure 解决的是：

```text
系统处理不过来
    |
    v
减少 source 输入，或者降低新 micro-batch 的生成速度
```

Group admission 解决的是：

```text
一旦启动一个 pipelined group
    |
    v
确保 producer 和 consumer 有共同前进所需的执行容量
```

即使 backpressure 已经把输入速率降得很低，如果 Scheduler 把所有 slots
都分配给 producers，导致 consumers 一个都无法启动，group 仍然会
死锁。

### Group admission 也不应该负责 checkpoint-aware rerun

Scheduler 知道 stage、task、slot 和 group 的运行状态，但它通常不知道：

- 哪个 checkpoint 可以安全恢复；
- 一个 micro-batch 是否允许重新提交；
- query result 是否已经对外可见；
- sink commit 是否具有幂等性。

这些是 query execution 和 Structured Streaming 的语义，因此 rerun
策略应该留在上层。

## Spark-Visible 路径下 Gluten Query Coordinator 的去留

### 结论

如果 Spark 真正补齐 Flink 式的 pipelined-region 能力，那么在
Spark-visible 路径下：

> Gluten 不需要继续维护 query-level coordinator，但仍然需要一个较薄的
> UCX/native shuffle control plane。

Spark-visible 路径中，Spark 已经能看到完整的 scheduling topology：

```text
Spark Stage A ===UCX===> Spark Stage B ===UCX===> Spark Stage C
```

Spark 能看到 stage、task、dependency、parallelism、resource profile、
attempt 和 failure。因此 group scheduling authority 应该只存在于 Spark。

如果 Spark 和 Gluten 同时维护如下 query/group 状态：

```text
REGISTERED
   |
   v
ADMITTED
   |
   v
READERS_READY
   |
   v
DRAINING
   |
   v
FINISHED / ABORTED
```

就可能产生两个 authoritative state machines。例如 Spark 已经 abort
group，而 Gluten 仍认为 query 正在 draining；或者 Spark admission
成功后，Gluten 又用独立策略拒绝启动 producers。这类 split-brain 应该
通过单一的 Spark scheduling authority 消除。

### 应该移到 Spark 的职责

| 当前 query-level 职责 | 最终 owner |
| --- | --- |
| Pipelined group topology 和 metadata | Spark `DAGScheduler` |
| Group `REGISTERED/ADMITTED/FINISHED/ABORTED` 状态 | Spark `DAGScheduler` |
| Slot feasibility 和 group admission | Spark Scheduler |
| Durable slot reservation 和 group deployment | TaskScheduler/SchedulerBackend |
| Producer/consumer co-scheduling | Spark Scheduler |
| Reader residency | Spark Scheduler |
| Producer task launch/refill cap | Spark Scheduler |
| Deferred completion | Spark `DAGScheduler` |
| Group completion 和 group-atomic abort | Spark `DAGScheduler` |
| Group attempt/generation lifecycle | Spark Scheduler |
| Query 或 micro-batch checkpoint-aware rerun | Spark SQL/Structured Streaming execution |

这意味着 Gluten 不应该继续根据独立的 query state 决定 Spark tasks 是否
可以 launch。Native runtime 可以报告 pressure，但 task launch policy
应该由 Spark 决定。

### Gluten 仍然必须保留的职责

即使 Spark 完整拥有 group scheduling，Gluten/UCX 仍然需要 data-plane
control：

- writer/reader endpoint 注册和发现；
- reader endpoint coverage 和 UCX rendezvous；
- native task ID、stage attempt 和 task attempt fencing；
- 拒绝迟到的旧 attempt 或旧 generation 消息；
- per-channel/per-writer credit；
- native queued bytes 和 blocked-writer 状态；
- transport-level backpressure；
- native reader `noMoreSplits` 和 writer `noMoreData`；
- UCX endpoint、queue、stream 和 native buffer 清理；
- 向 Spark 报告 `READY`、`BACKPRESSURED`、`FINISHED` 和 `FAILED`。

因此保留下来的组件更适合命名为：

```text
UcxShuffleControlPlane
UcxTransportCoordinator
NativeShuffleRuntime
```

它只报告 data-plane 事实并执行 Spark 下发的 lifecycle command，不再拥有
query scheduling policy。

推荐的最终结构是：

```text
Structured Streaming / Spark SQL execution
  checkpoint、micro-batch commit、whole-query/batch rerun
                         |
                         v
Spark DAGScheduler + TaskScheduler
  group topology、slot reservation、launch、completion、failure
                         |
                         | lifecycle commands
                         | readiness/pressure/failure reports
                         v
Gluten UCX Shuffle Control Plane
  endpoints、credits、attempt fencing、native cleanup
                         |
                         v
Velox / UCX data plane
```

### Backpressure 的拆分

Gluten 必须继续实现 transport-level backpressure，因为只有 UCX/native
runtime 知道：

- receiver 是否还有 network/native buffer；
- writer queue 积压多少；
- 哪个 channel 没有 credit；
- 哪些 writers 正在阻塞。

但这些信息应该作为 signal 上报给 Spark：

```text
Gluten 检测 queued bytes、blocked writers 和 credits
                         |
                         v
向 Spark Scheduler 报告 pressure
                         |
                         v
Spark 决定是否暂停 producer launch 或降低 refill cap
```

职责边界是：

- transport flow control：Gluten/UCX；
- Spark task launch 和 admission policy：Spark Scheduler；
- source 输入和 micro-batch 节奏：Structured Streaming backpressure。

### 移除 Query-Level Coordinator 的前置条件

对当前 AQE-off、all-pipelined POC，Gluten 的 query-level coordinator
只有在以下能力到位后才能删除：

1. Spark 能把 all-pipelined job 作为一个 group，并持续拒绝当前不支持的
   mixed DAG；当前 POC 不要求先实现通用 mixed-DAG group 构造。
2. Spark 或静态部署约束能保证 required readers 加最小 producer
   frontier 的共同推进容量；当前单 workload POC 不要求先实现 durable
   slot reservation。
3. Spark 能共同 deploy producer 和 consumer stages，并保证 required
   readers resident。
4. Spark 支持 group-atomic failure 和 attempt/generation lifecycle。
5. 对当前静态 producer-cap POC，transport pressure 可以先由 native
   flow control 内部消化；未来如果 Spark 要动态调节 refill，再增加标准
   readiness/pressure/failure fact 接口。
6. Deferred completion 或等价的 EndOfData contract 已经明确。
7. Producer launch/refill 由 Spark 的固定安全 cap 或 native-pressure
   signal 驱动，不再由 Gluten query-level state machine 决策。
8. 当前 batch POC 允许 group failure 直接使 query 失败；进入 Structured
   Streaming 后，再由其承担 checkpoint-aware micro-batch rerun。

通用 mixed-DAG connected-component 构造是 production-general
requirement，但不是删除当前受控 POC 中 Gluten query-level coordinator
的必要条件。

Upstream `master` 尚未全部满足这些条件，所以这仍然是 upstreamization
gap；但本地 shared MVP 分支在当前受控范围内已经满足所需闭环，并已删除
Gluten query-level scheduling policy。两者不矛盾：删除结论适用于当前
Spark-visible、静态单 workload POC，不能据此宣称 upstream 已具备通用
pipelined-region fault tolerance。

## 共享 CPU RTM 与 Gluten UCX 的 MVP

### 不再定义 GPU-Only Scheduler MVP

Spark CPU stream processing 已经有自己的 Real-Time Mode（RTM）演进路线。
第一版 RTM 是一个已经成立的 CPU MVP：

- 使用 long-running Spark tasks 持续处理记录；
- 支持 Kafka source/sink、filter、project、union 等 stateless operators；
- 支持 broadcast stream-static join；
- 使用 checkpoint interval 提供 exactly-once processing；
- 暂不支持 shuffle、streaming aggregation、stream-stream join 和其他
  stateful operators。

CPU RTM 的下一阶段是 multi-stage streaming shuffle。当前 Spark 代码中
已经存在：

- `StreamingShuffleManager`；
- `StreamingShuffleWriter` 和 `StreamingShuffleReader`；
- `StreamingShuffleOutputTracker`；
- Netty data transport；
- credit-based transport backpressure；
- termination control/ack；
- `MultiShuffleManager` 和对应 E2E tests。

CPU streaming shuffle 与 Gluten UCX 当前共同缺失的核心不是另一套数据
传输，而是同一套 Spark Scheduler 语义：

```text
group construction
admission and reader residency
producer/consumer co-scheduling
completion
group-atomic failure
attempt/generation fencing
```

因此新的 MVP 不再定义为 GPU-only scheduler，而是：

> 由 Spark 拥有一套通用 pipelined group scheduler，CPU
> `StreamingShuffleManager` 和 Gluten UCX shuffle manager 作为两个
> data-plane implementation 接入。

目标结构是：

```text
                   Spark Pipelined Scheduler
             group / admission / launch / failure
                    /                       \
                   /                         \
CPU StreamingShuffleManager          Gluten UCX ShuffleManager
Netty / UnsafeRow transport           UCX / Velox / GPU transport
credit + termination ack              credit + EOS + native cleanup
```

### 基于 Multi-Stage RTM 扩展 Residency Policy

这里需要区分当前已经可用的 stateless RTM 和正在 upstream 的
multi-stage RTM。

当前 stateless RTM 把 source、窄依赖 operators 和 sink 放在同一个
Spark stage 中。一个 input partition 对应一个 long-running task，task
持续运行到 checkpoint interval 结束。因此它只有一个 `TaskSet`，不涉及
多个 stage 的共同 admission 或 atomic publication。

Multi-stage RTM 通过 `PipelinedShuffleDependency` 连接多个同时运行的
stage。Upstream 第一版采用保守的 full-gang 模型：

```text
fullDemand(group) = sum(memberStage.numTasks)
admit only when fullDemand <= currentlyFreeSlots
```

这解释了第一版为何可以继续逐个调用普通 `submitTasks`。在严格
full-gang admission 成功后，第一个 producer 最多只能占用自身的
`numTasks` 个 slot，剩余容量按算术上仍足以运行其余 member stages。
`DAGScheduler` 又会在同一个 event-loop submission 中递归提交完整 DAG，
所以第一版没有单独引入 `submitTasksWithoutRevive` 或 group batch-submit
API。

但这个结论只对 strict full-gang 成立。不能只把 admission 中的
`sum(numTasks)` 改小，而继续沿用原来的 TaskScheduler 行为。否则先提交的
producer 可能占完可用 slots，尚未注册或尚未获得 slot 的 readers 无法
建立 endpoint，producer 又阻塞在 transport backpressure 上，最终形成
slot deadlock。

正确扩展方式不是改变 CPU RTM 的默认语义，而是在同一套 multi-stage RTM
pipelined scheduler 下支持两种 residency policy：

| Policy | Minimum residency | 首个 caller |
| --- | --- | --- |
| `FullGroupResidency` | 所有 member stages 的所有 tasks | CPU multi-stage RTM |
| `ReaderResidencyWithElasticProducers` | 所有 pipelined readers，加每个 pure producer 的最小推进 slots | bounded Spark SQL + Gluten UCX |

CPU RTM 继续默认使用 `FullGroupResidency`。当前 RTM 是 input partition
与 long-running source task 的固定一对一映射；如果只运行部分 source
tasks，其余 partitions 可能整个 checkpoint interval 都得不到处理。
除非未来 source 支持 partition multiplexing、cooperative yield 或
preemption，否则不应把 CPU RTM 默认放松为 elastic producer。

Gluten bounded batch 的 producer tasks 是有限任务：一个 task 完成后会
释放 slot，后续 partitions 可以轮转执行。因此可以使用
`ReaderResidencyWithElasticProducers`。设：

- `readerStages` 是具有 pipelined input 的 stages；intermediate stage
  同时读上游、写下游，但在集合中只计算一次；
- `pureProducerStages` 是没有 pipelined input、但具有 pipelined output
  的 source-side stages；
- `minProducerTasks(stage)` 是保证该 producer stage 能推进的最小 task
  数。

则 relaxed admission 的最低需求为：

```text
minimumDemand(group) =
    sum(readerStages.numTasks)
  + sum(minProducerTasks(pureProducerStages))
```

例如：

```text
Producer A: 60 tasks, min producer residency = 1
Producer B: 60 tasks, min producer residency = 1
Consumer:    4 tasks, all readers resident

FullGroupResidency demand                  = 124 slots
ReaderResidencyWithElasticProducers demand =   6 slots
```

#### 建议的通用 Contract

不要把 UCX-specific 配置写进 `DAGScheduler`。应由
`PipelinedShuffleManager` 或其 control-plane capability 声明静态
scheduling requirements，Spark 仍然是唯一的 admission 和 launch
authority。接口形状可以是：

```scala
sealed trait PipelinedGroupResidencyPolicy

case object FullGroupResidency
  extends PipelinedGroupResidencyPolicy

case class ReaderResidencyWithElasticProducers(
    minProducerTasksPerStage: Int,
    maxProducerTasksPerStage: Option[Int])
  extends PipelinedGroupResidencyPolicy

case class PipelinedGroupSchedulingRequirements(
    policy: PipelinedGroupResidencyPolicy,
    minRunningTasksByStage: Map[Int, Int],
    maxRunningTasksByStage: Map[Int, Int])
```

最终类型不必机械照搬以上草案，但必须满足以下 ownership：

- unknown/default pipelined manager 返回保守的 `FullGroupResidency`；
- CPU `StreamingShuffleManager` 对当前 RTM 返回
  `FullGroupResidency`；
- Gluten `UcxShuffleManager` 对 bounded batch 返回
  `ReaderResidencyWithElasticProducers`；
- manager 只声明 requirements，不自行 admission，不维护 query-level
  launch state machine；
- `DAGScheduler` 计算 group readiness 和 minimum demand；
- `TaskScheduler` 保证 requirements 对应的实际 residency。

当前本地 `PipelinedShuffleControlPlane` 中的
`requiresAllPipelinedShuffleReadersResident` 可以演进为上述 requirements
对象，避免长期保留多个 boolean capability 和 UCX-specific scheduler
分支。

#### Upstream 重构拆成两个独立接受面

这项重构不应作为一个“让 Spark 接受 Gluten UCX 调度策略”的整体改动
提交。更容易审查和 upstream 的方式，是把它拆成两个相互依赖、但可以
独立讨论的接受面：

```text
第一部分：Spark 接受 relaxed residency 作为通用 scheduler 语义
                              |
                              v
第二部分：Spark 接受一个窄的声明式 extension point 来选择该语义
```

这里有意把 scheduler capability 放在 extension point 之前。Spark 社区
首先需要确认 relaxed admission 本身的正确性；extension point 只负责
让某个 shuffle implementation 选择 Spark 已经定义和验证的 policy，
不能允许插件注入另一套 admission 算法。

##### 第一部分：接受 relaxed residency

第一部分只讨论 Spark scheduler 能否安全支持：

```text
ReaderResidencyWithElasticProducers
```

它不是 GPU 或 UCX feature。它表达的是一种通用的 producer execution
capability：

- 所有 pipelined reader/intermediate tasks 必须 resident；
- 每个 pure producer stage 只要求一个 minimum floor；
- producer task 是 bounded，完成后会释放 slot，剩余 partitions 可以
  继续轮转；
- minimum floors 满足后，surplus slots 按公平策略分配，并受到
  per-stage/per-executor cap 约束。

这部分由 Spark 完整拥有并实现：

```text
DAGScheduler:
  group construction
  -> role classification
  -> minimum demand
  -> admission

TaskScheduler:
  atomic group publication
  -> minimum-floor-first
  -> surplus round-robin/cap
```

第一部分不需要公开稳定的插件 API。测试可以通过 Spark 内部构造的
requirements 或临时 test shuffle manager 选择 relaxed policy。社区
评审的重点是：

1. relaxed demand 的计算是否正确；
2. atomic publication 是否消除了先提交 producer 导致的 slot deadlock；
3. reader 和 producer minimum floors 是否一定能满足；
4. producer 是否可以公平轮转且不会超过 cap；
5. completion、failure 和 attempt fencing 是否仍沿用同一套 group
   lifecycle。

`FullGroupResidency` 必须继续作为默认行为。没有选择 relaxed policy 的
CPU RTM、未知 manager 和现有 regular Spark job，其 admission、提交顺序
和 failure semantics 都不能变化。

##### 第二部分：接受声明式 extension point

只有在 Spark 已经拥有并验证 relaxed scheduler 语义之后，第二部分才
增加一个窄的 capability provider。建议的接口形状是：

```scala
trait PipelinedShuffleSchedulingProvider {
  def schedulingRequirements(
      group: PipelinedShuffleGroupInfo):
      PipelinedGroupSchedulingRequirements =
    PipelinedGroupSchedulingRequirements.fullGroupResidency
}
```

初期 extension point 应是 closed policy selection：manager 只能从 Spark
定义的 `FullGroupResidency` 和
`ReaderResidencyWithElasticProducers` 中选择，不能提供任意 scheduler
callback。返回值必须是 group attempt 期间不可变的静态 requirements。

允许的 extension 行为是：

```text
manager declares requirements once
Spark validates and resolves requirements
Spark performs admission/publication/scheduling
```

不允许的 extension 行为是：

```text
manager.canAdmit(freeSlots)
manager.chooseNextStage()
manager.refillProducers()
manager.pauseOrResumeSparkTasks()
```

后面这些回调会把资源状态和 launch authority 再次交给插件，本质上重新
引入 Gluten query coordinator。

建议把 scheduling provider 与现有 lifecycle listener 分开：

```text
PipelinedShuffleSchedulingProvider
  只声明静态 scheduling requirements

PipelinedShuffleLifecycleListener
  如有需要，只接收 register/complete/abort 事实
```

第二部分合入后，各实现的选择是：

| Implementation | Declared policy |
| --- | --- |
| unknown/default manager | `FullGroupResidency` |
| CPU `StreamingShuffleManager` | `FullGroupResidency` |
| Gluten `UcxShuffleManager` bounded batch | `ReaderResidencyWithElasticProducers` |

因此 upstream Spark 不包含任何 UCX class、Velox Driver 逻辑或
Gluten-specific 配置；Gluten 也不再实现 admission/refill state
machine。extension point 只连接 policy declaration，scheduler authority
仍完全属于 Spark。

这两个接受面可以对应两个 follow-up PR，也可以在一个 PR 中拆成两个
逻辑清晰的 commits。无论采用哪种提交形式，都应分别证明：

- 第一部分关闭 extension point 时，regular Spark 和
  `FullGroupResidency` 行为完全不变；
- 第二部分默认 provider 返回 `FullGroupResidency` 时，仍然没有行为
  变化；
- 只有 manager 显式选择 relaxed policy 时，才启用 minimum-demand 和
  elastic-producer scheduling；
- 本地 Gluten 集成在相同 TPC-H 22-query profile 上功能完整且无性能
  regression。

#### Relaxed Admission 必须配套 Atomic Group Publication

进入 elastic-producer policy 后，Spark 必须先让 TaskScheduler 看见完整
group，再开始第一次资源分配。推荐的终态接口是：

```scala
taskScheduler.submitPipelinedGroup(taskSets, requirements)
```

其语义是：

```text
register every TaskSetManager in the group
    -> publish group metadata and residency floors
    -> revive resource offers once
    -> satisfy every stage's minimum floor first
    -> distribute surplus slots round-robin up to per-stage caps
```

当前本地的：

```scala
submitTasksWithoutRevive(taskSet)
...
reviveOffers()
```

可以作为最小实现桥梁，但不是理想的最终 RTM API。它解决了“注册多个
TaskSet 后统一 revive”，却没有直接表达 group identity、requirements
和 all-or-nothing publication。主线程可以先保留该桥梁验证行为，再收敛
为 `submitPipelinedGroup`。

TaskScheduler 的 minimum-floor 调度至少需要满足：

1. 第一次有效 `resourceOffers` 之前，完整 group 的 TaskSetManagers 已
   注册。
2. 所有 reader/intermediate stages 先达到要求的 residency floor。
3. 每个 pure producer stage 至少获得 `minProducerTasks`，避免某个 source
   frontier 永久饥饿。
4. minimum floors 满足后，剩余 slots 在 producer stages 间
   round-robin 分配。
5. producer 不超过 per-stage/per-executor cap。
6. transport credit/backpressure 只控制在途数据和 writer readiness，
   不替代 slot admission。

Deferred completion、group-atomic failure 和 attempt fencing 不因 policy
变化而分叉。两种 policy 必须共用同一套 group lifecycle；区别只在
minimum residency 和 surplus-slot distribution。

#### 主线程实施顺序

建议不要扩大 upstream PR #57341 的第一版 scope。先把它作为
`FullGroupResidency` 基线，再按上述两个接受面推进 follow-up：

第一部分，先让 Spark 接受 relaxed scheduler capability：

1. 引入 Spark-internal `PipelinedGroupSchedulingRequirements`，默认使用
   `FullGroupResidency`。
2. 让 `DAGScheduler` 根据 internal policy 计算 full demand 或 minimum
   demand。
3. 增加 atomic group publication；短期可复用
   `submitTasksWithoutRevive`，终态使用 `submitPipelinedGroup`。
4. `TaskSchedulerImpl` 实现 minimum-floor-first 和 producer
   round-robin/cap。
5. 在没有公开 extension point 的条件下，用 Spark internal tests 证明
   relaxed policy 的 safety、liveness 和公平性。

第二部分，再让 Spark 接受 policy-selection extension point：

6. 引入窄的 `PipelinedShuffleSchedulingProvider`，默认返回
   `FullGroupResidency`。
7. 把现有 reader-residency boolean 收敛到 requirements contract，避免
   在 `TaskSet` 中继续扩散多个 capability flags。
8. CPU `StreamingShuffleManager` 保持默认或明确选择
   `FullGroupResidency`。
9. Gluten `UcxShuffleManager` 在 Gluten 仓库中选择
   `ReaderResidencyWithElasticProducers`。
10. 删除 Gluten query coordinator 中 admission/refill 决策，只保留
    transport execution、credit/backpressure 和必要的 lifecycle facts。

第一轮测试应至少覆盖：

- regular job 和 `FullGroupResidency` 的提交、slot check、offer order
  与现有行为一致；
- CPU RTM 在不能容纳全部 long-running tasks 时仍然拒绝 admission；
- `60 producer + 4 reader` 在 full policy 下需要 64 slots，在 reader
  policy 下按 `4 + minProducerTasks` admission；
- 第一次 resource offer 能看到完整 group；
- readers 达到全部 residency，pure producer 达到 minimum floor；
- producer surplus round-robin，且 cap 生效；
- consumer 提前完成仍被 deferred；
- 任意 member failure 仍然只产生一个 group terminal outcome；
- old `groupAttemptId` 的 endpoint/readiness/completion 被拒绝；
- 同一组测试分别使用 CPU Netty manager 和 Gluten UCX manager，证明
  scheduler contract 与 data plane 解耦。

### 性能达标基线

开始该 MVP 之前，当前 TPC-H 4-GPU 性能版本固定为同名本地 annotated
tag：

| 仓库 | Tag | Commit |
| --- | --- | --- |
| Spark | `poc/tpch4gpu-perf-qualified-20260727` | `718ea6cb55d` |
| Gluten | `poc/tpch4gpu-perf-qualified-20260727` | `90301a721578` |

新的 MVP 开发与该性能基线隔离：

| 仓库 | MVP branch |
| --- | --- |
| Spark | `poc/pipelined-shuffle-shared-mvp-20260727` |
| Gluten | `poc/ucx-transport-control-mvp-20260727` |

这些 tag 的作用是保留当前已验证性能版本；新的 ownership 和 lifecycle
改造不应改变或覆盖该基线。

### MVP 目标

在当前受控范围内实现：

> Spark 是 pipelined group lifecycle 的唯一 authority；CPU streaming
> shuffle 和 Gluten UCX 只提供 scheduling requirements、transport
> facts 和 lifecycle execution。

首期受控范围：

```text
all-pipelined whole-job group
AQE disabled
dynamic allocation disabled
static cluster
single active query/workload
group failure -> query failure
no DAGScheduler-internal automatic rerun
```

这不是最终 production-general scheduler，但必须形成完整的
progress/completion/failure 闭环。

### Spark 侧 MVP

Spark 负责：

1. 将 all-pipelined job 构造成一个 logical `groupId`。
2. 为每次运行生成独立的 `groupAttemptId`。当前 MVP 复用各 stage 已有的
   `stageId.stageAttemptId`，按 stage 排序后组成 attempt vector，并在
   group teardown 前由 DAGScheduler 的现有映射冻结，使同一轮 group
   始终使用同一个 ID。
3. 收集 shuffle manager 的 data-plane requirements，例如是否要求全部
   readers resident。
4. 执行 slot feasibility、group admission 和 producer/consumer
   co-scheduling。
5. 在 producer final 前延迟 consumer 的 job-visible completion。
6. 任意真实 task/stage/transport failure 都产生一个 authoritative
   group abort。
7. 将 `START/COMPLETE/ABORT/CLEANUP` 作为单向 lifecycle command 发送给
   shuffle runtime。

`groupId` 和 `groupAttemptId` 必须分开：

```text
groupId
  logical connected stage component
  例如：stages-10-20-30

groupAttemptId
  one runtime generation of that component
  例如：stages-10.0-20.0-30.1
```

这里不是在每次 stage 提交时重新计算一个变化中的 vector。DAGScheduler
第一次建立 group runtime 时计算一次，并复用已有的
`pipelinedShuffleGroupAttemptIds` 映射将其冻结到 complete/abort/cleanup。
这样无需再维护一个与 stage attempt 平行的全局 generation counter，也
减少了 Spark 内部重复 identity 状态。

TaskScheduler 的 group admission、producer cap 和 active TaskSet registry
必须使用 attempt-scoped ID，避免失败 generation 与新 generation 共享
调度状态。

### 公共接入 Contract

MVP 应尽量复用并收紧当前 `PipelinedShuffleControlPlane`，不再新增另一套
query coordinator。接口语义分为两类。

Shuffle manager 向 Spark 报告 requirements/facts：

```text
requiresAllReadersResident(group)
```

Spark 向 shuffle manager 下发 authoritative lifecycle：

```text
register(group metadata + groupAttemptId)
admit(groupAttemptId)
complete(groupAttemptId)
abort(groupAttemptId, reason)
```

约束是：

- manager 只声明必须全部 readers resident 这一静态 data-plane
  requirement；CPU streaming shuffle 和 UCX 通过同一个 marker trait
  复用该实现；
- producer launch cap 使用 Spark 自己的固定安全配置，不再让 manager
  动态返回 query/group producer cap；
- native/transport 的实时 pressure 继续由数据面内部 flow control 消化；
  如果未来需要反馈给 Spark，应另行定义事实型 signal，而不是恢复第二套
  query admission；
- 是否 launch、何时 abort、何时把 completion 对 job 生效由 Spark
  决定；
- manager 不得用另一套 query state 覆盖 Spark 的 terminal outcome；
- lifecycle callback 是 command/notification，不是第二次 admission vote。

### CPU Streaming Shuffle 接入

CPU `StreamingShuffleManager` 继续保留：

- Netty reader/writer transport；
- sequence validation；
- credit flow control；
- writer 等待所有 readers 的 termination ack；
- per-task buffer 和 channel cleanup。

由于 writer 在正常路径上必须等待所有 reader termination ack，CPU
streaming shuffle 也需要向公共 Scheduler 声明 reader-residency
requirement。这证明 reader residency 不是 UCX/GPU 特例。

CPU manager 不需要 query-level coordinator。它只需：

1. 实现公共 capability/lifecycle contract；
2. 使用 `groupAttemptId` 隔离旧 task/transport 状态；
3. 把 transport failure 上报给 Spark；
4. 根据 Spark abort command 解除 termination wait 并清理资源。

### Gluten UCX 接入

Gluten 的 Spark-visible 算子接入保持不变：

```text
SparkPlan
    |
    v
Gluten ColumnarRule
    |
    v
Velox scan / join / aggregate pipeline
    |
    v
PipelinedShuffleDependency
    |
    v
UCX ShuffleManager writer / reader
```

Scan、join、aggregate 不需要逐个增加 Scheduler API。跨 task 的
Exchange、TaskContext 和 group lifecycle 才是接入点。

MVP 阶段 Gluten 可以暂时保留 `UcxShuffleCoordinator` 类名，但必须把它
收缩为 transport-only mode。当前本地实现已经直接删除旧 query scheduling
branches，没有再保留 coordinator on/off 双路径。

继续保留：

- endpoint registration/discovery；
- reader-ready handshake；
- per-shuffle writer credit 和 native per-channel credit；
- `noMoreData`、`noMoreSplits` 和 EOS；
- writer/reader native state telemetry；
- attempt/generation fencing；
- abort 后 UCX/native cleanup。

停止拥有：

- query/group admission decision；
- query-level producer frontier/refill policy；
- independently 决定 query success/failure；
- independently 决定 Spark task 是否可以 launch；
- 与 Spark 并列的 authoritative terminal state。

同时删除了已经不再参与控制决策的 query-shaped telemetry：

- query runtime summary；
- query-wide active/queued/blocked writer 聚合；
- query backpressured launch decision；
- 重复于 `groupAttemptId` 的 `queryId`；
- SQLExecution 的 query complete/abort callback。

保留 `UcxShuffleCoordinator` 类名只是一项后续机械重命名工作，不表示它
仍然是 query coordinator。

### MVP 暂不实现

以下内容不是首期 blocker：

- mixed regular/pipelined DAG；
- 一个 job 内多个通用 connected regions；
- AQE；
- dynamic allocation；
- admission wait queue；
- strict/durable slot reservation；
- multi-workload fairness；
- stateful RTM；
- scheduler-internal automatic group rerun。

这些是后续 generalization，不能阻塞当前 ownership 收敛。

### 实施切片

建议按三个独立、可验证的切片推进。

#### Slice 1：公共 contract 和 generation

- 在 group metadata 中显式区分 `groupId` 和 `groupAttemptId`；
- TaskSet/TaskScheduler 使用 attempt-scoped key；
- CPU RTM manager 默认声明 `FullGroupResidency`；
- Gluten UCX manager 声明
  `ReaderResidencyWithElasticProducers`；
- lifecycle callback 明确为 Spark 下发的 command/notification；
- 增加旧 attempt 不能共享 active-group state 的测试。

#### Slice 2：Spark authoritative lifecycle

- 补齐并收紧 group-atomic abort；
- 验证 deferred completion 的 replay/drop；
- transport failure 映射为 group failure；
- producer/consumer/executor-loss fault injection；
- 保证一个 group generation 只有一个 terminal outcome。

#### Slice 3：Gluten transport-only mode

- 删除 query-level scheduling policy，而不是长期保留双路径开关；
- 固定 producer cap 由 Spark 配置拥有；
- 保留 transport backpressure 和 native state telemetry；
- A/B 对比性能 tag 与 transport-only candidate；
- 稳定后可将剩余组件机械重命名为 `UcxShuffleControlPlane` 或
  `UcxTransportCoordinator`。

### 当前推进状态

截至 2026-07-27，本地 MVP 已完成 shared contract、Spark ownership
收紧和 Gluten transport-only 删除，不再只是 Slice 1 的 identity
准备工作。

#### 最终代码边界

Spark 侧：

- `PipelinedShuffleGroupMetadata` 只保留 `groupId`、
  `groupAttemptId` 和 `stages`，不再携带 `jobId` 或
  `queryExecutionId`。
- `PipelinedShuffleControlPlane` 的 group lifecycle 方法使用默认 no-op，
  不再要求每个 manager 重复实现空方法。
- 新的 `RequiresAllPipelinedShuffleReadersResident` marker trait 统一服务
  CPU `StreamingShuffleManager`、`MultiShuffleManager` 和 Gluten UCX，
  删除三份相同的 capability override。
- DAGScheduler 继续拥有 group 构造、slot feasibility、admission、
  co-scheduling、deferred completion 和 authoritative complete/abort。
- `groupAttemptId` 复用 stage attempt vector，并由已有 group-attempt
  映射冻结；删除了额外的全局 generation counter。
- TaskScheduler 只使用 Spark 自己的固定 producer-stage cap；删除
  shuffle manager 动态返回 query/group producer cap 的路径。
- Router 只转发 group register/admit/complete/abort，不再转发 query
  complete/abort。
- `SQLExecution` 不再在 query terminal 时调用 shuffle manager。Group
  terminal callback 足以给出 authoritative scheduler outcome；实际
  transport runtime 清理由 Gluten 在 native drain barrier 后完成。

Gluten 侧：

- `UcxColumnarShuffleManager` 只声明 reader-residency requirement，并
  执行 Spark 下发的 group lifecycle。
- 删除 query-wide admission、fair-share、producer frontier、
  backpressured launch、query credit 和 query terminal RPC。
- transport runtime 以 `groupAttemptId` 为 key；不同 group attempt
  拥有独立状态，旧 stage/task attempt 继续由 fencing 拒绝。
- 保留 endpoint 注册/发现、reader-ready、native writer/reader state、
  per-shuffle writer credit、abort/unregister cleanup 和 UCX/native
  transport backpressure。
- Spark complete 后先进入 transport-local `Draining`；只有每个当前
  writer attempt 都满足 `noMoreData && finished` 才进入 `Finished`。
  提前到达的 shuffle unregister 会被延迟到 drain 完成。
- 删除不再参与控制决策的 query summary、query queued/blocked 聚合、
  重复 `queryId` 和 group-wide credit 字段。
- 删除 521 行的 `UcxPipelinedQueryCoordinatorSuite`，由 324 行、
  8 个用例的 `UcxPipelinedTransportCoordinatorSuite` 替代。

换句话说，当前 contract 已经收敛为：

```text
Spark -> Gluten
  register / admit / complete / abort(groupAttemptId)

Gluten -> Spark 的静态 requirement
  requiresAllPipelinedShuffleReadersResident

Gluten 内部
  endpoint / reader-ready / per-shuffle credit /
  native state / attempt fencing / cleanup
```

不存在 query complete/abort callback，也不存在由 Gluten 再投一次
admission vote 的路径。

#### 代码删减量

以下统计相对于两个性能基线 commit 的工作树 diff；测试统计包含新的
untracked transport suite：

| 仓库/范围 | 新增 | 删除 | 净变化 |
| --- | ---: | ---: | ---: |
| Spark 主代码 | 104 | 175 | -71 |
| Spark 测试 | 42 | 127 | -85 |
| Spark 合计 | 146 | 302 | -156 |
| Gluten 主代码 | 316 | 992 | -676 |
| Gluten 测试 | 324 | 521 | -197 |
| Gluten 合计 | 640 | 1513 | -873 |
| 两仓主代码合计 | 420 | 1167 | -747 |
| 两仓全部合计 | 786 | 1815 | **-1029** |

这说明 ownership 收敛不是把相同 coordinator 从 Gluten 搬到 Spark：
Spark 侧也通过复用已有 identity、默认 lifecycle 实现和公共 capability
trait 净删除了代码。

#### 编译和单元测试

- Spark core 主代码和最终 core/sql distribution 构建成功；同步后的
  `dist-mvp` core jar 与构建产物 SHA-256 完全一致。
- Spark 定向 Scala suites：352/352 通过，共 8 suites。
- 同一轮 Maven 自动执行的 Java tests：371/371 通过。
- 最终 Spark 二进制接口核对确认 metadata 为三字段，control plane
  不含 query terminal API。
- Gluten 的 3 个受影响主文件使用最终 Spark core jar 编译成功。
- `UcxPipelinedTransportCoordinatorSuite`：8/8 通过，覆盖 Spark-owned
  admission、group 隔离、attempt identity、group completion、
  native drain/unregister、shuffle generation reuse、per-shuffle credit
  和 abort fencing。其中明确验证 `finished=true` 但
  `noMoreData=false` 时 group 必须继续停留在 `Draining`。
- 新 artifact 中已确认不存在
  `CompleteUcxPipelinedQuery`、`AbortUcxPipelinedQuery`、
  `UcxPipelinedQueryState` 和 `QueryWriterCreditDecision` class。

最终候选 artifact：

```text
/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/
  tpch-4gpu-gpu03/artifacts/
  pipelined-transport-drain-v3-20260727
```

#### Transport-Only TPC-H 22Q 性能验证

最终版本在 4 张 B200 GPU（物理 GPU 4--7）、TPC-H SF1000、
Spark-visible pipelined shuffle 路径上完成三对交错 A/B。Baseline 使用
性能 tag 对应的旧 Spark distribution 和 Gluten artifact；candidate 使用
最终 `dist-mvp` 和 transport-only artifact。两侧冻结相同的 22Q SQL
bundle、per-query overrides 和 native `libgluten.so`。每个样本包含一次
独立 warmup 和一次计时。

三对原始总和：

| Pair | Baseline | Candidate | 变化 |
| --- | ---: | ---: | ---: |
| 1 | 38.891 s | 39.325 s | +1.12% |
| 2 | 39.865 s | 40.636 s | +1.93% |
| 3 | 40.233 s | 39.572 s | -1.64% |

按每个 query 的三样本中位数求和：

| 项目 | Baseline | Transport-only candidate | 变化 |
| --- | ---: | ---: | ---: |
| 22Q median 之和 | 39.335 s | 39.584 s | **+0.63%** |
| 22Q 成功率 | 22/22 × 3 | 22/22 × 3 | 相同 |
| 结果行数门禁 | 全部通过 | 全部通过 | 相同 |
| cuDF fallback | 0 | 0 | 相同 |
| Fetch/File error | 0 | 0 | 相同 |
| MPP launch/JNI fragment | 0 | 0 | 保持 Spark-visible 路径 |

最明显的慢向变化是 Q21 `+5.88%`，其次是 Q20 `+4.96%` 和 Q14
`+4.46%`；没有 query 出现双位数回退。Q11 为 `-6.44%`，说明样本仍有
正常的正负波动。总和 `+0.63%` 明显低于此前采用的 `+5%` 总回退门禁。

第一个未携带 per-query overrides 的诊断 run 虽然 22/22 计算成功，但
无法通过 result-row observation gate，已明确排除在正式统计之外。

因此当前性能结论是：

> 删除 Gluten query-level coordinator，并同步删除 Spark 中不再需要的
> query callback、动态 manager cap 和重复 capability 代码后，TPC-H
> 22Q 未观察到有意义的整体性能回退。

完整逐 query 报告位于：

```text
/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/
  tpch-4gpu-gpu03/runs/
  pipelined-transport-only-mvp-ab-comparison-20260727.md
```

#### 27 秒基线、回退调查和 native drain 修复

后续恢复 fast profile 后，第一组单样本出现：

| 版本 | 22Q 总和 |
| --- | ---: |
| 历史 old baseline | 27.322 s |
| 未修复 transport-only candidate | 32.743 s |
| 相对变化 | **+19.84%** |

所以这里不能表述成“相对之前 27 秒只慢一点点”。单看这两个数，确实是
明显回退。逐 query 和 stage 日志显示，未修复 candidate 的 Q10、Q12、
Q14 和 Q20 出现长尾；其中 Q10/Q14 的关键问题是 Spark task 返回后，
driver 立即 reset group transport runtime，而 detached UCX writer 的
输出队列仍在 drain。随后到达的 native writer state 被 `FINISHED` fence
拒绝。

修复不恢复 query-level coordinator，而是补齐 transport-local deferred
cleanup：

```text
Spark authoritative complete
          |
          v
transport group = Draining
          |
          v
所有当前 writer attempt:
noMoreData && finished
          |
          v
transport group = Finished
          |
          v
reset endpoint/native state
```

此外，writer 本地记录最终 drain state 是否已经成功送达；如果 task
线程已经完成终态上报，后台 poller 幂等退出，不再产生重复的晚到终态。

后续调查发现，下面四个所谓“同窗口”样本实际上没有使用 qualified
profile：

| Run | per-query overrides | result action | 22Q 总和 |
| --- | --- | --- | ---: |
| `regression-current-window-b3-20260727` | 空 | `python_collect` | 33.860 s |
| `regression-current-window-c2-v2-20260727` | 空 | `python_collect` | 31.747 s |
| `regression-current-window-c3-v3-20260727` | 空 | `python_collect` | 32.579 s |
| `regression-current-window-b4-20260727` | 空 | `python_collect` | 31.890 s |

因此此前从这组 `B-C-C-B` 得出的 `-2.17%` 不能用于性能验收。它只能证明
错误 profile 下 baseline 和 candidate 都可以完成计算；它既没有执行
历史 27.322 秒基线中的 22 条 query overrides，也没有经过
`jvm_collect` result-row gate。

根因是 qualified 参数只存在于一次性 shell 环境，没有固化在
`fully-streaming-4gpu-v1.sh`。新 shell 启动 benchmark 时变量为空，
`run_tpch.sh` 静默退回通用 AB root 和 `python_collect`。现已把以下内容
写回 profile 并加入 manifest：

- 完整的 query1--query22 overrides；
- `GLUTEN_TPCH_RESULT_ACTION=jvm_collect`；
- `TPCH_PROFILE_KEYS` 中记录上述两项，使后续 manifest diff 能直接发现
  漂移。

恢复 qualified profile 后，先做了一次单计时配对：

| 版本 | Artifact | 22Q 总和 |
| --- | --- | ---: |
| old baseline | `pipelined-perf-qualified-baseline-20260727` | 29.497 s |
| drain v3 candidate | `pipelined-transport-drain-v3-20260727` | 29.721 s |
| 变化 |  | `+0.76%` |

由于单样本的逐 query 长尾明显，又对 baseline 和 candidate 分别执行
`1 warmup + 3 timed iterations`。稳定 A/B 结果如下：

| 指标 | Old baseline | Drain v3 candidate | 变化 |
| --- | ---: | ---: | ---: |
| 三个同序号 22Q 样本之和 | 27.327 / 27.914 / 30.631 s | 28.581 / 27.966 / 27.396 s | - |
| 同序号样本最好值 | 27.327 s | 27.396 s | `+0.25%` |
| 同序号样本中位数 | 27.914 s | 27.966 s | `+0.19%` |
| 逐 query hot-min 之和 | 25.700 s | 26.325 s | `+2.43%` |
| 逐 query 中位数之和 | 27.571 s | 27.391 s | `-0.65%` |

“逐 query hot-min 之和”由不同计时槽位的单 query 最小值组成，不能冒充一轮
完整 22Q 样本。Runner 的执行顺序是“每条 query 连续执行三次计时，再进入
下一条 query”；这里的“同序号样本”是把所有 query 的第 1、2、3 个计时
分别求和，并不是三个物理上连续的端到端 power run。它仍与历史 27.322 秒
采用相同的 22Q query-time 求和口径：old baseline 最好值 27.327 秒只差
5 ms，candidate 最好值 27.396 秒只差 74 ms。两者同序号样本中位数只差
52 ms；因此历史性能水平已经复现，没有证据表明新
Spark-visible/transport-only 代码存在稳定回退。

最终 v3 的门禁结果：

- baseline 和 candidate 都是 22/22 query 成功；
- result-row 和 strict cuDF gate 全部通过；
- 两侧 writer/reader endpoint 计数一致；
- `FetchFailedException=0`、Gluten fallback=0；
- native writer state rejection=0；
- 重复终态 `accepted=false ... groupState=FINISHED`=0。

“SparkContext stop 前是否等待所有 transport cleanup acknowledgement”
仍应保留为 production teardown 集成验证项；不能用 `rejection=0` 代替
这一证明。

正式对应 run：

```text
/raid/ferdinandx/gtc/poc/spark5-pipelined-tpch4gpu-20260717/
  tpch-4gpu-gpu03/runs/
  regression-qualified-profile-b5-20260727
  regression-qualified-profile-c4-v3-20260727
  regression-qualified-profile-b6-3iter-20260727
  regression-qualified-profile-c5-v3-3iter-20260727
```

#### 仍未完成的 production-general 工作

当前结果完成了受控范围内的 ownership 和 transport-only 验证，但还不
等于完整 production fault-tolerance MVP：

- producer/consumer/`FetchFailed`/executor-loss 的 Spark E2E fault
  injection 仍需执行；
- transport failure 映射到 Spark authoritative group abort 的每条路径
  仍需做集成验证；
- SparkContext/application teardown 前等待或强制回收仍在 `Draining`
  的 transport group，需要单独做 E2E 验证；
- mixed DAG、AQE、dynamic allocation、admission wait queue、strict
  reservation 和 multi-workload fairness 仍不在本切片；
- scheduler-internal automatic rerun 仍不实现，由 Spark SQL 或
  Structured Streaming execution 决定完整 query/micro-batch 重提；
- `UcxShuffleCoordinator` 到 `UcxTransportCoordinator` 的类名调整只是
  后续机械重命名，不影响已经完成的 authority 删除；
- 本轮 performance gate 通过后，branch 应把 scheduler/provider、测试和本文
  作为同一个可审查变更集提交并 push；失败的 residency/cap 诊断变体不进入
  commit。

### 双重 Gate：社区接受与内部性能必须同时满足

后续推进不能只优化一个目标。每一波生产代码改动都必须同时通过两个互相独立的
gate；任何一个失败，都不进入下一波。

#### 外部 Gate：社区能够独立验证 proposal

对外论证只依赖 Apache Spark 仓库内可复现的 CPU 证据，不引用 Gluten、
UCX、GPU 或内部 TPC-H 环境。最低要求是：

1. 用确定性 DAG 复现 full-group residency 的容量限制；
2. 证明 relaxed residency 不是单独修改 admission 公式，而是与 atomic
   publication、reader/producer floor 和公平 refill 一起工作；
3. 使用 bounded CPU data plane 验证真实 backpressure、EOS、失败和
   attempt fencing；
4. 默认 manager 不实现 extension 时行为完全不变。

当前第一段 scheduler 证据已经落地：

```text
Producer A: 60 tasks
Producer B: 60 tasks
Reader:      4 tasks
Cluster:     6 slots

Full-group demand: 60 + 60 + 4 = 124 slots
Relaxed demand:     4 readers + 1 + 1 producer floors = 6 slots
```

新增的两个 `DAGSchedulerSuite` 用例均通过。当前原分支已机械收敛到
declarative-provider review tree；Maven 同口径验证结果为：

- `DAGSchedulerSuite`：196/196；
- `TaskSchedulerImplSuite`：131/131；
- router 与 streaming shuffle suites：27/27；
- Scala 合计：354/354，共 8 个 discovered suites；
- core Java tests：371/371。

本轮进一步加入了不依赖 Gluten、UCX 或 GPU 的 Spark SQL CPU E2E：

- 使用真实的 `PipelinedShuffleDependency` 和
  `StreamingShuffleManager`，构造一个 producer、一个 reader、100 万行
  输入的两阶段流水 DAG；
- reader 已经 resident，但先停在测试闸门上，不消费网络数据；
- reader memory quota 设置为 1 byte，network buffer 设置为 64 KiB，
  writer memory quota 设置为 128 KiB；
- reader 的 byte watermark 触发 Netty `autoRead=false`，TCP
  backpressure 继续传导到 writer 的 bounded buffer semaphore；
- 测试不靠超时猜测 backpressure，而是同时验证 producer 只生成了部分
  输入、job 尚未结束，并且 producer 线程确实停在
  `StreamingShuffleWriter.newBuffer`；
- 打开 reader 闸门后，producer 完成全部 100 万行，reader 得到正确的
  100 万行结果，整个 Spark job 正常结束，从而覆盖 EOS 和 writer
  termination acknowledgement。

因此这里不再使用“queue-depth=1”描述 CPU 实现；当前实现的有界单位是
byte quota，反压链路是 Netty auto-read、TCP 和 writer buffer semaphore。
相关验证结果为：

- `PipelinedBatchShuffleSuite`：2/2；
- `SQLExecutionSuite`：11/11；
- 本轮直接受影响 suites 合计：13/13。

同时删除了 `SQLExecution` 中仍然引用已移除 query-level control-plane
接口的 terminal callback，共减少 25 行 production code。query completion
继续由 Spark SQL 正常结束，而 pipelined group 的完成与失败由
`DAGScheduler` 的 authoritative group lifecycle 管理。

现在 CPU bounded backpressure、delayed reader、byte watermark、EOS 和
termination acknowledgement 已有端到端证据。尚未补齐的外部硬门槛是
injected attempt failure 与 attempt fencing E2E；scheduler 级 failure
语义已有测试，但还需要用真实 CPU data plane 覆盖 late/stale attempt。

#### 内部 Gate：Gluten-MPP 或 Flux 保持已达标性能

对内必须证明同一套 Spark extension 和调度语义能够被 Gluten-MPP 或
Flux 使用，并保持性能 tag 对应的能力与性能。固定验收环境为 4 张 B200
GPU、TPC-H SF1000、22 条 query、`fully-streaming-4gpu-v1.sh`
qualified profile，以及相同 SQL bundle、per-query overrides、
`jvm_collect` result-row gate 和 native runtime。

性能比较不能只看一个 aggregate。每一波生产代码改动至少检查：

1. baseline 和 candidate 都是 22/22 成功；
2. result-row、strict cuDF、零 fallback、零 Fetch/File error 全部通过；
3. 逐 query 三样本中位数，标出慢向异常和双位数回退；
4. 逐 query 中位数之和与同序号 22Q 样本中位数；
5. endpoint、attempt fence、native drain 和 terminal-state rejection
   没有异常。

固定参考线是已经复现的 qualified-profile 结果：

| 指标 | Old baseline | Drain v3 candidate | 变化 |
| --- | ---: | ---: | ---: |
| 同序号样本最好值 | 27.327 s | 27.396 s | +0.25% |
| 同序号样本中位数 | 27.914 s | 27.966 s | +0.19% |
| 逐 query 中位数之和 | 27.571 s | 27.391 s | -0.65% |

本轮已经修改 Spark production code：旧 query-level control-plane 路径
被收敛为声明式 scheduling provider。当前 10 个受影响 production source
与 `7d93c154c51` review tree 逐文件一致；本地新编译 jar 中
`DAGScheduler`、`TaskSchedulerImpl`、provider 和 router 的 class 字节，
也与冻结的 `pipelined-spark-provider-v3-20260727` candidate artifact
完全一致。此后又删除了 `SQLExecution` 中遗留的两个 query terminal
callback；它们引用的 control-plane API 已经不存在，既无法参与 runtime
调度，也会导致当前 SQL module 重新编译失败。这个删除不改变 scheduler
hot path 或 shuffle data path。

第一次正式 22Q gate 的确在提交 query 前被环境 preflight 拒绝：固定
lane 的 GPU 4 和 GPU 5 当时被外部 `presto_server` 分别占用约 140 GiB
和 112 GiB。没有终止或复用这些外部进程。资源恢复后，先在 GPU
1/2/3/6 上做诊断，再回到与历史完全相同的物理 GPU 4--7 做正式验证。

这次验证也暴露了一个重要的 benchmark 纪律：不能把跨 GPU、跨资源窗口的
绝对值直接归因给代码。同一个 old artifact 在 GPU 1/2/3/6 上得到
`36.567 s`，而回到稳定的 GPU 4--7 窗口后得到 `27.561 s` 和
`26.709 s`；同一个 provider candidate 也曾在冷窗口得到 `34.021 s`，
随后在相邻稳定窗口得到 `27.046 s`。因此 `37.353 s`、`43.758 s` 等
早期跨窗口结果只能用于发现环境或 policy 问题，不能作为最终 code
regression 结论。

最终采用 O--N--O sandwich：

| 顺序 | Artifact | Run root | hot-min 总和 | 逐 query 中位数总和 |
| --- | --- | --- | ---: | ---: |
| O1 | old transport/drain baseline | `ab-old-fast-gpu4567-c11-20260728` | 26.307 s | 27.561 s |
| N | declarative provider candidate | `ab-new-provider-gpu4567-c12-20260728` | 25.695 s | 27.046 s |
| O2 | old transport/drain baseline | `ab-old-fast-gpu4567-c13-20260728` | 25.303 s | 26.709 s |

三次均为 GPU 4--7、warmup=1、timed=3、TPC-H SF1000，并且：

- 22/22 query 成功；
- result rows 全部一致；
- strict cuDF gate 完整；
- cuDF fallback、Fetch/File error、MPP launch 和 MPP JNI fragment 均为 0；
- UCX writer/reader endpoint evidence 分别为 3004/3248。

把 O1 和 O2 的每条 query 共 6 个计时样本合并后，old 的逐-query
中位数总和为 `27.275 s`；candidate 为 `27.046 s`，变化
`-0.84%`。Candidate 相对此前 qualified reference `27.391 s` 为
`-1.26%`。逐 query 检查中最大的两个慢向点是：

- Q9：`+157.5 ms`，`+9.4%`；
- Q11：`+76.5 ms`，`+10.0%`。

Q11 的百分比被不足 100 ms 的绝对差放大；两者没有形成 aggregate
回退，且 candidate 的 hot-min 和中位数总和均落在 old sandwich 的正常
范围内。Q8 在单次 O1 对比中曾显示 `+262 ms`，合并两个 old
窗口后收敛为 `+50 ms`（`+2.8%`），也说明必须同时看绝对值、重复窗口和
aggregate，不能按单个短 query 的一次百分比判定。

因此本轮状态更新为：

```text
Spark functional gate: PASS（原门禁 Scala 354/354、Java 371/371；
                              新增/直接受影响 SQL suites 13/13）
Internal performance gate: PASS（22/22；27.046 s；vs pooled old -0.84%）
```

补入 CPU backpressure/EOS E2E 并删除遗留 SQL callback 后，又执行了一次
独立的 22Q follow-up gate。当前 SBT 重新编译得到的 8 个
`SQLExecution*` class 与上一轮通过门禁的 provider artifact 逐个
SHA-256 相同；也就是说，这次删除修复了 source tree 的可编译性，但没有
改变已经验证过的 runtime 字节码。尽管如此，仍然冻结新 artifact 并完成
一次正式运行：

| Artifact | Run root | hot-min 总和 | 逐 query 中位数总和 |
| --- | --- | ---: | ---: |
| CPU E2E follow-up | `spark-cpu-e2e-gpu4567-c14-20260728` | 25.312 s | 27.174 s |

该次运行仍使用 GPU 4--7、warmup=1、timed=3、TPC-H SF1000。结果为：

- 22/22 query 成功，result rows、strict cuDF gate 全部通过；
- cuDF fallback、Fetch/File error、MPP launch 和 MPP JNI fragment
  均为 0；
- UCX writer/reader endpoint evidence 仍为 3004/3248；
- 相对 pooled old `27.275 s` 为 `-0.37%`；
- 相对上一 candidate `27.046 s` 为 `+0.47%`；
- 最大的两个 pooled-old 慢向点是 Q18 `+82 ms`（`+5.9%`）和
  Q10 `+80 ms`（`+4.7%`），没有双位数逐 query 回退。

因此 CPU 测试波次同样通过内部性能门禁，且没有改变此前的性能结论。

当前 declarative extension/provider 波次可以进入提交和下一波；失败的
`FullGroupResidency` 与显式 executor-cap 诊断不保留为生产改动。

### MVP 验收标准

MVP 完成至少需要满足：

1. 同一套 Spark scheduler contract 能同时服务 CPU
   `StreamingShuffleManager` 和 Gluten UCX manager。
2. 22 个 TPC-H queries 在关闭 Gluten query-level scheduling policy 后
   结果正确，且性能没有不可解释的回退。
3. Consumer 提前返回不会导致 job 提前完成或取消 active producer。
4. Producer/consumer failure、`FetchFailed` 和 executor loss 都会 abort
   当前完整 group generation。
5. Producer failure 后 deferred consumer success 不会被采用。
6. 旧 `groupAttemptId` 的 endpoint、credit、native state 和 completion
   message 被拒绝。
7. Abort 后 CPU Netty/UCX endpoint、queue、credit、channel 和 native
   buffer 都完成清理。
8. Spark 和 Gluten 不再同时维护 authoritative query/group state。

MVP 的完成定义不是立即删除 `UcxShuffleCoordinator` 这个类，而是：

> 先删除它的 query-level 调度决策权，让 Spark 完整拥有 group lifecycle；
> 再把剩余代码机械收缩为 transport control plane。

## 推荐的 Upstream 演进顺序

1. 合入第一版 group scheduling、admission、co-scheduling 和 deferred
   completion。
2. 增加 group-atomic abort；完成之前，不应把 pipelined shuffle 视为
   已具备一般性的 fault tolerance。
3. 在第一阶段完成后，再从 whole-job group 推进到沿 pipelined edges
   构造 connected components，以支持 mixed DAG；这不是当前 POC 的
   blocker。
4. 明确资源不足时是 fail fast，还是进入 admission queue 并在资源变化
   后 reconsider。
5. 如果竞争 workload 下也需要严格 co-residency，引入 scheduler-level
   reservation 或 lease，而不只是瞬时 free-slot check。
6. 保持 checkpoint-aware query/micro-batch rerun 在 execution layer，
   同时由 `DAGScheduler` 提供清晰的 group failure contract。

## 最终职责边界

可以用一句话概括：

> Spark Scheduler 负责一次 pipelined group 的安全性、共同调度和失败
> 原子性；Spark SQL/Structured Streaming execution 负责 query 或
> micro-batch 的生命周期、checkpoint 和重提；Gluten 只负责 UCX/native
> transport control plane。

截至 2026-07-28：

- upstream `master` 只有 pipelined shuffle 基础设施，尚未合入五项 group
  调度能力；
- PR #57341 已实现前四项的第一版，但 group 构造仍受限，也没有 durable
  slot reservation；
- upstream PR 尚缺 group-atomic failure；
- POC fork 已有更完整的 mixed-DAG group 和 group-wide failure
  propagation；
- 五项能力是一张 ownership/capability checklist；当前 POC 的最小闭环是
  progress、completion 和 failure 三个语义不变量，不要求一次实现所有
  production-general 机制；
- automatic rerun 应继续保留在 Spark SQL 或 Structured Streaming
  execution 层；
- Spark SQL CPU 路径已有真实 bounded backpressure、delayed reader、
  EOS 和 termination acknowledgement E2E；真实 data-plane 的
  attempt failure/fencing 注入测试仍待补齐；
- Spark-visible 路径最终不需要 Gluten 再实现一套 query-level
  coordinator，但必须保留 UCX/native transport control plane；
- 本地 shared MVP 已在当前受控范围内完成这项删除：两仓主代码净减
  747 行；原始三对 A/B 的逐 query 中位数总和为 `+0.63%`，native
  drain 修复并恢复 qualified profile 后，同序号 22Q 样本中位数为
  `+0.19%`，逐 query 中位数之和为 `-0.65%`。功能、结果行数、严格
  cuDF、native state rejection 和 Spark-visible 路径门禁全部通过。
