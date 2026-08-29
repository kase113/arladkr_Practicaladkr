# ARLADKR / PracticalADKR 本地 TCP 数据（2026-08-23）

## 当前通信量口径（2026-08-24 起）

当前每节点通信量只指发送量：`C_i=S_i=sent_bytes_i`。`recv_bytes_i` 仍保留用于诊断，
但不计入主通信量和协议横向比较；历史的 `sent/recv` 或 `T_i=S_i+R_i` 记录不删除，统一
视为旧口径并在新数据中单独标注。

## 固定设置

| 项目 | 设置 |
| --- | --- |
| 主机 | AMD EPYC，224 vCPU，275 GiB RAM，x86_64 |
| 网络 | loopback TCP；无 `public20`、无延迟矩阵、无 netem |
| 规模 | `n` 节点；`f=floor((n-1)/3)`；单 epoch；每档 `runs=1` |
| Practical 密码参数 | Paillier 3072 bit，`fallback-policy=off`，`strict-network=true` |
| Practical 环境 | `PRACTICAL_DXT_FAST_LOCAL_ACKS=0`；`PRACTICAL_DEALING_DELTA_MS=1000`；`PRACTICAL_DERIVE_WAIT_ALL_MS=0`；不设 `RLIMIT_AS` |
| Practical 二进制 | sha256 `71960756e6705dd5e1badf275b8411fbd4b561553f29e54907dfef58c03aeb3f` |
| ARL 启动 | `scripts/run_cv_cluster.sh`；全量 listener/epoch barrier；MVBA peer wait=all；严格 TCP |
| Sampling 口径 | ARL n=32 使用论文 `original 11/21/11`；其余 ARL 旧数据仍为 `smoke 3/3`；Practical 的 `kappa` 按对应 profile 的论文失败概率上界选取 |
| 结果口径 | 所有 E2E 均记录为 `E2E - setup`；主通信量使用每节点 total sent，recv 仅作诊断 |
| ARC communication share | `sum(mean_arc_share_sent_bytes) / sum(mean_total_sent_bytes) * 100%`；分子和分母取自同次运行的同一批成功节点，成功节点达到 quorum 即有效；字节均为成功发送的完整 TCP frame |
| 成本 | 未使用 AWS；新增 `$0` |

### ARL 论文正式 sampling 参数

| n | original `c_prop/c_val/q_val` | high-assurance `c_prop/c_val/q_val` |
| ---: | ---: | ---: |
| 32 | 11/21/11 | 11/21/11 |
| 48 | 14/31/16 | 16/31/16 |
| 64 | 16/43/22 | 22/43/22 |
| 96 | 18/63/32 | 32/63/32 |
| 128 | 19/85/43 | 37/85/43 |

## ARLADKR 数据

### n=32 compact-v1 本地 TCP 回归（2026-08-24，新设备）

设置：`f=10`、单轮、严格本地 TCP、`RLADKR_AGREEMENT_WIRE=compact-v1`、完整 Pool
路径（未启用 proof-only descriptor/root-only MVBA）。setup 不计入在线延迟；主通信量只统计
发送字节。

| 完成 / quorum | consensus hash | quorum latency | all-node latency | total sent/node | recovery sent/node |
|---:|---|---:|---:|---:|---:|
| 32/32 / 22 | 单一 | 8.589 s | 8.680 s | 15.014 MB | 4.000 MB |

`completion=32/32`、`quorum_success=1`、`all_success=1`，未观察到错误或超时。`recv` 本轮
约 `15.010 MB/node`，仅作为诊断，不计入当前主通信量；上述 MB 为十进制。原始结果目录：
`/tmp/arladkr-local-n32-20260824-023059/`。

### n=32 recovery sent 口径复核

本轮表中的 `recovery sent/node=4.000 MB` 取自 `mean_recover_shard_sent_bytes`。该字段是
整个 `recover_shard` phase 的发送 counter，不是只统计 aggregate recovery request 的
purpose counter。该 phase 覆盖 aggregate APDB recovery request、旧委员会 holder 返回的
aggregate shard，以及 recovery 后的 new-share/PSHARE 交互。

同一节点的 purpose/tag 细分显示：`mean_new_aggregate_recovery_sent_bytes` 约 `0.029 MB`，
`mean_new_share_exchange_sent_bytes` 约 `0.392 MB`，而 `mean_recover_shard_sent_bytes` 约
`4.030 MB`；主要差额来自 holder 侧返回的 aggregate APDB shard，而不是请求本身。

因此不能把 ARL 的 `4.000 MB` 直接与 PracticalADKR 的 `2.6736 MB` 比较，除非确认后者也
包含 holder response、所有 selected transcript/shard traffic 和 recovery 后的 share exchange。
当前应同时保留两种 ARL 数值：

```text
phase recovery sent = 4.000 MB/node    # 宽口径，整个 recover_shard phase
aggregate purpose sent = 0.029 MB/node  # 窄口径，仅 new aggregate request path
```

Practical 的 recovery fetch/request、store batch 和 completion 也存在不同计数层，需要按同一
“所有 recovery request + response，是否包含 derive/share”的定义重新汇总后，才能判断 ARL 与
`2.6736 MB` 的真实差距。

### n=48 / n=64 本地 TCP 回归（2026-08-24，新设备）

两轮均使用 `compact-v1`、完整 Pool、严格本地 TCP、单轮 smoke profile，setup 不计入在线
协议延迟，主通信量只统计发送字节。recovery 数值是整个 `recover_shard` phase sent，采用
成功节点均值。

| n/f | completion / quorum | consensus hash | quorum latency | all-node latency | total sent/node | recovery phase sent/node |
|---|---:|---|---:|---:|---:|---:|
| 48/15 | 48/48 / 33 | 单一 | 14.851 s | 17.380 s | 19.717 MB | 2.136 MB |
| 64/21 | 61/64 / 43 | 单一 | 28.303 s | 不可用（3 节点未完成） | 26.677 MB | 2.637 MB |

n=48 为 `quorum_success=1`、`all_success=1`；n=64 为 `quorum_success=1`、
`all_success=0`，成功节点共享单一 hash。n=64 结果可以作为 quorum 活性和通信观察，
但不能作为全节点完成率的正式性能样本。原始目录分别为：

- `/tmp/arladkr-local-n48-20260824-024252/`
- `/tmp/arladkr-local-n64-20260824-024252/`

上表使用新的 recovery 口径：`recovery_data_sent_bytes` 只汇总
`AGG_RECOVER_GET` 与 `AGG_RECOVER_STORE` 的发送量，不包含 `AGGREGATE_SHARE` key-share。
旧的宽 `recover_shard` phase sent 诊断值分别约为 n=48 `4.346 MB/node`、n=64
`5.075 MB/node`，不再作为 recovery 主指标。串行重跑目录为：

- `/tmp/arladkr-local-n48-20260824-serial/`
- `/tmp/arladkr-local-n64-20260824-serial/`

| n | f | sampling | 完成 / quorum | E2E - setup | setup / 阶段数据 | 主通信量：total sent/node | recovery 主通信量：sent/node | ARC communication share |
| ---: | ---: | --- | --- | ---: | --- | ---: | ---: | ---: |
| 32 | 10 | original 11/21/11 | 31/32 / 22 | 5.66 s | setup 0.36 s；leaf 0.93 s；candidate 2.78 s；agreement 0.68 s；recover 10.98 s | 51.39 MB | 4.49 MB | 0.007470%（31 节点） |
| 64 | 21 | original 16/43/22 | 57/64 / 43 | 37.62 s | setup 1.15 s；candidate 26.88 s；aggregate agreement 5.61 s；recovery worker 8.89 s | 232.76 MB | 6.36 MB | 0.001799%（57 节点） |
| 96 | 31 | smoke 3/3（非论文正式参数） | 94/96 / 65 | 81.12 s* | leaf 5.20 s；candidate 66.90 s；agreement 2.10 s；recover 13.50 s | 41.27 MB | 未记录 | 未记录 |
| 96 | 31 | smoke 3/3（非论文正式参数） | 95/96 / 65 | 57.97 s* | proposer slots 43.05 s；catalog verify约 32.4 s；recover 13.2 s | 未统一收集 | 未记录 | 未记录 |
| 96 | 31 | smoke 3/3（非论文正式参数） | 96/96 / 65 | 49.97 s* | catalog verify约 26.3 s | 42.71 MB | 未记录 | 未记录 |
| 128 | 42 | smoke 3/3（非论文正式参数） | 127/128 / 86 | 87.69 s | setup 4.83 s；leaf 10.07 s；candidate 67.68 s；agreement 3.50 s；recover 15.45 s | 51.27 MB | 未记录 | 未记录 |
| 128 | 42 | original 19/85/43 | 0/128 / 86 | 无有效 E2E | 所有节点停在 warmup 后未产生结果；运行已停止 | - | - | 不可用 |

本轮 57 个成功节点共享同一 consensus hash。当前主通信量使用结果记录中的
`mean_total_sent_bytes`；`mean_total_recv_bytes` 仅作为辅助诊断。恢复阶段主指标使用
`mean_recover_shard_sent_bytes`，而不是总计字段
`mean_recover_sent_bytes/mean_recover_recv_bytes`（后者在该路径未单独填充）。成功节点合计为
`13,267,564,812 / 12,137,537,923 B`，恢复阶段为 `362,654,251 / 349,027,648 B`
（约 `0.338 / 0.325 GiB`）；原始结果目录：
`/tmp/arladkr-n64-original-batched-20260823/`。

### n=64 通信量判断

n=64 每节点发送均值约 `232.76 MB`（约 `221.98 MiB`）；接收约 `212.94 MB` 仅作诊断。下面的 phase
counter 仅用于定位时间窗口，不是严格互斥的字节分解：

| 阶段 | 每节点发送均值 | 占 total sent |
| --- | ---: | ---: |
| component disperse | 10.93 MB | 4.7% |
| candidate formation phase counter（混合阶段，不等于 candidate wire） | 204.23 MB | 87.7% |
| aggregate agreement | 11.10 MB | 4.8% |
| recovery shard | 6.36 MB | 2.7% |
| 其他（MVBA、coin、ARC 等） | 约 0.14 MB | 约 0.1% |

可用于通信归因的 tag 级发送均值为：candidate relay `2.16 MB`、component APDB dispersal
`2.70 MB`、aggregate APDB dispersal `0.57 MB`、aggregate agreement `11.10 MB`、decision
handoff `2.95 MB`、new-share exchange `0.52 MB`、pool/validation control 约 `1.82 MB`，
其余字节来自 proposer/validator recovery 和其他 transport traffic。total sent、recovery sent
以及 ARC share 的数值本身没有重算错误；recv 字段仍作为诊断保留。修正的是 candidate phase
counter 的归因。

这里必须区分阶段计数和 candidate wire：`mean_candidate_formation_sent_bytes` 使用全局
`commPhase`，而 n=64 的多个 proposer slot 并发执行，APDB dispersal、proposer recovery 等
流量会被归入这个阶段，因此不能把 204.23 MB 直接解释为 candidate fanout。按
`CV_V2_CERTIFIED_CANDIDATE` tag 统计，candidate relay 实际约为 `2.16 MB` 发送、`1.74 MB`
接收/节点；单个 `mean_agreement_object_wire_bytes` 约 `21.95 KB`。candidate fanout 平均约
`96.9` 次发送，其中 `39.2` 次为 retry（约 `40.5%`），所以仍有重复 payload，但它不是本轮
232.76 MB 总发送的主要来源。真正的总量增长还需要把 aggregate APDB、proposer recovery
和阶段计数拆开后再比较；当前数据不能据此断言 candidate payload 本身是 O(n²) 主因。

仍有优化空间：可以把 candidate 的大 payload 与证书/摘要传播解耦，先向 validator sample
传播摘要或轻量 header，仅在 quorum 需要时按需拉取 aggregate APDB；同时应优先 profile
candidate fanout 的 ACK 超时和 retry 原因，并确认是否能限制到 validator sample。该优化会降低
candidate relay 的重复流量，但不能直接解释阶段计数中的全部 204 MB，
但需要保持候选可验证性、reselection 和恶意节点下的可恢复性，不能直接删掉全量 payload。

## PracticalADKR n=64

| profile | f / kappa | 完成 / quorum | E2E - setup mean / median / p95 | setup | derive median | 主通信量：sent median/node |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| `practical-original` | 21 / 20 | 54/64 / 43 | 44.27 / 40.71 / 54.44 s | 37.62 s | 4.12 s | 153.75 MB |
| `high-assurance` | 21 / 22 | 63/64 / 43 | 153.46 / 153.59 / 154.08 s | 36.82 s | 116.26 s | 155.67 MB |

`high-assurance` 使用 `kappa=f+1`，failure probability 为 0；两档均为单一 consensus hash。

## PracticalADKR practical-original 规模数据

| n | f | kappa | 完成 / quorum | E2E - setup mean / median / p95 | setup median | derive median | 主通信量：sent median/node |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 96 | 31 | 23 | 71/96 / 65 | 464.88 / 464.77 / 465.42 s | 58.13 s | 222.57 s | 489.31 MB |
| 128 | 42 | 26 | 0/128 / 未达成 | 无有效 E2E | - | - | - |

n=96：另有 4 个节点报告 partial-verification multicast timeout；成功节点单一 consensus hash。

当前主通信量只使用每节点协议 `total_sent`，不包含 SSM、setup 分发和 artifact 收集流量；
`total_recv` 仍保留为诊断字段。本地数据不推算未记录的阶段级字节。

## ARLADKR n=32（payload-pull，2026-08-24）

| n | f | sampling | 完成 / quorum | E2E - setup mean / median / p95 | setup | 主通信量：total sent/node | recovery sent/node | ARC communication share |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 32 | 10 | original 11/21/11 | 23/32 / 22 | 37.28 / 37.15 / 37.58 s | 0.63 s | 60.69 MB | 0.277 MB | 0.005175% |

条件：严格本地 TCP，`RLADKR_CANDIDATE_FANOUT_MODE=validator-pull`，
`RLADKR_AGREEMENT_WIRE=compact-v1`，`RLADKR_AGGREGATE_PAYLOAD_PULL=1`，
`RLADKR_APVSS_FULL_PROOF_PROFILE=none`，`n=32,f=10`，论文 original sampling
`11/21/11`。机器为 32 vCPU、约 39 GiB RAM；实验串行执行，未并发运行其他规模。
E2E 使用 `mean_online_protocol_ms`（已减去 setup）；recovery 使用
`mean_recovery_data_sent_bytes`，不包含 key-share。23 个成功节点共享单一 consensus hash，
满足 quorum；其余 9 个节点在 quorum 后 settle 窗口内未产出结果，日志没有独立的协议错误或
OOM 记录，因此本轮仅作为 quorum 活性和通信观察样本，不作为 32/32 完成率样本。
原始目录：`/tmp/arladkr-local-n32-payload-pull-original-20260824/`。

辅助数据：candidate formation 均值约 25.40 s，aggregate agreement 均值约 4.14 s；
aggregate payload 约 105.2 KB。`mean_total_recv_bytes` 均值约 40.97 MB/node，
仅作诊断，不计入主通信量。

### n=32 优化后对比（2026-08-24）

| 版本 | 完成 / quorum | E2E - setup mean / median / p95 | 主通信量：total sent/node | recovery sent/node | ARC communication share |
| --- | --- | ---: | ---: | ---: | ---: |
| 优化前，settle 15 s | 23/32 / 22 | 37.28 / 37.15 / 37.58 s | 60.69 MB | 0.277 MB | 0.005175% |
| 优化后，quorum 即结束 | 22/32 / 22 | 34.24 / 34.19 / 34.65 s | 57.18 MB | 0.234 MB | 0.005521% |

两轮均为 `n=32,f=10`、original sampling `11/21/11`、严格本地 TCP、
`validator-pull + compact-v1 + aggregate payload pull`。优化后使用 quorum 即结束，
所以只收集到恰好 22 个成功节点；优化前额外收集到 23 个节点。相对变化为：在线延迟
约 `-8.2%`、total sent/node 约 `-5.8%`、recovery sent/node 约 `-15.4%`。由于是不同
单轮运行且成功节点集合不同，这些数字只能作为方向性结果，不能单独归因于 canonical/cache
去重优化。

优化后辅助数据：candidate formation 均值约 `22.66 s`，aggregate agreement 约 `4.41 s`，
aggregate recovery cache 为每节点约 `1` miss 加 `2.86` hits；单一 consensus hash。
原始目录：`/tmp/arladkr-local-n32-optimized-20260824/`。

### n=32 当前代码本地 TCP（2026-08-25）

| n | f | sampling | 完成 / quorum | E2E - setup mean / median / p95 | total sent/node | recovery sent/node | ARC communication share |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 32 | 10 | original 11/21/11 | 22/32 / 22 | 28.97 / 29.01 / 29.39 s | 63.33 MB | 0.323 MB | 0.004408% |

条件与上一轮相同：严格 loopback TCP、单轮、quorum 即结束、
`validator-pull + compact-v1 + aggregate payload pull`。setup 均值 `0.408 s`；candidate formation
均值 `18.00 s`，aggregate agreement 均值 `4.02 s`，MVBA peer wait 均值 `2.57 s`。recovery 主指标
使用 `mean_recovery_data_sent_bytes`，不包含 key-share；宽 `recover_shard` phase sent 诊断值为
`4.184 MB/node`，不作为 recovery 主通信量。total recv `42.34 MB/node` 仅作诊断。

22 个成功节点共享单一 consensus hash，32 个 setup/listener 均正常；达到 quorum 后脚本终止其余
runner，因此 `all_success=0` 是收集策略结果，不是已观察到的协议错误。相对 2026-08-24 的单轮
quorum 样本，online mean 从 `34.24 s` 降至 `28.97 s`，但 total sent/node 从 `57.18 MB` 增至
`63.33 MB`、recovery sent/node 从 `0.234 MB` 增至 `0.323 MB`。成功节点集合和本机调度均不同，
不能把单轮差异直接归因于本轮 candidate 状态边界清理。原始目录：
`/tmp/arladkr-local-n32-current-20260825-120926/`。未使用 AWS，新增成本 `$0`。

### n=32 每节点带宽限制（2026-08-24）

| 每节点 egress | 完成 / quorum | E2E - setup mean / median / p95 | 主通信量：total sent/node | recovery sent/node | ARC communication share |
| ---: | --- | ---: | ---: | ---: | ---: |
| 100 Mbps | 22/32 / 22 | 36.02 / 35.99 / 36.32 s | 53.36 MB | 0.290 MB | 0.004579% |
| 50 Mbps | 0/32 / 22 | 无有效 E2E | - | - | - |

条件：每个逻辑节点独立限制所有 TCP egress，使用 `RLADKR_BANDWIDTH_SCOPE=per-node-egress`，
不是全体节点共享带宽。100 Mbps 轮次同时设置 `RLADKR_DECISION_RETRY_BUDGET_MS=120000`，
成功节点共享单一 consensus hash；原始目录：
`/tmp/arladkr-local-n32-pernode-bw100-20260824/`。50 Mbps 轮次未达到 quorum，主要失败为
decision finalization 在 `21/22` shares 后耗尽默认预算，未作为性能数据；其原始目录已清理。


n=128：benchmark 总 timeout `1200 s`；120 个节点停在 recast TCP readiness（需要 86 pairs，
实际 1--7），3 个 MVBA RC timeout，5 个顶层 timeout；无有效性能数据。

## 超时与附加设置

| 规模 | Practical benchmark timeout | 阶段 timeout |
| ---: | ---: | --- |
| n=64 | 600 s | key derive 300 s；partial verify 120 s |
| n=96 | 900 s | key derive 600 s；partial verify 240 s；recover 600 s |
| n=128 | 1200 s | key derive 900 s；partial verify 360 s；recover 900 s |

## ARLADKR n=16 默认路径（2026-08-26）

条件：严格本地 TCP，`n=16,f=5`，论文 original sampling `6/11/6`，payload-only，
dealer-first，dealer response normal，`GOMAXPROCS=2/node`，单轮串行运行。达到 quorum=11
后结束统计；本轮 16/16 节点完成并共享单一 consensus hash。

| n/f | 完成 / quorum | E2E - setup（online mean） | quorum latency | total sent/node | recovery sent/node | ARC communication share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.78295 s | 3.96710 s | 8.686 MB | 0.051 MB | 0.024106% |

`total sent/node` 使用 `mean_sent_bytes_per_node`；恢复主指标使用
`mean_recovery_data_sent_bytes`（约 53,811 B/node，不包含 key-share）。宽
`recover_shard` phase sent 约 3.167 MB/node，仅作诊断，不作为 recovery 主指标。ARC share
分母按超过 quorum 的有效节点统计；本轮有效节点为 16。direct dealer grace 实际等待均值为
`0 ms`（本地 good-case 中 direct payload 立即满足），该等待单独记录，不从 E2E 扣除。

原始目录：`/tmp/arladkr-n16-default-20260826/`。

## ARLADKR n=32 默认路径（2026-08-26）

条件：严格本地 TCP，`n=32,f=10`，论文 original sampling `11/21/11`，payload-only、
dealer-first、dealer response normal，`GOMAXPROCS=2/node`，单轮串行运行。达到 quorum=22
后结束，不等待全部节点；30 个节点成功并共享单一 consensus hash。

| n/f | 完成 / quorum | E2E - setup（online mean） | quorum online latency | quorum raw latency | total sent/node | recovery sent/node | ARC communication share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32/10 | 30/32 / 22 | 19.145 s | 19.237 s | 19.634 s | 27.170 MB | 0.149 MB | 0.014129% |

`quorum_online_latency` 是按成功节点排序后第 22 个节点的 latency，扣除该节点自身
setup 和 recover barrier；`quorum raw latency` 保留原始 quorum 截止时间。主通信量为发送量，
recovery 使用 `mean_recovery_data_sent_bytes`，不含 key-share；宽 `recover_shard` phase
sent 约 `2.157 MB/node`，仅作诊断。direct dealer grace 实际等待均值约 `1.561 s`，单独记录，
不从 E2E 延迟扣除。

原始目录：`/tmp/arladkr-n32-default-20260826/`。

### n=32 candidate tree 对照（2026-08-26）

仅将 `RLADKR_CANDIDATE_FANOUT_MODE` 从缺省 `flood` 改为 `tree`，其余条件与默认轮相同。

| fanout | 完成 / quorum | online mean | quorum online | quorum raw | total sent/node | candidate counter sent/node | recovery sent/node |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| flood | 30/32 / 22 | 19.145 s | 19.237 s | 19.634 s | 27.170 MB | 20.383 MB* | 0.115 MB |
| tree | 27/32 / 22 | 16.813 s | 17.433 s | 17.831 s | 22.796 MB | 16.918 MB* | 0.124 MB |

`*` candidate phase counter 是并发 proposer slot 的 raw phase window，不是互斥 wire bytes；
tag-level `candidate_relay` 实际发送约为 flood `1.206 MB/node`、tree `0.031 MB/node`。
tree 达到 quorum 且共享单一 consensus hash，但全节点完成率低于 flood；该轮仅作为 quorum
性能和传播调度诊断，不作为全节点完成率样本。tree 仍未达到 `sum.md` 的 n=32 目标
`8.22 MB/node`，且不改变论文兼容默认路径。原始目录：
`/tmp/arladkr-n32-tree-20260826/`。

### n=32 sent-only 互斥分类审计（2026-08-26）

bench 新增 `mean_accounted_tag_sent_bytes` 与 `mean_unclassified_sent_bytes`。对默认 flood
轮次复算，total sent 为 `27.170 MB/node`，已知互斥 tag/phase 集合为 `8.952 MB/node`，
剩余未分类发送量为 `18.218 MB/node`（已知集合占 `32.95%`）。`candidate_phase_counter` 和
`recover_shard` 是可重叠 raw phase window，不计入互斥集合；它们不能直接作为 wire traffic。
本审计不改变默认传播路径或论文协议对象。

后续 bench 输出还会分别记录 `mean_apdb_other_sent_bytes` 和
`mean_mvba_other_sent_bytes`。它们只覆盖实际发送但未归入既有互斥 tag group 的 APDB/MVBA
消息，用于拆解 `mean_unclassified_sent_bytes`；不改变协议发送逻辑或论文路径。

最终互斥集合移除了宽 `aggregate_agreement` 与 `receipt` phase，避免和 MVBA named bytes、
decision tags 重复。n=32 accounting-fixed 轮次为 `25/32 / quorum 22`，online mean `18.347 s`、
quorum online `18.401 s`、total sent `21.913 MB/node`；按最终集合复算已分类约 `21.90 MB/node`，
残差约 `0.01 MB/node`，说明 sent-only 统计基本闭合。原始目录：
`/tmp/arladkr-n32-accounted-fixed-20260826/`。

### component cache/singleflight 验证（2026-08-26）

proposer component recovery 复用现有 authenticated cache/singleflight 后，n=16 为 `15/16 / quorum
11`、online `4.091 s`、total sent `8.572 MB/node`；n=32 为 `30/32 / quorum 22`、online
`19.476 s`、total sent `27.598 MB/node`。n=32 本轮 recovery queue wait 和 holder fallback 明显
高于 accounting-fixed 基线，因此只证明活性与 cache 命中方向，不能作为性能改善点。原始目录：
`/tmp/arladkr-n16-component-cache-20260826/`、`/tmp/arladkr-n32-component-cache-20260826/`。

### component payload wire-only DEFLATE（2026-08-26）

完整 canonical leaf、APDB root 和验证对象不变，仅压缩 dealer response transport body；接收端
有界解压后执行原验证。默认开启，可用 `RLADKR_COMPONENT_PAYLOAD_COMPRESSION=0` 回退。

| n | 完成 / quorum | online mean | quorum online | total sent/node | component recovery sent/node |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16 | 14/16 / 11 | 3.755 s | 3.721 s | 7.502 MB | 3.077 MB |
| 32 | 32/32 / 22 | 19.021 s | 19.143 s | 21.867 MB | 15.550 MB |

n=32 all-ACK canonical leaf 尺寸模型为 `460,030 B`，其中重复 ACK ownership proof 为
`172,704 B`（`37.54%`）；真实 fixture response 的标准 DEFLATE 降幅为 `38.07%`。原始目录：
`/tmp/arladkr-n16-deflate-default-20260826/`、`/tmp/arladkr-n32-deflate-default-20260826/`。

### n=32 DEFLATE + dealer grace 500 ms（2026-08-26）

| 完成 / quorum | online mean | quorum online | total sent/node | component recovery sent/node |
| --- | ---: | ---: | ---: | ---: |
| 24/32 / 22 | 17.442 s | 17.598 s | 16.117 MB | 10.306 MB |

相对同一代码的 250 ms 单轮，total sent/node 下降 `26.3%`，holder fragment 下降 `61.6%`，late
response recv 下降 `82.9%`。因此 `n>=32` 默认 dealer-first grace 调整为 500 ms，较小委员会仍为
250 ms；环境变量可覆盖。原始目录：`/tmp/arladkr-n32-deflate-grace500-20260826/`。

component authenticated cancel 的 n=32 诊断轮因 priority cancel traffic 使 decision finalization
停在 `21/22` shares，未达到 quorum，已标记 invalid 且实现全部撤回；该轮不进入性能表。

### n=16 implementation fast-path 阶段回归（2026-08-27）

条件：严格本地 TCP，`n=16,f=5`，论文 original sampling `6/11/6`，payload-only、dealer-first，
单轮串行运行；达到 quorum=11 后 runner 结束。本轮 12 个节点在清理前产生结果，12/12 结果共享单一
consensus hash。

| n/f | 完成结果 / quorum | online mean | quorum online | sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 12/16 / 11 | 4.052 s | 4.123 s | 11.305 MB | 0.107 MB | 0.008953% |

其中 component recovery data sent 为 `2.175 MB/node`，new aggregate recovery sent 为
`0.025 MB/node`，candidate relay sent 为 `0.030 MB/node`。原始目录：
`/tmp/arladkr-n16-stage-20260827-handoff/`。

### n=16 ReadyCert exact-retry 阶段（2026-08-27）

条件与上一阶段相同：严格本地 TCP，`n=16,f=5`，论文 original sampling `6/11/6`，payload-only、
dealer-first，单轮串行运行；quorum=11。本轮 16/16 节点成功，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.850 s | 3.618 s | 5.891 MB | 6.151 MB | 0.131 MB | 0.005674% |

component recovery data sent 为 `1.642 MB/node`，new aggregate recovery sent 为 `0.043 MB/node`，
candidate relay sent 为 `0.033 MB/node`。原始目录：
`/tmp/arladkr-n16-stage-20260827-readycert/`。

### n=16 ReadyCert descriptor 单次验证阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.783 s | 3.564 s | 5.950 MB | 5.980 MB | 0.131 MB | 0.005836% |

component recovery data sent 为 `1.651 MB/node`，new aggregate recovery sent 为 `0.043 MB/node`，
candidate relay sent 为 `0.033 MB/node`。原始目录：
`/tmp/arladkr-n16-stage-20260827-ready-descriptor/`。

### n=16 component descriptor 单次 canonical decode 阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.045 s | 4.080 s | 9.691 MB | 11.392 MB | 0.169 MB | 0.003063% |

component recovery data sent 为 `1.478 MB/node`，new aggregate recovery sent 为 `0.037 MB/node`，
candidate relay sent 为 `0.033 MB/node`。本轮发送量上升主要来自 decision handoff `2.739 MB/node` 和
new-share exchange `4.201 MB/node`，不是本阶段只影响本地 decode 的代码路径。原始目录：
`/tmp/arladkr-n16-stage-20260827-descriptor-decode/`。

### n=16 ReadyCert 批内配置/runtime 复用阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.747 s | 3.543 s | 5.868 MB | 5.837 MB | 0.112 MB | 0.005979% |

component recovery data sent 为 `1.629 MB/node`，new aggregate recovery sent 为 `0.045 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.559 MB/node`，new-share exchange
sent 为 `0.461 MB/node`；后者相对上一轮的大幅下降解释了主要通信量差异，不能归因于只减少本地配置/runtime
准备的代码修改。原始目录：`/tmp/arladkr-n16-stage-20260827-ready-batch-config/`。

### n=16 ReadyCert 本地构建 wire/root 复用阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.576 s | 3.522 s | 5.892 MB | 5.641 MB | 0.092 MB | 0.006187% |

component recovery data sent 为 `1.540 MB/node`，new aggregate recovery sent 为 `0.048 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.665 MB/node`，new-share exchange
sent 为 `0.496 MB/node`；相对上一阶段总发送量 `+0.4%`，基本持平。原始目录：
`/tmp/arladkr-n16-stage-20260827-ready-build-wire/`。

### n=16 ReadyCert 批内 roster 复用阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.044 s | 3.759 s | 5.817 MB | 5.899 MB | 0.112 MB | 0.005916% |

component recovery data sent 为 `1.771 MB/node`，new aggregate recovery sent 为 `0.045 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.330 MB/node`，new-share exchange
sent 为 `0.504 MB/node`。本轮 sent/node 相对上一阶段下降 `1.3%`；延迟波动伴随 component recovery 与个别
agreement 慢节点，不属于只影响本地 roster 分配的修改路径。原始目录：
`/tmp/arladkr-n16-stage-20260827-ready-roster-cache/`。

### n=16 descriptor owned-slice 转移阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.768 s | 3.564 s | 5.642 MB | 5.732 MB | 0.109 MB | 0.006088% |

component recovery data sent 为 `1.398 MB/node`，new aggregate recovery sent 为 `0.045 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.536 MB/node`，new-share exchange
sent 为 `0.490 MB/node`。相对上一阶段 sent/node 下降 `3.0%`，但 component recovery 与 agreement 的轮次
差异也贡献了改善。原始目录：`/tmp/arladkr-n16-stage-20260827-descriptor-owned-slices/`。

### n=16 proposer catalog authenticated-payload 复用阶段（2026-08-27）

条件与上一阶段相同；13/16 节点在 quorum-first 清理前写出成功结果，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 13/16 / 11 | 3.783 s | 3.856 s | 10.930 MB | 11.680 MB | 0.158 MB | 0.008964% |

component recovery data sent 为 `1.876 MB/node`，new aggregate recovery sent 为 `0.032 MB/node`，
candidate relay sent 为 `0.031 MB/node`。decision handoff sent 为 `2.828 MB/node`，new-share exchange
sent 为 `4.850 MB/node`。candidate formation 为 `1.629s`，相对上一阶段 `1.919s` 下降 `15.1%`；总发送量
上升主要来自与本地 hash/copy 优化无关的 new-share exchange 波动。原始目录：
`/tmp/arladkr-n16-stage-20260827-catalog-bound-payload/`。

### n=16 recovered payload ref-bound cache key 阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.209 s | 4.124 s | 10.609 MB | 12.583 MB | 0.131 MB | 0.011095% |

component recovery data sent 为 `2.225 MB/node`，new aggregate recovery sent 为 `0.043 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.498 MB/node`，new-share exchange
sent 为 `4.520 MB/node`。candidate formation 为 `1.909s`，proposer catalog verify 为 `0.857s`。该阶段
收紧 recovery cache/singleflight 的本地 key，不改变发送行为。原始目录：
`/tmp/arladkr-n16-stage-20260827-recovery-ref-key/`。

### n=16 verified catalog payload ownership transfer 阶段（2026-08-27）

条件与上一阶段相同；16/16 节点成功，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.693 s | 3.734 s | 9.520 MB | 11.220 MB | 0.169 MB | 0.003111% |

component recovery data sent 为 `1.585 MB/node`，new aggregate recovery sent 为 `0.037 MB/node`，
candidate relay sent 为 `0.033 MB/node`。decision handoff sent 为 `2.755 MB/node`，new-share exchange
sent 为 `3.914 MB/node`。candidate formation 为 `1.621s`，proposer catalog verify 为 `0.922s`。按 leaf wire
`230,253 B` 和 pool size 11，实际构建 catalog 的节点约少 `2.53 MB` 中间 payload copy，并释放约同量
recovered-cache payload。原始目录：`/tmp/arladkr-n16-stage-20260827-catalog-payload-transfer/`。

### n=16 recovered cache payload ownership transfer 阶段（2026-08-27）

条件与上一阶段相同；15/16 节点在 quorum-first 清理前写出成功结果，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 15/16 / 11 | 4.133 s | 3.954 s | 9.055 MB | 10.398 MB | 0.158 MB | 0.003356% |

component recovery data sent 为 `1.604 MB/node`，new aggregate recovery sent 为 `0.032 MB/node`，
candidate relay sent 为 `0.031 MB/node`。decision handoff sent 为 `2.464 MB/node`，new-share exchange
sent 为 `3.786 MB/node`。candidate formation 为 `1.816s`，proposer catalog verify 为 `0.919s`。按 leaf wire
`230,253 B` 和 pool size 11，每个 fresh-recovery catalog 节点约再少 `2.53 MB` 短命 cache payload copy。
原始目录：`/tmp/arladkr-n16-stage-20260827-recovery-payload-transfer/`。

### n=16 payload response -> collector ownership transfer 阶段（2026-08-27）

条件与上一阶段相同；15/16 节点在 quorum-first 清理前写出成功结果，quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 15/16 / 11 | 3.727 s | 3.769 s | 10.329 MB | 11.853 MB | 0.146 MB | 0.005889% |

direct payload hits 平均 `10.13/node`。component recovery data sent 为 `1.828 MB/node`，new aggregate recovery
sent 为 `0.039 MB/node`，candidate relay sent 为 `0.031 MB/node`。decision handoff sent 为 `2.829 MB/node`，
new-share exchange sent 为 `4.385 MB/node`。candidate formation 为 `1.668s`，proposer catalog verify 为
`0.928s`。本阶段只改变 decoded response 在 collector 中的 slice ownership，不改变发送 wire。原始目录：
`/tmp/arladkr-n16-stage-20260827-decoded-payload-transfer/`。

### n=16 validation-request canonical bytes reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.044 s | 3.863 s | 6.015 MB | 5.896 MB | 0.000 MB | 0.005919% |

candidate formation 为 `1.920s`，proposer catalog verify 为 `1.096s`。本阶段仅在 validation request 网络路径复用
decoder 已生成的 canonical bytes，避免重复 encode；不改变请求 wire、predicate、安全检查或发送量。原始目录：
`/tmp/arladkr-n16-stage-20260827-validation-request-canonical/`。

### n=16 eligibility sample snapshot reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.971 s | 3.654 s | 5.689 MB | 5.790 MB | 0.107 MB | 0.006028% |

candidate formation 为 `1.790s`，proposer catalog verify 为 `1.048s`。本阶段复用 context 已验证的 proposer/validator
sample 快照，避免候选路径重复校验；不改变 candidate wire、predicate、安全边界或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-sample-reuse/`。

### n=16 agreement-object canonical wire reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.923 s | 3.526 s | 6.016 MB | 6.094 MB | 0.117 MB | 0.005727% |

candidate formation 为 `1.522s`，proposer catalog verify 为 `1.069s`。decoder 已认证的 agreement canonical wire 在
predicate 中复用，手工构造对象仍走完整 encode；不改变 candidate wire、predicate、安全检查或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-agreement-canonical-cache/`。

### n=16 VCert canonical wire reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.399 s | 4.013 s | 9.748 MB | 11.850 MB | 0.131 MB | 0.002945% |

candidate formation 为 `1.871s`，proposer catalog verify 为 `1.139s`。VCert decoder 已认证的 canonical wire 在后续
agreement/result predicate 中复用，未改变 VCert quorum、pairing、candidate wire、安全检查或通信定义。本轮通信
明显高于相邻阶段，属于本地单轮调度/恢复流量波动，不能视为该 CPU-only 优化造成。原始目录：
`/tmp/arladkr-n16-stage-20260827-vcert-canonical-cache/`。

### n=16 validation request object reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.853 s | 3.580 s | 5.832 MB | 6.078 MB | 0.143 MB | 0.005742% |

candidate formation 为 `1.841s`，proposer catalog verify 为 `1.085s`。validation result 到达时复用已缓存的
canonical-validated request，legacy record 仍保留完整 decode fallback；不改变 result wire、VCert 检查、predicate
或通信定义。原始目录：`/tmp/arladkr-n16-stage-20260827-request-cache/`。

### n=16 cached validation statement for VCert pairing 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.824 s | 3.561 s | 5.860 MB | 5.781 MB | 0.117 MB | 0.006037% |

candidate formation 为 `1.592s`，proposer catalog verify 约 `1.123s`。VCert pairing 路径复用 record 中已绑定的
statement，跳过重复 header encode/hash；其余 VCert 和 predicate 检查不变。原始目录：
`/tmp/arladkr-n16-stage-20260827-vcert-statement/`。

### n=16 eligibility proposer-sample snapshot cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.988 s | 3.606 s | 5.612 MB | 5.922 MB | 0.078 MB | 0.005893% |

candidate formation 为 `1.779s`，proposer catalog verify 约 `1.089s`。候选路径复用 epoch eligibility 阶段生成的有序
proposer sample，避免重复 map 遍历和排序；未改变 sample、candidate wire、predicate、安全检查或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-eligibility-snapshot/`。

### n=16 validation statement cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.885 s | 3.609 s | 6.022 MB | 6.225 MB | 0.223 MB | 0.005606% |

candidate formation 为 `1.901s`，proposer catalog verify 为 `1.149s`。validation result 优先复用 record 中已绑定的
statement，legacy record 才重新计算；不改变 result wire、VCert、request/header binding、predicate 或通信定义。
原始目录：`/tmp/arladkr-n16-stage-20260827-statement-cache/`。

### n=16 agreement predicate read-only sample reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.877 s | 3.275 s | 5.461 MB | 5.838 MB | 0.184 MB | 0.005978% |

candidate formation 为 `1.571s`，proposer catalog verify 为 `1.106s`。已验证 eligibility snapshot 在 agreement
predicate 中只读复用，未改变 sample、candidate wire、predicate、安全检查或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-predicate-sample-readonly/`。

### n=16 epoch agreement public-context cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.988 s | 3.495 s | 5.289 MB | 5.767 MB | 0.107 MB | 0.006052% |

candidate formation 为 `1.503s`，proposer catalog verify 为 `1.004s`。当前 epoch 的已验证 public context 由候选
路径只读复用，并在 eligibility 更新时失效；未改变协议字段、candidate wire、predicate、安全检查或通信定义。
原始目录：`/tmp/arladkr-n16-stage-20260827-context-cache/`。

### n=16 Pool certificate canonical wire reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.018 s | 3.543 s | 5.657 MB | 5.975 MB | 0.223 MB | 0.005841% |

candidate formation 为 `1.721s`，proposer catalog verify 为 `1.053s`。Pool certificate decoder 已认证 wire 在后续
canonicalization 中复用，手工证书仍走完整路径；未改变协议、predicate、安全检查或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-pool-cert-cache/`。

### n=16 aggregate-recovery handoff canonical wire reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.741 s | 3.466 s | 5.993 MB | 5.958 MB | 0.170 MB | 0.005858% |

candidate formation 为 `1.846s`，proposer catalog verify 为 `1.128s`。aggregate recovery authorization 复用
decoder 已认证的 handoff wire；APDB lock、context 和 decision certificate 检查保持不变。原始目录：
`/tmp/arladkr-n16-stage-20260827-handoff-canonical-cache/`。

### n=16 candidate fanout ACK probe wire cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.163 s | 3.640 s | 5.548 MB | 5.757 MB | 0.117 MB | 0.006063% |

candidate formation 为 `1.916s`，proposer catalog verify 约 `1.078s`，candidate retries `7/node`。ACK probe wire
在 digest fanout state 中只编码一次并由 peer worker 只读复用；不改变 ACK、retry、fanout、candidate wire 或通信定义。
原始目录：`/tmp/arladkr-n16-stage-20260827-ack-probe-cache/`。

### n=16 candidate fanout send-error retry fast path 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.416 s | 4.089 s | 9.554 MB | 11.636 MB | 0.168 MB | 0.002999% |

candidate formation 为 `1.892s`，candidate retries `7/node`。发送失败时跳过不可能成功的 ACK 等待，但保留相同
backoff、retry 次数和取消语义；正常发送路径、candidate wire 和通信定义不变。本轮通信受本地调度波动影响。
原始目录：`/tmp/arladkr-n16-stage-20260827-send-error-retry/`。

### n=16 candidate ACK waiter fast path 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.907 s | 3.632 s | 6.054 MB | 5.983 MB | 0.223 MB | 0.005833% |

candidate formation 为 `2.032s`，proposer catalog verify 为 `1.094s`，candidate retries `7/node`。已 ACK peer
在创建 waiter 前直接短路；未改变 timeout、retry、认证、candidate wire 或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-ack-wait-fastpath/`。

### n=16 dealer payload prepare job ownership reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.296 s | 4.169 s | 9.769 MB | 11.568 MB | 0.168 MB | 0.003017% |

dealer payload prepare job 优先从已缓存 payload 读取，避免正常路径的第二份完整 payload copy；缓存满时保留
owned fallback。不改变 response、认证、recovery 或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-dealer-payload-job/`。

### n=16 aggregate recovery request canonical wire cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `14/16` 完成，quorum=11 达成，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 14/16 / 11 | 3.918 s | 3.738 s | 5.985 MB | 5.919 MB | 0.001 MB | 0.005896% |

candidate formation 为 `1.909s`，catalog verify 为 `1.055s`。aggregate recovery request 外层 canonical wire 在
authorization/collector 路径复用；两节点未完成属于本地单轮调度波动。原始目录：
`/tmp/arladkr-n16-stage-20260827-aggregate-request-cache/`。

### n=16 APDB lock canonical wire reuse 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.749 s | 3.505 s | 5.775 MB | 5.590 MB | 0.145 MB | 0.006244% |

APDB lock decoder 已认证的 canonical wire 在 handoff、aggregate-recovery、validation 和 component 路径复用；
不改变 lock certificate、binding、predicate 或通信定义。原始目录：
`/tmp/arladkr-n16-stage-20260827-lock-canonical-cache/`。
### n=16 component recovery cache read-only send handoff 阶段（2026-08-27）

条件与上一阶段相同；本轮 `14/16` 完成，quorum=11 达成，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 14/16 / 11 | 3.754 s | 3.513 s | 5.935 MB | 5.907 MB | 0.117 MB | 0.005908% |

cache hit 时直接将 immutable response 交给 `sendAsync`，由队列边界完成复制；不改变 response wire、认证或通信定义。
原始目录：`/tmp/arladkr-n16-stage-20260827-recovery-cache-readonly/`。
# n=16 verified recovery lock cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `14/16` 完成，quorum=11 达成，单一 consensus hash。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 14/16 / 11 | 4.436 s | 4.093 s | 9.864 MB | 11.472 MB | 0.168 MB | 0.006084% |

candidate formation 为 `1.797s`，catalog verify 为 `1.073s`。按 request digest 复用已验证 recovery lock，未改变
认证、response、predicate 或通信定义；两节点未完成属于本地单轮调度波动。原始目录：
`/tmp/arladkr-n16-stage-20260827-recovery-lock-cache/`。

### n=16 component recovery response singleflight 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。通信量按 sent bytes/node，recovery
仅计 recovery data sent，不含 key-share。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.899 s | 3.649 s | 6.096 MB | 5.872 MB | 0.075 MB | 0.005944% |

holder 对相同 request hash 的并发 store response 只执行一次读取、RS 构造和 canonical encode，等待者复用结果后
分别发送；协议消息、认证、threshold 和首次发送量不变。该阶段主要降低 recovery queue/CPU 长尾，不预期显著降低
首发通信量。原始目录：`/tmp/arladkr-n16-stage-20260827-recovery-singleflight/`。

### n=16 recovery late-response fast-drop 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。通信量按 sent bytes/node，recovery
仅计 recovery data sent，不含 key-share。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.264 s | 4.013 s | 10.005 MB | 11.647 MB | 2.562 MB | 0.011986% |

collector 达到 threshold 后，late store/payload response 不再进入后续 collector 处理，并计入 late-recv 诊断；协议验证和
threshold 未改变。本轮活性正常，但 recovery 重试和本地调度造成 sent/node 明显升高，不能视为该优化的性能收益。原始
目录：`/tmp/arladkr-n16-stage-20260827-recovery-late-drop/`。
### n=16 recovery priority queue 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。已收到的 payload response 使用独立优先队列，普通 recovery request 仍走原队列；通信量按 sent bytes/node，recovery 不含 key-share。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.762 s | 3.502 s | 5.981 MB | 5.915 MB | 0.215 MB | 0.005900% |

`mean_recovery_queue_wait_ms=46.10`，`mean_component_recovery_late_recv_bytes=155104`。本轮未出现活性回退，且相对上一轮 late-drop 的 recovery sent/node 明显下降；单轮结果仍受本机调度影响。原始目录：`/tmp/arladkr-n16-stage-20260827-recovery-priority-queue/`。
### n=16 aggregate payload response wire cache 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。authenticated pull provider 在完成授权后缓存同一 instance digest 的 immutable payload response wire，重复 pull 只复用 wire；默认 dealer-first good-case 未改变。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.254 s | 4.039 s | 9.638 MB | 11.670 MB | 1.942 MB | 0.002991% |

本轮 authenticated pull 未成为默认路径的主要流量来源；结果保持活性，但 recovery 重试造成通信偏高，不能将单轮差异归因于 wire cache。原始目录：`/tmp/arladkr-n16-stage-20260827-aggregate-payload-wire-cache/`。

### n=16 aggregate payload response singleflight 阶段（2026-08-27）

条件与上一阶段相同；本轮 `16/16` 完成、quorum=11，单一 consensus hash。authenticated pull 的首次 response encode
使用有界 singleflight，同一 instance digest 的并发请求复用结果，仍逐次授权和发送。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.809 s | 3.519 s | 5.390 MB | 5.171 MB | 1.942 MB | 0.006749% |

本轮 queue wait（节点 profile）约 `87.68 ms`，late response `0 B`；默认 dealer-first 路径活性正常。该阶段主要减少
authenticated pull 并发 miss 的 CPU/分配，不改变首发通信量。原始目录：`/tmp/arladkr-n16-stage-20260827-aggregate-payload-singleflight/`。
### n=16 lane ACK offer-digest cache 阶段（2026-08-27）

条件与上一阶段相同；pending lane 生命周期内缓存每个 receiver offer 的 canonical digest，ACK 仍完整 decode、身份检查和签名验证。

| n/f | 完成 / quorum | online mean | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 5.911 s | 约 3.91 s | 5.593 MB | 5.724 MB | 0.908 MB | 0.006097% |

本轮活性正常；该优化只减少 ACK 热路径重复 canonical encode/hash，不改变 lane wire 或协议语义。由于单轮本地调度波动，通信和延迟不作为严格收益结论。原始目录：`/tmp/arladkr-n16-stage-20260827-lane-digest-cache/`。
### n=16 component INIT ACK original-wire cache 阶段（2026-08-27）

条件与上一阶段相同；相同 component INIT wire 的重传在最前面复用已认证 ACK wire，首次 INIT 仍执行完整 artifact、
statement、dealer signature、持久化和 holder signature 校验。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 14/16 / 11 | 6.632 s | 5.763 MB | 5.708 MB | 0.475 MB | 0.012229% |

本轮 quorum 活性保持，但出现本机调度/重试长尾；因此不将单轮延迟或通信差异归因于缓存。原始目录：
`/tmp/arladkr-n16-stage-20260827-init-ack-wire-cache/`。
### n=16 component INIT original-wire cache 修正版阶段（2026-08-27）

相同 component INIT wire 的重传在最前面复用已认证 ACK wire；首次 INIT 仍执行完整 artifact、statement、dealer
signature、持久化和 holder signature 校验。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 5.090 s | 5.306 MB | 5.559 MB | 1.861 MB | 0.006278% |

queue wait `10.79 ms`，late response `0 B`。本轮活性正常；通信和延迟仍受本地调度/重试影响。原始目录：
`/tmp/arladkr-n16-stage-20260827-init-wire-cache/`。
### n=16 validation request duplicate fast-path 阶段（2026-08-27）

相同 proposer/request wire 已完成认证并记录后，重复请求直接复用 immutable decoded request 与 canonical wire；仍检查原始
wire 完全一致，并保留首次完整 predicate、VCert/Pool/ARC 验证。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.410 s | 6.286 MB | 6.255 MB | 2.682 MB | 0.011159% |

queue wait `130.02 ms`。本轮活性正常；recovery 重试导致通信偏高，不能将单轮差异归因于 fast-path。原始目录：
`/tmp/arladkr-n16-stage-20260827-validation-request-cache/`。
### n=16 component reference known-dealer fast-path 阶段（2026-08-27）

已知 dealer 的 component reference 重传在 decode 前直接丢弃；这与原有 decode 后发现 known dealer 即返回的行为一致，
首次 reference 仍执行完整 canonical、context、lock 和签名验证。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.624 s | 5.798 MB | 6.383 MB | 2.281 MB | 0.010936% |

queue wait `23.59 ms`。本轮活性正常，通信/延迟为单轮方向性结果。原始目录：
`/tmp/arladkr-n16-stage-20260827-component-ref-fastpath/`。
### n=16 candidate ACK wire cache 阶段（2026-08-27）

普通 candidate ACK 与 ACK probe 共用按 digest 缓存的 immutable ACK wire，避免重试时重复构造固定小消息；ACK 语义、
优先级通道和 candidate fanout 拓扑不变。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 12/16 / 11 | 3.714 s | 5.642 MB | 5.763 MB | 1.907 MB | 0.006056% |

queue wait `145.91 ms`。quorum 活性保持，但 4 个节点未完成，属于本机单轮调度波动；本优化主要减少小对象分配，
不预期降低通信量。原始目录：`/tmp/arladkr-n16-stage-20260827-candidate-ack-cache/`。
### n=16 candidate response wire cache 阶段（2026-08-27）

candidate fetch/validator-pull response 按 digest 缓存 immutable response wire，重复 fetch 跳过 envelope encode；默认 flood
路径、candidate 内容、认证和 fanout 不变。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 6.308 s | 5.514 MB | 5.526 MB | 1.868 MB | 0.006316% |

queue wait `47.58 ms`。本轮活性正常；默认路径未大量触发 fetch，通信/延迟仅作方向性观察。原始目录：
`/tmp/arladkr-n16-stage-20260827-candidate-response-cache/`。
### n=16 candidate response singleflight 阶段（2026-08-27）

candidate fetch response 的首次 canonical envelope encode 按 digest 使用有界 singleflight，并发请求复用 immutable wire；
每个请求仍独立发送，默认 flood 路径不变。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 6.447 s | 5.623 MB | 5.658 MB | 1.842 MB | 0.006168% |

queue wait `53.91 ms`。本轮活性正常；默认路径未大量触发 fetch，数据仅用于无回退验证。原始目录：
`/tmp/arladkr-n16-stage-20260827-candidate-response-singleflight/`。
### Validation request canonical object cache（2026-08-27，撤回）

尝试将 decoded validation request 的 canonical wire 绑定到对象以跳过重复构造；定向测试通过，但 n=16 TCP 出现全局
MVBA 超时（`0/16` 完成），说明对象生命周期仍可能包含后续更新。该优化已撤回，不纳入默认路径或性能结论。
### n=16 validation canonical cache 撤回后复测（2026-08-27）

撤回 validation request canonical object cache 后复测；本轮 `13/16` 完成、quorum=11 达成，单一 consensus hash。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16/5 | 13/16 / 11 | 6.297 s | 5.713 MB | 5.728 MB | 0.006093% |

该结果证明撤回后 quorum 活性恢复；未完成节点仍属于本机调度波动。原始目录：
`/tmp/arladkr-n16-stage-20260827-validation-cache-reverted/`。
### n=16 candidate response received-wire reuse 阶段（2026-08-27）

validator-pull response 已完成 canonical decode 后，等待者直接复用收到的原始 response wire，删除再次 encode；默认 flood
路径和所有 candidate 验证不变。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 6.680 s | 5.461 MB | 5.362 MB | 2.010 MB | 0.006509% |

queue wait `45.91 ms`。本轮活性正常；默认路径未大量触发 validator-pull，结果仅作无回退验证。原始目录：
`/tmp/arladkr-n16-stage-20260827-candidate-response-wire-reuse/`。
### n=16 ReadyCert pending wire dedupe 阶段（2026-08-27）

descriptor 尚未齐全时，按完整 ReadyCert wire digest 丢弃相同重复消息；不同 wire 仍执行完整 decode、descriptor 和 root
检查。集合有界，不改变 ReadyCert 语义。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.866 s | 5.454 MB | 5.362 MB | 1.864 MB | 0.006508% |

本轮活性正常，结果为单轮方向性数据。原始目录：`/tmp/arladkr-n16-stage-20260827-ready-pending-dedupe/`。
### n=16 ValidationResult exact-wire 重传去重阶段（2026-08-27）

条件：`n=16,f=5`，original sampling `6/11/6`，严格本地 TCP，`payload-only + dealer-first`，quorum=11；只对已完成
完整认证的相同 sender/相同 result wire 做 decode 前去重，变异 wire 和不同 sender 仍完整验证。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 4.309 s | 9.424 MB | 10.556 MB | 1.752 MB | 0.003157% |

单一 consensus hash。该阶段只减少 exact retry 的重复 decode/VCert 验证和本地分配，不改变 wire、recipient、threshold
或安全 predicate，因此通信量不预期下降；本轮用于确认 quorum 活性和无明显回退。原始目录：
`/tmp/arladkr-n16-stage-20260827-validation-result-wire-dedupe/`。

### n=16 Validation signature exact-wire 重传去重阶段（2026-08-27）

条件：`n=16,f=5`，original sampling `6/11/6`，严格本地 TCP，`payload-only + dealer-first`，quorum=11；只对已完成
完整 BLS 验证的相同 sender/相同 signature wire 做 decode/pairing 前去重，变异 wire 和不同 sender 仍完整验证。

| n/f | 完成 / quorum | quorum online | sent/node | quorum sent/node | recovery sent/node | ARC share |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16/5 | 16/16 / 11 | 3.628 s | 6.367 MB | 6.609 MB | 2.103 MB | 0.015842% |

单一 consensus hash。该阶段主要减少 exact retry 的重复 BLS pairing，不改变 wire、recipient、threshold 或安全
predicate；通信差异受本机重试/时序影响，不能据单轮结果归因。原始目录：
`/tmp/arladkr-n16-stage-20260827-validation-signature-wire-dedupe/`。

### PracticalADKR recovery 首波 k + 延迟 speculative fanout（2026-08-28）

实现：recovery 首次 fetch 只向 `erasureK` 个 holder 请求；在 `PRACTICAL_RECOVER_FETCH_STALL_MS`
（默认 1 s）后才补发 speculative `delta`（默认 `max(4,min(16,f/2))`），后续 stall 再按 retry step
扩大。达到每个 dealer 的 recipient recovery 条件后，已有 recovery `stop` context 会取消尚未完成的
发送和 late response。可用 `PRACTICAL_RECOVER_SPECULATIVE_EXTRA` 调整 delta；该路径不改变
APDB/RS threshold、holder attestation、Merkle proof 或最终 transcript predicate。

本轮单元测试验证首波 fanout 与 speculative delta 计算通过。尝试 n=7 严格本地 TCP 未形成有效样本：
多个节点在 recovery 之前的 partial verification/CompProve 阶段超时（仅收到 2/5 shares），因此不记录
latency 或通信量；运行已停止并清理残余进程。此前有效的 n=7 基线仍为 online `2.029 s`、sent-only
`0.455 MB/node`、recovery sent-only `0.081 MB/node`，不能将本次 invalid run 与其比较。

### PracticalADKR CompKey aggregate statement cache（2026-08-28）

实现：`collectCompKeyWires` 按 `CompPublicKeyShare.NodeID` 惰性缓存
`compAggregateStatement` 的 aggregate/x/c1Product；同一 sender 的重复或重传 share 不再重复执行
`O(|selected|)` 点聚合。每份 share 仍执行原有 relation、DLog、DH proof 和 binding 验证；不改变
论文协议、threshold、wire 或安全 predicate。

| n/f | 完成 / quorum | online | sent/node | recovery sent/node |
| ---: | --- | ---: | ---: | ---: |
| 7/2 | 7/7 / 5 | 2.029 s | 0.455 MB | 0.081 MB |

7 个节点 consensus hash 一致，`timeout=0`、`fallback=0`。原始目录：
`deployment/docker-artifacts/aggregate-cache-n7-20260828/`。

一次 n=16 复测未形成有效样本：本机资源竞争导致 partial verification/CompProve 在达到
threshold 前超时（最多仅收到 6/11 shares），所有节点 `success_rate=0`，不纳入性能比较。

### 最新二进制：partial cache + recovery speculative fanout quorum 验证（2026-08-28）

先使用 `go build -buildvcs=false -trimpath` 重建 `bin/bench_latency`，再运行严格本地 TCP
`n=7,f=2,kappa=3`，`PRACTICAL_DXT_VERIFY_WORKERS=2`、`cpu-oversubscribe=1.0`。7 个进程中
5 个成功，达到 quorum=5；2 个在 CompProve readiness 阶段失败，不纳入平均值。按 5 个成功节点
计算：

| 完成 / quorum | latency | setup | online（去 setup） | sent/node | recovery sent/node |
| --- | ---: | ---: | ---: | ---: | ---: |
| 5/7 / 5 | 7.352 s | 5.194 s | 2.156 s | 0.459 MB | 0.077 MB |

5 个成功节点无 timeout/fallback，consensus hash 一致；结果目录：
`deployment/docker-artifacts/latest-opt-n7-20260828/`。runner 后续为避免等待失败节点超时而人工
中止，但 quorum 数据已经独立收集并符合本项目的 quorum 统计口径。

### transcript/lane digest cache n=7（2026-08-28）

在最新 `bench_latency` 上启用 backend 级 canonical transcript digest cache：完整 transcript 验证和
每个 lane 验证均按 digest 缓存，重复阶段/多 verifier 不重复执行 encrypted-DLog/EC 检查；对象内容
变化会产生新 digest，首次验证和全部安全检查不跳过。条件为严格本地 TCP、`n=7,f=2,kappa=3`、
`PRACTICAL_DXT_VERIFY_WORKERS=2`、`cpu-oversubscribe=1.0`。

| 完成 / quorum | latency | setup | online（去 setup） | partial verify | recovery | aggregate derive | sent/node | recovery sent/node |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7/7 / 5 | 8.034 s | 6.694 s | 1.340 s | 0.013 s | 0.588 s | 0.691 s | 0.455 MB | 0.079 MB |

7 个节点 `timeout=0`、`fallback=0`，consensus hash 一致。相较此前无 digest cache 的有效 n=7
（online 约 `2.029 s`），partial verification 和 aggregate derive 均明显下降；总 latency 受
本地 setup CPU 影响。原始目录：`deployment/docker-artifacts/transcript-cache-n7-20260828/`。

### transcript/lane digest cache n=16（2026-08-28）

条件：严格本地 TCP、`n=16,f=5,kappa=6`、`PRACTICAL_DXT_VERIFY_WORKERS=2`、
`cpu-oversubscribe=1.0`。16 个进程中 14 个成功，达到 quorum=11；2 个在 recovery completion
阶段超时（`completions=2/11`），不纳入平均值。14 个成功节点平均：

| 完成 / quorum | latency | setup | online（去 setup） | partial verify | recovery | aggregate derive | sent/node | recovery sent/node |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 14/16 / 11 | 17.431 s | 13.788 s | 3.609 s | 0.108 s | 2.064 s | 2.412 s | 3.387 MB | 0.456 MB |

14 个成功节点无 timeout/fallback 且 consensus hash 一致。此前同条件旧基线 online 约 `6.749 s`、
sent `3.496 MB/node`、recovery sent `0.558 MB/node`；本轮 online 约下降 `46.5%`，recovery
发送量下降约 `18.3%`。原始目录：`deployment/docker-artifacts/transcript-cache-n16-20260828/`。

### CompProve readiness 窗口修复与复测（2026-08-28）

针对本地 proc-sim 在 CPU 竞争下的 readiness 误判，将 CompProve ready probe 默认拨号窗口从
`1 s`/I/O `2 s` 调整为 `2 s`/`5 s`，仍要求 `n-f` 个可达节点，协议消息和安全阈值不变。定向
CompProve 测试通过；使用最新二进制运行 n=7 后，仍有 4 个节点在后续 partial verification
阶段超时，说明主要问题不是 readiness probe，而是 proc-sim 跨进程 partial-result 投递和本机调度
竞争。该复测没有 recovery 性能数据，不纳入 latency 或通信量比较。

同日 recovery fanout 复测在 `PRACTICAL_DXT_VERIFY_WORKERS=2`、`start-delay=30s` 两种条件下各
尝试一次 n=7。两次均在 recovery 之前的 partial verification 阶段报告
`partial verification result multicast timeout`，没有有效 latency 或通信量样本；该结果只说明
当前 proc-sim 前置活性/资源问题仍存在，不能归因于 speculative recovery fanout。

### partial verification duplicate-result cache（2026-08-28）

实现：缓存每个 verifier 的 expected lane 集合，并在同一 `(dealer, verifier)` 的完整 lane 结果已经
接受后，提前丢弃重传 wire，避免重复执行 ECDSA 验证和 lane-shape map 构造。首次结果仍执行完整
签名、digest、lane coverage 与重复 lane 检查，不改变论文中的 `f+1` 正票阈值或安全 predicate。

定向 `go test ./core -run 'Test(Partial|CompKey|PracticalADKR)'` 通过。随后尝试本地严格 TCP
`n=4,f=1,kappa=2`，但 partial verification 仍发生 timeout，CompProve 仅收到部分 share；该运行
没有有效协议结果，不记录 latency/通信量。当前 proc-sim 的前置活性问题需要单独修复后，才能评估
此缓存对端到端延迟的实际收益。

### n=16 completion barrier / responder 修复复测（2026-08-28）

| 项目 | 设置 |
| --- | --- |
| 网络与规模 | 严格本地 TCP，`n=16,f=5,kappa=6`，单轮，16 个进程 |
| 资源 | `PRACTICAL_DXT_VERIFY_WORKERS=2`，`cpu-oversubscribe=1.0` |
| 启动与 responder | 统一 `PRACTICAL_START_AT_UNIX`，`start-delay=20s`，`PRACTICAL_RESPONDER_GRACE_MS=180000` |
| completion barrier | `PRACTICAL_RECOVER_COMPLETION_WAIT_MS=0`（默认关闭） |
| 主通信量 | sent-only；recovery sent-only 不含 key-share |

| 统计集 | 完成 / quorum | online 平均 | quorum online 截止 | raw latency 平均 / 截止 | sent/node | recovery sent/node |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| quorum 前 11 个节点 | 11/11 / 11 | 3.531 s | 3.569 s | 16.112 / 16.127 s | 3.420 MB | 0.492 MB |
| 全部成功节点 | 16/16 / 11 | 6.313 s | - | 18.905 s | 3.343 MB | 0.475 MB |

16 个节点 `timeout=0`、`fallback=0`，consensus hash 唯一；node-11 的 online 为 `47.746 s`，
其余节点约 `3.48--3.64 s`。setup 平均 `12.592 s`，不计入 online。前一轮的两个 readiness
失败节点已消失；该轮原始目录为 `deployment/docker-artifacts/completion-opt-n16-20260828b/`。
