# ARLADKR / PracticalADKR 本地 TCP 数据（2026-08-23）

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
| 结果口径 | 所有 E2E 均记录为 `E2E - setup`；同时记录 setup、quorum、共识和每节点 total sent/recv |
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

| n | f | sampling | 完成 / quorum | E2E - setup | setup / 阶段数据 | total sent/recv 每节点 | recovery sent/recv 每节点 | ARC communication share |
| ---: | ---: | --- | --- | ---: | --- | ---: | ---: | ---: |
| 32 | 10 | original 11/21/11 | 31/32 / 22 | 5.66 s | setup 0.36 s；leaf 0.93 s；candidate 2.78 s；agreement 0.68 s；recover 10.98 s | 51.39/49.67 MB | 4.49/4.57 MB | 0.007470%（31 节点） |
| 64 | 21 | original 16/43/22 | 57/64 / 43 | 37.62 s | setup 1.15 s；candidate 26.88 s；aggregate agreement 5.61 s；recovery worker 8.89 s | 232.76/212.94 MB | 6.36/6.12 MB | 0.001799%（57 节点） |
| 96 | 31 | smoke 3/3（非论文正式参数） | 94/96 / 65 | 81.12 s* | leaf 5.20 s；candidate 66.90 s；agreement 2.10 s；recover 13.50 s | 41.27/33.83 MB | 未记录 | 未记录 |
| 96 | 31 | smoke 3/3（非论文正式参数） | 95/96 / 65 | 57.97 s* | proposer slots 43.05 s；catalog verify约 32.4 s；recover 13.2 s | 未统一收集 | 未记录 | 未记录 |
| 96 | 31 | smoke 3/3（非论文正式参数） | 96/96 / 65 | 49.97 s* | catalog verify约 26.3 s | 42.71/42.69 MB | 未记录 | 未记录 |
| 128 | 42 | smoke 3/3（非论文正式参数） | 127/128 / 86 | 87.69 s | setup 4.83 s；leaf 10.07 s；candidate 67.68 s；agreement 3.50 s；recover 15.45 s | 51.27/46.01 MB | 未记录 | 未记录 |
| 128 | 42 | original 19/85/43 | 0/128 / 86 | 无有效 E2E | 所有节点停在 warmup 后未产生结果；运行已停止 | - | - | 不可用 |

本轮 57 个成功节点共享同一 consensus hash。每节点通信量是结果记录中的
`mean_total_sent_bytes/mean_total_recv_bytes`；恢复阶段使用
`mean_recover_shard_sent_bytes/mean_recover_shard_recv_bytes`，而不是总计字段
`mean_recover_sent_bytes/mean_recover_recv_bytes`（后者在该路径未单独填充）。成功节点合计为
`13,267,564,812 / 12,137,537,923 B`，恢复阶段为 `362,654,251 / 349,027,648 B`
（约 `0.338 / 0.325 GiB`）；原始结果目录：
`/tmp/arladkr-n64-original-batched-20260823/`。

### n=64 通信量判断

n=64 每节点发送均值约 `232.76 MB`（约 `221.98 MiB`），接收约 `212.94 MB`。下面的 phase
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
其余字节来自 proposer/validator recovery 和其他 transport traffic。total sent/recv、recovery
sent/recv 以及 ARC share 的数值本身没有重算错误；修正的是 candidate phase counter 的归因。

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

| profile | f / kappa | 完成 / quorum | E2E - setup mean / median / p95 | setup | derive median | sent/recv median 每节点 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| `practical-original` | 21 / 20 | 54/64 / 43 | 44.27 / 40.71 / 54.44 s | 37.62 s | 4.12 s | 153.75/153.72 MB |
| `high-assurance` | 21 / 22 | 63/64 / 43 | 153.46 / 153.59 / 154.08 s | 36.82 s | 116.26 s | 155.67/154.66 MB |

`high-assurance` 使用 `kappa=f+1`，failure probability 为 0；两档均为单一 consensus hash。

## PracticalADKR practical-original 规模数据

| n | f | kappa | 完成 / quorum | E2E - setup mean / median / p95 | setup median | derive median | sent/recv median 每节点 |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 96 | 31 | 23 | 71/96 / 65 | 464.88 / 464.77 / 465.42 s | 58.13 s | 222.57 s | 489.31/488.23 MB |
| 128 | 42 | 26 | 0/128 / 未达成 | 无有效 E2E | - | - | - |

n=96：另有 4 个节点报告 partial-verification multicast timeout；成功节点单一 consensus hash。

通信量口径与 AWS 追踪文档一致：每节点协议 `total_sent/total_recv`，不包含 SSM、setup 分发和
artifact 收集流量。当前本地数据保留总量，不推算未记录的阶段级字节。

n=128：benchmark 总 timeout `1200 s`；120 个节点停在 recast TCP readiness（需要 86 pairs，
实际 1--7），3 个 MVBA RC timeout，5 个顶层 timeout；无有效性能数据。

## 超时与附加设置

| 规模 | Practical benchmark timeout | 阶段 timeout |
| ---: | ---: | --- |
| n=64 | 600 s | key derive 300 s；partial verify 120 s |
| n=96 | 900 s | key derive 600 s；partial verify 240 s；recover 600 s |
| n=128 | 1200 s | key derive 900 s；partial verify 360 s；recover 900 s |
