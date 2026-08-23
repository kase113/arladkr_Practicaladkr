# AWS 实验过程追踪

本文记录 ARLADKR 与 PracticalADKR 在 AWS 上进行学术实验的实际执行状态、资源、费用和清理结果。
它是操作账本，不替代 [AWS 公网实验推荐流程](AWS_PUBLIC_EXPERIMENT_GUIDE.md)。文档不得记录
AWS access key、SSO token、SSH private key、节点 secret share 或 setup bundle 内容。

## 当前状态

| 项目 | 当前值 |
| --- | --- |
| AWS profile | `arladkr-sso` |
| 账号 | `992382847511` |
| Region | `us-east-1` |
| AZ | `us-east-1f` (`use1-az5`) |
| 实例类型 | `c7g.xlarge` Spot，4 vCPU、8 GiB、ARM64 |
| 最近 ExperimentGroup | `paper-private-n64-current-20260823-a1`（首次 n=64，双协议均未完成，invalidated，已销毁） |
| 固定实验 AMI | `ami-0da946b587756eba5` (v6, commit `98bce4f`) |
| 当前基线 AMI snapshot | `snap-006de34947715f68d`（v6；v5 `snap-03ef25b557c1a77a2` 保留为历史基线） |
| 保留自有 AMI / snapshot | `1 / 1`（仅保留最新 v6 AMI 与其 30 GiB snapshot） |
| Terraform instance count | `0` |
| 当前运行实例 | `0`（debug fleet 已于 2026-08-22 16:23Z 销毁） |
| 当前挂载 EBS | `0` |
| 当前临时 S3 | `0` |

当前 AMI 为 Amazon Linux ARM64，Go `1.26.5 linux/arm64`。实验记录同时固定 AMI ID 与
`source_revision`；后者在工作树有修改时是 HEAD、diff 和相关未跟踪源码的 SHA-256，而不是只记录
可能失真的 Git HEAD。

## 执行时间线

时间均为 UTC。实例生命周期以 EC2 返回的时间为准，避免用聊天时间估算费用。

| 时间 | 事件 | 结果 |
| --- | --- | --- |
| 2026-08-17 14:38:15 | 首次启动 10 台 `c7g.xlarge` Spot | 同一 AZ，私网协议流量，SSM 在线 |
| 2026-08-17 14:41:32-33 | 首次缩容 | 9 台终止，保留 1 台 image-source |
| 2026-08-17 14:48-14:49 | 安装 Go 并同步源码 | Go 与源码 SHA-256 校验通过；临时 S3 随后删除 |
| 2026-08-17 14:50 | 两套 benchmark 构建 | ARLADKR、PracticalADKR 全包 compile-only 通过 |
| 2026-08-17 14:55:37 | 创建 AMI | `ami-0746b30452d74675f`，随后等待 snapshot 100% |
| 2026-08-17 15:02:29 | 终止 image-source | 根盘随实例删除 |
| 2026-08-17 15:06:15 | 从固定 AMI 启动 1 台克隆 | SSM、`node-slot`、二进制哈希和 `-h` smoke 通过 |
| 2026-08-17 15:08:23 | 终止克隆 | 根盘随实例删除 |
| 2026-08-17 15:29-15:31 | 固定 AMI 显式扩容 n=10 | 10 台 `c7g.xlarge` Spot，全部 `us-east-1f` |
| 2026-08-17 15:32 | Fabric SSM preflight | 10/10 SSM Online；ARM64、Go、二进制验证通过 |
| 2026-08-17 15:34-15:39 | ARLADKR trusted setup | 10/10 SSM/S3 下载成功，bundle digest 为 `5ff46e3ea2f995faa50a002b319247649c52392a8c409c41727339e14d0e3cf7` |
| 2026-08-17 15:40 | setup 权限审计 | 10/10 marker、5 个 scalar、1 个 identity 文件和 `0600` 权限通过 |
| 2026-08-17 17:54 | ARLADKR 分布式 smoke | 修复 receiver actor 地址表与 `f_new` 个 lane-offer 发送失败的 fallback 活性后，10/10 成功 |
| 2026-08-17 18:07 | PracticalADKR setup v2 | 增加 Dumbo equivalent path 的 `f+1`/`n-f` 双阈值 BLS material；bundle digest `ac9d13f4bf49ad4b89865c915a904858659b51ce6ef5ab4fa9be88f3be17b77e` |
| 2026-08-17 18:11-18:13 | Practical 两组对照 | matched-lifetime 与 high-assurance 均 10/10 成功 |
| 2026-08-17 18:23:33 | 最终实验 fleet 缩容 | Terraform 销毁 10 台实例；实例实际运行约 65.6 分钟 |
| 2026-08-18 | 清理复核 | 运行实例、实验 EBS、EIP、NAT Gateway、临时 S3 object/bucket 均为 0；AMI 与 snapshot 保留 |
| 2026-08-18 | 公私网 roster 流程收口 | 未启动资源；增加确定性 `/23` 私网地址、整数 `NodeSlot` roster 和可选动态公网 `/32` 白名单 |
| 2026-08-18 08:06-08:10 | 一键生命周期 workflow validation | `aws-paper-run` 创建 n=10、完成 PracticalADKR、收集 artifact 并销毁全部 29 个 Terraform 资源 |
| 2026-08-18 08:24-08:27 | ARL 一键生命周期 workflow validation | n=10 公网 TCP 10/10 成功，收集 artifact 并销毁全部 29 个 Terraform 资源 |
| 2026-08-18 08:40-08:57 | 同 fleet 交替验证 | ARL 成功后 Practical 默认 10/10 timeout；整轮 invalidated，Terraform 销毁全部 29 个资源 |
| 2026-08-18 10:03-10:07 | cleanup barrier 首轮 AWS 验证 | barrier 的 path `pkill` 自匹配当前 shell，0/10 cleanup-ready；整轮 invalidated，29 个资源已销毁 |
| 2026-08-18 10:10-10:16 | cleanup barrier 修复后验证 | cleanup-ready 10/10、runner ready 10/10；Practical 0/7 quorum，整轮 invalidated，29 个资源已销毁 |
| 2026-08-22 09:00-09:14 | n=10 当前 checkout 私网共享 fleet | ARLADKR 与 PracticalADKR 均 10/10 完成；SSM inline summary 被截断，性能结果不可验证；20 个 Terraform 资源已销毁 |
| 2026-08-22 09:39-09:46 | n=10 当前 checkout ARL-only 私网复测 | ARLADKR 10/10 完成、quorum 10/7；schema v3 压缩 summary 仍超过 SSM inline 上限，结果不可验证；20 个 Terraform 资源已销毁 |
| 2026-08-22 09:54-10:01 | n=10 当前 checkout ARL-only 私网复测 r2 | ARLADKR `success=9/10`、quorum 9/7；1 节点失败；schema v4 summary 仍 missing bench；20 个 Terraform 资源已销毁 |
| 2026-08-22 16:23 | 销毁保留的 debug fleet | 发现仅 7/10 台存活（3 台于约 11:32-11:52Z 被 Spot 容量回收）；Terraform 销毁 17 个资源；复核实例/VPC 均为 0 |
| 2026-08-22 16:33-17:13 | n=10 私网双协议 `paper-private-n10-current-20260822-ad` | ARL 9/10、Practical 10/10 均 quorum 成功且 schema v4 收集验证通过；本地 SSO token 过期造成一次中断后用短期静态凭证在同一 fleet 续跑完成；20 个 Terraform 资源已销毁 |
| 2026-08-22 17:46-18:15 | n=10 私网双协议 `paper-private-n10-current-20260822-ae`（耗时度量轮） | ARL 10/10、Practical 8/10 quorum 成功；全程零人工干预 29m34s；行缓冲与凭证预检生效；20 个 Terraform 资源已销毁 |
| 2026-08-23 02:23-02:31 | n=10 私网双协议 `paper-private-n10-current-20260823-af`（wait 加速验证轮） | ARL 10/10、Practical 10/10 quorum 成功；全程 7m50s（上轮 29m34s）；ARL wait 3s 检测 10/10、Practical wait 63s 无返回停滞；20 个 Terraform 资源已销毁 |
| 2026-08-23 02:36-04:20 | n=64 私网双协议 `paper-private-n64-current-20260823-a1`（首次 n=64） | **整轮 invalidated**：ARL n=64 活性停滞（0 成功、节点空闲等待）；Practical runner ready quorum 0/43（未定位）；修复 quorum 等待 >50 上限；74 个 Terraform 资源已销毁 |

## 镜像内容与验证

镜像构建在真实 `c7g.xlarge` ARM64 实例完成，使用统一 Go `1.26.5`，避免两套协议使用不同
编译器或架构。已验证：

- `go test -run '^$' ./...`：ARLADKR 全包通过；
- `go test -run '^$' ./...`：PracticalADKR 全包通过；
- `rladkrbench`：ARM aarch64 ELF，SHA-256 `b6de050edfcca05c1066a3e9a9c67a131f1d9c29a698e53057fe1b92e2ba11de`；
- `bench_latency`：ARM aarch64 ELF，SHA-256 `c5ba736ccc06175d461ab4b69748b80f66ab6f00df8abb283a4e890e4e8dc3e1`；
- 克隆实例可通过 SSM 执行两个二进制的 help smoke；
- 源码归档 SHA-256：`714d82712bd38d7718922f2ab5e004f3d7d1264f898bf48241704155967060fd`；
- 源码、`/etc/rladkr` 和实验 artifact 中没有节点私钥、`.scalar`、setup bundle 或证书。

节点密钥不能写入 AMI。扩容后必须针对每个逻辑节点独立生成并 provision trusted setup；一台
EC2 只对应一个逻辑节点，不能为了省钱把多个节点塞进同一台实例。

## Terraform 操作

Terraform 栈位于 `deployment/terraform/aws-smoke`。`instance_count` 默认值已经改为 `0`，
防止不带参数执行时意外产生计费实例；`ami_id` 用于固定实验镜像。

### 启动 n=10

```bash
export AWS_PROFILE=arladkr-sso
export AWS_REGION=us-east-1
cd /home/yzc/arladkr/ARL-ADKR-CV-sAPVSS-handoff-2026-07-23/arladkr/deployment/terraform/aws-smoke

terraform plan \
  -var instance_count=10 \
  -var ami_id=ami-0cee8a82967ef97ac \
  -out=n10.tfplan
terraform apply n10.tfplan
terraform output -json
```

启动后先确认所有节点 SSM `Online`，再生成私网 roster、独立 setup bundle 和实验环境文件。
不得把公网 IP 写入协议地址，公网 IP 仅用于管理面；节点协议使用同一 VPC 内的私网 IP。

### 立即缩容

```bash
terraform apply -auto-approve \
  -var instance_count=0 \
  -var ami_id=ami-0cee8a82967ef97ac
```

若需要删除整个临时网络，在确认 AMI 不再使用后执行 `terraform destroy`，并另外处理 AMI 与
snapshot。AMI 不属于当前 Terraform 栈的销毁范围。

## 费用账本

实时费用以 AWS Cost Explorer 最终账单为准；实验期间用资源时长估算，且每次扩容前后都要更新
累计值。本轮 AWS Spot 历史返回 `c7g.xlarge us-east-1f` 约 `$0.0527/小时/台`。以下累计只使用本文已经给出金额的
历史条目，不把单轮金额误写成总成本；未量化的更早镜像构建/中断 fleet 仍不在其中。

| 已记录阶段 | 估算成本 | 累计 |
| --- | ---: | ---: |
| 2026-08-17 最终 n=10 fleet | `$0.66` | `$0.66` |
| 2026-08-18 单 Region 公网 smoke | `$0.22` | `$0.88` |
| 新 AMI 与 Practical 公网 smoke | `$0.08` | `$0.96` |
| Practical 一键生命周期验证 | `$0.04` | `$1.00` |
| ARL 一键生命周期验证 | `$0.02` | `$1.02` |
| 同 fleet 交替失败轮 | `$0.18` | `$1.20` |
| cleanup barrier 自匹配失败轮，0.499 instance-hours | `$0.030` | `$1.230` |
| cleanup barrier 修复后 Practical 失败轮，0.748 instance-hours | `$0.046` | `$1.276` |
| boto3 profile 缺失的 preflight 失败轮，约 0.169 instance-hours | `$0.011` | `$1.287` |
| DXT readiness 修复后 Practical 成功轮，约 1.032 instance-hours | `$0.063` | **`$1.350`（约 `$1.35`）** |
| 三洲 n=10 协议失败轮及 n=4 基础设施失败尝试 | 约 `$0.29` | 约 `$1.64` |
| 三洲 n=4 `r03` Spot 回收轮，约 0.574 instance-hours | 约 `$0.05` | **约 `$1.69`** |
| 三洲 n=4 `r04` Terraform 重复 ingress 失败轮 | 约 `$0.03` | 约 `$1.72` |
| 三洲 n=4 `r05` listener 启动偏斜定位轮，约 0.589 instance-hours | 约 `$0.04` | **约 `$1.76`** |
| 三洲 n=4 `r06` listener 修复验证与 SSM 截断定位轮 | 约 `$0.06` | **约 `$1.82`** |
| 2026-08-20 最新 AMI 单 Region 同 AZ 私网 ARL n=10 `paper-arl-private-use1-n10-20260820-v`，约 2.86 instance-hours | 约 `$0.17` | **约 `$3.78`** |
| 2026-08-20 us-east-1 n=32 私网容量验证，协议未执行 | 约 `$0.55` | **约 `$4.33`** |
| 2026-08-21 ARL n=32 `paper-n32-arl-fix-r1-20260821`，SSM 最终一致性诊断轮 | 约 `$0.26` | **约 `$4.59`** |
| 2026-08-21 ARL n=32 `paper-n32-arl-fix-r2-20260821`，29/32 quorum smoke | 约 `$0.55` | **约 `$5.14`** |
| 2026-08-21 Practical n=32 `paper-n32-practical-fix-r1-20260821`，协议阈值诊断轮 | 约 `$0.36` | **约 `$5.50`** |
| 2026-08-21 ARL/Practical 修复后 ARM64 v4 AMI bake，源实例约 0.161 instance-hours | 约 `$0.05` | **约 `$5.55`** |
| 2026-08-21 后续已逐节记录的 shared/v5/v6/n=10/n=32 轮次 | 约 `$3.98` | **约 `$9.53`** |
| 2026-08-22 n=10 当前 checkout 共享私网轮次，约 2.28 instance-hours | 约 `$0.14` | **约 `$9.67`** |
| 2026-08-22 保留 debug fleet 至 16:23Z 销毁的追加运行（7 台 x 约 2.47 h，另 3 台早前被 Spot 回收） | 约 `$1.05` | **约 `$18.09` 前值 + `$1.05` = 约 `$19.14`** |
| 2026-08-22 n=10 私网双协议 `paper-private-n10-current-20260822-ad`，6.121 instance-hours | 约 `$0.37` | **约 `$19.51`** |
| 2026-08-22 n=10 私网双协议 `paper-private-n10-current-20260822-ae`，4.477 instance-hours | 约 `$0.27` | **约 `$19.78`** |
| 2026-08-23 n=10 私网双协议 `paper-private-n10-current-20260823-af`，1.046 instance-hours | 约 `$0.06` | **约 `$19.84`** |
| 2026-08-23 n=64 私网双协议 `paper-private-n64-current-20260823-a1`（invalidated），110.35 instance-hours | 约 `$6.75` | **约 `$26.59`** |

以上累计是逐轮资源时长估算，不是 AWS 账单；表中 `$9.67` 之后的轮次（n=32 公私网、debug fleet
追加运行与两次 n=10 双协议轮）在正文各节逐笔累加，当前实验账本口径约 **`$26.59`**。2026-08-22T17:20Z
查询 Cost Explorer 得到 `2026-08-17--2026-08-22` 已归集 Net/Unblended Cost **`$13.5558`**，其中
`2026-08-22` 当日仅 `$0.0054`，明显尚未入账——8 月 22 日全天的 n=32 公私网轮次、debug fleet
追加运行（约 `$1.05`）与三次 n=10 双协议轮（约 `$0.70`）及 n=64 invalidated 轮（约 `$6.75`）都不在其中。因此当前应采用两种口径：
实验账本估算约 **`$26.59`**；账号已归集账单 **`$13.56`**（待 8 月 22 日入账后差距收窄）。差额
来自账本早期明确排除的未量化轮次、持续存储/公网 IPv4/KMS 等费用，也可能包含账号内未按
ExperimentGroup 分摊的资源；在 Cost Explorer 当日结算前不能把估算写成最终账单。

持续成本另计：清理后仅保留 1 个 30 GiB snapshot。按 `$0.05/GiB-month` 粗略上界约
**`$1.50/月`**；EBS snapshot 实际按已用增量块计费，真实值通常低于该上界。当前运行实例、公网
IPv4、实验 gp3、临时 S3、实验 VPC 均为 0，因此当前 fleet 小时成本为 `$0/小时`；仅该最新
AMI/snapshot 继续产生存储费。

VPC、subnet、route table、security group、IAM role 和 instance profile 当前保留。此前一批 n=10 Spot
集群中有 2 台被 AWS 回收，该轮不计入论文数据；最终用于三组成功实验的 10 台实例已由 Terraform
全部销毁。当前没有运行实例、实验 EBS、EIP、NAT Gateway 或临时 S3 桶；账号仅保留 1 个自有 AMI
及其 1 个 snapshot。最终账单仍以 AWS Cost Explorer 为准。

## 每轮实验清理清单

实验结果写入本地并确认完整后，按以下顺序执行：

1. 将实验状态标记为 `success`、`failed` 或 `invalidated`；Spot interruption、节点未达到
   `n-f` 就绪或任一协议失败时，整轮标记 `invalidated`，不能混入论文数据。
2. 保存 run ID、源码提交、AMI、实例类型、Region/AZ、私网 roster、n/f、采样模式、延迟和通信量。
3. 执行 `terraform apply -var instance_count=0 -var ami_id=...`。
4. 用 `describe-instances`、`describe-volumes`、`describe-addresses` 和 `describe-nat-gateways`
   按 `ExperimentGroup` 检查没有运行实例、EBS、EIP 或 NAT Gateway。
5. 删除本轮临时 S3 object/bucket、SSM 临时 artifact 和本地临时 setup 目录。复用的
   `arladkr-ssm-<account>` 分发桶在轮末必须显式清空（`aws s3 rm --recursive` 后视情况删除桶），
   不能依赖单轮命令内的自动删除路径——2026-08-22 曾残留三轮共 211 个 setup 分片。
6. 只有确认后续不再使用时，才注销 AMI 并删除对应 snapshot：

```bash
aws ec2 deregister-image --profile arladkr-sso --region us-east-1 \
  --image-id ami-0746b30452d74675f
aws ec2 delete-snapshot --profile arladkr-sso --region us-east-1 \
  --snapshot-id snap-0d79faf532738800c
```

删除前必须确认没有实例仍引用该 AMI。清理完成后把资源清点和费用估算追加到本文件。

## Fabric 适配结果

本轮已完成 `practicaladkr_project_code/fabfile.py` 的关键 AWS 适配：

- 默认 AWS 管理面改为 SSM，运行用户改为 `ec2-user`；
- bootstrap 支持 Amazon Linux 的 `dnf`，并按 `arm64/amd64` 选择 Go 包；
- 预构建 AMI 模式跳过 Ubuntu 包安装、源码同步和不存在的 DXT 目录，只验证 Go、二进制和 SSM；
- `aws-up` 改为通过 SSM 检查节点，不要求 SSH；
- SSM setup 上传使用临时 SSE-S3 object、预签名 URL 和 SHA-256 校验，完成后删除 object/bucket；
- `aws-collect` 在 `management: ssm` 时通过 SSM 返回的有界 base64 records 收集 benchmark/status/log
  artifact，不再调用 SSH/SCP；每文件最多 4096 原始字节，以保持在 SSM inline-output 上限内。完整协议
  原始日志不属于该轻量采集路径，需要时应改用受控的临时 S3 artifact bucket；
- 论文实验配置固定保存 n=10 私网 roster；Spot interruption 后可在 preflight 中保留固定 roster 和
  故障节点，但 `aws-run-bench` 的新轮次必须先让完整 n 个在线节点通过 cleanup-ready，不能在缺节点时
  复用旧 fleet；缺节点轮次标记为 invalidated，不重新编号在线节点；
- setup 改为 `shared-public` 实验模式：本地一次生成全体节点材料并按项目/n/f/Paillier bits/源码提交缓存，
  单个公共 archive 只上传一个临时 S3 object，再用一次批量 SSM command 安装到全部在线节点。传输材料
  可公开，但为兼容协议加载器，secret 文件在实例上仍保持 `0600`；不再执行逐节点权限审计；
- `aws-up` 使用一次批量 SSM 健康检查；`aws-run-bench` 现在先执行跨协议的全节点 `cleanup-ready`
  barrier：停止并回收 `rladkr-*.service`、清理 benchmark/runner 进程和旧 marker，轮询 `pgrep` 归零，
  用 `ss` 检查 ARL 与 Practical 的全部声明端口，并在每个节点写入、校验新的 env/address map。
  只有 n 个节点全部返回 `cleanup-ready` 后才生成新的同步 `start_at`；runner 随后仍在 `n-f` 节点
  ready 后启动，artifact collect 对在线节点并行；
- n=10 首次缓存构建与安装实测：ARLADKR 约 4 秒，PracticalADKR 约 10 秒。后续 cache hit 时两项目
  可并行完成，整体约 10 秒量级；旧串行流程每项目需要数分钟和约 30 次 SSM command；
- 新增配置 `practicaladkr_project_code/deployment/config.aws-arm64-ssm.yaml`，固定 AMI、私网地址、
  单 AZ、Spot 和 n=10。
- ARL 分布式 env 现在显式提供每节点 `RLADKR_ARTIFACT_CACHE_DIR`，并把 old actor `0..n-1` 与
  receiver actor `n..2n-1` 映射到同一实例的两组固定端口；lane offer 允许至多 `f_new` 个发送失败
  进入既有 fallback 证明路径，不再因单个启动竞态终止整个 epoch。
- Practical 的 threshold setup 升级为 v2：同一 artifact 同时携带 `n-f` high-threshold 与 `f+1`
  low-threshold BLS shares，运行时按 Dumbo domain 选择 signer。离线 setup 仍只生成一次并分发，不计入
  在线 latency。
- Terraform 继续保留现有 `10.42.1.0/24` smoke 子网，并从 host offset 10 为每个 slot 分配确定性
  私网 IP；n=256 时必须显式传入不小于 `/23` 的 `node_subnet_cidr`。`node_roster` 按 slot 输出
  instance ID、private/public IP、Region 和 AZ。
- Fabric 动态 roster 强制校验唯一且连续的整数 `NodeSlot=0..n-1`，不再按 IP 字符串排序。新增独立
  `config.aws-public-ssm.yaml`；公网协议模式默认关闭，开启后 Terraform 只允许本 fleet 公网 `/32` 和
  显式跨 Region peer `/32` 访问 inventory 指定的 TCP 端口。管理面仍使用 SSM，不开放 SSH。
- SSM 管理模式的源码同步不再依赖 SSH：控制机只打包一次配置的源码树，经临时 SSE-S3 object 分发，
  节点校验 SHA-256 后安装；object 和临时 bucket 在完成或失败后都会删除。该路径用于源码同步和 AMI
  预热，预构建 AMI 的普通 `aws-paper-run` 不会在每轮重复构建源码。
- 新增 `aws-paper-run`，为每轮创建独立 Terraform state、运行配置、inventory、artifact 与 JSON
  实验记录，并顺序执行 apply、SSM 检查、setup、benchmark、wait、collect 和 destroy。异常及 Ctrl-C
  同样进入 finally 清理；只有显式 `--keep-fleet` 才保留资源。实验名限制为至多 37 个 IAM 安全字符。

## n=10 同 AZ 实测结果

以下三轮均使用 `us-east-1f`、10 台 `c7g.xlarge` Spot、私网 TCP、`n=10/f=3`、`runs=1`，
且 setup keygen 不计入在线延迟。通信量为单节点 benchmark 报告值；论文正式数据仍应增加重复轮次并
报告跨节点/跨轮次分布。

| run_id | 项目/设置 | latency | online | setup | sent | recv | 状态 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `run-20260817-175428` | ARLADKR，CV smoke | 4136.18 ms | 4016.91 ms | 119.27 ms | 2,934,856 B | 1,936,224 B | 10/10 success |
| `run-20260817-181151` | Practical，matched-lifetime | 4437.09 ms | 4429.11 ms | 7.91 ms | 1,045,108 B | 999,783 B | 10/10 success |
| `run-20260817-181301` | Practical，high-assurance | 4102.60 ms | 4094.94 ms | 7.58 ms | 990,883 B | 992,709 B | 10/10 success |

ARL 的报告 latency 已按既定口径扣除 recovery service grace；该轮原始 latency 为 5136.88 ms，
扣除的 service grace 为 1000.70 ms。ARL candidate formation 为 2572 ms，平均 ACK/fallback 数为
9/1。n=10 下 `smoke` 仅用于流程验证，不是正式安全参数点；`2^-80` 需要的 sample 超过 n=10。

## 尚未完成的下一步

- 单 Region 一键生命周期已用 PracticalADKR n=10 实际验证。cleanup-ready barrier 已通过定向 Fabric
  测试，下一步先在同一 AMI/topology 下完成
  ARL、Practical 默认和 Practical high-assurance 各至少 5-10 个 matched fresh run，报告 median/p95，
  不把单轮数值直接作为论文结论。
- ARL n=10 只能使用 smoke sampling；正式安全参数比较需要选择能容纳目标 sample 的更大 n。
- 在 n=16/32 前验证 Spot 容量；正式论文数据优先考虑 On-Demand，Spot interruption 的轮次不保留。
- 多 Region 的统一 roster、跨 Region SSM 同步启动和收集仍未实现；当前公网改动只完成单 Region
  动态公网流程和 regional stack 的 peer CIDR 基础，不得据此声称已支持正式跨洲实验。

## 追踪条目模板

复制以下表格追加到本文件末尾，每个 `run_id` 一行：

| 日期/UTC | run_id | 项目/采样 | n/f | Region/AZ | AMI | 实例数 | 状态 | latency | comm | 费用估算 | 清理 |
| --- | --- | --- | ---: | --- | --- | ---: | --- | ---: | ---: | ---: | --- |
|  |  |  |  |  |  |  |  |  |  |  | pending |

## 2026-08-18 单 Region 公网 smoke

本轮用于验证公网 TCP 编排，不作为论文安全参数或正式性能数据。配置为
`us-east-1/us-east-1f`、AMI `ami-0746b30452d74675f`、10 台 `c7g.xlarge` Spot、`n=10`、`f=3`，
公网协议端口 `30000-60000`，管理面为 SSM；setup/keygen 不计入在线协议 latency。

| run_id | 项目/参数 | ready | 结果 | latency | grace | 在线协议 | sent/recv | 状态 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `run-20260818-040740` | ARLADKR，错误参数 `-cv-sampling-target smoke` | 10/10 | 0/10 | - | - | - | - | invalidated：参数名不存在 |
| `run-20260818-041039` | ARLADKR，`-cv-failure-target smoke`，缺少确定性 base port | 10/10 | 1/10 | - | - | - | - | invalidated：receiver `:30011` 连接拒绝 |
| `run-20260818-042133` | ARLADKR，`-cv-failure-target smoke` | 10/10 | 10/10 | **4663.83 ms** | 1001.39 ms | **4544.39 ms** | **35,978,407 / 35,797,564 B** | success |

有效轮的 10 个节点均报告 `success_runs=1`，唯一 consensus hash 为
`e7e30fc260a4a9d0318af276c61d10ab42291a2772caefa1d4bf2e9b16f3afea`，setup bundle digest 为
`5972bf860b245aeaf8440356d23cd87e2e08a6dd35a1ed6408fe03a4972f50b9`。10 个节点报告 latency 均值为
4663.83 ms；按本项目约定扣除 recovery-service grace 后，在线协议均值为 4544.39 ms，原始均值为
5665.21 ms。`candidate_formation_ms` 均值为 2803.40 ms，`leaf_build_ms` 均值为 912.70 ms；
`cv_failure_target=smoke` 只验证流程，不代表目标安全参数。

041039 轮失败的根因是 Fabric 生成了与 `network.node_port_base=30000` 一致的公网地址表，但没有
把 `-base-port 30000` 传给 ARL 二进制，导致本地监听器使用随机端口而远端拨号固定的 `:30011`。
Fabric 已在 `_normalize_aws_bench_args` 中对 `arladkr`/`rladkr-go` 自动注入配置的 base port，并增加
回归测试；协议实现和论文参数未改变。

### 本轮 AWS 成本与清理

实例启动时间为 `04:03:21-04:03:25 UTC`，终止时间为 `04:24:52-04:24:53 UTC`，平均单实例存活
1291.1 秒，合计约 3.586 instance-hours。按本时段 Spot 观察价 `$0.0524/h` 估算：

| 项目 | 计算 | 估算 |
| --- | --- | ---: |
| c7g.xlarge Spot | 3.586 h x `$0.0524` | `$0.188` |
| 公网 IPv4 | 3.586 h x `$0.005` | `$0.018` |
| gp3 根盘 | 10 x 30 GiB x 0.3586 h / 730 x `$0.08/GiB-month` | `$0.012` |
| 公网出站流量上界 | 35,978,407 B x `$0.09/GB` | `$0.003` |
| 合计 | 不含 AMI snapshot 长期存储 | **约 `$0.22`** |

费用是实验期间的实时估算，Spot 账单、IPv4 计费粒度和同 Region 公网流量最终以 Cost Explorer 为准。
Terraform 缩容第一次遇到旧 SG ingress revoke 的 AWS 幂等竞态，重试后已显示 `No changes`。最终清点：
实验 tag 下运行/停止实例 `0`、creating/available/in-use 实验 EBS `0`、已关联或已分配 EIP `0`、
可用/待处理 NAT Gateway `0`。VPC、subnet、route table、SG、IAM role/profile 和 AMI 未删除，后者
仍产生 snapshot 存储费。

## 2026-08-18 新 AMI 后 PracticalADKR 公网 smoke

旧 AMI `ami-0746b30452d74675f` 内置的 `bench_latency` 仍是 threshold-setup v1，
与当前源码 v2 不兼容。本轮先从旧 AMI 启动临时 source instance，通过 SSM 安装当前源码构建的
ARM64 二进制（`bench_latency` SHA-256 `7399ea6b...ccb02c`，`rladkrbench` SHA-256
`3eef2b5f...995b63d`），创建新 AMI `ami-0cee8a82967ef97ac`，再启动实验 fleet。

实验配置为 `us-east-1/us-east-1f`、10 台 `c7g.xlarge` Spot、公网 TCP、SSM 管理、`n=10/f=3`、
Practical `paillier-bits=3072`、`runs=1`、`kappa-profile=matched-lifetime`。setup bundle digest 为
`ac9d13f4bf49ad4b89865c915a904858659b51ce6ef5ab4fa9be88f3be17b77e`。

| run_id | ready/result | mean latency | mean online | p50/p95 | 状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| `run-20260818-054826` | 10/10, 10/10 | 4438.63 ms | 4428.76 ms | 3899.42/4707.69 ms | success |

10 个节点的 consensus hash 一致；每节点 `success_runs=1`，`fallback_runs=0`，`timeout_runs=0`。
本轮未启用 `comm-metrics`，因此通信字节字段为 0，不用于通信量结论。该结果仅为公网流程 smoke，
不是论文正式性能数据。

说明：账号当前仅配置 SSM、没有 SSH key，标准 Fabric 源码同步步骤未执行；AMI 中运行的
`bench_latency` 与 `rladkrbench` 已由当前工作树交叉编译为 ARM64、完成 SHA-256 校验后通过 SSM 安装，
因此本轮执行二进制版本与当前源码一致。后续若需要在 AMI 内保留完整源码树，应补充 SSM 源码归档同步流程。

实例已全部清理，临时 S3 bucket 已删除。AWS 记录显示 source instance 存活约 11.3 分钟，10 节点
fleet 存活约 6.3 分钟，合计约 1.24 instance-hours。按 c7g.xlarge Spot 约 `$0.0524/h` 估算，
实例费用约 `$0.065`，公网 IPv4、gp3 与少量流量约 `$0.01`，合计约 `$0.08`；新 AMI snapshot
当前可见逻辑块约 2.67 GiB，按 `$0.05/GiB-month` 约 `$0.13/月`，实际增量账单以 Cost Explorer 为准。

## 2026-08-18 单 Region 一键生命周期验证

本轮验证新增的隔离 Terraform/Fabric 流程，不作为论文正式性能数据。两次预检查
`paper-practical-n10-use1-20260818-ssm-v1` 和 `paper-practical-n10-use1-20260818-ssm-v2` 分别在
provider 下载阶段被中断、在 plan 阶段发现 IAM 名称过长；两次都未创建 AWS 资源。修复后执行：

```bash
AWS_PROFILE=arladkr-sso fab aws-paper-run \
  --project=practical-adkr \
  --bench-args='-n 10 -f 3 -runs 1 -timeout 60s -paillier-bits 3072 -mvba-network tcp -strict-network=true -comm-metrics=true' \
  --config-path=deployment/config.aws-public-ssm.yaml \
  --experiment-name=p10-use1-20260818-ssmv3 \
  --timeout-s=300
```

| experiment/run | n/f | ready/result | mean latency | mean online | mean sent/recv per node | fleet sent/recv | 状态 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `p10-use1-20260818-ssmv3` / `run-20260818-080926` | 10/3 | 10/10, 10/10 | 3928.81 ms | 3918.52 ms | 989,639 / 989,588 B | 9,896,392 / 9,895,879 B | success |

10 个节点的 consensus hash 均为
`88a5b20bb87530aa241602f85bbe709c784c591477b3f8101bbb251d7434fba9`，setup digest 均为
`b157e08a9b3ca0e34d18367907232379964235d30b35fab2ff891fb23909f953`。实验固定
AMI `ami-0cee8a82967ef97ac`，源码身份为
`6e554391ee862b761ebc76c494b51d827e20a8561273578fa60adac3d6201fb4`。本地记录位于
`practicaladkr_project_code/deployment/aws-state/p10-use1-20260818-ssmv3/`。

实例从创建到销毁约 3.4 分钟，10 台合计约 0.57 instance-hours。按本时段 Spot 约 `$0.0524/h`、
公网 IPv4 `$0.005/h`，加 gp3 和不足 0.02 GB 的协议流量，估算约 `$0.04`，不含持续保留的 AMI
snapshot。流程完成后 Terraform 成功销毁 29 个资源；按 ExperimentGroup 复核，pending/running/
stopping/stopped 实例为 0，VPC 为 0，临时 S3 object/bucket 为 0。

### ARLADKR 验证轮

随后用同一 AMI、AZ、实例类型和一键生命周期运行 ARLADKR：

| experiment/run | n/f | ready/result | mean latency | mean online | mean raw/grace | mean sent/recv per node | fleet sent/recv | 状态 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `a10-use1-20260818-ssm01` / `run-20260818-082651` | 10/3 | 10/10, 10/10 | 5244.69 ms | 5121.67 ms | 6245.57 / 1000.88 ms | 3,793,560 / 3,780,903 B | 37,935,599 / 37,809,028 B | success |

所有节点 consensus hash 均为
`7f6fb4e5baa7d52466eafecf90bf5c7c2ffa86ee22e09d92e6e50204c71ec504`，setup digest 均为
`8e5c81c6cce7b2040d096f3c8592d389a592ba914550d1b899cf1029f5798b95`。平均 leaf build 为
1067.50 ms，candidate formation 为 3154.10 ms，ACK/fallback 为 8.5/1.5。结果使用 `smoke`
sampling，只验证 n=10 流程；延迟按既定口径扣除了 recovery service grace。

实验记录的源码身份为 `5fb95a25961c648835e239cdd404bd17eb8b71a313262a0bc7cb89f68d15184f`，
本地 record 与 artifact 位于
`practicaladkr_project_code/deployment/aws-state/a10-use1-20260818-ssm01/`。10 台实例实际存活约
99-103 秒，合计约 0.286 instance-hours；按 Spot、IPv4、gp3 和公网出站上界估算约 `$0.02`。
Terraform 成功销毁 29 个资源，复核 pending/running/stopping/stopped 实例、VPC 和 EBS 均为 0。

### 同 fleet 交替验证失败轮

`suite10-use1-20260818-r01` 首次尝试以同一批 10 台 `c7g.xlarge` Spot、同一 AMI、AZ、roster、
公网 TCP 和 Security Group 依次运行 ARL、Practical 默认、Practical high-assurance。ARL
`run-20260818-084113` 已 10/10 成功；随后 Practical 默认 `run-20260818-084926` 的 10 个节点均为
`success_runs=0`、`timeout_runs=1`，没有 consensus hash。因此整轮标记为 **invalidated**，未运行
high-assurance，也不纳入任何 latency/communication 比较。

现有 artifact 只能确认该失败发生在同 fleet 的跨协议切换后，尚不足以证明具体原因；不得把它归因于
任一协议。失败 artifact 保留在
`practicaladkr_project_code/deployment/aws-state/suite10-use1-20260818-r01/artifacts/practical-default/`。
实例于 `08:40:15-19 UTC` 启动、`08:57:31-33 UTC` 终止，合计约 2.88 instance-hours，按 Spot、IPv4、
gp3 与少量流量估算约 `$0.18`。复核实例、VPC 和 EBS 均为 0，Terraform 销毁 29 个资源。

## 2026-08-18 cleanup-ready barrier AWS 验证

第一次使用 ExperimentGroup `p10-use1-barrier-20260818`。10 台实例于 `10:03:15-19 UTC` 启动，
barrier 中按 path 执行的 `pkill -f` 同时匹配了当前 cleanup shell 命令行里的旧 runner 文件名，导致
0/10 cleanup-ready。协议没有启动，轮次标记为 invalidated。实例于 `10:06:15-17 UTC` 终止，累计
1795 instance-seconds，即 0.499 instance-hours：Spot `$0.0263`、公网 IPv4 `$0.0025`、gp3
`$0.0016`，合计约 `$0.030`。Terraform 销毁全部 29 个资源。

修复后使用 ExperimentGroup `p10-use1-barrierfix-20260818` 和 run ID
`run-20260818-101237`。本轮得到：

- cleanup-ready `10/10`；
- runner launch `10/10`；
- runner ready `10/10`，quorum 要求 `7`；
- 只有上述 barrier 完成后才发布同步 `start_at=1787047980`；
- 70 秒状态为 success `0/7`、failed `8`、running `2`，因此 Practical benchmark 未形成 quorum。

该轮只证明 Fabric cleanup/env/address/start barrier 在真实 AWS 上通过，不是 Practical 性能结果，
也不能据此归因协议失败原因。旧失败路径在 destroy 前没有调用 collect，因此本轮没有保存 journal；
代码随后改为失败时先尽力 collect，并为每节点保存对应 transient unit 的 `systemctl status` 与
`journalctl -u`。相关 Fabric 单元测试为 29/29 通过。

第二轮实例于 `10:10:24-28 UTC` 启动、`10:14:54-58 UTC` 终止，累计 2691 instance-seconds，
即 0.748 instance-hours：Spot `$0.0394`、公网 IPv4 `$0.0037`、gp3 `$0.0025`，加少量未采集协议
流量后按 `$0.046` 记账。两轮新增约 `$0.076`，本文已量化历史成本由 `$1.20` 累计到约 `$1.276`
（取两位小数 `$1.28`），不含 snapshot 持续费用和更早未量化资源。

最终按两个 ExperimentGroup 复核：pending/running/stopping/stopped 实例、实验 EBS、VPC 均为 0，
两次 Terraform 都销毁 29 个资源。下一次付费重试必须使用新增的失败诊断收集路径；在拿到 unit journal
并定位 Practical 失败前，不继续盲目创建 fleet。完成单项目 fresh-fleet 验证后，再做三配置同 fleet
交替和 matched repeated runs；多 Region 工作仍按原计划后置。

## 2026-08-18 Practical DXT 启动竞争修复（本地）

继续分析旧的 `suite10-use1-20260818-r01` artifact 后，发现失败节点的单轮退出时间分成明显层次：
4 个节点分别约为 `3.851s`、`3.925s`、`4.328s`、`4.354s`，贴近 DXT 网络 ACK 的默认 `4s`
窗口；其余节点约为 `18-19s` 或 `55s`。同一 AMI、源码 revision、n/f 与 setup digest 的独立
fresh-fleet 轮次 `run-20260818-080926` 曾 10/10 成功。这说明 cleanup barrier 已不是当前失败点，
更可能是各进程完成密钥加载和 listener bind 的时间不同，而 DXT dealer 在本机 listener 建立后就立即
启动，没有等待远端 receiver listener 达到协议所需阈值。旧轮次没有保存 journal，因此这里记录为
高概率定位，而不是已由运行日志严格证明的根因。

已在 PracticalADKR 的 DXT TCP service 中增加带 `SID`、`epoch` 和目标 node ID 绑定的 readiness
request/ack。每个分布式 dealer 在发起 DXT 前等待至少 `2f+1` 个新委员会 receiver 返回有效 ACK；
该阈值与 DXT transcript 的真实 ACK 条件一致，不要求无故障的 n/n，也不改变 DXT 密文、证明、
APDB、MVBA 或恢复协议。等待耗时写入现有 `dxt_network_wait` phase；readiness 控制流量不计入协议
通信量。benchmark 现在还会把 `PRACTICAL_RUN_ERROR` 写进每节点 bench artifact，下一次失败无需仅
依赖全局 stderr 即可看到具体阶段。

新增测试覆盖延迟启动时不会提前越过 `2f+1` barrier、达到 quorum 后继续、错误 epoch 被拒绝，
以及 readiness 字节不进入协议通信统计。本地定向 network tests 和全包编译检查通过。本地修复阶段
尚未创建 AWS 资源，当时累计量化成本保持约 `$1.276`；随后按下节只运行一次 n=10 Practical
fresh-fleet 复验，并使用已经启用的 unit journal 收集。

### Fresh-fleet AWS 复验

第一次复验使用 `p10-use1-dxtready-20260818`。Terraform 成功创建 29 个资源，但随后 Fabric 的
dynamic inventory 使用裸 `boto3.client`，没有继承 Terraform 已显式使用的 `arladkr-sso` profile，
因此在协议启动前报 `NoCredentialsError`。`finally` 正常销毁全部 29 个资源。已把 Fabric 内 EC2、
SSM、S3 和 STS 的 14 个 client 创建点统一到 profile-aware factory，并在公网配置中显式固定
`profile: arladkr-sso`；新增单测验证 profile/Region 传递。Fabric 测试为 30/30 通过，真实 STS
调用也返回账号 `992382847511`。

CloudTrail 显示该失败轮实例约从 `10:38:48-51 UTC` 存活到 TerminateInstances
`10:39:50 UTC`，按每台至少 60 秒计约 0.169 instance-hours。Spot、IPv4 和 gp3 合计保守记
`$0.011`，没有协议流量。

修复后以 `p10-use1-dxtreadyfix-20260818`、run ID `run-20260818-104738` 重跑相同 n=10、f=3、
3072-bit Paillier、strict public TCP 配置，结果为：

- SSM online、cleanup-ready、launch、runner ready 均为 10/10；
- 同步 `start_at=1787050206` 只在 runner ready 10/10 后发布；
- 4 秒状态检查已经 success 10/10、failed 0，quorum 要求为 7；
- artifact 10/10 收集成功，setup bundle digest 一致；
- 10 个节点的 consensus hash 均为
  `2bc13120e69b17cf2c98a2c5deecdcb7f0db4386a0ecd58d71f405a5ba1923aa`；
- 节点延迟均值 `3892.41 ms`，范围 `3665.01-4117.56 ms`；平均 online protocol
  `3881.83 ms`，平均发送/接收 `985038/984810` bytes；
- 本轮所有节点在进入 DXT 时已达到 readiness quorum，因此记录的 `dxt_network_wait` 为 `0 ms`；
  该值不表示 barrier 未执行，只表示没有额外等待。

成功轮 CloudTrail launch 到 TerminateInstances 合计约 3714 instance-seconds，即 1.032
instance-hours。Spot 约 `$0.0544`、公网 IPv4 约 `$0.0052`、gp3 约 `$0.0034`，少量流量后按
`$0.063` 记账。两轮新增约 `$0.074`，量化累计由 `$1.276` 更新为 `$1.350`（约 `$1.35`），
不含持续 snapshot 费用。

成功轮 artifact 位于
`practicaladkr_project_code/deployment/aws-state/p10-use1-dxtreadyfix-20260818/artifacts/`。最终复核两个
ExperimentGroup 的实例均为 `terminated`，EBS 和 VPC 查询均为空，Terraform 两轮各销毁 29 个资源。

## 2026-08-18 三洲 n=10 编排准备

新增最小的跨 Region Fabric 编排，固定 `us-east-1:4`、`eu-west-1:3`、
`ap-southeast-1:3` 和连续 NodeSlot 0-9。SSM discovery、单节点命令、区域批量命令、ready quorum、
状态轮询和 artifact 收集都按目标 Region 路由；三份 Terraform state 先独立创建，再使用其他 Region
公网地址的 `/32` 二次 apply。ARLADKR 与 PracticalADKR 将复用同一 fleet，并由 cleanup-ready 屏障
隔开。新增 3 项跨 Region 测试后 Fabric 全套为 33/33 通过，三 Region dry-run 也完成 apply/peer
CIDR plan/协议顺序/逆序 destroy 全流程，没有创建实例。

源 AMI `ami-0cee8a82967ef97ac` 已复制为 `eu-west-1/ami-09c02ed1bf7b2b15b` 和
`ap-southeast-1/ami-0091cf6c0499f49fe`，两者均已 available。复制前确认目标 Region 无可复用镜像，
三 Region 无 pending/running/stopping/stopped 的 `ProtocolSuite=rla` 实例。按此前记录的约
21.34 GiB 实际 snapshot 数据估算，两份副本持续存储约 `$2.13/月`，另有一次性跨 Region copy
数据传输费用，需以后续账单为准。该项暂不并入按实例生命周期量化的 `$1.350`，成本台账记为
`$1.350 + AMI copy/storage pending`；实验结束后若不再重复跨 Region 测试，应注销两份 AMI 并删除
对应 snapshot，停止持续计费。

## 2026-08-18 三洲 n=4 Spot 中断定位与悉尼替代

`cross-n4-3c-20260818-r03` 使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-1:1`，所有实例均为 `c7g.xlarge Spot`。四节点完成 SSM online、setup 分发、
cleanup-ready、runner launch 和 ready 4/4，并在 `start_at=2026-08-18T12:07:43Z` 同步进入协议。
本轮不能用于判断 90 秒是否足够：新加坡实例的 Spot request `sir-rcizhd7p` 在
`12:07:22Z` 已收到 `instance-terminated-no-capacity`，即同步启动前 21 秒已进入 AWS 两分钟
回收通知窗口，最终由 AWS service 在 `12:09:25Z` 终止。其余实例由 Terraform 正常终止。

四台实例合计存活约 2068 instance-seconds，即 0.574 instance-hours；按运行时三地 Spot 价、
公网 IPv4、gp3 与少量流量估算约 `$0.05`。加上此前跨 Region 尝试后，本文量化累计暂记约
`$1.69`，AMI copy 和 snapshot 持续费用仍单列。三 Region 的实验实例、VPC 和 EBS 已复核为 0。

为避免 Spot 中断掩盖协议诊断，Fabric 的失败收集现在自动只对仍在线节点执行 best-effort collect，
manifest 记录 expected/unavailable hosts；cross-region suite 保留 benchmark quorum failure 为主错误，
把 collect failure 作为附加字段。该修改不改变协议、计时或通信口径，Fabric 测试为 34/34 通过。

按 Spot placement score，亚太候选当前最高仅 3/10；后续仍坚持 Spot，第三地改为
`ap-southeast-2/ap-southeast-2c`。预烘焙镜像已复制为
`ap-southeast-2/ami-09b5f867c562fbd39` 并 available。该副本约增加 21.34 GiB snapshot 的持续
存储和一次性跨 Region copy 费用，最终以账单为准。

## 2026-08-18 三洲 n=4 `r04/r05` 启动路径定位

`cross-n4-3c-20260818-r04` 的四台 Spot 实例均成功创建，但跨 Region `/32` 规则的第二次
Terraform apply 报 `InvalidPermission.Duplicate`，协议没有启动。原因是同一 security group 同时由
inline `ingress` 和独立 `aws_vpc_security_group_ingress_rule` 管理。Terraform 已改为仅使用独立的
`private_self` ingress rule；`terraform fmt -check` 和 `terraform validate` 通过。该轮资源全部销毁，
估算新增约 `$0.03`。

`cross-n4-3c-20260818-r05` 使用 `us-east-1:2`、`eu-west-1:1`、`ap-southeast-2:1`，四台实例
均为 Spot，且实验期间没有回收事件。SSM 4/4、setup、cleanup-ready、launch 和 runner ready 均成功，
但 ARLADKR 很快失败为 `remote readiness timeout: ready=2/3`。各节点日志显示欧洲/悉尼节点先打开
listener，等待远端 120 秒后退出；较慢的美国节点约一分钟后才进入同一阶段，此时早期 listener 已
关闭并产生 `connection refused`。因此本轮定位为 listener 生命周期覆盖范围不足，而不是 90 秒
benchmark timeout 或 MVBA 工作量问题；PracticalADKR 没有启动。

`RunCVEpochV2` 现于本地 epoch runtime/密码学材料加载前创建 agreement TCP transport，并让该
transport 在整个加载阶段保持存活。该修改不改变协议消息、证明或在线 latency 口径。Fabric suite
还会在 SSM fleet 全部在线后、协议 setup 前将当前源码交叉编译为 Linux ARM64 二进制并原子安装，
把 archive、`rladkrbench` 和 `bench_latency` 的 SHA-256 写入 `experiment-record.json`；因此后续轮次
不会误用预烘焙 AMI 中的旧二进制。失败 artifact 改为逐文件 SSM 收集，避免 4096-byte inline output
截断。相关 Fabric 测试为 37/37，通过 Go transport/readiness 定向测试与 compile-only 校验。

`r05` 从 `12:31:42Z` 至 `12:40:32Z`，四台合计约 0.589 instance-hours；计入 Spot、IPv4、gp3
和少量跨区流量后保守估算约 `$0.04`。`r04/r05` 新增约 `$0.07`，量化累计从 `$1.69` 更新为约
`$1.76`；AMI copy/snapshot 持续成本仍单列。销毁后已复核美国、爱尔兰、悉尼三地实验实例和 EBS
均为 0。

## 2026-08-18 三洲 n=4 `r06` listener 修复实机验证

`cross-n4-3c-20260818-r06` 继续使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-2:1`，Terraform plan、state 和实例 metadata 均确认四台为 `c7g.xlarge Spot`，没有
On-Demand fallback。跨区 `/32` 二次 apply、SSM 4/4、当前源码二进制 staging、setup、cleanup-ready
与 runner ready 4/4 均成功。实验记录的 `rladkrbench` SHA-256 为
`b3c208f078d1af1febdd53cd705e2ac97a7293f3e491476abc4c3b02f47492ee`，与本地当前源码 ARM64
构建一致。

ARLADKR 达到论文 runner 的 n-f=`3/3` 成功判据，三名成功节点 consensus hash 均为
`6033c1421699a2e4f7829596a9c86a406cf8c5b7be44d322cab45e4ebb5c4d45`。成功节点报告的
service-grace-adjusted latency 约 `23.71-26.29 s`，raw latency 约 `24.71-27.29 s`，candidate
formation 约 `8.98-9.64 s`。悉尼节点失败为 aggregate recovery 仅达到 1 holder、需要 2；这不影响
n-f 成功判据，且已确认不再是 `r05` 的 listener readiness 启动偏斜。

PracticalADKR 本轮没有启动，因为 artifact 收集器仍将单个 ARL benchmark 文件限制为 4096 bytes。
ARL 的单行结果超过该上限，虽逐文件 SSM 收集避免了文件间截断，单文件本身仍被静默截断，summary
解析为 0 results 并报 `collected nodes disagree on setup bundle or timing metadata`。收集器现改为先查询
文件字节数、再以不超过 2 KiB 的 base64 块分页读取并严格校验块长度，默认单文件上限 1 MiB；summary
的一致性也只在成功的 n-f 样本集合内比较，失败节点仍保留诊断。新增 7 KiB artifact 重组与
3-success/1-failure quorum 回归测试后，Fabric 为 39/39 通过。

`r06` 从 `13:00:23Z` 至 `13:11:17Z`，按三地当时 Spot 价（美国 `$0.0732`、爱尔兰
`$0.0744`、悉尼 `$0.0887` 每台小时）、公网 IPv4、gp3 与少量流量保守记约 `$0.06`；量化累计
由约 `$1.76` 更新为约 `$1.82`，AMI copy/snapshot 持续成本仍单列。Terraform 逆序 destroy 完成后，
三地 pending/running/stopping/stopped 实验实例与 available/in-use 实验 EBS 均复核为 0。

## 2026-08-18 三洲 n=4 `r07` 同 fleet 比较与 Practical APDB 定位

`cross-n4-3c-20260818-r07` 继续使用 `us-east-1:2`、`eu-west-1:1`、
`ap-southeast-2:1`。四台实例均为 `c7g.xlarge Spot`，Terraform 的
`instance_market_options.market_type` 为 `spot` 且中断行为为 `terminate`，没有 On-Demand fallback。
当前源码 ARM64 二进制、跨区公网 `/32` allowlist、SSM、setup、cleanup-ready、launch 和 runner-ready
均为 4/4；ARLADKR 与 PracticalADKR 使用相同实例、公网地址和拓扑，中间经过 cleanup-ready 屏障。

ARLADKR 达到 n-f=`3/3`，三名成功节点 consensus hash 均为
`9053aec0dd50fca4556cb97f3f3cf96d98182786f5b52e1947bf9130b1279469`。成功节点报告的
service-grace-adjusted latency 约 `15.97-20.16 s`，raw latency 约 `16.97-21.16 s`，candidate
formation 约 `6.08-6.32 s`。悉尼节点 aggregate recovery 未达到所需 holder 数，但不影响 n-f 成功
判据。新的分块 SSM 收集器完整收集了四份 ARL artifact，验证了 `r06` 的截断修复。

PracticalADKR 四个节点均未完成。悉尼节点先失败为
`network APDB readiness: reachable=1 need=3`；美国和爱尔兰节点随后分别在 Dumbo-MVBA 的
quitPD 或 permutation coin 阶段超时。代码审计确认 APDB readiness 将每个 peer 的 TCP dial 固定为
`100 ms`、完整 request/ack I/O 固定为 `200 ms`。该窗口适用于同 Region，但小于或接近悉尼到美国/
爱尔兰的公网 RTT，因此悉尼只能计入本地节点；其他节点继续推进后形成阶段偏斜。这不是 Spot 容量、
Terraform、SSM、地址表或 90 秒总 timeout 问题。

APDB readiness 现使用可配置的 `PRACTICAL_APDB_READY_DIAL_TIMEOUT_MS` 和
`PRACTICAL_APDB_READY_IO_TIMEOUT_MS`，默认分别为 `1000 ms` 和 `2000 ms`；peer 探测并发执行，
quorum 仍严格为 n-f，不改变 APDB、MVBA 或密码学协议。新增测试模拟 `350 ms` ACK，验证跨洲 RTT
不再被旧的 `200 ms` 窗口拒绝；两份 Practical module 的定向测试及 compile-only 检查均通过。

`r07` 从 `13:22:47Z` 至 `13:37:45Z`，四台实例主要运行约 15 分钟。按三地 Spot 价、公网 IPv4、
gp3 和少量跨区流量保守新增约 `$0.09`，量化累计由约 `$1.82` 更新为约 `$1.91`；AMI copy/snapshot
持续成本仍单列。Terraform destroy 完成后已再次查询美国、爱尔兰、悉尼三地，
pending/running/stopping/stopped 实例及 available/in-use EBS 均为 0。

## 2026-08-18 三洲 n=4 `r08` CompProve 定位与销毁流程补强

`cross-n4-3c-20260818-r08` 使用与 `r07` 相同的美国 2、爱尔兰 1、悉尼 1 topology，四台均为
`c7g.xlarge Spot`，没有 On-Demand fallback。当前源码 ARM64 binary staging、SSM、跨区 `/32`、
cleanup-ready 和 runner-ready 均为 4/4。ARLADKR 达到 n-f=`3/3`，成功节点 consensus hash 均为
`e76706d468f8d357f53145e5931f68d69275f37d7eb8f430819316b49b670372`；成功节点
service-grace-adjusted latency 约 `20.07-24.69 s`。悉尼节点仍因 aggregate recovery holder 不足失败，
但不影响 n-f 成功判据。

PracticalADKR 不再出现 `network APDB readiness: reachable=1 need=3`，证明 `r07` 后增加的 APDB
跨洲 readiness 窗口已生效。失败推进到 Algorithm 3 CompProve：两个接收者只有
`valid=2 ids=[5 6] need=3`，另一节点报告本地 ACK aux 缺失。代码审计发现 CompProve listener 在各
进程内创建，但 share multicast 前没有跨节点 readiness；单次 route 默认约 `500 ms`，整个 key
derivation 默认 `15 s`，对跨美国、爱尔兰、悉尼的阶段偏斜过于激进。

CompProve 现于发送 key share 前并发探测新委员会 listener，并要求 n-f 返回绑定 `SID`、epoch 和
recipient 的 ready-ack；该控制流不计入协议通信量。严格网络默认 key-derivation 窗口调整为 `45 s`，
CompProve route I/O 至少 `2 s`，分别可由 `PRACTICAL_KEY_DERIVE_TIMEOUT_MS`、
`PRACTICAL_COMPPROVE_ROUTE_TIMEOUT_MS`、`PRACTICAL_COMPPROVE_READY_DIAL_TIMEOUT_MS` 和
`PRACTICAL_COMPPROVE_READY_IO_TIMEOUT_MS` 覆盖。n-f share threshold、CompProve 证明及验证逻辑均未
改变。新增测试验证 listener 数不足时不会提前继续，达到 n-f 后才放行；两份源码镜像保持逐字一致。

Fabric cross-region suite 现在还会在最后一个协议 collect 后、Terraform destroy 前执行一次全节点
cleanup-ready，复用已有的 systemd stop/kill、`pgrep`、`ss` 端口释放和 marker 清理逻辑。最终 cleanup
失败只写入 `experiment-record.json`，不会阻止逆序 destroy，避免资源因诊断失败滞留。Fabric 39 项
测试通过；CompProve、APDB 定向测试及 compile-only 检查通过。完整 Practical core 测试中既有的
`TestPartialVerifyN7Comparison` 曾因时序进入 `full-local-fallback`，启用 trace 重跑后 21 个 vote 条目
全部达到 5 票并通过；该项记录为与本次修改无调用关系的测试时序不稳定。

`r08` 从 `13:55:45Z` 至 `14:10:55Z`，四台 Spot 主要存活约 15 分钟，按三地 Spot、公网 IPv4、gp3
和少量流量保守新增约 `$0.09`，量化累计由约 `$1.91` 更新为约 `$2.00`；AMI snapshot 持续费用仍
单列。实验记录为 `cleanup=destroyed`。本次审计没有发现 OS、SSM agent、systemd 或依赖层缺陷；当前
启动后 staging 会校验最新二进制 digest，因此暂不重建 AMI，避免无必要的 snapshot 和跨区复制成本。

## 2026-08-19 三洲 n=4 `r09` Spot 回收与资源清理

运行 `cross-n4-3c-20260819-r09` 前，另发现并清除了 `us-east-1` 中遗留的
`smoke-n10-use1-20260818-practical-v2` VPC `vpc-03903797302e14bd2`，包括其 subnet、security
group、route table 和 internet gateway；清理前确认该 VPC 已无实例、ENI、EBS 或 NAT gateway。

`r09` 继续使用美国 2、爱尔兰 1、悉尼 1 的三洲 topology，四台均为 `c7g.xlarge Spot`，没有
On-Demand fallback。四台一度全部达到 SSM reachable，当前 ARM64 binaries 也在四台全部安装并通过
SHA-256 校验。ARL setup bundle 在本地成功生成，digest 为
`15a9f84c994e34826026afbafe2412ea84d4d17ce12a200314cff9554d92fc2c`，但在发出共享 setup 安装命令前，
悉尼实例 `i-0cd39804e2addf1de` 已于 `04:02:10Z` 被 AWS 回收；命令于 `04:02:17Z` 发出后，SSM 返回
`StatusDetails=Undeliverable`、`ResponseCode=-1`，所以本轮失败与 setup bundle 内容、协议实现或网络
timeout 无关，ARLADKR 和 PracticalADKR 均未启动。本轮结果标记为 invalidated，不纳入论文延迟数据。

四台实例共存活 2086 instance-seconds：美国两台分别约 647/648 秒、爱尔兰约 510 秒、悉尼约 281 秒。
按当时 `c7g.xlarge` Spot 单价（`us-east-1a $0.0738/h`、`eu-west-1c $0.0745-$0.0746/h`、
`ap-southeast-2c $0.0890/h`）计算，EC2 约 `$0.044`；加入公网 IPv4、短时 gp3 和少量控制/传输流量，
本轮保守记约 `$0.05`，量化累计由约 `$2.00` 更新为约 `$2.05`。最终账单仍以 Cost Explorer 为准，
AMI snapshot 持续费用继续单列。

Terraform 已逆序销毁三地 stack。AWS CLI 复核显示四台实例均为 `terminated`，三地该实验标签下的
Spot request、EBS volume、VPC、EIP 和非 deleted NAT gateway 均为 0。最终 cleanup-ready 因悉尼实例
已被回收而无法解析该 host，记录为 failed，但不影响 Terraform destroy。Fabric 的 SSM batch 错误现在
同时记录 `StatusDetails`、response code、stdout 和 stderr，后续 Spot 回收不会再被误报为空错误。

## 2026-08-19 三洲 n=4 `r10` Mumbai Spot smoke

由于 `r09` 的悉尼 Region placement score 仅为 `1/10`，且实例在 setup 命令发出前被 Spot 回收，
本轮不再使用悉尼；新加坡此前已有 `instance-terminated-no-capacity`，也不回退到新加坡。现有三洲
配置改为 `us-east-1:2`、`eu-west-1:1`、`ap-south-1:1`，Mumbai `aps1-az3` 的 placement score
为 `3/10`，四台仍全部是 `c7g.xlarge Spot`，无 On-Demand fallback。Mumbai 使用从已验证的新加坡
AMI 临时复制的 `ami-00466faea4dfcbe0f`，复制完成后本轮结束即注销 AMI 并删除
`snap-080b81fdd07ce23e8`；不重建操作系统镜像。

实验 `cross-n4-3c-20260819-r10` 于 `04:12:51Z` 开始，四台均 SSM Online、setup bundle 和当前
ARM64 binary digest 校验通过，四台均通过 cleanup-ready。ARLADKR 于 `run-20260819-041845` 达到
`n-f=3`：成功节点 service-grace-adjusted latency 为 `15.101 s`、`15.296 s`、`24.300 s`，
三个成功节点 consensus hash 均为
`12bfd72c593d2a8fc2ef9a5e2b3e3d61e362c1717d32e78a04f71a95be2c263e`；Mumbai 节点未完成 CV APDB
recovery（本地 holder 不足），但不影响本轮 n-f smoke 判据。PracticalADKR 于
`run-20260819-042430` 也达到 `n-f=3`，三个成功节点 latency 为 `5.021 s`、`5.115 s`、`7.994 s`，
consensus hash 均为 `3ac65a752a12327ee6087f06e948c843a046a2decef6efc8ece45ddac1bbe899`，
`success_rate=1.0`、`fallback_policy=off`。这些是跨洲公网 smoke，不是论文正式性能结论；ARL
启用了 `comm-metrics`，Practical 本轮未启用通信量统计，不做通信量横向结论。

四台实例分别于 `04:13:23Z`、`04:14:07Z`、`04:14:49Z` 启动，美国两台于 `04:30:56Z`、爱尔兰
于 `04:29:58Z`、Mumbai 于 `04:28:05Z` 由 Terraform 终止，合计约 3853 instance-seconds。
按运行时 Spot 价（美国 `$0.0738/h`、爱尔兰约 `$0.0746/h`、Mumbai `$0.0456/h`），EC2 约 `$0.073`；
公网 IPv4、短时 30 GiB gp3 和少量控制流量约 `$0.007`，本轮生命周期成本保守记约 `$0.08`，
量化累计由约 `$2.05` 更新为约 `$2.13`。AMI 跨区复制的数据传输/快照复制费用取决于实际有效块数，
不并入上述实例生命周期累计，待 Cost Explorer 最终账单确认。

Terraform 三地 stack 均 destroy 完成，`final_cleanup=cleanup-ready`。AWS CLI 复核三地该
`ExperimentGroup` 下实例、Spot request、EBS、VPC、EIP 和非 deleted NAT gateway 均为 0；临时
Mumbai AMI/snapshot 也已注销。`r10` 是可用于 smoke 记录的成功轮次，Spot 未发生中断。

## 2026-08-19 单 Region n=10 `r11` ARLADKR Spot smoke

本轮只复测 ARLADKR，不启动 PracticalADKR。实验名为
`paper-arladkr-n10-20260819-r11`，run ID 为 `run-20260819-044443`，使用
`us-east-1` 的 `use1-az5`（`us-east-1f`）单 AZ topology、10 台 `c7g.xlarge` Spot，
无 On-Demand fallback；AMI 为 `ami-0cee8a82967ef97ac`。参数为 `n=10, f=3, runs=1,
epochs=1, timeout=180s`，公网 SSM 编排和 `base-port=30000`，实验二进制及 setup bundle
均通过 digest 校验。

资源阶段为 10/10 实例创建、10/10 SSM Online、10/10 setup、10/10 cleanup-ready、
10/10 runner 启动；最终收集到 10 份 host 目录，其中 9 份包含有效 bench artifact，
1 台（`98.81.19.23`）没有生成 bench 文件。有效节点数为 `9/10`，协议 quorum 为
`n-f=7`，因此 `quorum_success=true`，但这不是“10 个节点全部完成”的性能样本。
9 个有效 artifact 的 consensus hash 全部一致：
`dff584168b98b22352a58baff69820a08e475bc8767babbacd215a249a6cffb9`。

有效节点的 service-grace-adjusted latency（ms）为
`4868.78, 4942.82, 5498.13, 5544.76, 5553.13, 5575.33, 5588.22, 5623.53,
5644.52`；均值 `5426.58 ms`，中位数 `5553.13 ms`，p95 `5644.52 ms`，最大值
`5644.52 ms`。对应 raw latency 均值约 `6426.58 ms`，每个节点扣除的
`mean_recover_service_grace_ms` 约 `1000 ms`。因此报告时必须同时给出 `9/10` 完成率和
`7/10` quorum 判定，不能将均值表述为全体 10 节点延迟。

本轮使用 `mode=strict`、`online_protocol_excludes_setup=true`、`comm_metrics=true`、
`cv_failure_target=smoke`，proposer/validator sample 均为 3；APVSS 为
`ack-fallback`，fallback profile 为 `feldman-batch-v1`，各节点 fallback count 为 1 或 3。
这些设置属于当前 smoke 配置，不能替代 high-assurance 或完整 I-only backend 的正式论文实验。
同 Region、同 AZ 的低 RTT 是本轮约 5.43 秒延迟明显低于此前跨洲 `r10` 的主要环境原因，
不是计时器跳过协议阶段的证据；setup 仍被单独计时，latency 只排除约 1 秒 recovery-service grace。

实验记录时间为 `04:41:59Z`--`04:51:27Z`。按本轮历史 `c7g.xlarge us-east-1f Spot`
约 `$0.0527/小时/台`、10 台实例生命周期，加上公网 IPv4、短时 30 GiB gp3 和少量控制流量，
生命周期成本保守估算约 `$0.10`；累计量化成本由约 `$2.13` 更新为约 `$2.23`。AMI snapshot
持续费用和最终 Cost Explorer 账单仍单列，以账单为准。

Fabric 最终记录 `status=success, cleanup=destroyed`。AWS CLI 复核本实验标签下没有
pending/running/stopping/stopped 实例、Spot request、残留 EBS、VPC、EIP 或 NAT gateway。

## 2026-08-19 三洲 n=4 `r12` ARLADKR-only Spot smoke

本轮按用户要求只测试 ARLADKR，不启动 PracticalADKR。实验名为
`paper-arladkr-cross-n4-20260819-r12`，run ID 为 `run-20260819-071424`，使用固定跨洲
公网 topology：`us-east-1:2`（`use1-az1`, slots 0--1）、`eu-west-1:1`
（`euw1-az1`, slot 2）和 `ap-southeast-2:1`（`apse2-az2`, slot 3）。四台均为
`c7g.xlarge` Spot，无 On-Demand fallback；AMI 分别为 `ami-0cee8a82967ef97ac`、
`ami-09c02ed1bf7b2b15b` 和 `ami-09b5f867c562fbd39`。参数为
`n=4, f=1, runs=1, epochs=1, timeout=900s`，公网 TCP `/32` allowlist、SSM 管理、
setup cache 和当前 ARM64 binary digest 均通过校验。

资源和启动阶段为 4/4 实例创建、4/4 SSM Online、4/4 setup、4/4 cleanup-ready、
4/4 runner 启动。`aws-wait` 在 3 个节点成功后达到 `n-f=3`，因此返回 smoke 成功；
artifact 收集结果为 `3/4`：美国两节点和爱尔兰节点有 bench 文件，悉尼节点在收集时仍为
`running`，没有有效 bench artifact。三个有效节点的 consensus hash 全部一致：
`b61816d2b53288114618c09fdf32a63fca2ec2be2d8f449cd0f9f24a9f5b1335`。

三个有效节点的 service-grace-adjusted latency（ms）为
`16430.06, 17498.81, 19873.10`；均值 `17933.99 ms`，中位数 `17498.81 ms`，p95
`19873.10 ms`，最大值 `19873.10 ms`。raw latency 均值为 `18934.83 ms`，每个节点
扣除约 `1000 ms` recovery-service grace。candidate formation 分别约 `5683 ms`、
`5877 ms` 和 `5167 ms`。因此本轮应报告为 `3/4` artifact、`3/4` quorum smoke，
不能称作完整四节点延迟样本。

本轮仍是 `mode=strict`、`online_protocol_excludes_setup=true`、`comm_metrics=true`、
`cv_failure_target=smoke`，proposer/validator sample 为 3，APVSS 使用
`ack-fallback`/`feldman-batch-v1`。跨洲 RTT、抖动和节点阶段偏斜使 online protocol
约 `16.4--19.8 s`，显著高于同 AZ r11 的约 `4.9--5.6 s`；这正是环境差异，不应直接解释
为协议计时器少算阶段。悉尼节点未完成 artifact 也说明 `n-f` quorum smoke 不能替代
完整 fleet 成功。

实验从 `07:08:56Z` 持续到 `07:17:38Z`。按三地当时 Spot 价格、四台实例实际生命周期、
公网 IPv4、30 GiB gp3 和少量跨区控制/协议流量，生命周期成本保守估算约 `$0.10`，
量化累计由约 `$2.23` 更新为约 `$2.33`；最终账单以 Cost Explorer 为准，AMI snapshot
持续费用单列。实验记录为 `status=success`、Terraform `cleanup=destroyed`。最终 cleanup
barrier 因悉尼实例在收集时仍运行且地址解析状态变化记录为 failed，但 Terraform 已逆序
销毁三地 stack；随后 AWS 资源复核应以实例、Spot request、EBS、VPC、EIP 和 NAT 全部为零
为完成标准。

## 2026-08-19 法兰克福拓扑 `r13` 编排中止与清理

按用户指定的 `us-east-1:2`、`eu-west-1:1`、`eu-central-1:1` topology 启动了
`paper-arl-euc1-n4-r13`。四台实例均为 `c7g.xlarge` Spot，分别使用
`ami-0cee8a82967ef97ac`、`ami-09c02ed1bf7b2b15b` 和临时复制的
`eu-central-1/ami-03013d3446cc2edce`。首次实验名过长触发 Terraform IAM
`name_prefix` 长度校验，未创建资源；缩短名称后四台实例成功创建，但在全部节点进入
SSM/setup 前用户要求改用两区域拓扑，因此 ARLADKR 协议没有启动，不产生延迟或通信数据。

随后按法兰克福、爱尔兰、美国逆序执行 Terraform destroy，并经过最终一致性复核确认三地
active instances、Spot 资源、EBS、VPC 和安全组均为 0。四台实例仅短暂运行，按当时
美国 `$0.0738/h`、爱尔兰 `$0.0746/h`、法兰克福 `$0.1028/h` Spot 价，加公网 IPv4、
30 GiB gp3 和少量控制流量，保守将本次编排成本记为约 `$0.04`；累计量化成本由约 `$2.33`
更新为约 `$2.37`。该轮标记为 `invalidated`，不纳入论文性能样本。法兰克福 AMI 副本
`ami-03013d3446cc2edce` 及其快照未随实验销毁，持续存储费用单独计账。

后续两区域配置固定为 `us-east-1:2`、`eu-west-1:2`，见
`practicaladkr_project_code/deployment/config.aws-cross-region-n4-use1-euw1.yaml`；
干跑 `paper-arl-use1-euw1-n4-r14-dryrun` 已通过，尚未启动实际实例。

在后续确定只使用美国和爱尔兰两区后，法兰克福 AMI
`ami-03013d3446cc2edce` 已注销，其专用 snapshot `snap-009519f0112eb9bb0` 已删除；因此该副本
不再产生持续存储费用。美国和爱尔兰的已验证基线 AMI 继续复用。

## 2026-08-19 两区域 n=4 `r14/r15` 编排失败与流程优化

用户将 topology 改为 `us-east-1:2`、`eu-west-1:2`，固定使用
`use1-az1`/`ami-0cee8a82967ef97ac` 和 `euw1-az1`/`ami-09c02ed1bf7b2b15b`，四台均为
`c7g.xlarge` Spot。`r14` 首个 Region apply 在两个本地 `/32` 规则并发创建时触发
`InvalidPermission.Duplicate`；实例已创建但协议未启动。根因是 Terraform 用两个独立的
`aws_vpc_security_group_ingress_rule` 管理同一安全组的本地规则，AWS 已接受其中一个请求后
provider 重试产生重复授权。该轮通过 state destroy 清理，未产生协议数据，成本保守记约 `$0.02`。

Terraform 模块随后将同一 Region 的本地公网 CIDR 合并为一个
`aws_security_group_rule`，跨 Region peer CIDR 仍使用独立规则；`terraform fmt -check`、
`terraform validate` 和 Fabric 回归均通过。

`r15` 使用修复后的模块成功完成两区四台 Spot 创建、跨区 peer allowlist、SSM Online、当前
ARM64 binary staging 和共享 ARL setup 安装；setup digest 为
`170842fc1aabf5fded7ac078881716d78fb387c6b84f018f0abc27d7803780dd`。协议尚未启动时用户要求
停止，因此没有 latency、consensus 或通信数据。停止后按爱尔兰、美国逆序 destroy，并复核
两区 active instances、open/active Spot requests、EBS、VPC、安全组、EIP 和 NAT 全部为 0。
本轮四台约运行 10--12 分钟，按美国 `$0.0738/h`、爱尔兰 `$0.0746/h`、公网 IPv4、30 GiB
gp3 和少量 SSM/S3 流量，保守记约 `$0.06`；累计量化成本由约 `$2.39` 更新为约 `$2.45`。
`r14/r15` 均标记为 `invalidated`，不纳入论文性能样本。

### AWS 流程复用与优化审计

- setup key material 已按 `project/n/f/Paillier bits/source revision` 缓存；只要源码 revision
  和实验参数不变，下一轮直接命中 `deployment/setup-cache`，不重复生成密码学材料。
- 当前二进制仍按源码交叉编译并校验 digest；它保留了论文实验的“运行当前源码”语义，但可将
  `aws.runner.s3_bucket` 配置为一个预先创建且有生命周期规则的实验 bucket，复用 bucket，避免
  每个命令创建/删除临时 bucket。对象仍按 digest 命名并在成功或失败后删除。
- AMI、Terraform provider cache、AWS 实验配置和本地 setup cache 都可以跨轮复用；AMI 只能在
  OS/依赖确实变化时重建，源码变化由 binary staging 覆盖。AMI snapshot 持续成本单列。
- 每轮仍必须重新申请 Spot fleet、生成独立 Terraform state、重新写公网 `/32` allowlist、执行
  全节点 cleanup-ready、分发当前 binary/setup，并在收集后 destroy。复用运行中的实例或旧监听
  进程会污染论文 latency 和网络条件，不建议。
- Fabric 的跨 Region SSM batch 现已并发执行，控制命令使用独立的
  `ssm_command_timeout_seconds=180`，不再继承 `bench_timeout_seconds=900`；这只改变编排等待，
  不改变协议 timeout 或 latency 口径。Fabric 39/39 测试通过。

## 2026-08-19 两区域 n=4 `r16` 性能审计与 WAN fan-out 修复

`paper-arl-use1-euw1-n4-r16` 使用 `us-east-1:2` 和 `eu-west-1:2` 的四台
`c7g.xlarge` Spot，4/4 节点完成且 consensus hash 一致。四个
service-grace-adjusted latency 为 `11522.90`、`11261.29`、`11386.63` 和
`11961.72 ms`，均值 `11533.14 ms`；raw 均值为 `12533.61 ms`，报告正确扣除了约
`1000 ms` 的 recovery service grace。setup 约 `48 ms`，离线 key generation 和
同步启动等待均不在 latency 内。四个实例的 service CPU time 约 `2.8--3.0 s`，因此
`11.5 s` 的主要来源是 WAN 轮次/阈值等待而不是标量解密计算。

阶段均值为：leaf build `822 ms`、component disperse `577 ms`、candidate formation
`4725 ms`、aggregate agreement `1201 ms`、recover shard `3412 ms`（其中约 `1000 ms`
为已从报告 latency 扣除的 service grace）、receipt/handoff `1499 ms`。标量 bounded-DLog
仅 `4.30 ms`。candidate relay 每节点发送约 `25.6--37.0 KiB`，结合旧的 `100 ms` ACK
初始等待，表明跨大西洋 ACK 往返和验证时延会造成不必要重发。

修复保持协议消息、阈值、签名、候选验证和决定规则不变：认证 envelope 的 candidate delivery
现在先返回非语义 ACK，候选仍在后续完整验证后才被缓存、转发或参与决定；已缓存的相同
canonical wire 快速抑制；ACK wait 改为 per-peer channel，避免一个 peer 的 ACK 错误唤醒另一
peer；candidate ACK 基础等待从 `100 ms` 调整为 `250 ms`。decision share、handoff、scalar
share 和 recovery request 使用最多 16 路的有界并行 fan-out，控制重传周期从 `100 ms` 调整为
`250 ms`。这消除串行 TCP send 对 WAN 关键路径的放大，同时不改变收件人集合。

本地验证通过：candidate/ACK 聚焦测试 `0.59 s`，真实 APDB recovery/decision 网络回归
`14.29 s`，`go test ./cmd/rladkrbench -count=1` 通过，`go test ./... -run '^$' -count=1`
通过，`git diff --check` 通过。严格 benchmark 拒绝 `tcp-loopback` 是有意的
`strict-network` 防护，不把本地 loopback 当作公网实验结果。

AMI 不需因本修复重建。两区现有 AMI 为 `arladkr-bench-arm64-v2-20260818`
(`ami-0cee8a82967ef97ac`) 和 `arladkr-bench-arm64-v2-20260818-cross`
(`ami-09c02ed1bf7b2b15b`)；`run_arladkr_cross_region.py` 每轮在实例上线后都会交叉编译当前
ARM64 `rladkrbench`，以 SHA-256 校验并经 SSM 原子安装。因此后续 r17 复测会运行本次提交的
二进制，不会误用 AMI 内旧版本；仅 OS、Go 版本或基础依赖变化时才重新 bake AMI。

## 2026-08-19 修复后两区域 n=4 `r17` quorum smoke

本轮使用提交 `8ee3736` 的 candidate ACK、per-peer wait 和有界并行 fan-out 修复，拓扑仍为
`us-east-1:2`（`use1-az1`）和 `eu-west-1:2`（`euw1-az1`），四台均为 `c7g.xlarge` Spot，
AMI 与 r16 相同。实验名为 `paper-arl-use1-euw1-n4-r17`，run ID 为
`run-20260819-100628`。SSM/setup/cleanup barrier 均为 4/4，ARM64 binary digest 为
`e9759c848dae25893a0f2d67dcd9143201d4505ed6ce7535cbe04b86ffcedf4f`。

本轮只收集到 3/4 bench artifact：美国 slot 0、slot 1 和爱尔兰 slot 3 成功，爱尔兰
slot 2（`3.248.249.130`）在收集时仍显示 `running`，没有 bench 文件，随后由 finally cleanup
终止。三个成功节点 consensus hash 均为
`9632dc1e1011c1861a1b1715f17facb2a90b7bd6be484642c6284ca41fb8c6d9`，因此这是 quorum smoke，
不是完整四节点 latency 样本，标记为 `invalidated`，不纳入论文主表。

三个 artifact 的 service-grace-adjusted latency 为 `10293.00`、`10918.94`、`10975.26 ms`，
均值 `10729.07 ms`；raw 均值 `11729.81 ms`。与 r16 三个指标均值（`11533.14 ms`，完整
4/4）相比，方向性下降约 `7.0%`，但由于 r17 缺失一个节点且每轮只有一个 epoch，不能宣称
统计显著的性能提升。阶段均值（仅 3 个成功节点）为：leaf `804 ms`、component disperse
`615 ms`、candidate formation `4891 ms`、aggregate agreement `1219 ms`、recover shard
`3173 ms`（含约 `1001 ms` grace）、receipt/handoff `792 ms`。candidate formation 比 r16
的 `4725 ms` 略高，说明 ACK/fan-out 修复的主要收益目前出现在 handoff/control wait，candidate
formation 仍是下一步瓶颈。总发送/接收均值约 `1.30/1.29 MB`，没有观察到通信量异常下降。

本轮 AWS 资源已确认清理：四台实例均 `terminated`，两区 active Spot request 为零，root
EBS volume 不存在，Terraform VPC、subnet、security group、IGW、IAM role/profile 均已销毁。
按实际启动到终止时间、当时约 `$0.0738/h`（美国）和 `$0.0746/h`（爱尔兰）Spot 价、四个
公网 IPv4、30 GiB gp3 和少量 SSM/跨区流量，保守记本轮约 `$0.04`；累计量化成本由约
`$2.50` 更新为约 `$2.54`，最终以 Cost Explorer 为准。

## 2026-08-19 两区域 n=4 live 对照与运行中诊断

为验证“公网 RTT 是否足以解释 ARLADKR 的秒级额外延迟”，使用同一公网 topology
`us-east-1:2`（`use1-az1`）加 `eu-west-1:2`（`euw1-az1`）、四台 `c7g.xlarge Spot`、
同一 AMI、同一连续 NodeSlot 和同一跨区 `/32` ingress allowlist，运行 ARLADKR 后经
`cleanup-ready` barrier 运行 PracticalADKR。两套二进制均由本地当前源码交叉编译、经 SHA-256
校验后由 SSM 原子安装。测试期间不只等待 summary：通过逐 Region SSM 读取每节点的进程、监听端口、
artifact/status 文件和 transient systemd unit。

第一轮 `paper-compare-use1-euw1-n4-live` 运行时间为 `10:37:50Z--10:48:01Z`。ARLADKR 达到
`3/3` quorum，但美国 slot 0 未产生 bench artifact，故其结果不作正式样本。PracticalADKR 的四台
进程均在协议前退出；journal 明确显示 `flag provided but not defined: -base-port`。根因是人工调用时
给 `bench_latency` 传入了仅 ARL benchmark 支持的 `-base-port`，与公网、协议实现或 RTT 无关。
本轮标记为 **invalidated**，Terraform finally destroy 与 final cleanup 已完成。

修正参数后，第二轮 `paper-compare-use1-euw1-n4-live2` 于 `10:55:03Z--11:06:53Z` 成功：
`final_cleanup=cleanup-ready`、`cleanup=destroyed`。运行中观测显示 ARL 的三个节点约在一轮完成后
释放协议 listener；爱尔兰 slot 3 仍保有 `:30003`、`:30007` listener 和 benchmark 进程，直至
finally cleanup，因此 ARL 只有 3/4 artifact，不能作为完整四节点主表数据。Practical 四节点均完成，
无残留 protocol process 或 listener。

| 项目 | 完成 | 成功节点 latency | 均值 | 结论 |
| --- | --- | --- | ---: | --- |
| ARLADKR | 3/4 quorum | 9184.10、9705.32、10142.19 ms | 9677.20 ms | quorum smoke，排除论文主表 |
| PracticalADKR | 4/4 | 2936.43、3633.49、3712.80、3559.17 ms | 3460.47 ms | 完整但单 epoch smoke |

Practical 的跨区阶段数据为：DXT network wait `137--412 ms`、APDB `142--638 ms`、MVBA
`567--792 ms`、recovery `774--839 ms`。这再次说明跨大西洋 RTT 不是从约 3--4 秒直接变为约
10 秒的充分解释；ARL 的额外时间仍主要在 candidate formation（本轮约 `4.5--4.9 s`）以及后续
aggregate/recovery 等阈值等待。该对照也不能独立得出论文结论：每项仅一 epoch，ARL 缺一个节点，且
Practical 本轮未启用通信量统计。下一轮应保持相同 topology，启用两边的通信量统计，要求 4/4 artifact，
并连续至少 5 个 fresh epoch 后报告 median/p95 和分阶段分布。

两轮均为四台 Spot、约 10--12 分钟生命周期；按美国/爱尔兰历史 Spot 价、公网 IPv4、30 GiB gp3
和少量 SSM/跨区流量各保守记约 `$0.05`，新增约 `$0.10`，量化累计由约 `$2.54` 更新为约 **`$2.64`**。
第二轮的 Terraform state 记录已确认 destroy；最终 AWS API 复核时本地 SSO token 正好过期，待重新
`aws sso login --profile arladkr-sso` 后再执行只读的实例、Spot request、EBS、VPC 和 EIP 零资源复核。

## 2026-08-19 Candidate Path WAN 调度优化（待公网复测）

对第二轮 ARLADKR 的 phase 分解表明，`candidate_formation_ms` 的 `4.5--4.9 s` 并不等同于
单次 candidate relay；它覆盖 eligibility threshold coin、proposer component catalog recovery、PoolCert、
contributor coin、aggregate APDB Lock、validation certificate，以及首个 verified candidate 的传输与验证。
因此不能把该值直接归因于公网 RTT，也不应在论文的端到端 latency 中扣除这些协议阶段。

本地源码已作一项不改变协议语义的 WAN 调度优化：coin share 与 recipient-specific APDB Store offer
均改用已有的最多 16 路 bounded fan-out。原先的逐 peer 同步发送会把 TCP transport ACK 的等待串联为
多次 WAN 往返；现在仍发送相同的认证消息，仍要求原有的阈值，且 Store offer 仍按接收者独立构造。
candidate 的 ACK/retry 策略（最多四次，`250/500/1000/2000 ms`）没有改变，只新增观测。

`E2E_BENCH_RESULT` 现额外报告 `eligibility_coin_ms`、`proposer_slots_ms`、
`mean_coin_fanout_ms`、`aggregate_offer_send_ms`、`mean_candidate_ack_wait_ms`、
`mean_candidate_retry_wait_ms`、`mean_candidate_fanout_max_peer_ms`、
`mean_candidate_fanout_attempts` 和 `mean_candidate_fanout_retries`。其中前两项拆分 candidate 大阶段，
其余项用于定位发送与 ACK 重试的 WAN 放大；它们是解释性指标，不改变既有 E2E 口径（仍仅扣除 setup
和已定义的 recovery-service grace）。

此处尚无 AWS 复测，不能据此声称跨区 latency 已改善。下一次应使用同一
`us-east-1:2 + eu-west-1:2`、`n=4,f=1` fresh fleet，要求 4/4 artifacts，并重点比较上述字段与本节
之前记录的优化前基线；运行中继续用 SSM 观察各节点的进程、端口和 artifact 状态。

## 2026-08-19 Candidate Path 优化后两区域 n=4 复测

运行 `paper-arl-use1-euw1-n4-r18-20260819`，继续使用 `us-east-1:2 + eu-west-1:2`、
四台 `c7g.xlarge Spot`、公网 `/32` allowlist 和 `n=4,f=1`。ARLADKR 与 PracticalADKR 使用同一
fresh fleet；本地当前源码交叉编译后以 SHA-256 校验并原子安装。ARL 完成后，所有四台节点通过
`cleanup-ready` barrier，才启动 Practical。实验记录为 `success`，最终 `cleanup-ready` 和 Terraform
destroy 均完成。

必须区分 runner quorum 与完整样本：ARL 在 `3/3` 成功后，`aws_wait` 即返回并触发收集及下一协议的
cleanup；当时第四个节点仍为 `running`，其 `bench.txt` 为空。因此 Fabric 的 `collect 4/4` 只表示四台
主机的收集命令执行成功，并不表示存在四份成功 bench artifact。本轮 ARL 仍是 **3/4 quorum smoke**，
不能进入论文主表。Practical 为 4/4 成功。

| 项目 | 成功节点 service-grace-adjusted latency | 均值 | 样本状态 |
| --- | --- | ---: | --- |
| ARLADKR | 10131.64、10393.07、10555.22 ms | 10359.98 ms | 3/4 quorum smoke |
| PracticalADKR | 3105.12、3177.85、3549.13、3592.13 ms | 3356.06 ms | 4/4 单 epoch smoke |

ARL 三个成功节点的 candidate formation 为 `4090/4166/4273 ms`，均值 `4176.33 ms`；其中
eligibility coin 均值 `129.78 ms`，proposer slots 均值 `4046.76 ms`。相对前一次同 topology 的
candidate formation `4492/4616/4866 ms`（均值约 `4658 ms`），本轮方向性下降约 `10.3%`，但样本均
只有一个 epoch 且都缺一个节点，不能据此宣称统计显著改善。ARL 总延迟没有同步下降，恢复与 handoff
波动仍然很大：recover shard 均值 `3059 ms`，receipt 均值 `1222 ms`。

新增观测显示 aggregate Store offer 在实际发送节点为 `137--203 ms`；`mean_coin_fanout_ms` 为
`442--917 ms`，它累计该节点本 epoch 的多次 coin fan-out，不等同于 eligibility coin 单阶段延迟。
candidate ACK wait/retry wait 只有 `0.02--0.04 ms`，说明固定 `250/500/1000/2000 ms` backoff 没有成为
本轮秒级瓶颈。与此同时 attempts/retries 均为 `12/12`，这是因为当前计数把 proposer slot 被取消后立即
返回的未 ACK attempt 也算作 retry；该字段不能直接解释为 12 次真实超时重传。复测后已在本地修正：
取消的 wait 仍计入 attempt/ACK wait，但不再计入 retry，且发送循环在 context 或 service 取消后立即返回。
该修正尚未重新部署到 AWS，因此本轮 artifact 中的 retry 字段仍按旧观测定义解释。
当前证据把 candidate 的剩余主要成本进一步定位到 proposer slots 内部，尤其成功 proposer 的 component
recovery（本轮约 `1713--2015 ms`）及后续阈值证书路径，而不是 candidate relay ACK backoff。

Practical 的在线协议均值为 `3351.55 ms`，DXT network wait 均值 `393.71 ms`、APDB `442.44 ms`、
MVBA `599.52 ms`、recovery `769.29 ms`。本轮命令未启用 Practical 的 `-comm-metrics`，其字节字段为零，
不能用于通信量公平对照；延迟结果仍可作为同 fleet 的单 epoch smoke。

本轮资源生命周期为 `12:25:28Z--12:41:35Z`，约 16.1 分钟。按复核时 `c7g.xlarge` Spot 价格范围
（美国约 `$0.0526--0.0738/h`、爱尔兰约 `$0.0726--0.0775/h`）、四个公网 IPv4、120 GiB gp3 和少量
跨区流量，保守记约 `$0.06`；累计量化成本由约 `$2.64` 更新为约 **`$2.70`**，最终仍以 Cost Explorer
为准。AWS API 已复核两区 active 实例、open/active Spot request、实验 EBS volume 和实验 VPC 均为零。

## 2026-08-19 WAN 重发与 transport 队头阻塞修复（本地验证）

针对 r18 暴露的 `validation_request_wire_bytes=2631 B` 但实际发送约 `82--106 KB`、以及跨区
`candidate_formation_ms` 约 `4.2 s` 的实现层放大，完成了不改变协议语义的 P0/P1 修复：

- `CertifyPool`、`CertifyAggregate` 和 `runCoin` 首次使用 bounded fan-out，后续最多四轮
  `250/500/1000/2000 ms` 指数退避，并只向尚未贡献 share/signature 的 peer 重试；删除 PoolCert
  完成后的 5 秒全 fleet 后台重发。
- APDB stored/recovery response、coin reply、pool/validation signature、decision/aggregate share
  和 candidate ACK 改由每个 service 的有界 outbound worker queue 发送。dispatch 仍串行执行验证、
  去重和 one-shot signing，但不再等待 TCP transport ACK。
- TCP pooled connection 按 `(from,to,address,lane)` 建立 deterministic control/bulk 两 lane。
  APDB/recovery/组件/candidate 大消息走 bulk lane，coin、certificate、MVBA 等控制消息走 control
  lane；同 lane 顺序保持不变，跨 lane 不再互相阻塞。

协议阈值、采样、签名、验证、候选规则和 latency 报告口径均未修改；没有扣除 candidate 或 recovery
阶段，也没有降低 `n-f`/证书阈值。新增回归覆盖异步 candidate ACK、PoolCert 完成后无后台重发、非 validator
不重复收到 validation request、双 lane key 分类和 TCP pooled reconnect。

验证结果：

- `go test ./core -run` 针对 Pool/VCert/recovery/candidate：通过。
- `go test ./core -count=1`：通过，`433.711 s`。
- `go test ./... -run '^$'`：通过。
- `go test ./cmd/rladkrbench -run '^TestBenchMultiProcessFourNodePrivateStyleSubsets$' -count=1`：通过，`4.040 s`。
- 本地四节点严格 TCP benchmark 的四个节点均 `success_runs=1`，共识 hash 一致；service-grace-adjusted
  latency 为 `1947.55--2003.11 ms`，平均约 `1976 ms`。candidate formation 为 `615--1156 ms`，
  `mean_candidate_fanout_retries=0`，validation request 单节点发送量约 `0.8--12.9 KB`，不再出现
  r18 的 `82--106 KB` 级别重复广播。

这只是本地验证，不能替代 AWS 跨区复测；当前累计 AWS 成本仍为约 `$2.70`，本节没有新增 AWS 资源或费用。
下一轮应在同一 `us-east-1:2 + eu-west-1:2` fresh fleet 上要求 4/4 artifact，启用两边 comm metrics，
连续至少 5 个 epoch，再比较 r18 的 `10359.98 ms` ARL 基线与新的分阶段分布。

## 2026-08-19 下一步执行状态：AWS MCP 阻塞与本地回归

本轮按 r18 后续计划检查了跨区 n=4 配置
`practicaladkr_project_code/deployment/config.aws-cross-region-n4-use1-euw1.yaml`。配置仍为
`us-east-1:2 + eu-west-1:2`、`c7g.xlarge` Spot、公网 IPv4、SSM 管理、`allow_partial_fleet=false`，
并要求 4/4 节点完成后才作为正式样本。

当前 Codex 会话没有注册 `aws-api` 的 `call_aws`/`suggest_aws_commands` 工具，且 MCP resource/template
列表为空。依据 `cloud-operation` 技能的执行规则，本轮没有绕过授权直接运行 AWS CLI，也没有启动、修改或
销毁任何 AWS 资源。因此本轮新增 AWS 成本为 `$0.00`，累计量化成本保持约 **`$2.70`**；此前资源均已清理，
最终账单仍以 Cost Explorer 为准。

在等待可审计 AWS 通道期间完成了本地验证：

- `go test ./core -run 'Test(CVAPDB|CVCandidate|CVCertified|CVPool|CVValidation|CVSAPVSSRouter|TCPPool|TCPPooled|CVLaneNetwork|CVRunAgreement|CVComponentMaterialization|CVCoinOutput)' -count=1`：通过，`37.113s`。
- `git diff --check`：通过。
- `graft build --deep`：完成结构图刷新，`8970` 节点、`19695` 条边、`726` 个文件卡片；无 API key 时使用结构化构建。

上述 MCP 状态仅记录当时环境。随后在用户明确授权下，已按既有 Fabric/Terraform 流程完成本配置的 r19
复测，结果、清理和成本见下一节。

## 2026-08-19 WAN 调度修复后两区域 n=4 `r19` 完整 smoke

本轮不依赖 MCP，沿用 Fabric/Terraform 的既有可审计流程，实验名
`paper-arl-use1-euw1-n4-r19-20260819`，run ID `run-20260819-140900`。拓扑保持
`us-east-1:2`（`use1-az1`）加 `eu-west-1:2`（`euw1-az1`），四台均为 `c7g.xlarge` Spot、
公网 IPv4 和跨区 `/32` TCP allowlist。使用当前 ARM64 二进制（`rladkrbench` SHA-256
`e1c1b137ca134187b70be284fa0d0fcf24d0a977dbeb60c0fd4f0a314f0257d6`），并开启
`-strict-network -comm-metrics`；四节点 setup bundle digest 一致。

执行期实际观测到：`aws-up=4/4`、pre-launch `cleanup-ready=4/4`、同步启动前 runner readiness
为 `3/4`（协议阈值），协议完成后四台均已经退出并产出成功 artifact。收集结果为 **4/4**、
`success_runs=1`、一致 consensus hash
`09a1ffbd0dde65a44d26eaef69a4ed91bc912aaaad87a1fa7946d7338577f125`，不存在遗留 runner stderr。
finally cleanup 再次得到 `cleanup-ready=4/4`，两区 Terraform 都报告 destroy 完成；实例、EBS、VPC、
security group、IGW、IAM profile/role 与 Spot request 均由该 destroy 路径回收。

| 指标 | r19 四节点均值 | r18 quorum smoke | 说明 |
| --- | ---: | ---: | --- |
| service-grace-adjusted latency | `4660.29 ms` | `10359.98 ms` | r19 是完整 4/4 单 epoch smoke |
| raw latency | `5660.98 ms` | 未作为本比较口径 | 保留约 `1000 ms` recovery service grace 的原始值 |
| candidate formation | `1936.25 ms` | `4176.33 ms` | 约下降 `53.6%` |
| proposer slots | `1821.09 ms` | 约 `4046.76 ms` | candidate 的主要剩余时间 |
| leaf / component disperse | `808.25 / 468.00 ms` | `804 / 615 ms` | 同量级 |
| aggregate agreement / recover shard / receipt | `536.75 / 1403.25 / 301.00 ms` | `~1222 / 3059 / 1222 ms` | r18 的 3/4 样本不可作显著性结论 |
| total sent / recv per node | `1.188 / 1.179 MB` | 约 `1.30 / 1.29 MB` | 以 comm metrics 实测 |
| validation request sent | `12.53 KB` | 约 `82--106 KB` | 定向重发和去除后台广播已消除主要放大 |
| candidate fan-out retries | `0` | 旧观测口径不可靠 | r19 使用已修正的取消计数定义 |

各节点 adjusted latency 为 `4692.95`、`4670.36`、`4603.62`、`4674.22 ms`，因此这轮验证了 WAN
调度修复在同一公网 topology 下确实消除了 r18 的异常秒级放大。它仍仅有一个 epoch，不能作为论文
median/p95 或统计显著性结论；正式对照仍需在相同 fresh-fleet 拓扑下让 ARLADKR 和 PracticalADKR
各完成至少五个完整 epoch，并保留两边通信量指标。

实验记录的 provision-to-collection 区间为 `14:02:40Z--14:13:31Z`；随后两区实例终止和网络销毁
额外约数分钟。按四台实例约 `13--16` 分钟实际生命周期、追踪文档既用的 `c7g.xlarge` Spot 保守价、
四个公网 IPv4、`4 x 30 GiB` gp3 与约数 MB 的跨区实验流量估算，本轮记 **约 `$0.05`**。累计量化成本
由约 `$2.70` 更新为约 **`$2.75`**，最终以 AWS Cost Explorer 实际账单为准。

销毁完成后，以 `arladkr-sso` profile 对 `us-east-1` 和 `eu-west-1` 做了只读 API 复核：两区按
`ExperimentGroup=paper-arl-use1-euw1-n4-r19-20260819` 过滤的 non-terminated instance 均为零，
open/active Spot request 也均为零。

## 2026-08-19 百节点部署路径优化（本地验证）

为避免部署控制面成为 `n=100--256` 论文实验的主要等待来源，Fabric 的 SSM 批处理上限和默认并行度
均改为 `50`。SSM API 的一个 `send-command` 最多接受 50 个 instance ID；实现继续按 Region 并发，
每个 Region 内将超过 50 个节点切为连续批次，且每批可同时启动 50 个下载/安装命令。所有当前可编辑的
AWS 基础配置（含两区域 n=4 配置）也显式设为 `ssm_parallelism: 50`，历史 experiment state 不回写。
binary 与 shared setup 的 presigned artifact URL 默认有效期同步提升到 `3600s`（最低 `900s`），避免 256
节点在后续 SSM 批次开始前 URL 已过期。

`shared-public` setup 不再将 `public/` 与全部 `node-XXXXXX/` 目录打进一个 archive 后让每台节点下载。
现在流程为：上传一份仅含 `public/` 的 archive、每个 NodeSlot 一份独立 shard、以及一份短时 presigned
URL index；每个 SSM target 先并发下载公共 archive，再从 index 选择自己的 shard，逐项 SHA-256 校验后
原子安装。这样每节点接收量从 `P(n) + n*S` 降为 `P(n) + S`，集群总量从
`n*P(n) + n^2*S` 降为 `n*P(n) + n*S`，消除了全部私有 shard 的二次重复项。公共 registry `P(n)`
本身通常随 n 线性增长且每台协议节点都必须持有，因此严格的总下载复杂度仍可能为 `O(n^2)`；本修改不虚称
降为 `O(n)`，重点是减少无协议必要性的重复材料与部署尾部。节点磁盘上只安装本 NodeSlot 的材料；短时 index 仍可见所有 shard URL，
因此该模式仍是 academic shared-public
部署而不是生产级私钥隔离。它不改变 trusted-offline setup、协议消息、阈值或 latency 统计口径。

本地验证：`python3 -m unittest test_fabfile.py` 通过（`41` 项，约 `0.3s`），覆盖 51 个目标拆成 `50+1`
且第一批并发为 50、公共 archive 不含 node shard、每节点 shard/index 安装命令存在；`py_compile` 与
空白检查通过。此项仅修改编排代码与配置，未启动 AWS 资源，新增成本 `$0.00`，累计量化成本仍约 **`$2.75`**。

后续可继续简化但尚未实现的流程包括：将当前临时 S3 artifact 改为按源码 digest 缓存的固定实验 bucket；
为多 Region 在各 Region 复制同一不可变 binary/setup object；以及将多 epoch 同一 fleet 的 setup 与 binary
安装复用为一次。这三项均不应让 GitHub clone 或远端编译进入测量路径，以保持节点二进制、构建环境和实验
启动时间可复现。

## 2026-08-19 现有 AMI n=10 两区域 deployment smoke

为验证 AMI 不变时的新 SSM/shard 部署路径，新增并使用仅含两个 Region 的配置
`practicaladkr_project_code/deployment/config.aws-cross-region-n10-use1-euw1.yaml`：
`us-east-1:5`（`use1-az1`）加 `eu-west-1:5`（`euw1-az1`），总 `n=10,f=3`，全部为现有
`c7g.xlarge` Spot 和原 AMI（美国 `ami-0cee8a82967ef97ac`、爱尔兰 `ami-09c02ed1bf7b2b15b`）。
实验名经安全截断为 `paper-arl-use1-euw1-n10-deploy-r20-20`，run ID 为
`run-20260819-145457`。

部署链路验证结果：

- `aws-up=10/10`，两 Region 的 SSM target 全部可达。
- setup cache 生成 n=10/f=3 bundle，digest 为
  `e7ca89e3cf7dcb1734cc14061e1c2f814d5efa2990e4b9c6eb06425bc43211f3`。
- shared-public 新路径完成公共 archive、NodeSlot shard 和 index 分发，pre-launch
  `cleanup-ready=10/10`；没有重建 AMI，也没有远端编译。
- runner 启动 `10/10`，协议 readiness `7/10`，协议最终 `success=10/10`，收集 `10/10`。
- 十个 artifact 的 consensus hash 全部为
  `28470e01498da4ed8dd55d8b7970cc90f1617af8862b2c30f8798a0f3d5287db`，setup digest 一致，
  candidate fan-out retries 总数为 `0`。

本轮单 epoch ARL smoke 指标（只用于部署/规模 sanity check，不进入论文统计主表）：平均
service-grace-adjusted latency `10071.77 ms`，raw latency `11072.44 ms`，setup `119.23 ms`，
candidate formation `4995.80 ms`，每节点平均发送/接收 `3.451/3.372 MB`。n=10 的 candidate 和
recovery 成本明显高于 n=4，符合协议规模增长预期；这轮目标是证明现有 AMI 能承载新部署流程，不能
单独归因于 AMI 或宣布性能结论。

实验记录时间为 `14:50:25Z--15:00:26Z`，随后完成 `cleanup-ready=10/10` 和两区 Terraform destroy。
按十台 Spot 实例约 10--15 分钟生命周期、十个公网 IPv4、`10 x 30 GiB` gp3、SSM 与少量跨区流量，
本轮保守记 **约 `$0.14`**；AWS 只读复核显示两区 non-terminated instance 与 open/active Spot
request 均为零。累计量化成本由约 `$2.75` 更新为约 **`$2.89`**，最终以 Cost Explorer 为准。

结论：现有 AMI 足以支持优化后的百节点方向部署路径，当前没有重建 AMI 的必要。下一步若进入
`n>=100`，应先复用同一 AMI 做纯 setup/deployment soak，再决定是否把稳定 binary 预置进新 AMI；
AMI bake 不应与论文协议 latency 样本混在同一轮。

## 2026-08-19 PracticalADKR 同 topology 跨 Region smoke（r21）

为回答 ARL r20 的同 topology 对照问题，本轮新增并执行 Practical-only runner
`practicaladkr_project_code/deployment/run_practical_cross_region.py`。它复用了同一套 Terraform、
公网 `/32` allowlist、SSM shared-public setup、10 节点 cleanup-ready barrier 和 artifact collector，
没有先在同一 fleet 上运行 ARL，也没有重建 AMI。实验名为
`practical-use1-euw1-n10-r21-20260819`，拓扑与 ARL r20 完全一致：`us-east-1:5`（`use1-az1`）+
`eu-west-1:5`（`euw1-az1`），`n=10,f=3`，`c7g.xlarge` Spot，现有 AMI；参数为
`runs=1`、`paillier-bits=3072`、`kappa-profile=matched-lifetime`、`mvba-network=tcp`、
`strict-network=true`、`comm-metrics=true`。

部署和结果完整性：

- 两区 SSM `aws-up=10/10`，setup bundle digest 为
  `653b68ea4946e30e21a35f335ea5abf5e40232a8e91d92ed2ff31d87b067870f`，10/10 节点完成 cleanup-ready；
- Practical readiness `10/10`（quorum=7），最终 `success=10/10`，artifact 收集 `10/10`；
- 十个节点的 consensus hash 均为
  `3f3855face8f9948e583a805d7efb08c84d6d6c3a72c1a637983bf030c57da82`，fallback/timeout 均为 0；
- 运行从 `15:19:12Z` 到 `15:42:46Z`，随后两区 Terraform 资源全部销毁，最终 cleanup-ready barrier
  通过，non-terminated instance 和 Spot request 均为 0。

十个节点 artifact 的逐节点范围和均值如下。这里的均值是同一轮各节点报告的 local e2e latency
的算术平均；因为只有一个 epoch，它是 smoke 描述统计，不是论文主表的 median/p95 结论。

| 指标 | 节点范围 | 10 节点均值 |
| --- | ---: | ---: |
| `mean_latency_ms` | `6171.45--7480.80` ms | **`6541.07` ms** |
| `mean_online_protocol_ms` | `6163.63--7472.95` ms | **`6533.18` ms** |
| `mean_setup_ms` | `7.72--7.99` ms | **`7.86` ms** |
| `mean_dxt_dealing_ms` | `738.53--1352.42` ms | `938.50` ms |
| `mean_apdb_dispersal_ms` | `275.88--508.49` ms | `425.95` ms |
| `mean_mvba_agree_ms` | `1266.10--1267.67` ms | `1266.44` ms |
| `mean_recover_ms` | `1577.08--1752.84` ms | `1607.71` ms |
| `mean_derive_ms` | `1198.32--1917.33` ms | `1357.86` ms |
| `mean_aggregate_derive_ms` | `3615.58--4295.16` ms | `3764.31` ms |
| `mean_total_sent_bytes` | `984,441--1,050,770` B | **`1,033,708` B** |
| `mean_total_recv_bytes` | `1,002,636--1,046,333` B | **`1,028,170` B** |

### 对结果的判断

这轮 Practical 数据在协议和统计完整性上符合预期：所有节点成功、决定集合为 7、选择/验证数量为
`4/4`、共识 hash 一致，setup 也被明确排除在 online latency 外。它比同 AZ n=10 的既有
`4.10--4.44 s` smoke 高约 `2.1--2.4 s`，但仍低于同一跨区 topology 的 ARL r20
`10.07177 s`（约低 35%）。通信量约 `1.034/1.028 MB` 每节点，也与 Practical 的单 lane
协议结构相符，明显低于 ARL r20 的 `3.451/3.372 MB`；没有发现因 artifact 截断、fallback、
本地 shortcut 或 quorum 不足造成的虚低数据。

跨区增量不能简单解释成公网 RTT 本身。Practical 的 MVBA agree 在节点间几乎稳定在 `1.266 s`，
而 DXT dealing/network wait、APDB dispersal、recovery 和 derive/aggregate derive 的 barrier
会把跨区的几十毫秒级 RTT 放大为多轮等待；最高的 `7.481 s` 节点同时出现 `derive=1.917 s`、
`aggregate_derive=4.295 s`，说明尾部主要来自协议阶段和节点本地计算/调度，而不是单个 TCP 握手。
因此本轮结果“方向上合理”，但不能用单 epoch 证明固定的跨区开销，更不能把 6.541 s 直接作为论文
最终性能结论。正式比较仍应在该 fresh-fleet topology 下各运行至少 5--10 个 epoch，报告 median、
p95、阶段分布和通信量；ARL 与 Practical 必须继续使用相同 AMI、n/f、TCP、setup 排除口径和
cleanup barrier。

本轮十台 Spot 实例约 23.6 分钟生命周期，按两区 c7g.xlarge Spot、10 个 30 GiB gp3、临时公网
IPv4、SSM 和少量跨区流量保守计 **约 `$0.24`**，累计量化成本由约 `$2.89` 更新为约 **`$3.13`**；
最终账单以 Cost Explorer 为准。该轮仍属于实验 smoke，未修改协议设计。

## 2026-08-20 ARL 公网延迟异常审计（不启动 AWS）

本轮只做本地 A/B 和代码审计，没有创建实例，也没有新增 AWS 成本。审计对象是
`paper-arl-use1-euw1-n10-deploy-r20-20` 的 `n=10,f=3`、`us-east-1:5 + eu-west-1:5` 公网结果。

结论：数据不是统计脚本把 service grace 重复计入造成的。r20 的平均值为
`mean_latency=10071.77 ms`、`mean_raw_latency=11072.44 ms`、`service_grace=1000.18 ms`，
十个节点成功且 consensus hash 一致。candidate ACK 等待均值约 `63.91 ms`，重试为 `0`，
所以 candidate ACK backoff 不是主要瓶颈。

最可疑的代码路径是 `core/transport_tcp_loopback.go` 的 pooled TCP：每个 frame 写入后必须
等待远端 1-byte transport ACK；同一 `(from,to,tag)` 的 pooled connection 由 `pc.mu` 串行保护。
而 `cvRunSampledProposerSlotsV2` 同时运行多个 proposer，多个 component/APDB recovery 请求会
共享同一 peer/tag 连接。公网每条消息都引入一次 WAN RTT，本地 loopback 不会暴露该排队效应。
component INIT 还在 `disperseComponentWire` 中逐 holder 同步发送，进一步放大跨区 RTT。

对照结果：

- `ff91394` 的本地严格 TCP n=10 smoke 约 `6.13 s`，说明协议阶段本身并非固定 10 秒；
- 当前 `d63add8`/未提交 WAN 优化工作区的本地结果在 `8.0--10.5 s` 间波动，不能直接作为论文基线；
- 在 loopback 临时注入约 `35 ms` 单向延迟（约 `70 ms RTT`）时，基线一次运行达到约 `39.68 s`，
  仅 `7/10` 达到 quorum，且 proposer component recovery 累积约 `23.5 s`。实验结束后 qdisc
  已确认恢复为 `noqueue`。

因此，公网 r20 的约 10 秒是当前 transport ACK/连接串行化对 WAN RTT 的放大结果，数据并非虚低或
单纯报告错误。一个未改变协议语义的本地原型已按 recovery payload digest 将 bulk 消息稳定分到
3 条 pooled lane；在 `ff91394` 本地 n=10 上从约 `6.13 s` 降至约 `4.64 s`，并达到 `10/10`
完成。35 ms 单向 RTT 注入下，原型约 `36.68 s`，较单 lane 的约 `39.68 s` 有限改善，说明
连接并发确实命中瓶颈但不能单独消除 WAN 多轮等待。该原型仍需补充按 tag 的 ACK RTT、pool lock
wait、dial 次数和 recovery request 消息计数，再决定是否纳入正式实现；在此之前不应把 r20
与 Practical 的延迟直接作为论文最终结论，也不应重建 AMI。

## 2026-08-20 本地 n=10 recovery/scalar-exchange liveness 收口

本轮继续使用本地严格 TCP `n=10,f=3` 审计上述候选版，没有启动 AWS、没有创建云资源，新增 AWS
成本为 `$0`，累计量化成本仍约 **`$3.13`**。

首先修正了本地共享主机 harness 的启动条件：component listener 默认等待全部 `n` 个进程，独立
MVBA listener 默认等待全部 peer，并按 `host_cpus/n` 设置每节点 `GOMAXPROCS`。这些只是本地 artifact
收集与共享 CPU 调度规则；协议、AWS runner 和最终成功条件仍为 `n-f`。

随后通过 60 秒 settle 和 Go `SIGQUIT` 堆栈确认存在两条真实 liveness 问题：

- APDB aggregate recovery 首轮 transport send 只有 `3/4` 成功时立即返回。现在保留初始全 holder
  并行 fan-out，只对发送失败的 holder 做 4 次指数退避重试；recipient 集合和 `dataShards=4` 不变，
  collector 继续按认证 holder/index 幂等去重。
- `RecoverAndExchangeScalarShare` 和 `FinalizeDecision` 原来每 250 ms 向整个 roster 无限重发。早完成
  节点退出后，尾部节点可能永远达不到 `n-f=7` 并持续增加通信量。两条路径现在只向尚未贡献有效
  share 的 peer 做 4 次有界重试，阈值仍为 `n-f`；不足时返回明确错误，不再静默卡死。

本地共享主机上，500 ms route timeout 只保留约 1 秒 recovery-service grace，CPU 调度尾部会让 honest
receiver 在 holder 退出后才开始 aggregate recovery。将现有 route timeout 设为 1 秒会选择既有的
10 秒 holder-service grace，且报告口径已从 latency 中扣除此 grace。因此 `run_cv_cluster.sh` 现在仅对
本地 harness 默认使用 `1s`；AWS runner 未改，后续公网复测应显式记录该参数。

最终代码的本地严格 TCP 诊断轮为：

- `10/10` 节点成功，quorum=`7`，all-success=`true`，consensus hash 只有 1 个；
- quorum latency `8660.64 ms`，all-nodes latency `8724.17 ms`，节点均值 `8633.06 ms`；
- mean setup `145.72 ms`，平均发送/接收约 `4.891/4.809 MB` 每节点；
- 没有 `APDB recovery reached ... holders`、scalar-share threshold、decision threshold 或 timeout 错误。

该轮只证明 liveness 收口。共享主机多进程的 leaf/candidate 调度波动仍很大，同一候选版曾出现 quorum
约 `4.36 s` 的运行，因此 `8.66 s` 不能作为论文性能基线。下一步应先提交并推送当前候选版，再在
相同 `us-east-1:5 + eu-west-1:5` Spot topology 上复测 ARL `n=10`，同时记录 route timeout、service
grace、成功节点数、candidate/recovery 分解和通信量；在新公网数据稳定前不重建 AMI。

## 2026-08-20 ARL liveness 候选版两区域公网复测（r22）

上述候选版已提交并推送到 `origin/main`，提交为
`905679c Harden WAN recovery and share exchange liveness`。随后执行实验
`paper-arl-use1-euw1-n10-r22-20260820`，继续使用与 r20/r21 相同的
`us-east-1:5`（`use1-az1`）加 `eu-west-1:5`（`euw1-az1`）公网 Spot topology、现有 AMI、
`c7g.xlarge`、`n=10,f=3`。参数为 `runs=1`、`epochs=1`、`strict-network`、
`comm-metrics`、`route-send-timeout=1s`；因此 holder service grace 为约 10 秒，并按既定
`service_grace_adjusted` 口径从报告 latency 中扣除。setup/keygen 仍在 online latency 之外。

部署版本和完整性：

- 本地按 runner 相同的 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath` 重新构建，
  `rladkrbench` SHA-256 为
  `9841a42f08e865a57dc17421d61c054aac42241c4cc78ff0e23287a1390d19ee`，与实验记录完全一致；
  Go build metadata 指向 `905679c`。
- 两区 SSM `aws-up=10/10`，setup bundle digest 为
  `ca0111697b1c165319dfbc94c5d77bdd3755b6f48583359ec7322cac620a3868`；pre-launch
  `cleanup-ready=10/10`、runner readiness `10/10`，成功门槛保持 `n-f=7`。
- 最终 `success=10/10`、artifact `10/10`，十个节点 consensus hash 均为
  `0de65ee061ad37275feb849bda46d9b0ecf0d9956796f8ffa80e4c7367a26b4f`；setup digest 和 timing
  metadata 一致，没有 timeout、threshold failure 或错误 summary。

本轮单 epoch 节点统计如下。quorum latency 是按十个节点 local latency 排序后的第七个值；它与
runner 的 `n-f` 成功条件一致。这里只作为候选版公网 smoke，不进入论文最终 median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `8935.16--9436.79` ms | **`9093.36` ms** |
| raw latency | `18935.53--19437.18` ms | `19093.95` ms |
| quorum / all-nodes adjusted latency | `9121.64 / 9436.79` ms | - |
| setup / online protocol | - | `119.23 / 8974.13` ms |
| leaf build | `1240--2676` ms | `2227.90` ms |
| component dispersal | `635--1026` ms | `789.70` ms |
| candidate formation | `3603--4794` ms | **`4017.80` ms** |
| aggregate agreement | `637--838` ms | `756.60` ms |
| aggregate recovery after decision | - | `138.37` ms |
| APVSS ACK / fallback count | - | `7.2 / 2.8` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.106 / 4.020 MB` per node** |

### 对结果的判断

本轮证明 liveness 修复在公网路径成立：APDB holder 发送、scalar-share exchange 和 decision
finalization 都没有出现阈值不足或无限重发，10/10 节点完成，且新增有界 retry 实际没有触发。
两区节点的 adjusted latency 均值分别为 `9093.42 ms`（美国）和 `9093.31 ms`（爱尔兰），几乎相同，
不存在单一 Region 尾节点拖慢结果的现象。

相对 ARL r20，adjusted latency 从 `10071.77 ms` 降到 `9093.36 ms`，改善约 **9.7%**；candidate
formation 从 `4995.80 ms` 降到 `4017.80 ms`，改善约 **19.6%**。但这还没有把 ARL 降到同 topology
Practical r21 的 `6541.07 ms`：当前仍慢约 `2552 ms`（约 39%）。aggregate recovery 后的新
recovery/share exchange 仅约 `138 ms`，candidate retry 为 0，说明本轮刚修复的尾部重试路径已经不是
主要性能瓶颈。剩余差距主要集中在 leaf build（均值 `2.23 s`）和 candidate proposer slots（candidate
总计约 `4.02 s`），同时 ARL 通信量约 `4.106/4.020 MB` 每节点，仍约为 Practical r21
`1.034/1.028 MB` 的四倍。因此结论是“公网 liveness 问题已解决、WAN 性能部分改善”，不能写成
“ARL 已达到 Practical 延迟”。下一步应围绕 leaf/candidate 的计算与多轮公网等待做不改变协议设计的
profiling；在获得多 epoch 数据前仍不重建 AMI，也不把单轮 smoke 当作论文最终结果。

资源与成本：美国五台实例实际生命周期为 `08:20:54Z--08:34:23Z`（每台 809 秒），爱尔兰五台为
`08:21:58Z--08:32:43Z`（每台 645 秒）。按当时 `us-east-1a $0.0736/小时`、
`eu-west-1c $0.0752/小时` 的 Spot 价，计算费约 `$0.150`；加十个临时公网 IPv4、`10 x 30 GiB`
gp3 和少量 SSM/S3/跨区流量后，本轮保守记 **约 `$0.17`**。累计量化成本由约 `$3.13` 更新为约
**`$3.30`**，最终仍以 Cost Explorer 为准。实验结束后两区 Terraform 各销毁 21 个资源；AWS 只读
复核显示 non-terminated instance 与 open/active Spot request 均为 0。

## 2026-08-20 ARL 单区域同 AZ 私网对照（r23）

为隔离跨 Region 公网路径对 r22 的影响，执行实验
`paper-arl-private-use1-n10-r23-202608`。10 台 `c7g.xlarge` Spot 全部位于
`us-east-1f`（`use1-az5`），协议 roster 使用 `10.42.1.10--19` 私网地址；security group 只允许
同组节点私网互通，不开放公网协议 ingress。AMI 为 `ami-0cee8a82967ef97ac`，参数保持
`n=10,f=3,runs=1,epochs=1`、`strict-network`、`comm-metrics`、
`route-send-timeout=1s`。成功门槛仍为 `n-f=7`，holder service grace 仍按既定
`service_grace_adjusted` 口径扣除，setup/keygen 仍不计入 online protocol。

本轮为编排地址选择增加了显式 `use_private_ip` 支持，使 runtime roster 与 topology 配置一致；
该调整只改变实验网络地址，不改变 ARL 协议、安全阈值或 latency 口径。部署归档 SHA-256 为
`30a955ff13bc9223a5c3a54c961fe785f8bcd0452f7fe679dfa5ce18f295f7e4`，其中
`rladkrbench` SHA-256 为
`f41623d824ecbe0ed2c71177628de07a5f27c3639749b9ef6774c203177a4b33`。
setup bundle digest 为
`6078821bb505b642e723dcf63811c93482702f6f63cba7ad767a6e3acbb083ee`。

运行完整性：SSM、pre-launch cleanup、runner readiness 均为 `10/10`；最终 success 和 artifact
均为 `10/10`。十个节点 consensus hash 均为
`eefd8c4095681b2b44cd8c2aa5743ab7300ab196875d9c91036d51ac23a4f77f`，setup digest 和 timing
metadata 一致，没有 timeout 或错误 summary。以下仍只是单 epoch topology smoke，不进入论文最终
median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `4146.78--4863.10` ms | **`4407.50` ms** |
| raw latency | `14147.14--14863.42` ms | `14407.91` ms |
| quorum / all-nodes adjusted latency | `4435.64 / 4863.10` ms | - |
| setup / online protocol | - | `119.36 / 4288.13` ms |
| leaf build | `470--1031` ms | `855.80` ms |
| component dispersal | `36--51` ms | `39.80` ms |
| candidate formation | `2432--3132` ms | **`2704.40` ms** |
| proposer slots | `2409.81--2749.53` ms | `2629.95` ms |
| aggregate agreement | `195--204` ms | `200.30` ms |
| aggregate recovery after decision | `43.73--66.34` ms | `56.83` ms |
| APVSS ACK / fallback count | - | `9.1 / 0.9` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.862 / 4.852 MB` per node** |

### 与两区域公网 r22 的对照

同 AZ 私网 adjusted latency 均值为 `4407.50 ms`，比 r22 的 `9093.36 ms` 低
`4685.86 ms`，约 **51.5%**；quorum latency 从 `9121.64 ms` 降至 `4435.64 ms`。
主要阶段也同步缩短：leaf build 从 `2227.90 ms` 降至 `855.80 ms`，candidate formation 从
`4017.80 ms` 降至 `2704.40 ms`，component dispersal 从 `789.70 ms` 降至 `39.80 ms`，aggregate
agreement 从 `756.60 ms` 降至 `200.30 ms`。candidate retry 在两轮均为零，因此差距不是 retry
退避造成；它表明公网跨区运行的主要额外代价位于多轮通信和远端数据获取路径，而不是最终
aggregate recovery。私网通信量均值略高于 r22（`4.862/4.852 MB` 对 `4.106/4.020 MB`），来自节点
角色分布和单轮消息到达顺序的差异；仅凭这两个单 epoch 样本不能断定通信量随 topology 的稳定变化。
两轮均报告相同的协议模式、阈值和主要 wire size，因此没有证据表明私网轮次通过跳过协议步骤降低 latency。

本结果也说明当前代码在同 AZ 私网下仍有约 `2.63 s` 的 proposer slots 和约 `0.86 s` 的 leaf
构建计算成本；因此 `4.41 s` 是当前实现的可信单轮基线，而不是网络近零时协议应瞬时完成。后续若要形成
论文数据，应在相同 AMI 和 topology 下运行多 epoch、多次独立 fleet，报告 median/p95，并用同样口径
运行 PracticalADKR 对照。

资源与成本：实例实际约在 `08:46:10--14Z` 启动、`08:58:56--58Z` 终止，累计约 7657
instance-seconds。按当时 `us-east-1f c7g.xlarge` Spot 价 `$0.0523/小时`，计算费约 `$0.111`；加十个
临时公网 IPv4（仅用于 SSM/部署）、`10 x 30 GiB` gp3 和少量 SSM/S3 流量后，本轮保守记
**约 `$0.13`**。累计量化成本由约 `$3.30` 更新为约 **`$3.43`**，最终仍以 Cost Explorer 为准。
实验后 cleanup-ready 为 `10/10`，Terraform 销毁 20 个资源；AWS 只读复核显示该 ExperimentGroup
的 non-terminated instance 和 open/active Spot request 均为 0。

## 2026-08-20 ARL TCP 传输层对照 PracticalADKR 的修复（本地验证）

针对 r22 公网与 r23 同 AZ 私网的阶段差异，进一步对照了 PracticalADKR 的传输实现。Practical 的
MVBA pooled TCP 在一条连接上只等待完整 frame 写入，不等待额外的 transport ACK；接收端持续读取
length-prefixed frame，并把消息交给协议 inbox。Practical 的 application-level DXT/APDB 仍通过
receipt、certificate ACK 和阈值消息完成可靠性，因此没有把每个通用 TCP frame 都变成 stop-and-wait
RPC。

ARL 原先的 `core/transport_tcp_loopback.go` 在每个 frame 写入后等待远端 1-byte ACK，并在同一
`(from,to,tag,lane)` pooled connection 上持锁直到 ACK 返回。跨 Region 时，这会把多个 proposer、coin、
certificate 和 recovery 消息串成 WAN RTT 队列；同 AZ 私网中则几乎不显现。该路径与协议层 candidate ACK、
APDB receipt 不是同一种确认，属于传输层重复确认。

本次实现调整保持协议 wire、认证封装、阈值和密码学检查不变：

- ARL TCP `Send` 改为写入完整 frame 后返回，连接锁只覆盖写入；删除冗余的 transport ACK 读写。
- pooled connection 的接收端在 idle read timeout 时继续等待，并在 inbox 满时施加 TCP 自然反压，不再
  静默丢弃消息；这与 Practical 的 `readConn` 行为一致。
- pooled connection 并发建连时保留先进入连接池的连接，关闭重复连接，避免 WAN 下连接替换抖动。
- CV lane offer 从逐 receiver 顺序发送改为已有的最多 16 路 bounded fan-out；仍发送相同 offer、仍要求
  原有 ACK quorum 和 fallback 规则。
- 本地 `deployment/docker/run_proc_sim.py` 删除已经从 `rladkrbench` 移除的旧
  `-fallback-policy force` 注入，并在启动计时前生成共享 CV setup、为每个进程设置独立 secret/state 目录。
  这是实验编排修复，不改变协议设计或论文 latency 口径。

验证结果：`go test ./core -run 'TestTCP|TestCVACKSettleGrace|TestCVAPDBNetwork|TestCV.*Lane|TestWaitForRemoteNodeReadiness|TestNewTCPLoopback' -count=1`
通过；`go test ./... -run '^$'` 编译检查通过；新增测试覆盖 write-only remote send、idle pooled connection
和 inbox backpressure。随后本地严格 TCP proc-sim 使用当前二进制运行：`n=10,f=3` 达到 `8/10` 成功、
共识 hash 一致，`n=4,f=1` 达到 `3/4` 成功；失败节点分别出现在 APDB recovery 或 MVBA 尾部，而不是
参数解析、setup、listener 或 frame 丢包。由于 proc-sim 中每个节点完成本地 epoch 后会独立退出，快节点
退出可能使慢节点在最终 recovery/MVBA 阶段失去服务者；因此这些本地轮次只作为传输回归 smoke，不作为
性能或全节点成功数据。

该修复尚未在 AWS 公网重测，未产生 AWS 费用，也不应把 r22/r23 结果回写为修复后的公网性能。下一轮应在
fresh fleet、相同 `us-east-1:5 + eu-west-1:5` topology 下使用新二进制运行 ARL，并同时运行 Practical
对照；必须确认 `10/10` artifact、单一 consensus hash、协议 listener 在最终 cleanup barrier 前保持可用，
再比较 adjusted latency、candidate formation、component dispersal、recovery 和通信量。

## 2026-08-20 ARL TCP 修复版两区域公网 fresh-fleet 复测（r24）

使用实验 `paper-arl-use1-euw1-n10-r24-20260820` 在与 r22 完全相同的公网 topology 上复测当前本地
TCP/fan-out 修复：`us-east-1:5`（`us-east-1a`）加 `eu-west-1:5`（`eu-west-1c`），10 台
`c7g.xlarge` Spot，`n=10,f=3,runs=1,epochs=1`，启用 `strict-network`、`comm-metrics` 和
`route-send-timeout=1s`。协议 roster 使用公网地址；成功门槛仍为 `n-f=7`，holder service grace
仍按既定 `service_grace_adjusted` 口径扣除，setup/keygen 仍不计入 online protocol。未重建 AMI，runner
从当前工作树重新构建并分发 ARM64 二进制；`rladkrbench` SHA-256 为
`4cf49546c2a2d8838ff6623a3195547f96771760062d3af73351ff09595a0420`。

运行完整性：两区 SSM、pre-launch cleanup 和 runner readiness 均为 `10/10`；setup bundle digest 为
`0a3ab4245f85efa853709954a5c4fbe8545795148657904548ea1c82a95407a3`，十个节点一致。最终 success 和
artifact 均为 `10/10`，十个节点 consensus hash 均为
`285c83457579b38395caff5566c4381f80e0a15f0b70f63b93f9ba78d8e8d84d`，没有 timeout、错误 summary
或 candidate retry。以下仍是单 epoch fresh-fleet smoke，不进入论文最终 median/p95 主表。

| 指标 | 节点范围/门槛 | 10 节点均值 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `5892.95--6854.25` ms | **`6530.37` ms** |
| raw latency | `15893.13--16855.21` ms | `16530.63` ms |
| quorum / all-nodes adjusted latency | `6680.00 / 6854.25` ms | - |
| setup / online protocol | - | `119.29 / 6411.09` ms |
| leaf build | `838--1295` ms | **`1071.90` ms** |
| component dispersal | `225--639` ms | **`404.10` ms** |
| candidate formation | `3257--3482` ms | **`3371.20` ms** |
| eligibility coin / proposer slots | - | `42.57 / 3328.62` ms |
| candidate ACK wait / max-peer fan-out | - | `1.64 / 15.79` ms |
| aggregate agreement | `653--719` ms | `684.80` ms |
| aggregate recovery after decision | `69.68--70.07` ms | `69.85` ms |
| APVSS ACK / fallback count | `8--9 / 1--2` | `8.7 / 1.3` |
| candidate fan-out retries | all nodes `0` | `0` |
| total sent / received | - | **`4.959 / 4.951 MB` per node** |

### 与 r22 和 r23 的判断

在相同公网 topology 下，r24 adjusted mean 从 r22 的 `9093.36 ms` 降至 `6530.37 ms`，下降
`2562.99 ms`，约 **28.2%**；quorum 从 `9121.64 ms` 降至 `6680.00 ms`，all-nodes 从
`9436.79 ms` 降至 `6854.25 ms`。分阶段看，leaf build 下降约 **51.9%**，component dispersal
下降约 **48.8%**，candidate formation 下降约 **16.1%**，aggregate agreement 下降约 **9.5%**，
decision 后 aggregate recovery 下降约 **49.5%**。candidate ACK wait 均值只有 `1.64 ms`，retry 为
零，说明删除通用逐 frame transport ACK、缩短连接锁范围和 lane bounded fan-out 确实命中了 r22 的
WAN 串行等待，而没有通过放宽协议 ACK、阈值或密码验证获得数字。

r24 adjusted mean 与相同 topology 的 Practical r21 单轮均值 `6541.07 ms` 接近，但不能据一个 epoch
宣称两者性能等价：ARL 本轮每节点通信量约 `4.959/4.951 MB`，仍约为 Practical r21
`1.034/1.028 MB` 的 4.8 倍，而且两套协议的密码工作和安全口径不同。相对同 AZ 私网 r23，公网 r24
仍高 `2122.87 ms`；主要差异位于 candidate、component、agreement 和远端恢复通信，已经不再呈现 r22
那种额外 transport ACK 造成的近一倍放大。正式论文数据仍应在 clean commit 上对 ARL 与 Practical
分别执行多次独立 fresh fleet，并报告 attempt 成功率、median 和 p95。

资源与成本：美国五台实例约从 `10:04:48--49Z` 运行到 `10:14:25--26Z`，每台约 577 秒；爱尔兰
五台从 `10:05:36Z` 运行到 `10:13:09Z`，每台约 453 秒。按当时
`us-east-1a c7g.xlarge $0.0731/小时` 和 `eu-west-1c $0.0752/小时` 的 Spot 价，计算费约
`$0.106`；加临时公网 IPv4、短时 `10 x 30 GiB` gp3、SSM/S3 和少量跨区流量，本轮保守记
**约 `$0.12`**。累计量化成本由约 `$3.43` 更新为约 **`$3.55`**，最终仍以 Cost Explorer 为准。
实验完成后两区 Terraform 各销毁 21 个资源；AWS API 复核两区 non-terminated instance 和
open/active Spot request 均为 0。

## 2026-08-20 百节点公网前置扩展性修复（仅本地代码验证）

在 r24 证明逐 frame transport ACK 已移除后，继续针对 `n>=100` 的实现瓶颈完成了不改变协议
消息、密码学关系和阈值的扩展性修复。本轮没有启动 AWS 资源，因此新增费用为 `$0`，累计量化成本
仍为约 `$3.55`。

ARL 修改如下：

- 保留并纳入当前提交的 write-only pooled TCP、idle connection 和 inbox backpressure 修复；
- `cvAPDBNetworkServiceV2` 将 receiver lane offer 与 certified candidate 的重密码学验证移入同一个
  有界 worker queue，主 dispatch 继续顺序处理 coin、receipt、certificate 和 recovery 控制消息；
- lane offer 按 `(dealer,receiver)` 去重，candidate 按 canonical digest 去重；candidate delivery ACK
  仍在进入验证队列前发送，不改变 ACK 的“认证 envelope 已到达”语义；
- candidate fan-out 不再固定 4 路，而按 peer 数使用 `8/16/24/32` 路并发，最大 64，支持
  `RLADKR_CANDIDATE_FANOUT_PARALLEL` 覆盖；
- crypto queue 最小 64、最大 2048，worker 数继续受 `RLADKR_CRYPTO_WORKERS` 和现有 CPU 上限约束。

PracticalADKR 修改如下，并已同步到 ARL 仓库的 `experiments/practical-adkr` 镜像：

- DXT transcript 接收不再为每个连接同时执行无界 full verification，而是进入有界队列，默认使用
  `GOMAXPROCS-1`、最多 4 个 worker；可用 `PRACTICAL_DXT_VERIFY_WORKERS` 覆盖；
- DXT deadline 从固定 4 秒改为随委员会规模增长：`n<32` 为 8 秒，随后在
  `32/64/96/128/192` 起使用 `30/90/180/300/600s`；仍可由 `PRACTICAL_DXT_TIMEOUT_MS` 覆盖；
- `bench_latency` 未显式传入 timeout 时使用 `90/300/600/900/1200/1800s` 的规模化预算。

AWS 编排修改如下：

- Fabric 会为 ARL 和 Practical 显式补齐 scale-aware `-timeout`，cross-region wait timeout 至少比
  binary timeout 多 300 秒；
- 公网来源不超过 48 时保留每节点 `/32` allowlist；超过 48 时 Terraform 自动切换为一个临时
  large-fleet CIDR rule，默认 `0.0.0.0/0`，避免 SG 默认入站规则额度阻止 n=100 apply；该 CIDR
  可配置，实验记录会写入实际 ingress mode；
- large-fleet rule 只覆盖协议端口，并随本轮 Terraform state 销毁。该模式依赖协议认证，仅用于
  临时论文实验，不作为生产安全组方案。

本地验证：ARL transport/candidate/APDB 定向测试通过，约 25 秒；Practical DXT 与 benchmark timeout
测试通过，约 8 秒；Fabric `44/44` 测试通过；Terraform `fmt -check` 和 `validate` 通过。尚未运行
百节点 AWS 数据，因此这些修改只能说明已移除已知实现和编排硬限制，不能预先宣称 n=100 latency
已经符合预期。下一轮仍应按 `n=32 -> 64 -> 96 -> 128` 逐档记录 phase、CPU、RSS、连接数、重传和通信量。

## 2026-08-20 ARL 论文采样参数口径修复（仅本地代码验证）

对照 `bare.tex` 后确认，ARL 的 proposer、validator 和 contributor 均使用公开阈值币驱动的无放回
采样；此前采样器和证书绑定逻辑正确，但非-smoke 参数求解使用了委员会规模无关的 `1/3` 保守界，
导致 `n=32--128` 无法运行正式 profile，也没有按论文要求把总预算 `Delta` 分成两个 `Delta/2`。

本轮只修改采样参数、报告、reference matrix 和测试，没有修改 TCP transport、连接复用、candidate
fan-out、AWS timeout、Security Group 或部署编排：

- 正式 profile 改为按实际 `n,f` 枚举精确超几何界并选择最小 proposer/validator sample；
- `original` 固定为总预算 `Delta=1e-10`，`high-assurance` 固定为
  `Delta=2^-64/525600`，自定义 `1e-*` 和 `2^-*` 也解释为总预算；
- validator 阈值统一为论文定义的 `floor(c_val/2)+1`，允许偶数样本；
- benchmark 新增 profile、policy、fault fraction、总预算和每项预算字段；
- reference matrix 覆盖两套 profile 的 `n=32,48,64,96,128` manifest-only 参数点。

此前 AWS 产物仍全部是 `(3,3)` smoke，不能追溯升级为正式安全参数数据，正式曲线必须重新运行。
本轮未启动 AWS 资源，新增费用 `$0`，累计量化成本仍约 `$3.55`。

## 2026-08-20 最新代码 ARM64 AMI 重建

为避免 r23 私网 smoke 使用旧 AMI 内不识别 `original` sampling profile 的
`rladkrbench`，本轮按最新源码重新 bake。旧 AMI `ami-0cee8a82967ef97ac` 仅作为临时源
实例基线；源实例使用 `c7g.xlarge` Spot、`us-east-1f`（`use1-az5`）、私网地址
`10.42.1.10`，实验组为 `arladkr-ami-bake-20260820`。

构建过程使用临时 Terraform state
`deployment/aws-state/ami-bake-20260820`，只创建 1 台源实例。`aws-bake-prewarm`
同步当前工作树中的 ARL、PracticalADKR 和 dumbomvba-go，显式设置 `HOME`、`GOPATH`、
`GOMODCACHE`、`GOCACHE`，完成以下 ARM64 空测试：

```text
ok  rladkr_go/cmd/cvv2ref
ok  rladkr_go/cmd/rladkrbench
ok  rladkr_go/core
ok  practical_adkr/cmd/bench_latency
ok  practical_adkr/core
ok  dumbomvba_go/core
```

随后在源实例上编译 `/opt/rladkr/bin/rladkrbench` 和
`/opt/rladkr/bin/bench_latency`。构建源码 bundle digest 为
`12e0ae4eb6d907a2908af9d1db7d0a292668f3ae038ac30121dd3b77cd328e08`。
创建并等待可用的 AMI 为：

```text
ami-053e9be88b591d821
name: arladkr-bench-arm64-v3-20260820
state: available
architecture: arm64
root volume: 30 GiB gp3
```

正式同 AZ 私网配置 `deployment/config.aws-private-n10-use1.yaml` 已切换到该 AMI；
临时构建配置保留在 `deployment/config.aws-ami-bake-use1.yaml` 供后续重复 bake 使用。
本轮修复了三个仅影响 bake 编排的兼容问题：缺失项目目录不再被默认配置强制同步，
预热和二进制构建不再硬编码不存在的 `DXT+24-adkg` 路径，Amazon Linux SSM 命令显式
设置 Go 缓存目录。协议 wire、采样参数、TCP transport 和公网通信路径均未修改。

AMI 创建后，源 Spot 实例 `i-00c0d5fdf245f1c2c`、VPC、subnet、route table、IGW、
security group、IAM role/profile 和 SSM policy 共 11 个 Terraform 资源全部销毁；
实例状态为 `terminated`，Spot request、VPC 和 SG 查询均为空。AMI 本身按实验需要保留，
后续 n=10 论文 smoke 应使用新 AMI 并在记录中注明其 ID。

资源与成本：源实例和构建资源约运行 20 分钟。按 `us-east-1f c7g.xlarge` 当时
Spot 约 `$0.0523/小时`，EC2 计算约 `$0.02`；30 GiB gp3 短时占用、临时公网 IPv4、
SSM/S3 下载和 AMI 30 GiB EBS snapshot/storage 合计保守记约 `$0.04`。本轮 AMI bake
新增成本按 **`$0.06`** 计入（最终以 Cost Explorer 为准），累计量化成本由约 `$3.55`
更新为约 **`$3.61`**。本轮没有运行论文 benchmark，因此没有 latency 或通信量数据。

## 2026-08-20 单 Region 同 AZ 私网 ARL n=10（最新 AMI）

为验证最新 ARM64 AMI `ami-053e9be88b591d821` 与当前 `original` 采样实现，使用
实验组 `paper-arl-private-use1-n10-20260820-v` 在 `us-east-1f/use1-az5` 启动 10 台
`c7g.xlarge` Spot。节点通过私网 `10.42.1.10`--`10.42.1.19` 通信，参数为
`n=10, f=3, runs=1, epochs=1`，proposer sample `4`、validator sample `7`、
validator threshold `4`，setup digest 为
`0f29761dbe70950a8ac5606f8225717bd064e0800ae57ea9132bc4973a5cc299`。

部署和启动屏障均完整通过：SSM `10/10`、cleanup-ready `10/10`、runner-ready `10/10`，
`n-f=7` quorum 要求满足。Fabric 结果为 `status=success` 并自动销毁全部 Terraform
资源；AWS 复核显示该实验组没有运行实例、活动 Spot request、VPC、subnet、route table、
IGW、security group、ENI 或 EBS volume。

协议结果不是全节点成功：`8/10` 节点完成一轮并形成同一 consensus hash
`789aac5097e6aebffc3d1fe1df8011392b45f69461b8cb19cf959bd7e80b11f9`，达到 quorum；
`10.42.1.13` 在 CV V2 APDB aggregate recovery 中仅得到 `2` 个 holder（需要 `4`），
`10.42.1.15` 的 scalar-share exchange 仅得到 `3` 个 output（需要 `7`）。这两项是
协议恢复活性失败，不是 SSM、listener、端口或 timeout 初始化失败。因此本轮只能作为
recovery-liveness 诊断和 quorum smoke，不能作为干净的全节点论文性能点。

8 个成功节点的 `service_grace_adjusted` 延迟（已扣除约 `1000 ms` recovery service grace）
为 `3713.97, 3774.92, 3785.24, 3897.90, 4101.42, 4189.48, 4525.39, 4664.89 ms`：
均值 `4081.65 ms`、中位数 `3999.66 ms`、p95 `4664.89 ms`。对应 raw 延迟均值
`5082.17 ms`、中位数 `5000.02 ms`、p95 `5665.25 ms`。阶段均值为 leaf build
`716.88 ms`、candidate formation `2419.75 ms`、aggregate agreement `190.38 ms`；
平均每节点发送 `5.22 MB`、接收 `5.02 MB`（十进制 MB）。失败节点的延迟和通信量
不计入上述统计。

资源与成本：10 台实例约从 `2026-08-20 13:22:20--25Z` 运行至
`13:39:30--32Z`，合计约 `2.86 instance-hours`。按该 AZ `c7g.xlarge` Spot 约
`$0.0523/h`，加 30 GiB gp3 短时占用、SSM/S3 和私网控制流量，保守记本轮增量
**约 `$0.17`**（最终以 Cost Explorer 为准）。累计量化成本由约 `$3.61` 更新为
**约 `$3.78`**；AMI snapshot 的持续存储费仍单列。

## 2026-08-20 us-east-1 n=32 Spot 私网容量验证（协议未执行）

先检查 `us-east-1` 的标准 Spot 配额和实例供给：
`All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests` 为 `600 vCPU`，
`c7g.xlarge` 在 `us-east-1a/b/c/d/f` 均有售；本轮 32 台只需要约 `128 vCPU`。
使用最新 AMI `ami-053e9be88b591d821`、`us-east-1f/use1-az5`、私网地址
`10.42.1.10`--`10.42.1.41` 和 `c7g.xlarge` Spot 启动
`paper-private-use1-n32-arl-20260820`。Terraform 成功创建 42 个资源，32/32 个
Spot 实例全部获得运行状态，证明该区域和配额可以承载 n=32。

随后原始 Fabric 会话在 setup/SSM 阶段异常退出，实验记录停留在 `starting`，没有
生成 ARL 或 PracticalADKR 的协议 artifact；补执行 setup 也没有返回有效结果。为避免
持续计费，未继续启动协议，直接执行 Terraform destroy。最终 42 个资源全部销毁，
32 个实例均为 `terminated`，Spot request、VPC、subnet、route table、IGW、Security
Group 和 IAM 资源均已释放。因此本轮不能计入任何 latency、通信量或协议成功率样本，
只作为容量和部署路径验证。

资源生命周期约 `15` 分钟、累计约 `8.0 instance-hours`。按 `us-east-1f`
`c7g.xlarge` Spot 约 `$0.0523/h`，加临时 30 GiB gp3、自动公网 IPv4、SSM/S3 和
短时网络资源，保守将本轮增量记为 **约 `$0.55`**（最终以 Cost Explorer 为准）。
累计量化成本由约 `$3.78` 更新为 **约 `$4.33`**。

## 2026-08-21 大规模 AWS setup 编排修复

针对上一轮 `us-east-1` n=32 仅有两个 SSM 节点超时、但随后 32/32 health check 成功的
现象，修复了部署层，不改变协议实现：

- 新增独立的 `ssm_setup_timeout_seconds`，默认 `600s`，不再复用短的普通管理命令 timeout；
- 新增 `ssm_ready_timeout_seconds`，默认 `600s`；`aws-up` 和直接 setup 都等待完整 fleet 的
  EC2 running + SSM Online，不再在 agent 注册尾部立即失败；
- setup 分发默认按 `16` 台一批执行，单批仍受 AWS SSM `50` 台硬上限约束；
- 每批失败会保留同批成功结果，只精确重试失败实例，默认最多 `2` 次，已成功节点不会重复执行；
- setup 前先执行 `SSM_READY` 全节点轻量 barrier，避免 cloud-init/SSM agent 注册尾部与
  大型 bundle 下载同时发生；
- 保留公共 bundle + 单节点 shard 的分发结构，并将 readiness、批次、重试和 timeout 写入配置；
- 单区域 `aws-paper-run` 与跨区域 suite 都在非保留 fleet 的 destroy 前尝试最终 cleanup-ready；
  cleanup 失败不会阻断 Terraform destroy，两个结果分别进入 experiment record；
- 单元测试覆盖默认参数、注册等待、批次切分、同批部分成功和精确失败节点重试。

32 节点配置 `deployment/config.aws-private-n32-use1.yaml` 已显式设置：
`ssm_parallelism=50`、`ssm_ready_timeout_seconds=600`、`ssm_setup_batch_size=16`、`ssm_setup_retries=2`、
`ssm_setup_timeout_seconds=600`。对 100--256 节点，建议每 Region 仍最多 50 台一批，
setup batch 采用 16--25 台并发；先完成 SSM_READY，再分批上传公共 bundle 和 shard，
避免把全部节点压进一个 command invocation。

100+ 节点仍可继续优化但本轮未实现：固定加密 artifact bucket + digest object 复用、公共对象按
Region 复制，以及节点将 artifact 直接上传 S3 后由控制机只收 manifest。公共 registry 是每个协议
节点必需且随 n 增长，集群总下载量仍可能为 `O(n^2)`；本轮只消除了“每台下载全部私有 shard”的
无必要重复，不能将整体 setup 复杂度表述为 `O(n)`。

当前尚未重新启动 AWS 32 节点协议实验；本轮只做本地编排修复和测试，新增 AWS 成本为
`$0`，累计量化成本仍约 **`$4.33`**。

## 2026-08-20 AWS 资源清理复核

用户反馈账号仍显示实验资源后，按实验标签、`ProtocolSuite=rla` 和 Terraform 管理标记
进行了跨 Region 清点。所有实验 Region 均无 `pending/running/stopping/stopped` EC2、
无 `open/active` Spot request；`eu-west-1` 中按标签检出的 r22/r24 实例均已是历史
`terminated` 记录。

另外发现 `ap-southeast-1` 一个无标签、无实例、无 ENI、无 NAT 的孤立实验 VPC
`vpc-0bddf5e28173f79eb`，以及其子网 `subnet-01b723b391df9cb16`、IGW
`igw-0d4f0e9e0daaa91a2` 和路由表；已完成 detach/delete。AWS API 复核均返回
`NotFound`，目标 Region 的实例和 Spot 查询为空。AMI 与 snapshot 未删除，作为后续
实验的预构建镜像并继续单列存储成本；本次清理不增加实验成本，累计量化成本仍约 `$3.78`。

## 2026-08-21 us-east-1 n=32 私网 ARL 与 Practical 实测

三轮均使用 `us-east-1f/use1-az5`、32 台 `c7g.xlarge` Spot、私网
`10.42.1.10`--`10.42.1.41` 和 AMI `ami-053e9be88b591d821`。每轮 setup、launch、
protocol-ready 和最终 cleanup-ready 都达到 `32/32`；每个 Terraform 栈最终销毁 42 个资源。
按实验标签复核 non-terminated EC2、EBS volume 和 VPC 均为空。

`paper-n32-arl-fix-r1-20260821` 没有运行协议。AWS 后端最终记录 health command
`32/32 Success`，但 `ListCommandInvocations` 在轮询期限内长期只列出 30 台，旧控制面因此误判
两台失败。部署层现已在列表轮询 deadline 后并发调用逐实例 `GetCommandInvocation` 对账；setup
继续按 16 台分批并只重试失败实例。本轮生命周期 6 分 20 秒，约 3.38 instance-hours，保守记
约 `$0.26`。

`paper-n32-arl-fix-r2-20260821`、run ID `run-20260820-171615` 成功达到 quorum：
`29/32` 节点完成，要求为 `22`，且成功节点 consensus hash 唯一：
`d2372c89ec9f3db10fe3799f369f428ea4dc69cc77b0cdf6cfdedd4ebb3eb2ae`。成功节点 adjusted
latency 均值 `27957.78 ms`，raw latency 均值 `37958.07 ms`，online protocol 均值
`27463.25 ms`。主要阶段均值为 leaf build `3259.90 ms`、candidate formation
`22169.66 ms`、aggregate agreement `572.55 ms`、recover shard `11079.69 ms`。
recover shard 包含固定 `10000.29 ms` responder service grace，扣除后实际恢复约 `1.08s`；
该固定 grace 已从 adjusted latency 中扣除。候选 ACK 等待均值仅 `1.87 ms`、fan-out 最慢 peer
均值 `2.36 ms` 且无 retry，说明约 22 秒 candidate formation 主要是密码计算、聚合构造和验证
路径，不是同 AZ 私网 RTT 或 90 秒整轮 timeout。

失败节点 `10.42.1.11`、`10.42.1.28`、`10.42.1.40` 分别只收集到 `5/22`、`3/22`、
`3/22` scalar outputs。代码审计确认，节点达到阈值后会删除 active collector；外层虽继续保留
服务 10 秒，scalar handler 却要求 collector 仍存在才验证和回复晚到 share，使 service grace 对
该交换实际无效。修复后，每个 epoch service 保留本节点已验证 aggregate 的有界 responder 上下文；
collector 完成后仍验证晚到 proof 并回复缓存 share，未知 digest 和无效 proof 仍被拒绝。本轮生命周期
15 分 28 秒，约 8.25 instance-hours，保守记约 `$0.55`。

`paper-n32-practical-fix-r1-20260821`、run ID `run-20260820-173513` 的部署控制面同样
`32/32` 成功，但协议 `0/32`。31 台报告 `dumbo-mvba ... local input rejected by predicate`，
另一台只得到 `7/21` APDB certificates 后超时。根因是 MVBA external-validity 校验把两个不同
阈值混用：n=32、f=10 时 dealer set 为 `2f+1=21`，每个 APDB certificate receipts 则为
`n-f=22`，旧代码错误要求 receipts 也等于 21。n=10、f=3 时两者恰好都为 7，因而旧测试没有
暴露问题。修复后分别校验两个阈值，并新增 `n>3f+1` 回归测试。本轮生命周期 9 分 47 秒，约
5.22 instance-hours，保守记约 `$0.36`。

三轮新增估算费用约 `$1.17`，累计量化成本由约 `$4.33` 更新为约 **`$5.50`**，最终以
Cost Explorer 为准。32 节点诊断还暴露出 artifact 收集的扩展性问题：当前控制机通过逐节点、
分块 SSM 输出拉回日志，协议快速失败后，收集反而成为主要控制面尾部。100+ 节点前应改为节点直接
上传加密 S3 prefix，控制机只下载 manifest 和必要失败样本；否则收集时间和 SSM 输出量会近似随
节点数及 artifact 大小线性放大。

## 2026-08-21 ARL/Practical 修复后 ARM64 v4 AMI

提交 `b50bcaf` 推送到 `origin/main` 后，使用实验组 `ami-bake-20260821` 在
`us-east-1f/use1-az5` 创建一台 `c7g.xlarge` Spot 源实例
`i-0b218795cdb65e445`，基线为 v3 AMI `ami-053e9be88b591d821`。源码同步覆盖 ARL、
PracticalADKR 和 dumbomvba-go，bundle digest 为
`2ad3dda1acd0fd92af06e8b2939a427dc30578ae7d69641fc4d7323ef2f3f0a8`。ARM64 空测试通过：

```text
ok  rladkr_go/cmd/cvv2ref
ok  rladkr_go/cmd/rladkrbench
ok  rladkr_go/core
ok  practical_adkr/cmd/bench_latency
ok  practical_adkr/core
ok  dumbomvba_go/core
```

构建产物均为静态链接 ARM aarch64 ELF：

```text
rladkrbench   sha256=27dd907d682277b6bb71281e1afcdce10444361a38cd3da0b227d7164eb1da81
bench_latency sha256=a1a6eee0cb1639716d416ed893bac64258b1029bd6383f6a784f07c916f87935
```

新镜像信息：

```text
ami-08952339a071d1772
name: arladkr-bench-arm64-v4-20260821
state: available
architecture: arm64
root: encrypted 30 GiB gp3
snapshot: snap-05d6b514965a9ddc8
```

`deployment/config.aws-private-n10-use1.yaml`、`deployment/config.aws-private-n32-use1.yaml`
和后续 bake 配置均已切换到 v4；历史 experiment record 保留其实际使用的旧 AMI ID，不做改写。
源实例从 `2026-08-20T18:18:05Z` 运行至 `18:27:45Z`，约 0.161 instance-hours。
AMI available 后 Terraform 销毁 11 个源栈资源；独立查询确认实验组无 non-terminated EC2、
open/active Spot request、EBS volume、VPC、Security Group 或 IAM role。

按当时约 `$0.0522/h` Spot、短时公网 IPv4/gp3 和新增 snapshot 的保守口径，本次 bake 记
约 `$0.05`；累计量化成本由约 `$5.50` 更新为约 **`$5.55`**，最终以 Cost Explorer 为准。
新 30 GiB snapshot 的持续存储费用单列，旧 AMI 在确认不再需要复现历史实验前不自动删除。

## 2026-08-21 n=32 共享私网 fleet 失败轮与二进制 staging 修复

`paper-n32-shared-v4-use1f-20260821` 使用 `us-east-1f/use1-az5`、32 台
`c7g.xlarge` Spot、私网 `10.42.1.10`--`10.42.1.41` 和 v4 AMI
`ami-08952339a071d1772`。Terraform apply 和 SSM Online 均达到 32/32，setup 分两批
16/16 成功，ARL 进程也启动 32/32，但最终全部报告 `quitpd failed: context deadline exceeded`，
没有成功协议样本。本轮不能解释为 proposer timeout 太短：失败发生在 MVBA agreement/quitpd，
且部署流程使用当前 checkout 生成 setup，却遗漏了当前 benchmark binary staging，实际执行的是
AMI v4 中的旧二进制。因此本轮标记为 `invalidated`，不计入协议性能统计。

修复后，单区域 `aws-private-suite` 与跨区域 suite 一样，在 fleet health check 后、任何 setup/run
之前交叉编译当前 ARM64 `rladkrbench` 和 `bench_latency`，通过临时加密 S3 对象分发并原子安装，
把 archive 和两个 binary SHA-256 写入 experiment record。这样 AMI 继续作为固定系统环境和构建
缓存，不再决定实际运行的代码版本。当前有界 component recovery/verification 修改可以用 v4 AMI
直接做 n=10 验证；验证通过前无需额外承担 v5 bake 成本，后续正式 32/100+ 节点批次再制作 v5。

本轮 32 台实例从约 `03:24:16--05Z` 运行至 `03:50:51--03:52:27Z`，合计约
`14.6 instance-hours`。按 `c7g.xlarge` Spot 约 `$0.0522/h`，加短时 30 GiB gp3、公网 IPv4、
SSM/S3，保守记增量 **约 `$0.84`**；累计量化成本由约 `$5.55` 更新为约 **`$6.39`**。
Terraform 最终报告 42 个资源全部销毁；AWS 标签复核显示 32 台实例均为 `terminated`，EBS volume、
VPC、subnet 和 security group 均为空。

## 2026-08-21 n=10 当前代码私网 smoke 与 artifact collector 阻塞

`paper-n10-bounded-v4-use1f-20260821` 在同一 `us-east-1f/use1-az5` 启动 10 台
`c7g.xlarge` Spot，使用 v4 AMI，但在 setup 后强制 staging 当前 `eefde30` checkout 的 ARM64
二进制。ARL run `run-20260821-040328` 成功，`success_rate=1.0`，调整后延迟均值
`5654.36 ms`，proposer slots `3054.55 ms`，recover shard `1316 ms`；binary digests 已写入
experiment record。说明有界 component verification 修改在 n=10 私网下可以完成协议。

本轮未形成 ARL/Practical 对比样本：ARL artifact 已收集，但 SSM artifact collector 在拉取
`unit_diagnostics` 时重复请求相同 offset，阻塞了 suite 进入 Practical。为停止无效计费，已停止
控制服务并手动 Terraform destroy；20 个资源全部销毁，10 台实例均 terminated。后续必须先修复
collector 的 offset 去重/进度检查，再重跑共享 suite。本轮标记 `invalidated`。
实例约运行 `04:01:10--04:13:00Z`，约 `2.0 instance-hours`；按 Spot、gp3、IPv4、SSM/S3
保守记增量 **约 `$0.17`**，累计量化成本约 **`$6.56`**（Cost Explorer 为最终账单）。

部署修复：`aws_collect` 新增 `artifact_mode=summary|full`。共享 suite 在每个协议完成后只同步收集
bench/status summary，并以 best-effort 处理节点级缺失；两个协议都完成后才收集 diagnostics/stderr
等 full artifacts。full 失败记录为 `full_artifact_collection=partial`，不再阻塞 Practical 启动，
也不会把日志控制面失败误报为协议失败或阻止最终 destroy。

## 2026-08-21 n=32 bounded-worker 私网 ARL 结果与用户终止

`paper-n32-summary-v4-use1f-20260821` 使用 `us-east-1f/use1-az5`、32 台
`c7g.xlarge` Spot、私网协议和当前 `dcccd90` checkout staging binary。ARL 在 32/32 节点上
完成；用户在 summary 收集尾部终止 suite，因此 Practical 未启动。已收集的 31 个成功节点达到
`n-f=22` quorum，consensus hash 唯一：
`8a89a6e527e499e3b4b324fa5ea2d1397949decacacc4d1ec44904ff59bb6a1f`。

31 节点均值：service-grace-adjusted latency `35519.68 ms`，raw latency `45519.98 ms`，
实际 responder service grace `10000.30 ms`；leaf build `3281.77 ms`，candidate formation
`29775.65 ms`，proposer slots `29708.48 ms`，aggregate agreement `525.42 ms`，recover shard
`11101.68 ms`。3 个 proposer 各扫描 22 个 component，component network recovery 只有
`1239.51/1295.99/1562.69 ms`，但 slot 为 `29695.17/29427.76/29877.44 ms`。剩余约 28 秒主要是
component decode/密码验证。`cvLeafVerifyWorkers` 在 4 vCPU 上使用 3 workers；该修改限制外层并发以
降低 CPU/内存峰值并保障 liveness，不是 latency 优化，22 项重验证被排成更多批次后可能比无界并发更慢。

下一步性能优化应拆分 I/O recovery 与 CPU verification，提前或流水化 verified-catalog 构建，并评估
4-worker 和 batch verification；不能简单跳过完整 22-component 验证，否则会改变当前安全契约。
Terraform 最终销毁 42 个资源；32 台实例均 terminated，EBS 和 VPC 为空。实例累计约 15
instance-hours，本轮保守记增量 **约 `$0.86`**，累计量化成本约 **`$7.42`**，最终以 Cost Explorer 为准。

## 2026-08-21 n=32 proposer catalog 两级流水线与本地基准

针对上一轮 proposer slots `29708.48 ms`、其中网络恢复仅约 `1.2--1.6 s` 的结果，catalog 路径已改为
两个有界阶段：第一阶段用独立 recovery worker pool 恢复 APDB payload 并校验 payload digest；第二阶段
按 leaf worker budget 对已恢复 payload 解码并完成原有逐 component 密码验证。`c7g.xlarge` 的
`GOMAXPROCS=4` 默认使用 4 个 leaf workers，不再固定预留一个 CPU；recovery 默认使用
`2*GOMAXPROCS`，上限 16，也可分别用 `RLADKR_LEAF_VERIFY_WORKERS` 和
`RLADKR_COMPONENT_RECOVERY_WORKERS` 覆盖。n=32 的 22 项 catalog 因而按 `4+4+4+4+4+2`
执行验证，同时 recovery 可在当前验证批运行时填充后续缓冲区。

eligibility coin 确定后，只有被抽中的本地 proposer 会启动一次后台 catalog prewarm；如果 component ref
尚未全部到达，已有 update channel 会继续唤醒 builder。成功结果写入 service 级
`verifiedComponentsV2`，后续 pool selection 和同 service 的 proposer 路径直接复用，第二次读取冻结
catalog 不触发 APDB recovery 或重复验证。非 proposer 节点不会预热，避免把 22 项重验证放大到全部
32 台。新输出 `mean_proposer_catalog_verify_ms` 记录各 CPU 验证批墙钟时间之和，和旧的
`mean_proposer_component_recovery_ms` 分开；后者是各 component recovery latency 的累计值，不等于
整个 recovery stage 的墙钟时间。

本地隔离基准命令：

```bash
RLADKR_RUN_N32_LOCAL_BENCH=1 GOMAXPROCS=4 \
  go test ./core -run '^$' \
  -bench '^BenchmarkCVV2ProposerCatalogVerifyN32$' -benchtime=1x -count=1 -timeout=15m
```

AMD EPYC 7H12 主机上，22 个真实 n=32 APVSS payload 的 4-worker 验证为
`14159401959 ns/op`，即 **`14159.40 ms`**，约为旧 AWS proposer slots 均值的 47.7%。该数字只包含
payload decode/逐 component proof verification，不包含 APDB network recovery、PoolCert、coin、aggregate
或 candidate relay，也不是 ARM `c7g.xlarge` 的替代数据。32 个本地进程的完整 TCP distributed opt-in
测试在共享主机上因 CPU 超卖未在 420 秒外层限制内完成，node 0 在被终止前未输出结果，因此本轮没有
可报告的本地完整 proposer slots 数字；该失败不能解释为协议阻塞或 AWS 性能回归。

这里的 batch verification 是有界批执行，仍对 22 个 component 分别运行现有完整验证。没有实现随机
线性组合、共享 pairing 或其他聚合密码学 verifier；在独立安全分析、错误定位策略和 adversarial 测试
完成前，不能把本次优化表述为减少了密码学验证方程。新增回归覆盖 4-worker/recovery worker budget、
eligible-only 一次性 prewarm、无效 payload 拒绝、catalog dealer 顺序及缓存命中。此次仅使用本地计算，
没有启动 AWS 资源，新增 AWS 成本 `$0`，累计量化成本仍约 **`$7.42`**。
## 2026-08-21 n=10 v4 AMI 同 AZ 私网 ARL 验证

`paper-n10-catalog-pipeline-v4-use1f-2` 在 `us-east-1f/use1-az5` 启动 10 台 `c7g.xlarge` Spot，使用 v4 AMI `ami-08952339a071d1772`，并 staging 当前 `44e8b84` ARM64 二进制。10/10 节点成功，quorum 7，consensus hash 唯一：`893497522c333e0282c94d48466f6feaa69a22f648ad1d535d6f6a72bcc166f7`。

平均 service-grace-adjusted latency `3821.12 ms`，raw latency `4821.48 ms`，`mean_recover_service_grace_ms=1000.35 ms` 已扣除；proposer slots `2096.92 ms`，catalog verify `502.10 ms`，component recovery `164.10 ms`，scan count `2.1`。没有 artifact collector 阻塞。Terraform destroy 完成，EC2/EBS/VPC/Spot request 均清理。约 `1.83` aggregate instance-hours，本轮保守增量成本 **`$0.16`**，累计量化成本更新为 **`$8.07`**（Cost Explorer 为最终依据）。完整 artifact、summary、manifest、inventory 与成本字段已写入 experiment record。

## 2026-08-21 proposer receiver-evaluation 批量验证

为降低 n=127 时 proposer 对 `L=85` 个 component 的验证成本，leaf verifier 不再为每个 receiver
分别执行一次 coefficient-commitment polynomial MSM。实现先用域分离 Fiat-Shamir challenge 固定
随机线性组合，再以两个 MSM 检查全部 receiver evaluation；批检查失败时回退逐项验证并拒绝具体
错误项。该修改没有减少被验证的 component、ownership proof 或 ACK，也不改变 `L=n-f` pool 与
`K=f+1` contributor selection。

AMD EPYC 7H12、`GOMAXPROCS=4` 本地结果：n=127 单 leaf evaluation 检查由
`374.72--495.55 ms` 降至 `9.31--10.38 ms`，约快 `39--48x`，分配量由约 `4.44 MB`
降至约 `0.15 MB`。完整 n=32、22-component、4-worker catalog benchmark 从修改前
`14159.40 ms` 降至 `10770.48 ms`，改善约 `23.9%`；剩余成本主要在 ownership proof 和 ACK
验证。本轮只使用本地计算，没有新增 AWS 成本，累计量化成本仍约 **`$8.07`**。

## 2026-08-21 proposer ownership 方程批量验证与测试加速

leaf verifier 现将所有 ACK lane 的 ownership Schnorr 方程放入一个域分离的随机线性组合。批量
challenge 在 context、dealer、按 receiver 排序的 public key 和完整 canonical offer/proof 固定后产生；
系数按方程位置使用非零 challenge 的连续幂。实现先严格检查 lane shape、proof dimensions 和点有效性，
再把每个 chunk 的 coin/ciphertext 方程及 blinding/evaluation 三个方程合并为一次 G1 MSM。批检查失败
时仍逐 receiver 执行原精确 verifier，返回真实 receiver index；成功后 ACK ownership equality 和
Ed25519 signature 仍逐项检查。若一片 leaf 含有 $E$ 个方程，随机预言机模型中的附加 soundness loss
至多为 $E/q$，并且未减少 `L=n-f` component 验证或任何 ACK/fallback 证据。

AMD EPYC 7H12、`GOMAXPROCS=4`、n=127 单 leaf ownership 基准：batch 为
`87.46 ms/op`，exact 为 `3197.51 ms/op`，约快 **`36.6x`**。n=32、22-component、4-worker
catalog 从 evaluation batch 后的 `10770.48 ms` 再降到 **`6686.03 ms`**，再改善 `37.9%`；相对
最初 `14159.40 ms` 共改善约 **`52.8%`**。该本地 catalog 数字仍不包含 APDB 网络、PoolCert、coin、
aggregate 或 candidate relay。

测试耗时分析使用 `go test -json ./core -count=1` 的逐 test elapsed。主要重复开销是 41 个测试各自
重新生成两份 exact-range M4 leaf。现在 proof-heavy 母夹具每个 test process 只生成一次，每个测试
获得 leaf、proof、context 和 secrets 的完整深拷贝，并继续使用独立 `t.TempDir()` 和 runtime config；
mutation/adversarial 覆盖未删除。完整 `core` suite 从 `485.053 s` 降至 `309.226 s`，减少
`175.827 s`（`36.2%`）。`go test -short ./core -count=1` 实测通过，耗时 `81.104 s`；合并前仍运行
完整 suite。n=127
性能夹具仅由 `RLADKR_RUN_N127_OWNERSHIP_BENCH=1` 显式开启，不增加默认测试成本。本轮没有启动
AWS 资源，新增 AWS 成本 `$0`，累计量化成本仍约 **`$8.07`**。

## 2026-08-21 ownership batch v5 AMI 与 n=10 共享私网验证

ownership 方程 batch、receiver evaluation batch 和密码学测试夹具复用已随提交 `252fe21`
（完整提交 `252fe210325938ae0fe5739be4d6a42add376b4a`）推送到 `origin/main`。随后在
`us-east-1f/use1-az5` 使用一台 `c7g.xlarge` 构建 ARM64 v5 镜像：

- AMI：`ami-0a31eb4903947c28a`，名称 `arladkr-bench-arm64-v5-252fe21-20260821`；
- source bundle SHA-256：`5efab9405c168dba727312dff88b40d362907c7eaaea8f10b6e952df3d827ee2`；
- AMI 内 `rladkrbench` SHA-256：`1a1cf1e138b74cc2b3d09ff962eaa18066b5489476e2ec59bf45d0d0addb00c3`；
- AMI 内 `bench_latency` SHA-256：`a1a6eee0cb1639716d416ed893bac64258b1029bd6383f6a784f07c916f87935`。

bake 源实例 `i-0486cebf6802692c1` 从 `08:59:05Z` 到 `09:10:25Z`，Terraform 11/11
资源已销毁。AMI 保持 `available`，仅有其预期的 30 GiB snapshot
`snap-03ef25b557c1a77a2` 被保留；该 snapshot 后续存储约 `$1.50/月`，不计入本轮之后的未来累计。

共享 suite `paper-n10-ownership-v5-use1f-20260821` 只 apply 一次，在同一组 10 台
`c7g.xlarge` Spot、同一 AZ、私网 `10.42.1.10--10.42.1.19` 上依次运行 ARLADKR 和
PracticalADKR。suite 仍按当前 checkout 重新构建并 staging 二进制，实际受测 SHA-256 为
`rladkrbench=384b8db57383ed57a77e92186af21fd1d50b44f0db6d9ce52343ea10cda306d1`、
`bench_latency=bc8b911498a2f13122d8bafbf2863666da8da24727bccd23ec9d235085792ec2`。

ARLADKR `run-20260821-091504` 为 10/10 成功、quorum 7、唯一 consensus hash
`10802e971fa5c83b4f4f8cff8667c43ade8a078cdfb89fded2b84581df7919ee`。10 节点平均
service-grace-adjusted latency 为 **`3489.75 ms`**，raw latency `4490.11 ms`，已单列并扣除
`1000.36 ms` responder service grace。`proposer_slots` 平均 `1889.75 ms`
（范围 `1787.78--1951.13 ms`），4 个实际执行 catalog verification 的节点平均
`746.40 ms`，其 component recovery 累计平均 `435.38 ms`；所有节点 leaf build 平均
`716.60 ms`。setup digest 为
`6e4b62922b8811ad77420349aaa471d7f6aea02898ecaeca4e6235580447713e`。

PracticalADKR `run-20260821-092333` 达到 quorum，但不是全节点成功：8/10 成功，成功节点唯一
consensus hash 为 `5b5f550bae04ba144baba29692236a08bdeead137a5d5d199b38d16afda0ceab`，
平均 latency `4205.47 ms`（范围 `3798.36--4533.13 ms`），其中 partial verify
`767.52 ms`、recover `1039.89 ms`、derive `1062.47 ms`。setup digest 为
`d2c480c53f7c0e7e348b51341785df494d6f0435f0bc5d7ceadc2509b016eaaa`。节点
`10.42.1.16` 和 `10.42.1.17` 分别在约 `49.30 s` 和 `49.00 s` 失败，错误为 CompProve
readiness `reachable=2/7` 和 `1/7`。成功节点约在 `09:25:38--39Z` 已退出，而两个慢节点直到
`09:26:23--24Z` 才超时，证据指向成功节点过早关闭 CompProve responder service 的尾部竞态；
增加总 benchmark timeout 不能修复该问题，后续应给 Practical responder 增加有界 service grace
或完成屏障。

部署控制面也得到量化：ARL summary 到 `09:20:54Z` 才完成，Practical 在 `09:23:33Z` 启动，
协议只运行数秒，但 2 KiB SSM 分块使 summary/full artifact 产生大量独立 command。控制脚本现将
summary 限定为 bench/status，并将默认有界分块提高到 12 KiB；旧 2 KiB 配置仍兼容，完整 Fabric
回归 `53/53` 通过。100+ 节点仍应使用节点到 S3 prefix 的上传式收集，而不是把控制机分块下载
继续横向放大。

suite 记录最终为 `status=success`、`final_cleanup=cleanup-ready`、`cleanup=destroyed`；Terraform
20/20 资源已销毁。AWS 复核中实验与 bake 均无 EBS、VPC、Security Group 或 open/active Spot
request 残留，两个 state 的 resource count 都为 0。10 台 suite 实例累计约 `3.91`
instance-hours，bake 约 `0.19` instance-hours；按 `us-east-1f` Spot `$0.052/h`，加 gp3、公网
IPv4、SSM/S3 并保守上浮，本轮记约 **`$0.30`**。累计量化成本由 `$8.07` 更新为约
**`$8.37`**，最终仍以 Cost Explorer 为准。

## 2026-08-21 proposer component 持续流式验证

n=32 的 proposer catalog 路径已从“recovery 结果凑满 4 个后同步验证、完成后再处理下一批”改为
真正的两级有界流水线。APDB recovery worker 持续产出 component，完成一个即送入有界 channel；
4 个常驻 leaf verifier worker 持续消费，不再存在 4-component wave 之间的同步屏障。流水线内部仍
按输入索引恢复确定性结果顺序，worker 数继续由现有有界配置控制，默认 4 vCPU 节点使用 4 个
verifier。旧 batch helper 已删除，避免后续调用重新引入同步等待。

`mean_proposer_catalog_verify_ms` 的语义相应调整为首个验证开始到最后一个验证结束的墙钟窗口。该窗口
会和 `mean_proposer_component_recovery_ms` 重叠，两项不能再相加推导 `proposer_slots_ms`；正式 AWS
结果应以 proposer slots 的端到端变化为主，两个分项只用于定位流水线瓶颈。

新增确定性测试验证：(1) 第一个 component 恢复后、其余 recovery 仍阻塞时 verifier 已开始工作；
(2) 12 个输入下最大 verifier 并发严格为 4；(3) 输出顺序保持稳定。`go test -race ./core -run
'TestCVComponentPipeline|TestCVVerifiedCatalogPrewarm' -count=1` 与 `go test -short ./core -count=1`
均通过，后者耗时 `69.481 s`。

AMD EPYC 7H12、`GOMAXPROCS=4`、22-component、4-worker 单次本地 catalog benchmark 为
**`3643.17 ms/op`**，相对上一版同步 wave 的 `6686.03 ms/op` 再降低约 **`45.5%`**，相对最初
`14159.40 ms/op` 累计降低约 **`74.3%`**。该基准使用已恢复的 payload，主要量化固定 verifier pool
消除 wave 尾部等待的收益；APDB recovery 与 verification 的真实重叠及 proposer slots 改善仍须在
下一轮 AWS n=32 私网实验验证。本轮没有启动 AWS 资源，新增 AWS 成本 `$0`。

## 2026-08-21 v6 流式验证 AMI

为承载提交 `98bce4f39d2bdd13bcc7113b36ca566e37555cf3` 的连续 recovery producer 与四个固定
verifier workers，基于 v5 历史镜像重新创建 ARM64 AMI。新镜像与 v5 严格区分：

- AMI：`ami-0da946b587756eba5`，名称 `arladkr-bench-arm64-v6-pipeline-98bce4f-20260821`；
- snapshot：`snap-006de34947715f68d`，状态 `available`；
- 源实例：`i-004d754c78029388a`，`us-east-1f`；烘焙 Terraform state 为
  `deployment/aws-state/ami-bake-pipeline-98bce4f-20260821`；
- 源 bundle digest：`78ba893c506db66089e362c22521bddd778670e5a9141341dfee8b9031f83118`；
- `rladkrbench` digest：`477f8f9158fc2c4efa94fe5e01d974548497c82f32bcf7d716ce1e9b4bb63ddf`；
- `bench_latency` digest：`a1a6eee0cb1639716d416ed893bac64258b1029bd6383f6a784f07c916f87935`。

n=10 与 n=32 私网配置已切换到该 AMI，并启用 `stage_current_binaries: false`、单批 SSM
setup、批量 summary、成功节点跳过完整 artifact 收集及预期 digest 校验。这样实验启动阶段不再
重复源码同步和远程编译；失败节点仍保留诊断收集。v5 AMI 不删除，继续作为历史对照。

本次只计入 AMI 烘焙源实例、临时 gp3、SSM/S3 的保守估算约 `$0.06`；没有启动实验 fleet，新增
实验成本为 `$0`。v6 snapshot 的持续存储成本单列，最终金额以 Cost Explorer 为准。临时烘焙
VPC、subnet、route table、IGW、SG、IAM 和 source instance 已在凭证恢复后通过该 state destroy，
Terraform 报告 `11 destroyed`，并复核实例、Spot request、EBS、VPC、subnet、SG、IAM role/profile
均为 0。AMI 与 snapshot 不属于 destroy 范围，仍按实验需要保留。烘焙成本约 `$0.06`，累计量化
成本由约 `$8.37` 更新为约 **`$8.43`**（最终金额以 Cost Explorer 为准）。
## 2026-08-21 v6 n=32 ARL 私网验证（收集失败，invalidated）

使用 v6 AMI `ami-0da946b587756eba5` 在 `us-east-1f/use1-az5` 启动 32 台
`c7g.xlarge` Spot，仅运行 ARLADKR，实验组为 `paper-arl-v6-pipeline-n32-use1f-20260`。
32 台节点固定私网地址 `10.42.1.10--10.42.1.41`，SSM、setup、ready quorum 和 benchmark
启动均成功：setup bundle digest 为
`6f3f4fe5ba4424c8f6e2d09969d51fa7f6515017065ad7c15503a24bca0c8a3d`；benchmark run 为
`run-20260821-135655`；`start` 32/32、`ready` 32/32、quorum `32/22`，协议状态轮询约
11 秒时显示 `success=32/22, failed=0, running=0`。

随后 compact summary 收集在节点 `i-081d5f3c38589a846` 返回缺少 `bench` 字段，控制面报错
`invalid compact summary response ... missing bench`，因此没有生成完整的 `proposer_slots_ms`
汇总。本轮不能作为性能样本；这是收集器 schema 校验失败，不是 32 节点协议失败。所有 42 个
Terraform 资源已由 finally 自动销毁。按 32 台 Spot 约 11 分钟、gp3、SSM/S3 保守估算新增约
`$0.38`，累计量化成本由约 `$8.43` 更新为约 **`$8.81`**，最终金额以 Cost Explorer 为准。

后续重跑前应修复 compact summary：单节点缺少 `bench` 时标记该节点 unavailable 并保留其余
节点原始结果，不应使整轮收集失败；同时为 summary 增加 schema 版本。

## 2026-08-21 v6 n=10 ARL compact-fix 验证（仍 invalidated）

使用修复后的 compact summary 在 `us-east-1f` 启动 10 台 v6 `c7g.xlarge` Spot，仅运行
ARLADKR。setup、10/10 launch、10/10 ready、quorum `10/7` 均成功，run 为
`run-20260821-141835`，状态轮询在 86 秒显示 `success=10/7, failed=0`。

但收集结果显示 10 个节点均缺少 bench/status 内容，最终因
`collected nodes disagree on setup bundle or timing metadata` 被标记 invalidated；这说明
单节点容错修复已生效，但还需要在 compact SSM 命令中等待 benchmark/status 文件落盘后再读取。
该等待修复已在本地实现并通过 56 个部署测试；本轮 AWS 代码仍未包含该最新等待修复，因此不
重复启动 fleet。20 个 Terraform 资源已自动销毁，新增成本保守约 `$0.14`，累计量化成本由
约 `$8.81` 更新为约 **`$8.95`**。

## 2026-08-21 v6 n=10 ARL 私网 compact-fix 重跑（成功）

使用同一 v6 AMI `ami-0da946b587756eba5` 在 `us-east-1f/use1-az5` 启动 10 台
`c7g.xlarge` Spot，仅运行 ARLADKR，实验组为
`paper-arl-v6-finalcollect-n10-use1f-2`，run 为 `run-20260821-145915`。10/10 节点通过
binary digest、cleanup barrier、launch 和 ready 检查，quorum 为 `10/7`，协议状态为
`success=10/7, failed=0, running=0`；setup bundle digest
`9c10f6aa1c53c7ae134577f8bee3b175227c9ac0296083bf59767675e704cfaf` 在所有节点一致。

新的逐节点 fallback 收集器成功保留了 10/10 节点的原始 bench 结果，尽管 compact 命令仍记录
`missing bench,status` 的诊断信息；这不再使整轮失效，但说明后续应把 compact 命令的文件等待
和 fallback 状态显式纳入 schema，避免把“fallback 成功”显示成收集错误。10 个节点的
`mean_latency_ms` 平均为 **`3419.07 ms`**（`3042.84--3897.38 ms`），
`proposer_slots_ms` 平均为 **`1722.35 ms`**（`1611.24--1784.74 ms`）。
`mean_recover_service_grace_ms` 平均约 `1000.32 ms`；catalog verify 和 component recovery
分别平均 `217.55 ms`、`168.06 ms`，仅在实际 proposer 节点非零，不能按节点简单相加。
本轮没有 PracticalADKR，不能用于两协议比较；n=10 仍是 smoke sampling，不是正式安全参数点。

实验记录最终为 `status=success`、`cleanup=destroyed`；Terraform 20/20 资源已销毁，AWS
复核没有残留运行/停止实例。按本轮 10 台 Spot 的实际生命周期、gp3、公网 IPv4、SSM/S3 和少量
控制流量保守记约 **`$0.18`**，量化累计成本由约 `$8.95` 更新为约 **`$9.13`**；AMI
snapshot 持续存储费仍单列，最终金额以 Cost Explorer 为准。

## 2026-08-21 v6 n=32 ARL 私网预检失败（Spot roster invalidated）

尝试在 `us-east-1f/use1-az5` 使用 v6 AMI `ami-0da946b587756eba5` 启动 32 台
`c7g.xlarge` Spot，仅运行 ARLADKR，实验组为
`paper-arl-v6-final-n32-use1f-20260821`。Terraform 初始 apply 报告 32/32 实例创建，
inventory 也成功写出；但 setup 前 Fabric 重新按 `NodeSlot` 查询 AWS roster 时发现
`expected=0..31 missing=[14,18,20]`，因此没有生成 setup、没有启动 benchmark，也没有产生
`proposer_slots_ms` 数据。

该轮记录为 `status=failed`、`run_id=null`，不是协议失败或性能样本。原因是 Spot fleet 在创建后
出现节点回收/EC2 查询最终一致性导致的 roster 不完整；控制脚本正确拒绝在缺少节点时继续，以免
形成错误的 n=32 实验。Terraform finally 已销毁全部 38 个剩余资源，state resource count 为
0，按 32 台实例约 12 分钟、gp3、SSM/S3 和公网 IPv4 保守估算新增成本约 **`$0.40`**，累计
量化成本由约 `$9.13` 更新为约 **`$9.53`**；最终金额以 Cost Explorer 为准。

下次 n=32 重试应在 apply 后增加一次稳定性窗口，连续两次查询都必须得到完整 `NodeSlot=0..31`
且实例状态为 running/SSM Online；若仍使用 Spot，建议设置更高的 max price 或改用短时 On-Demand
验证，以区分 Spot 回收与控制面最终一致性。

## 2026-08-22 n=10 当前 checkout 私网共享验证与 summary schema v3

实验组 `paper-private-n10-current-20260822-ac` 在 `us-east-1f/use1-az5` 使用 10 台
`c7g.xlarge` Spot、v6 AMI `ami-0da946b587756eba5` 和固定私网
`10.42.1.10--10.42.1.19`。AMI 未重建；`stage_current_binaries=true` 将当前 checkout 的 ARM64
二进制安装到所有节点，实际 digest 为：

- archive：`5e2c45853b39d01a54231f34892577bb5cef66f3fe39d91a49acef9a3bb14e03`；
- `rladkrbench`：`9390b708ff7a2c0847fc3d3a3f11a79bcebac3f25adf5f784083dd48a703ba6d`；
- `bench_latency`：`8542e695481cc12ce41970db45bfe9325ea18290e8dc81ab3a68f5917e370e31`。

ARLADKR `run-20260822-090513` 与 PracticalADKR `run-20260822-091213` 都通过 10/10 launch、
10/10 ready，并在首次状态轮询时达到 `success=10/7`。两次 setup digest 分别为
`2c5588b3786d6a9b72eefcdffbc07726e2d1f6ec41f9d3f05b403d2d5e9e7102` 和
`53b6a00241bd628d631ef9c00abe2c1027340d7640f0096b3beab421d516d954`。但两个 summary 的 10 个
节点全部记录 `compact summary unavailable: missing bench,status`，因此本轮只能证明协议进程完成，
不能提供可信 latency、通信量或 consensus hash，也不能作为论文性能样本。历史 record 写成
`status=success` 是控制面语义缺陷；按当前验证标准应解释为 **协议完成但结果不可验证**。

根因不是文件落盘慢。compact SSM command 先输出 schema/path marker，再直接输出持续增长的整条
`E2E_BENCH_RESULT`，而 `_ssm_run_command_many` 从 SSM `ListCommandInvocations` 的 inline output
读取结果。新增 profiling 字段使结果行超过 SSM inline 上限，stdout 在 bench 行中部被截断，导致
解析器看不到 `RLADKR_COMPACT_BENCH_END` 与后续 status marker。所谓 60 秒 precise retry 仍执行
同一输出格式，所以必然再次截断；此前将其归因于 shutdown/落盘 race 不完整。

修复后的 compact schema v3 在节点端对单条 bench result 执行 gzip+base64，再放入有界 stdout，
控制端严格 base64/gzip 解码后写回原始 `bench.txt`。同时完成以下一致性收口：

- 空 status 现在视为缺失，不再仅检查 bench；
- 成功节点缺少 consensus hash 时 `quorum_success=false`，避免空字符串被当作唯一共识；
- `aws_collect` 同时要求 setup digest、timing metadata 和 quorum consensus 验证通过；
- 私网与跨 Region shared suite 仍会尝试运行第二个协议，但任一项目 summary 不可验证时最终状态不再
  写成 `success`；错误延迟到两个协议都尝试完后统一返回并进入 Terraform finally 清理；
- 成功重试会删除该节点旧的 `collection_error.txt`，避免复用输出目录时残留假错误。

针对性 Fabric 回归共 7 项通过，包含约 95 KiB 的模拟结果行压缩/还原、缺 consensus hash、缺节点
重试、私网 shared suite 和跨 Region shared suite。没有为了验证收集器再次启动 AWS fleet。

资源与成本：10 台实例从约 `09:00:47--52Z` 运行至 `09:14:28--29Z`，合计约 2.28
instance-hours；当时 Spot 价 `$0.0523/h`，计算约 `$0.119`，再计公网 IPv4、短时 gp3 与 SSM/S3，
本轮保守记 **约 `$0.14`**，实验逐轮累计由 `$9.53` 更新为 **约 `$9.67`**。Terraform destroy
报告 20/20 资源销毁，复核 10 台实例均 `terminated`，实验组无 volume 或 snapshot 残留。

### 仍存在的问题

1. schema v3 已通过本地真实 gzip/base64 工具链和 mocked SSM 输出测试，但尚未用新 fleet 做端到端
   AWS 验证；下一次本来就需要的协议实验应顺带验证，不应单独为 collector 再开 10 台实例。
2. 当前 `E2E_BENCH_RESULT` 是空格分隔的无转义 `key=value`；只要字段值保持无空格即可解析，但它不是
   稳健的结构化格式。后续应考虑在 artifact 中增加 JSON 结果，同时保留文本行兼容旧分析脚本。
3. `aws_wait` 的 10/10 success 只证明远端 status marker 成功，不等价于结果证据已收集；文档和
   experiment record 的正式成功必须以 `summary.quorum_success=true` 为准。
4. Cost Explorer 无法按现有 `ExperimentGroup` 直接追溯全部历史成本，因为成本分配标签未确认激活，
   逐轮估算与账号账单存在约 `$3.86` 差额。后续应启用 cost allocation tag，或至少为每轮记录
   aggregate instance-hours、IPv4-hours、gp3 GB-hours 和 Region 单价。
5. 历史 AMI/snapshot 已按授权清理，目前只保留最新 v6 AMI 与 snapshot；历史实验若需复现，必须
   依赖本地 tracking 文档中的二进制/source digest，不能再依赖已删除的旧镜像。

## 2026-08-22 AMI/snapshot 清理与 ARL-only 复测

按“只保留最新镜像”的授权，已在 `us-east-1`、`eu-west-1`、`ap-southeast-2` 核验无
`pending/running/stopping/stopped` 实例后执行清理。注销旧 AMI 9 个（含跨 Region v2 副本），
删除其关联 snapshot 及旧 orphan snapshot；当前仅保留：

- `ami-0da946b587756eba5`，`arladkr-bench-arm64-v6-pipeline-98bce4f-20260821`；
- `snap-006de34947715f68d`，30 GiB。

随后只启动 ARLADKR，不运行 PracticalADKR。实验组为
`paper-private-n10-arl-only-20260822`，run ID `run-20260822-094427`，使用 10 台
`c7g.xlarge` Spot、`us-east-1f/use1-az5`、私网 `10.42.1.10--10.42.1.19`。10/10 SSM、
cleanup-ready、launch、ready 均成功，协议状态 `success=10/7`；当前 checkout staging 成功，
`rladkrbench` digest 为 `924019ec58956ba945590a87df789da410c884cc8d9dc4dd478e49e930af5c41`。

但 ARL summary 10/10 节点仍为 `compact summary unavailable: missing bench,status`，实验最终按
修复后的控制面标记 `status=failed`，错误为 `collected summary failed validation: setup bundle,
timing metadata, quorum consensus`。这次复测证明：schema v3 的整行 gzip/base64 仍可能超过 SSM
inline output 上限，不能把压缩视为充分保证；协议本身和私网网络没有显示故障。20/20 Terraform
资源已销毁，`final_cleanup=cleanup-ready`，当前无运行实例、实验 EBS 或 VPC 残留。

已补 schema v4：节点端只通过 inline summary 返回论文需要的字段白名单（latency、阶段时间、通信量、
setup digest、consensus hash 等），去掉大体量 profiling 明细；完整 result 行必须改走受控 S3/分块
artifact 路径。该修复尚未再次消耗 AWS fleet，需在下一次正常 ARL 实验中端到端确认。此次 ARL-only
复测约 10 台实例运行 7 分钟，保守新增约 `$0.08`；AMI/snapshot 清理本身不产生实验运行费，但从
后续账单中移除了旧 snapshot 持续存储成本。
## 2026-08-22 保留 fleet 的 ARL summary 调试

应用户要求重新启动并保留实例，实验组为 `paper-private-n10-arl-debug-20260822`，没有运行
PracticalADKR，也没有自动 destroy。10 台 `c7g.xlarge` Spot 在 `10:08:35--39Z` 启动，私网
`10.42.1.10--10.42.1.19`，run ID `run-20260822-101401`。10/10 cleanup-ready、launch、ready，
状态 `success=10/7`。

通过 SSM 进入实例直接检查后确认：每个节点的 bench 文件存在且约 6.8 KiB，result 行约 6.8 KiB，
gzip+base64 后仅约 2.9 KiB，远低于 SSM inline 上限；runner stderr 为空。真正原因是 schema v4
远端 `awk` 白名单命令语法错误，SSM stderr 没有被 compact collector 保留，最终被错误表现为
`missing bench`。随后改为 POSIX shell `case` 白名单，并修复遗漏 `E2E_BENCH_RESULT` 前缀的问题。

不重新运行协议，直接用 SSM 重新收集到
`deployment/aws-state/paper-private-n10-arl-debug-20260822/artifacts-v5`，结果验证成功：

- successful hosts：`10/10`，quorum：`7`；
- setup digest：`213eaf11f4d715e408b7659855ec14e9e6177b1f22ba6c553e0cfee49a04bf55`；
- consensus hash：`712c35cdaf5e676e315a75fd6d255a1413f3679d65ff162a79df4de91b16a19d`；
- 节点 10 latency：`1855.70 ms`，online `1736.85 ms`，sent `3889302 B`，recv `1535118 B`；
- summary flags：setup digest 一致、timing metadata 一致、`quorum_success=true`。

因此当前已经证明：私网 ARL 协议和 summary 数据本身均正常，之前连续失败完全是 collector 命令生成器
问题，而不是 AWS 网络或 result 文件落盘问题。轮询优化保留：SSM 单实例查询 1 秒、状态轮询默认
2 秒；本轮状态在 8 秒完成 quorum。

资源当前**刻意保留**，不要执行 destroy：截至 `2026-08-22T10:21:54Z`，10 台仍为 `running`。
按已知 Spot `$0.0523/h`，从启动至该时刻约 2.22 instance-hours，计算成本约 `$0.116`；加公网
IPv4、gp3、SSM/S3 后本轮暂估约 **`$0.14`**，且每小时仍继续增加约 `$0.52` 的 Spot 计算费加
附加费。Cost Explorer 当前已归集 `2026-08-17--2026-08-21` **`$13.5289738994`**，
`2026-08-22` 仍为 estimated `$0`；因此账号已归集累计仍约 `$13.53`，含本轮当前运行时长的
暂估约 **`$13.67`**，最终以日结账单为准。

后续销毁记录（2026-08-22T16:23Z）：复查时该 fleet 仅剩 `7/10` 台 running；Spot 请求历史显示
另外 3 台（`i-01db79bac3f7630ad`、`i-0fdff7a5669a5ad03`、`i-01352aa83db5d93fb`）已于约
`11:32--11:52Z` 被 AWS 以 `no Spot capacity` 回收，对应 Spot 请求的 StartTime 为空，
describe-instances 记录已过期不可见。由于缺节点的 fleet 不能复用于新 benchmark，且空转持续计费，
已用其 Terraform state 执行 destroy，销毁 17 个资源（state 中仍登记 10 台实例，其中 3 台实际早已
终止）。从上一计费截点（约 `13:55Z`）到销毁，7 台新增约 17.3 instance-hours，追加约 **`$1.05`**；
上节按 10 台存活计入的 `$2.17` 对这 3 台存在约 `$0.4` 的高估，按保守口径不追溯冲减。

## 2026-08-22 私网 n=32 ARLADKR + PracticalADKR 当前 checkout 复测

使用唯一保留的 `ami-0da946b587756eba5` 作为 ARM64 运行环境，`stage_current_binaries=true`，由当前 checkout 交叉编译并分发二进制。实验组 `paper-private-n32-current-20260822` 使用 `us-east-1/us-east-1f/use1-az5` 的 32 台 `c7g.xlarge` Spot；协议仅允许同安全组私网通信，地址 `10.42.1.10--10.42.1.41`，`f=10`、quorum 阈值 `22`。32/32 slot、SSM、setup、cleanup-ready 和 launch 均成功。

ARLADKR run `run-20260822-103823`：32/32 成功，quorum `32/22`，`quorum_success=true`，共识 hash `d6bd10e7dc06408fe3787bba9a8b9299d2fd72f0761df09f91016b77a452a21b`，setup digest `0aba2acb983391ab724de038e72178cacafe888ece58a65caa18b29ef3b879b3`。平均总延迟约 `11929 ms`，setup `493 ms`，online protocol `11436 ms`，最慢约 `14899.8 ms`，超过 10 秒目标；该超时来自 n=32 在线阶段，不是 SSM 收集等待。

PracticalADKR run `run-20260822-104505`：达到 `27/22` quorum，32/32 launch/status 成功；对 5 个无 bench 输出节点执行 batched precise retry。最终 `summary.quorum_success=true`，但仅 27 个节点有 bench，5 个共识字段为 `none`，应标为“协议 quorum 成功、summary 证据不完整”，不作为完整 32 节点性能样本。可用节点平均总延迟约 `27954 ms`、online `27937 ms`、最大约 `33556.5 ms`，可用 hash 为 `0759606c966dccf52d5c97ae713609436291506add28d9b31bb774656ab2d9f6`。

两个项目完成后执行 cleanup-ready 和 Terraform destroy，记录 `status=success`、`cleanup=destroyed`；32 台实例、VPC、子网、安全组和 IAM 均已销毁，AMI/snapshot 未修改。本轮约 14.4 分钟，按 Spot `$0.0523/h` 及 IPv4/gp3/SSM/S3 附加项保守新增约 **`$0.45`**，累计暂估由 `$13.67` 更新为 **`$14.12`**，Cost Explorer 当日数据可能延迟。schema v4 在 n=32 ARL summary 上端到端验证通过；PracticalADKR 的 5 节点重试仍需继续分析 bench 产出/退出时序。

## 2026-08-22 美爱两区公网 n=32 纯 Spot 双协议复测

启动前核验：`us-east-1` 最新且唯一自有镜像为 `ami-0da946b587756eba5`；`eu-west-1` 已无旧自有 AMI，因此从美国最新镜像复制出 `ami-06bcbb8c1d5efc9b8`，关联 snapshot `snap-0352d7343a05c5125`，状态 `available`、架构 `arm64`。新增配置 `deployment/config.aws-cross-region-n32-use1-euw1.yaml`，固定 `us-east-1a/use1-az1:16` 加 `eu-west-1c/euw1-az1:16`、`n=32,f=10`、公网 `/32` peer allowlist、SSM 管理和 `purchase_option=spot`。三次实际 fleet 均由 EC2 API 复核为每区 `16 spot`，没有 On-Demand 或 fallback；二进制仍从当前 checkout staging。

前两组 fleet 没有产生协议性能结果。`paper-public-use1-euw1-n32-current-20` 在用户要求清理时中止，协议启动前即 `cleanup=destroyed`。`paper-public-use1-euw1-n32-spot-r2-20` 暴露 shared setup S3 缓存错误：node shard 对象 key 只包含逻辑 setup digest，而每次 `tar.gz` 的元数据会改变实际归档 digest；命中旧对象时，新 index digest 与下载对象不一致，导致 32/32 `setup shard digest mismatch`。现已将 shard key 改为同时包含实际 archive digest，并删除本轮对应的陈旧 S3 prefix；针对性测试和 `py_compile` 通过。修复后的 r3 两协议 setup 均在 batch 1 两区 16/16 成功。

有效实验 `paper-public-use1-euw1-n32-spot-r3-20` 使用当前二进制：`rladkrbench` `924019ec58956ba945590a87df789da410c884cc8d9dc4dd478e49e930af5c41`，`bench_latency` `35a09e8c1aaffe45d0a900a651bf5fbee3f024df4a1a4a71e979b2e0dd9a1895`。轮询仍为 SSM 单实例 1 秒、状态默认 2 秒；观察到的较长控制面间隔来自跨 Region SSM command/API 完成时间，不是本地 sleep 恢复成 30 秒。

ARLADKR run `run-20260822-133958`：实际状态 `31/22` 成功、1 失败；quorum-only collector 只取 22 个正常节点（美国 15、爱尔兰 7），`summary.quorum_success=true`，22/22 共识 hash 均为 `5a73ceb21fd8d73eb87dc024ff88ca9f408aaca0ac20fb1261004d9c5763f91a`。22 节点平均总延迟 `294659 ms`，setup `493 ms`，online `294166 ms`，范围 `294096--294902 ms`。通过 SSM 在协议完成后直接进入实例确认 CPU/负载已空闲、bench/status 已落盘；代表性爱尔兰节点的 `aggregate_agreement_ms=285591 ms`，约占 online 的 97%，而 candidate formation `4557 ms`、recover shard `11314 ms`。因此约 295 秒差距是真实的 aggregate agreement/MVBA WAN 放大，不是 SSM setup 或收集时间；控制面只额外增加数十秒的完成识别延迟。

PracticalADKR run `run-20260822-135131`：实际状态 `23/22` 成功、9 失败；collector 取 22 个正常节点（美国 10、爱尔兰 12），`summary.quorum_success=true`，22/22 hash 均为 `555c003ba41e1d4ecec8c1e4cbcba0c9b18c99f1b7520bf136784a96a276518a`。平均总延迟 `43393 ms`，setup `20 ms`，online `43373 ms`，范围 `42811--43862 ms`。该轮达到 quorum，但 9 个失败节点未进入 quorum-only artifact，不能写成 32/32 完整成功样本。

r3 结束后两区各 43 个 Terraform 资源均销毁，复核本实验组无活跃实例；美国源 AMI、爱尔兰最新副本及其 snapshot 保留。三个纯 Spot fleet 分别消耗约 `4.575`、`4.167`、`12.525` instance-hours，共 `21.267 instance-hours`。按当时 `us-east-1a $0.0729/h`、`eu-west-1c $0.0766/h`，EC2 约 `$1.59`；公网 IPv4 约 `$0.11`，加入 gp3、SSM/S3 和少量跨区流量，三组保守计 **约 `$1.80`**。同时，刻意保留的 n=10 debug fleet 从上一计费截点继续运行，新增约 `$2.17`。故累计暂估由 `$14.12` 更新为 **约 `$18.09`**。Cost Explorer 当前归集约 `$13.5558`，其中 8 月 22 日仅 `$0.0054`，明显尚未入账；爱尔兰 30 GiB snapshot 还会产生持续存储费，最终成本以日结账单为准。

## 2026-08-22 私网 n=10 ARLADKR + PracticalADKR 最新 checkout 复测（schema v4 双协议验证）

销毁 debug fleet 后，使用 `fab aws-private-suite`、配置 `deployment/config.aws-private-n10-use1.yaml`
启动实验组 `paper-private-n10-current-20260822-ad`：`us-east-1f/use1-az5`、10 台 `c7g.xlarge` Spot、
v6 AMI `ami-0da946b587756eba5`、私网 `10.42.1.10--10.42.1.19`，`n=10,f=3,runs=1,epochs=1`，
strict-network 与 comm-metrics 均开启。`stage_current_binaries=true` 从当前 checkout（提交
`8cee734`）交叉编译分发：`rladkrbench` `924019ec58956ba945590a87df789da410c884cc8d9dc4dd478e49e930af5c41`、
`bench_latency` `35a09e8c1aaffe45d0a900a651bf5fbee3f024df4a1a4a71e979b2e0dd9a1895`，与 8 月 22 日
公网 r3 轮相同。ARL setup bundle digest 为
`f451090d912277ee82d6ca06d77f742a859a6380c50323243902d5c263ec6727`；Practical 命中 setup cache，digest
`53b6a00241bd628d631ef9c00abe2c1027340d7640f0096b3beab421d516d954`。

执行过程中本地 SSO token 于 ARL collect 完成后过期（botocore `TokenRetrievalError`，refresh token
已失效），suite 的 finally destroy 同步失败，fleet 完整保留。随后从仍有效的 CLI 角色凭证缓存导出
短期静态凭证（至 `20:52Z` 失效），在**同一 fleet** 上按 suite 原语义续跑 Practical
setup/cleanup-ready/launch/wait/collect，再完成 Terraform destroy；该临时 profile 与 state 配置中的
profile 指向已在销毁后恢复并删除，凭证未写入任何文档。协议、参数、计时与通信量口径无任何改变。

| 项目 | run_id | 完成 | mean latency | median | p95 | online/setup | sent/recv（成功节点均值） | 共识 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| ARLADKR | `run-20260822-164120` | `9/10`（quorum `9/7`） | **`1896.01 ms`**（范围 `1733.1--2014.0`） | `1908.18 ms` | `1977.28 ms` | `1777.00 / 118.9 ms` | `3.83 / 3.31 MB` | 单一 hash `d2174413...75711fc` |
| PracticalADKR | `run-20260822-170102` | `10/10`（quorum `10/7`） | **`4335.03 ms`**（范围 `3754.6--4782.1`） | `4654.50 ms` | `4747.48 ms` | `4327.11 / 7.8 ms` | `1.00 / 1.00 MB` | 单一 hash `b42a54ea...77afe67` |

两个 summary 的 `quorum_success=true`、setup digest 与 timing metadata 一致性检查全部通过；这是
schema v4 compact 收集路径首次在私网 fleet 上对两协议端到端验证成功，此前连续三轮的 collector
失败未复现。ARL 节点 `10.42.1.16` bench 结果为全零（无 collection_error/error_summary），按 9/10
计入；Practical 全部 10 节点成功，延迟呈双峰（4 台约 `3.75--3.78 s`，6 台约 `4.62--4.78 s`）。
本轮 ARL 平均延迟约为 Practical 的 `44%`（约 2.3 倍优势），通信量约为其 3.8 倍；两协议为单 epoch
smoke，n=10 仍非论文安全参数点，以上比较不能直接写入论文主表。

实例 `16:35:00Z` 启动、约 `17:11:44Z` 终止，合计 **6.121 instance-hours**：Spot（`$0.0523/h`）约
`$0.320`、公网 IPv4 约 `$0.031`、gp3 约 `$0.020`，本轮保守计 **约 `$0.37`**。Terraform destroy
20/20 完成；AWS 复核 non-terminated 实例、实验 EBS、EIP 均为 0，账号无运行实例。实验逐轮累计由
约 `$19.14`（含 debug fleet 追加 `$1.05`）更新为 **约 `$19.51`**；Cost Explorer 8 月 22 日当日数据
尚未入账，最终以日结账单为准。

清理补记：复核发现复用的临时桶 `arladkr-ssm-992382847511` 内残留 8 月 22 日三轮（n=32 私网
10:37Z、n=32 公网 r3 13:39Z、本轮 Practical 17:00Z）共 211 个 setup 分片对象，均为可公开传输
材料、总体积不足 1 MB；已全部删除并移除该桶（非本实验的 `system-backup-*` 桶未动）。后续每轮
结束应把该桶清空纳入固定清理步骤，避免依赖单轮命令的自动删除路径。

## 2026-08-22 suite 运维修复：stdout 行缓冲与凭证预检（本地，无 AWS 费用）

针对本轮暴露的两个运维缺陷修改 `practicaladkr_project_code/fabfile.py`，不触碰协议、bench 参数、
latency 或通信量口径：

1. **stdout 行缓冲**：fabric 长任务输出到管道/文件时 Python 默认 8 KiB 块缓冲，`tee` 侧日志会
   静止数分钟，曾被迫改用 SSM 命令历史判断进度。现 fabfile 导入时对非 TTY 的 stdout/stderr 执行
   `reconfigure(line_buffering=True)`，经计时验证 print 后 1 秒内可见（旧逻辑需等块满或进程退出）。
   该修复对 `PYTHONUNBUFFERED=1` 环境变量方式二选一即可，代码内修复优先后续调用方无需再记忆。
2. **凭证预检**：新增 `_aws_credential_preflight`，在 `aws-paper-run` 与 `aws-private-suite`
   terraform apply 之前执行：(a) STS `get_caller_identity` 快速失败，凭证已死时不再创建 fleet；
   (b) 读取 `~/.aws/sso/cache` 中 token 的 `expiresAt`，剩余时间低于该轮 `timeout_s+1200s`
   预留时打印告警。本轮 16:51Z 的 SSO 中断即属该类（token 于运行中过期且 refresh token 已被
   单次消费失效）；预检不能完全阻止运行中过期，但把"启动前就注定失败"的轮次挡在计费之前。
   dry-run 路径不触发预检；两个既有 suite 单测已补 `_aws_credential_preflight` mock，另新增
   预检专项测试（有效/过期/死凭证三分支）。`test_fabfile` 全套 **62/62 通过**，`py_compile` 通过。

### 提速结论（已验证的时间线拆解）

本轮 16:33:49Z--17:13:30Z 共约 40 分钟，其中 SSO 事故与人工恢复约 15 分钟；正常路径约 25 分钟，
而协议本体仅 2--5 秒。固定开销构成为：fleet 启动 + SSM Online 等待约 6--8 分钟（AWS 侧固有）、
当前源码交叉编译与分发约 2--3 分钟、逐阶段 SSM 批量命令每条 5--15 秒、destroy 约 2 分钟。按收益
排序的执行规则（后续轮次遵循）：

1. **一轮多采样**：bench 支持 `-runs N`；单轮 `-runs 1` 即销毁 fleet 把 25 分钟基础设施摊到 1 个
   样本。正式数据轮应使用同一 fresh fleet 执行 `-runs 5--10`（ARL 与 Practical 各自多 run，中间以
   cleanup-ready barrier 隔离），单样本成本降约一个数量级，同时满足 median/p95 报告要求。
2. **源码未变时跳过 staging**：`stage_current_binaries: false` + pipeline AMI 可省约 3 分钟，但
   仅当 AMI 内置二进制 digest 与当前 checkout 构建一致时允许（论文"运行当前源码"语义）；digest
   不一致必须重新 bake 或保持 staging。
3. **非论文调试轮可保留 fleet 复用**（约 `$0.57/小时`/10 台）：本轮 Practical 续跑已验证同 fleet
   跨协议复用可行；论文数据轮仍必须 fresh fleet。
4. **启动前凭证检查已由预检自动化**（见上）。

### PracticalADKR "recast/partial-verify" 优化启用情况查证

全库检索不存在名为 "good cast" 的代码或文档标识；与该称呼对应的是论文
share-dispersal-then-agree-and-**recast** 范式及其配套验证优化。本轮 Practical 测试
（`run-20260822-170102`，`-n 10 -f 3 -kappa-profile matched-lifetime -strict-network=true`，
未传 `-ablation-mode`）的启用情况：

- **Recast 阶段**：始终执行。`core/kappa.go` 按 profile 选择 k；f=3 时任何 profile 的 k 循环都
  终止于 `k=f+1=4`（k>f 时 honest inclusion 确定性成立，失败概率 `-inf`），即确定性包含的 Recast。
- **Partial-verify（条目级预调度部分验证 + 结果多播）**：**已启用**。`core/adkr.go` Phase 6 在
  `ablation-mode=none`（默认）走 `runPartialVerificationMulticast`——每方只验证 2f+1 个条目并交换
  签名投票，f+1 正票即接受（`core/partial_verify_multicast.go`）；lane 覆盖不足 2f+1 会显式报错。
  两个消融开关 `no-partial-verify`/`full-local-verify` 在 `strict-network=true` 下被直接拒绝
  （adkr.go:585-593），且 multicast 路径失败时 strict 模式不允许回退全本地验证。本轮 10/10 成功
  且使用 strict-network，故 partial-verify 多播路径在全部节点实际走通。
- 证据缺口：schema v4 compact 白名单未保留 `kappa=`/`ablation_mode`/`mean_partial_verify_ms`
  字段，artifact 单独不可证；启用结论由 bench 参数 + 代码分支 + strict 成功判据联合得出。建议后续
  把这三个字段加入 compact 白名单（每行仅增加约 60 字节），使优化启用情况可直接从 artifact 复核。

### 更正与补充：PracticalADKR 的 Delta（δ）好情况优化未启用

上一小节回答了 recast/partial-verify；用户实际询问的是论文的 **δ（Delta）好情况优化**
（论文 Fig. 4c/4d 与实验章节："wait for a short time δ after distributing the shares, instead of
proceeding immediately after receiving 2f+1 signatures"，论文取 δ=1s@n=127/196、2s@n=56，好情况下
运行时间降 40--54%）。代码结论：

- **δ dealing 窗口已实现**：`experiments/practical-adkr/core/pvss_dxt.go:617-656`——dealer 收满
  2f+1 ACK 后不立即结束，额外等待 δ 窗口收集慢节点的签名，使其进入 transcript、减少后续 VE 验证
  条目；受环境变量 `PRACTICAL_DEALING_DELTA_MS` 控制，**默认 0 = 关闭（legacy 阈值即推进）**。
- **配套 KEY wait-all 已实现**：`core/comp_multicast.go:446-448`（论文自 [23] 的第二个好情况优化，
  Fig. 4d）——key derivation 达到插值阈值后额外等待窗口收集其余委员会 KEY 消息，受
  `PRACTICAL_DERIVE_WAIT_ALL_MS` 控制，**默认 0 = 关闭**。
- **本轮 `run-20260822-170102` 未启用任何一个**：bench 参数与 fabric 编排均未注入上述环境变量，
  Practical 以 legacy proceed-at-threshold 基线运行。这不会让 Practical 的成绩被低估为不公平——
  恰恰相反，δ 优化只会让 Practical 更快，因此本轮 ARL 对 Practical 约 2.3 倍的延迟优势是在
  Practical 未开好情况优化的保守基线上取得的；若为论文比较 Practical 最佳配置，必须补一轮启用
  δ 的对照，届时 ARL 优势可能收窄。
- **启用方式（无需改代码）**：`_remote_env_lines` 支持按项目透传环境变量
  （fabfile `_remote_env_lines`，`projects.<project>.env` 映射）。在实验 config 中加入：

```yaml
projects:
  practical-adkr:
    env:
      PRACTICAL_DEALING_DELTA_MS: "1000"   # 论文 n>=127 用 1s；n=10 无论文推荐值，需自定 sweep
      PRACTICAL_DERIVE_WAIT_ALL_MS: "1000"
```

并在实验记录与本文表中显式登记；同 fleet 的 ARL/Practical 对照轮必须声明两者各自的优化配置，
避免不可比。注：n=10 下论文没有 δ 推荐值（其实验从 n=56 起），小委员会的 straggler 收益需要
单独 sweep 后再定。

## 2026-08-22 私网 n=10 双协议复测 `paper-private-n10-current-20260822-ae`（部署耗时度量轮）

与 `-ad` 轮相同的配置与 bench 参数（v6 AMI、`us-east-1f`、10 台 `c7g.xlarge` Spot、私网
`10.42.1.10--19`、`n=10,f=3,runs=1`），目的：(a) 验证行缓冲与凭证预检两项运维修复在真实 suite
中的表现；(b) 首次以实时日志逐段度量部署编排耗时。当日 SSO token 仍处于过期状态（refresh token
已失效），沿用 CLI 角色凭证缓存（有效至 `20:52Z`）生成临时静态 profile 后一次性完成，全程**零人工
干预**：`17:46:12Z` 启动，`18:15:46Z` 结束，**29m34s**，`status=success`、`cleanup=destroyed`、
`final_cleanup=cleanup-ready`。预检正确打印 `credentials OK` 与 `cached SSO token already expired`
告警；实时日志全程每 10 秒有推进，无需再进入实例判断进度（仅按用户要求做了一次实例内验证：协议
status 早已 `success`，控制面检测落后于协议完成）。

### 阶段耗时拆解（UTC）

| 阶段 | 区间 | 耗时 | 备注 |
| --- | --- | ---: | --- |
| Terraform apply | 17:46:40-17:50:30 | 3.8 min | node[0] Spot 分配独占约 3 min；其余 9 台 30-40 s |
| aws-up SSM Online 等待 | 17:50:30-17:53:45 | 3.2 min | 实例 17:47:22 启动，末节点 17:51:54 online |
| staging + ARL setup | 17:53:45-17:57:36 | 3.9 min | Go 缓存秒编译（digest 同昨日）；ARL setup 缓存 miss 重建（见下） |
| ARL barrier+launch+ready | 17:57:36-18:01:04 | 3.5 min | cleanup-ready 40 s；start_at=18:00:50；协议本体约 2 s |
| ARL wait 检测 | 18:01:04-18:04:54 | 3.8 min | 实例内 status 早已 success；轮询粒度约 90 s/轮 |
| ARL collect | 18:04:54-18:06:41 | 1.8 min | |
| Practical setup（缓存命中） | 18:06:41-18:08:36 | 1.9 min | |
| Practical barrier+launch+ready | 18:08:36-18:10:26 | 1.8 min | cleanup-ready 20 s；start_at=18:10:24 |
| Practical wait 检测 | 18:10:26-18:12:33 | 2.1 min | 协议本体 4-12 s；`[12s]` 时已 8/7 |
| Practical collect | 18:12:33-18:12:53 | 0.3 min | |
| final cleanup + destroy | 18:12:53-18:15:46 | 2.9 min | |

### 结果

| 项目 | run_id | 完成 | mean latency | median | min--max | sent/recv 均值 | 共识 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| ARLADKR | `run-20260822-175905` | `10/10`（quorum `10/7`） | **`1888.87 ms`** | `1868.42` | `1785.07--2004.83` | `4.08 / 4.03 MB` | 单一 hash `69c9d62f...569ee77` |
| PracticalADKR | `run-20260822-180845` | `8/10`（quorum `8/7`） | **`3804.53 ms`** | `3795.89` | `3731.51--3904.52` | `0.99 / 0.98 MB` | 单一 hash `b13caec4...b60c50` |

ARL 与 `-ad` 轮几乎一致（`1888.87` 对 `1896.01 ms`），且节点 `10.42.1.16` 本轮恢复成功（上轮全零）。
Practical 在 wait 达到 quorum 时 2 台节点（`.13`/`.17`）仍在运行，collect 只取得 8 份快组样本——
本轮 `3804.53 ms` 全部来自 3.7-3.9 s 快组，缺少上轮 4.6-4.8 s 慢组，**不能与 `-ad` 轮 10 节点的
`4335.03 ms` 直接比较为"Practical 变快"**；这同时说明 quorum 即返回的 wait 策略对延迟分布有采样
偏差，正式数据轮应等待全部节点或固定时间窗后再收集。

### 与 `-ad` 轮的流程对比与新优化点

本轮 29m34s vs `-ad` 事故轮 40 min（含约 15 min SSO 中断）；扣除本轮两个一次性异常（node[0] Spot
等待约 3 min、ARL setup 缓存 miss 重建约 2 min）后约 26 min，与 `-ad` 正常基线相当——**部署流程
本身未变快（无代码改动），质变在于全程实时可观测与零人工干预**。本轮拆解确认的下一批优化点按收益
排序：

1. ~~**`aws_wait` 检测延迟（两协议合计约 6 min，最大可优化项）**~~ **已实现并经 2026-08-23
   `-af` 轮实测验证：ARL wait 3s、Practical wait 63s、无返回停滞，整轮 7m50s。**更正根因：状态扫描本就是一条批量 SSM 命令，慢在两处——(a) sweep 要等全部
   10 台到达终态才返回，一个慢 agent 即把 ARL 首轮拖到约 88 s（协议本体约 2 s）；(b) 每轮循环
   开头执行 `_assert_aws_fleet_unchanged` EC2 describe，`-ae` 轮 Practical 在 quorum 判定后到
   返回之间实测停滞约 100 s（疑似 describe 限流重试）。修复见下节：quorum 即返回 + sweep 时限
   20 s + 断言移至决策边界。
2. **setup 缓存键应排除编排代码**：本轮修改了 `fabfile.py`/`test_fabfile.py`，协议 Go 源码与二进制
   digest 均未变（`rladkrbench` 仍为 `924019ec...`），但整树归档 digest 变化导致 ARL setup 缓存
   miss、重建耗时约 2 min。缓存键应改用协议二进制/Go 源 digest。
3. Practical 的 8/10 收集偏差：见上，wait 返回策略需在正式数据轮调整。
4. 单节点 Spot 分配等待（3 min）为 AWS 侧方差，代码不可修；可接受或预查 placement score。

资源：10 台实例 `17:47:22--28Z` 启动、约 `18:14:14Z` 前后终止，合计 **4.477 instance-hours**；
Spot `$0.234` + 公网 IPv4 `$0.022` + gp3 `$0.015` ≈ **`$0.27`**。Terraform destroy 20/20；
复核 non-terminated 实例、EIP 均为 0；本轮复用的 `arladkr-ssm-*` 分发桶已按新清单规则清空删除。
实验逐轮累计由约 `$19.51` 更新为 **约 `$19.78`**。base config 的 profile 指向与本地临时静态
profile 已在轮末恢复/删除。

## 2026-08-23 `aws_wait` 状态检测加速与轮询间隔审计（本地，无 AWS 费用）

按用户要求把状态轮询节奏压到 10 秒级。根因更正与实现（全部在 `fabfile.py`，协议与计时口径不变）：

1. **`_ssm_run_command_many` 新增 best-effort sweep 参数**：`early_success_threshold`（成功数达到
   阈值即返回已得输出，并对仍 pending 的实例执行 `cancel_command`）与 `max_wait_seconds`（sweep
   时限，到期返回已完成的终端结果，同样取消 pending）。部分模式下不抛 SSM 批量错误——未报告的
   节点在下轮 sweep 中自然重新可见；这使状态读摆脱"最慢 agent 决定整轮"的等待（`-ae` 轮 ARL
   首轮 sweep 约 88 s 即此因，协议本体约 2 s）。
2. **`aws_wait`（SSM 路径）**：状态 sweep 以 `early_success_threshold=quorum`、
   `max_wait_seconds=status_sweep_timeout_seconds`（runner 配置，默认 20 s）调用；实测有效检测
   节奏 = SSM agent 拾取（约 5-15 s，AWS 侧物理下限）+ 1-2 s，达到用户要求的 10 秒级；
   `interval_s` 保持 2 s（非瓶颈）。fleet 一致性断言从"每轮循环一次 EC2 describe"改为
   入口/成功/失败/超时四个决策边界各一次——`-ae` 轮 Practical quorum 判定后约 100 s 的返回
   停滞即来自该每轮 describe（疑似限流重试）；Spot 回收的 invalidated 语义经边界断言保留。
3. **轮询间隔审计（全部检视，仅上述两处需要改）**：批量 SSM 命令内轮询 1 s、单实例 SSM 等待
   1 s、runner ready quorum 轮询 1 s、setup 重试退避 `2^n` 封顶 8 s——均已是紧的；SSM Online
   等待重试 5 s 与 roster 稳定窗 15 s（`roster_stability_seconds`）为正确性保护（防 Spot 静默
   替换，曾有 n=32 轮因此 invalidated），保留不缩减。

新增 3 项单测（quorum 早返回并取消 pending、sweep 时限部分返回不抛错、`aws_wait` 边界断言与
参数传递），既有 1 项区域路由测试的 mock 签名随内部调用约定微调（接受关键字参数）。全套
**65/65 通过**，`py_compile` 通过。尚未在 AWS 实测：静态凭证已于 `2026-08-22T20:52Z` 过期且
SSO refresh token 失效，下一次实验前需先 `aws sso login --profile arladkr-sso`；预期收益为
`-ae` 轮时间线中的 ARL wait 3.8 min → 约 0.5 min、Practical wait 2.1 min → 约 0.5 min，
外加消除返回停滞。注意：本修改继续改变整树源码 digest，若 setup 缓存键未先修复（优化点 2），
下轮 ARL setup 仍会缓存 miss 重建。

## 2026-08-23 私网 n=10 双协议 `paper-private-n10-current-20260823-af`（wait 加速实测验证轮）

用户重新 `aws sso login` 后（新 token 至 `03:21Z`，CLI 与 fabric 的 boto3 均直接可用，无需静态
profile），以与 `-ae` 完全相同的配置与 bench 参数复测，验证 `aws_wait` 加速改造。结果
`status=success`、`cleanup=destroyed`、`final_cleanup=cleanup-ready`，全程
**02:23:08Z--02:30:58Z 共 7m50s**（`-ae` 轮 29m34s，其中本_round 亦受益于本轮 Spot 分配与 SSM
注册都较快：apply 约 1 min、SSM Online 约 0.5 min，属 AWS 侧方差；结构性收益见下）。

**wait 加速验证（本轮目的，达成）**：

- ARL wait：synchronized start `02:26:11Z` 后首轮 sweep `[3s] success=10/7`，quorum 即返回，
  含返回断言共约 13 s——`-ae` 轮同阶段 3.8 min（首 sweep 88 s + 逐轮 EC2 断言）。
- Practical wait：`[63s] success=10/7` 后立即返回，无 `-ae` 轮 quorum 判定后约 100 s 的停滞；
  本轮 **10/10 全部成功并收集**（`-ae` 轮 wait 在 8/10 即返回、丢失 2 个慢节点样本）。
- 其余阶段：ARL setup 缓存 miss（fabfile 又改，新键 `a244b66fd4f3`）重建约 1 min；Practical
  setup 缓存命中；两协议 collect 合计约 0.9 min；final cleanup-ready + destroy 约 2.2 min。

| 项目 | run_id | 完成 | mean latency | median | min--max | 共识 |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| ARLADKR | `run-20260823-022543` | `10/10` | **`2461.49 ms`** | `2478.24` | `2339.56--2559.51` | 单一 hash `1befb01f...590e90d` |
| PracticalADKR | `run-20260823-022730` | `10/10` | **`3806.73 ms`** | `3809.01` | `3731.52--3884.18` | 单一 hash `5f9fa202...e800b` |

延迟口径注意：ARL 三轮同源码同拓扑均值为 `1896/1889/2461 ms`（`-ad/-ae/-af`），单 epoch 跨
fleet 方差约 `30%`，再次说明单轮 smoke 不能作为论文数值，正式数据需多轮 median/p95。Practical
本轮 10/10 全在快组（`3.73--3.88 s`），与 `-ae` 轮 8 节点快组均值 `3804.53` 一致；两轮 Practical
的慢组样本（`4.6--4.8 s`）仅在 wait 等全量时出现，提示快慢双峰可能与节点启动顺序/角色分布相关，
值得在多轮采集中验证。两个 summary 的 `quorum_success=true`、digest/timing 一致性检查全部通过。

资源：10 台实例平均存活 `6.3 min`，合计 **1.046 instance-hours**；Spot `$0.055` + IPv4 `$0.005` +
gp3 `$0.004` ≈ **`$0.06`**。Terraform destroy 20/20；non-terminated 实例、EIP 均为 0；复用的
`arladkr-ssm-*` 分发桶已清空删除。实验逐轮累计由约 `$19.78` 更新为 **约 `$19.84`**。

## 2026-08-23 私网 n=64 双协议首测 `paper-private-n64-current-20260823-a1`（invalidated）

使用新配置 `deployment/config.aws-private-n64-use1.yaml`（n=64、f=21、quorum 43、`/24` 私网
`10.42.1.10--73`、v6 AMI、us-east-1f、64 台 `c7g.xlarge` Spot=256 vCPU，配额内）。本轮为首次
n=64：暴露并修复一个编排层规模缺陷，两个协议均未产出有效数据，整轮 **invalidated**，不纳入任何
性能结论。时间线（UTC）：

| 时间 | 事件 |
| --- | --- |
| 02:36-02:39 | Terraform apply：64 台全部快速创建（约 2.5 min，无 Spot 尾延迟），74 资源 |
| 02:39-02:47 | aws-up：64 agent 渐次 SSM Online（约 8 min），stability recheck 通过 |
| 02:47-02:50 | staging（Go 缓存秒编译）+ ARL n=64 CV keygen（新缓存 `7e6b4e7f419e`，约 2.5 min）+ S3 分发 + 2x32 批安装成功 |
| 02:50-03:00 | **本地 boto3 卡死**：setup 安装后的 S3 清理调用挂在 CLOSE-WAIT 半关闭连接上（SSL read 60 s 超时 × 重试），主线程 futex 等待 ~10 min；杀掉 suite 进程 |
| 03:02-03:12 | 手动续跑 ARL：cleanup-ready barrier 64/64；**发现 `_ssm_wait_quorum` 单 Region >50 台直接 ValueError**（run-20260823-030219 未发布 start 即中止） |
| 03:12-03:15 | 修复：quorum 等待按 50/批分块发送命令并合并轮询；新增单测（64 台 → 50+14 分块、quorum 43），全套 **66/66 通过** |
| 03:16-03:25 | 重启 ARL `run-20260823-031557`：barrier 64/64、launch 64/64、**分块 ready quorum 实测通过（50/43）**、同步 start_at=03:25:11Z |
| 03:26-03:44 | **ARL 协议停滞**：sweep 全程 running、无 success/failed；节点 load 0.01、bench 进程 sleeping、SIGQUIT 转储显示 23307 个 goroutine、大量 `[chan receive, 12 minutes]`；约 780s 后 13 台 failed、其余仍卡，`[wait] quorum impossible: failed=27 required=43` |
| 03:47-03:52 | 诊断性 collect：50 台 failed 节点 bench 行 `success_runs=0`、`mean_all_latency_ms≈1057592`、`consensus_hash=none`；14 台 unavailable（进程仍卡）；journald 限流截断了 goroutine 转储仅存片段 |
| 03:54-03:57 | Practical n=64 keygen（约 2 min，新缓存）+ 2x32 批安装成功；随后又遇同型 S3 清理 boto3 卡死，杀掉续跑 |
| 04:01-04:12 | Practical `run-20260823-040134`：barrier 64/64、launch 64/64，但 **runner ready quorum 0/43**——节点上 transient 单元未产生 `.ready` marker（run 脚本本身未执行；按用户指示收尾，未继续定位） |
| 04:16-04:20 | Terraform destroy 74/74；non-terminated 实例、EIP 均为 0；S3 分发桶残留已清空删除 |

### 问题分析（按证据强度排序）

1. **ARLADKR n=64 活性失败（协议层，最有价值的负结果）**：全部节点空闲等待而非计算（load 0.01），
   goroutine 阻塞在 channel receive 超过 12 min，最终 0 成功。活跃节点 ≥50 > n-f=43，阈值理论上
   可满足，排除简单的"缺席节点过多"。可能方向：某条等待路径在 n=64 下假设了全 n 响应、
   receiver/actor 地址表在 2n=128 个逻辑 actor 下的 lane 映射问题、或 14 台未随 start 发布的节点
   的 listener 缺失破坏了某个未设阈值的服务。需要本地 proc-sim n=64 复现 + goroutine 全量转储
   （journald 会截断，应转储到文件再 S3/分块拉取）。n=10/n=32 同代码路径正常。
2. **编排层 >50 台 quorum 等待缺陷（已修复）**：`_ssm_wait_quorum` 原先单 Region >50 台直接
   抛错，SSM 单命令 50 实例上限未分块。已改为 50/批发送 + 合并轮询，66/66 测试通过并在本轮
   ARL launch 实测验证（ready=50/43）。
3. **本地 boto3 SSL 卡死（环境层）**：02:50Z 后本机到 AWS 的网络质量下降，setup 安装后的 S3
   清理调用挂在 CLOSE-WAIT 连接（60 s SSL read × botocore 重试），两轮各损失约 10/5 分钟。
   `_aws_boto3_client` 未配置显式 connect/read timeout——建议后续为所有 boto3 client 注入
   `botocore.config.Config(connect_timeout=5, read_timeout=30, retries={'max_attempts': 3})`，
   让慢调用快速失败而不是无限磨。
4. **Practical ready quorum 0/43（未定位）**：run 脚本未在节点执行（`.ready` 未生成），与 ARL
   卡住进程是否残留占用端口的关系未验证（barrier 报告 64/64 cleanup-ready，但 ARL 的 31 个
   sleeping 进程是否被正确回收未复核）。下次 n=64 Practical 应先验证 ARL 进程归零再 launch。
5. 64 台 barrier 约 4.5 min、aws-up 约 8 min——n=64 的编排固定开销显著大于 n=10（barrier 内
   多轮 SSM × 64 台），如需多轮 n=64 实验应考虑进一步并行化 barrier 内部步骤。

### 成本

64 台实例 `02:37:22Z` 前后启动、`04:19-04:20Z` 终止，平均存活 103.5 min，合计
**110.35 instance-hours**：Spot（`$0.0523/h`）约 `$5.77`、公网 IPv4 约 `$0.55`、gp3 约 `$0.43`，
本轮保守计 **约 `$6.75`**（为当前最贵单轮；其中协议停滞与诊断占约 40 min ≈ `$2.4`，属首次 n=64
的必要试错）。实验逐轮累计由约 `$19.84` 更新为 **约 `$26.59`**。base config、tfvars 的 profile
指向与本地临时静态 profile 已恢复/删除；S3 分发桶已清空删除。

## 2026-08-23 本地 n=64 双协议 TCP 测试（无 AWS 资源，新增成本 `$0`）

按上节"尚未完成的下一步"在本地复现 n=64。环境：单台 224 vCPU（AMD EPYC）x86_64、
275 GiB 内存；ARLADKR 用 `scripts/run_cv_cluster.sh 64 21`（组件 20000-20127、MVBA
20228-20291，等全部 64 个 listener 就绪、每节点 GOMAXPROCS=3）；PracticalADKR 用
`deployment/docker/run_proc_sim.py`，`bench_latency` 由当前 checkout 的
`experiments/practical-adkr` 镜像构建为 x86-64（sha256
`71960756e6705dd5e1badf275b8411fbd4b561553f29e54907dfef58c03aeb3f`；注意
`practicaladkr_project_code/practical-adkr` 副本已落后，无 δ 代码，AWS 配置的
`local_path` 也指向 ARL 仓库镜像）。

### ARLADKR n=64：64/64 成功，未复现 AWS 停滞

单轮全流程（含 keygen）约 2.5 分钟：`successful_nodes=64`、quorum `43` 达成、唯一
consensus hash `faa526fecbe2529a69b2b84408460b99c3606bd9159fd4491a64dc37fcf8fc39`。
service-grace-adjusted latency 均值 `28020.56 ms`（min/max `27758-28401`，raw 约
`38020` 含 `10000 ms` grace）；阶段均值：leaf build `2251 ms`、candidate formation
`20170 ms`（proposer slots `19951 ms`）、aggregate agreement `1317 ms`、recover shard
`12451 ms`（含 grace）、receipt `156 ms`；通信量 `30.44/30.40 MB` 每节点。仍为
smoke sampling（proposer/validator sample=3）。

与 AWS n=64 停滞的关键差异是启动语义：本地 harness 等全部 `n=64` listener 就绪才放行
（`RLADKR_LISTENER_READY_NODE_COUNT=n` + epoch barrier + MVBA peer wait=all），AWS runner
在 `n-f` ready 即发布同步 start（当轮 64 台 launch 但 ready 只到 `50/43`，14 台未随
start 进入）。本地全量就绪下协议完整完成，说明当前证据**不支持**"n=64 存在协议层死锁"，
更支持"未就绪节点缺失破坏某条未设阈值的服务"这一假设。但这不是 AWS 失败的证明：本地
共享主机 GOMAXPROCS=3/节点、回环零 RTT，仍需按下节方向在 AWS 复测（例如临时把 runner
readiness 提为全量 n 或延长 ready 等待后对照）。

### PracticalADKR n=64：三轮定位 + dealing-δ 达 quorum；发现 wait-all δ 严格等值 bug

编排/环境修复（不改协议代码）：

1. `run_proc_sim.py` 在无延迟 profile 时无条件注入 `PRACTICAL_DXT_FAST_LOCAL_ACKS=1`，
   与 strict-network 的拒绝守卫（`adkr.go:2196`）冲突，首轮 64/64 立即失败。已改为尊重
   外部覆盖，本地 strict 轮以 `=0` 运行。
2. `bench_latency` 不会自建 `PRACTICAL_ARTIFACT_CACHE_DIR`，AWS 由 fabric 预建；本地需
   预创建 `artifact-cache/` 目录，否则 64/64 死于 signing setup lock ENOENT。
3. n=64 本地规模调参（均为文档已记录的环境变量）：`PRACTICAL_KEY_DERIVE_TIMEOUT_MS`
   45s→300000、`PRACTICAL_PARTIAL_VERIFY_TIMEOUT_MS` 8s→60000（该默认值 n=10/32 够用、
   n=64 全员同时进入时不足，64/64 死于 partial-verify multicast timeout；建议后续像 DXT
   deadline 一样做成规模自适应）；proc-sim 新增 `PROC_SIM_AFFINITY_SPAN=3`（每节点 3 核
   亲和，默认 1 保持旧行为）压缩 64 进程的阶段性偏斜。

**协议 bug（Fig. 4d δ / `PRACTICAL_DERIVE_WAIT_ALL_MS>0` 路径不可用）**：开启
derive wait-all 后两轮分别 `22/64`、`29/64` 节点死于 `CompProve completion input
incomplete`。根因是 `comp_multicast.go:581` 的 `len(valid) != threshold` 严格等值检查
（`:606` 验证侧 `len(ShareDigests) != Threshold` 同样严格）：wait-all 窗口让 collector
在达到 43 后继续收集，收集数几乎必然 >43，构建完成证书必然失败。该路径默认关闭、无任何
`waitAll>0` 测试覆盖。修复方向为构建证书时按确定性规则（如最小 sender id）截取 threshold
个子集；本轮未改协议代码。

**有效结果**（同一调参环境，单 epoch，本地回环）：

| 轮次 | δ dealing | 成功 | 均值 latency | median / max | 共识 |
| --- | --- | ---: | ---: | ---: | --- |
| r6 | `PRACTICAL_DEALING_DELTA_MS=1000` | `45/64`（quorum 43 达成） | `110851 ms` | `112616 / 124757` | 唯一 `6c51ba21…` |
| r7（对照） | 关闭 | `52/64`（quorum 达成） | `171077 ms` | `171226 / 180819` | 唯一 `77251d24…` |

r7 各阶段（MVBA `48.6s`、recover `28.2s`、partial verify `18.6s`）显著慢于 r6
（`29.5/5.1/2.2s`），但**不能归因 δ**：本地回环 ACK 全部快速到达，dealer 走
"收满全体立即结束"分支（`pvss_dxt.go:636`），δ 窗口基本不构成约束（两轮 DXT 字节
仅差约 1%）；且两轮为单样本、共享主机 run-to-run 方差大（测试期间 5/15 分钟负载均值
16-20）。δ 的真实收益需在 WAN/straggler 环境（AWS）验证。每轮 12-19 个尾部节点因快
节点完成即退出（`-runs 1`）导致 readiness 探测不足而失败，与 AWS n=32 Practical
`27/32` 的尾部形态同型。通信量约 `154.8/154.7 MB` 每节点，约为 ARL 本地 n=64
（`30.4 MB`）的 5 倍。

### 产物与遗留

ARL 产物：`/tmp/arladkr-n64-local-r1/`（cluster-results.log 含 64 条 E2E 结果）；Practical
产物：`/tmp/practical-n64-{delta-r1..r4,nodelta-r5..r7}/`（r1/r2 为失败定位轮）。两处
harness 修改在 `practicaladkr_project_code/deployment/docker/run_proc_sim.py`（该目录无
git，改动未入库）。未启动任何 AWS 资源，本轮新增 AWS 成本 `$0`；下一步若在 AWS 复测
n=64，应先在 ARL 侧对照"全量 n readiness"与现行为，并为 Practical 打开 dealing-δ、
保持 wait-all 关闭直至上述 bug 修复。

## 2026-08-23 本地 n=96 双协议 TCP 测试 + CPU 监控（无 AWS 资源，新增成本 `$0`）

同一 224 vCPU 主机。CPU 监控用自写 `/tmp/cpu_monitor.py`（每 5 s 从 `/proc/<pid>/stat`
tick 差分统计目标进程 CPU% 总和/均值/峰值、RSS 与系统 CPU%，避免 ps 的生命周期平均失真；
注意 `pkill -f` 匹配模式会命中自身 shell，需用 `[.]` 转义规避——与本文 cleanup barrier
自匹配历史教训同源）。

### ARLADKR n=96：94/96 成功，quorum 65 达成

`run_cv_cluster.sh 96 31`（f=31、kappa=32、quorum 65；组件 20000-20191、MVBA
20292-20387；每节点 GOMAXPROCS=2/leaf workers 2；epoch timeout 900s 只用掉约 81s）。
全流程含 keygen 约 4 分钟：`successful_nodes=94`、`quorum_success=1`、唯一 consensus
hash `30a7dc03595f65b85fbfd1004283ae3614b6a76e92cce22e1bf74a6925e20376`；2 个节点未在
quorum 后 15s settle 窗口内完成、按 harness 规则被清理（NO_RESULT，不影响 quorum 判定）。

| 指标 | 94 节点均值 | 范围 |
| --- | ---: | ---: |
| service-grace-adjusted latency | `81119.10 ms` | `80823.99-81475.21` |
| raw latency（含 10 s grace） | 约 `91119 ms` | - |
| leaf build | `5204.64 ms` | `2218-8721` |
| candidate formation / proposer slots | `66897.96 / 66393.83 ms` | `63406-69931 / 63347-67524` |
| aggregate agreement / recover shard / receipt | `2103.28 / 13498.74 / 279.81 ms` | - |
| 每节点发送/接收 | `41.27 / 33.83 MB` | recv 最高 `384.0 MB`（proposer 节点） |

相对本地 n=64（均值 `28020 ms`、proposer slots `19951 ms`），总延迟约 2.9 倍、proposer
slots 约 3.3 倍，超线性增长主要来自 proposer slots 内的 component catalog 恢复与验证
（每 proposer 需扫 65 个 component）。仍为 smoke sampling。

**CPU 剖析**（96 进程，活动窗口约 100 s）：前 ~60 s 为 setup/leaf 阶段，持续仅约
`1500-1700%`（15-17 核）；约 `13:39` 进入密码验证突发，**峰值 `19145%`（191 核，主机
85%）**、系统 CPU 峰值 `84.6%`；峰值总 RSS `34.7 GiB`（约 360 MiB/进程）；随后节点集中
退出、RSS 骤降。即本地 n=96 的瓶颈是短时 CPU 突发而非持续满载，224 核主机可承载。

### PracticalADKR n=96：0/96，recast recovery 结构性卡死（用户中止后续测试）

配置沿用 n=64 有效配方（dealing-δ=1000、`FAST_LOCAL_ACKS=0`、`KEY_DERIVE=300s`、
`PARTIAL_VERIFY=90s`、亲和跨度 2、`-timeout 1200s`）。r1 全部 96 节点在约 `307 s` 墙钟
同时失败：`recast recovery timeout: dealer=X holders=65 recipients=0; …; holder=0
completions=0/65`（adkr.go:1926）。各节点对约 17-31 个 selected dealer 全部零 recipient
完成；恢复进入前各阶段正常（无 CompProve/readiness/partial-verify 错误）。

诊断证据：(a) 失败前 CPU 每进程仅 `0.5-0.8%`（纯等待，非计算饱和）；(b) 96 进程在
同一期限同时退出（采样器在 5 s 内观测 96→22→0）；(c) 恢复默认窗口 120 s
（adkr.go:1088，`PRACTICAL_RECOVER_TIMEOUT_MS` 可覆盖）内 `holderSeen=65` 齐而
`recipientSeen=0`，与 n=64 同配置 5-28 s 完成形成质变。r2 将恢复窗口放大到 `600 s`
重跑：至约 330 s（用户按需中止 Practical 测试）仍 0 成功、0 协议级失败、全体停在恢复
等待，说明不是单纯窗口不足，n=96 的 recast fetch/完成交换存在结构性卡点，需代码级定位
（候选方向：fetch 响应路径的串行 accept/限流、`lnByID` 监听器在 192 逻辑参与者下的服务
容量、completion 阈值路径）。失败与 δ 无关（同配置 n=64 达 quorum；失败阶段在 recovery）。

测试中止后已清理：bench 进程 0 残留、proto/MVBA 端口全部释放。产物：
`/tmp/practical-n96-dealdelta-r{1,2}/`（r2 为中止轮，92 节点无结果行）。CPU 采样 CSV：
`/tmp/cpu-arl-n96.csv`、`/tmp/cpu-practical-n96*.csv`。ARL n=96 产物：
`/tmp/arladkr-n96-local-r1/`。本轮未启动 AWS 资源；在 Practical recovery 修复前，不应
把 n=96 纳入 AWS 论文计划（n=64 及以下不受此影响）。

### ARL n=96 延迟剖析与 4-worker A/B（81 s → 58 s 的归因）

针对"n=96 均值 81 s 是否异常"做了逐节点分解与 A/B 复测。结论：**约 23 s 是本地 harness
算力伪影，其余 ~58 s 中 ~2/3 是 proposer catalog 验证的 O(n²) 密码工作量**，不是网络或
活性异常。

逐节点分解（r1，每节点 GOMAXPROCS=leaf workers=224/96=2）：94 节点中仅 4-5 个 proposer
（scan=65）实际执行 catalog 验证，其 `proposer_slots` 66.0-67.4 s 中 catalog verify 占
55.4-62.4 s；其余 ~90 个节点 verify/recovery 计数为 0、slots 同为 65-67 s——它们在等首个
verified candidate（candidate 为 ready-cert 模式，非 proposer 不重验 component）。191 核
CPU 爆发窗口对应的是决策后**全体节点同时执行 aggregate recovery**（每人 2 核满载），
不是 candidate 阶段。

A/B 复测（`RLADKR_CV_GOMAXPROCS=4 RLADKR_LEAF_VERIFY_WORKERS=4`，即 AWS c7g.xlarge
的 4 vCPU 口径，产物 `/tmp/arladkr-n96-local-w4/`）：95/96 成功、quorum 65、唯一共识。
均值 `57969 ms`（-28.5%），proposer slots `43051 ms`，catalog verify `~32400 ms`
（2 worker 时的 ~58.7 s × 2/4，符合预期）；`recover_shard` 13.2 s 不变（该阶段全体节点
并发、主机总核为界）；leaf 5.2→5.9 s（轻微争用）。CPU 峰值 209 核 / sys 93.3%。

catalog 验证每 proposer 总核时（components × 每 component 核时）：

| n | components (n-f) | 每 component 接收者 L | 每 proposer 核时 | 相对 n=32 | components×L（O(n²) 预测） |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32（本地基准） | 22 | 22 | ~14.6 core-s | 1x | 1x |
| 64（本地 r1） | 43 | 43 | ~43 core-s | 2.9x | 3.8x |
| 96（本地 r1/w4） | 65 | 65 | ~117-130 core-s | 8.0-8.9x | 8.7x |

即现有 per-leaf 批量验证（receiver-evaluation batch + ownership batch）已消除更高阶
项，但 **每个 proposer 仍需验证 n-f 个 component、每个 component 含 L=n-f 个 receiver
的方程，总核时本质 O(n²)**；且每 epoch 有 proposer sample（3+fallback）个节点重复
扫描同一批 component（n=96 时 ~5×130 ≈ 650 core-s 重复工作；validator prewarm 已被
size-aware gate 关闭，未额外放大）。

推论：(a) 本地 81 s 中 ~23 s 来自 harness `host_cpus/n` 整数除法把每节点压到 2 worker
（n=64 为 3），AWS 4 vCPU 口径应接近 58 s 量级（ARM 与 EPYC 单核吞吐差异另计）；
(b) 照当前实现外推 n=128（85 comps × 85 receivers ≈ 232 core-s/proposer）4-worker
约 58 s、总延迟 ~85 s——**在 n≥96 论文实验前，catalog 验证需要一个结构性优化**：
跨 proposer 共享/背书已验证 component（消 3-5× 重复）、跨 component 随机线性组合批量
验证（需如既有 batch 工作一样做 soundness 分析）、或协议层减少 proposer 必验的
component 数。本次仅做测试与剖析，未修改协议代码。

### n=128 门控基准校准与 58 s 的压缩空间评估

补充跑了 `BenchmarkCVV2ProposerCatalogVerifyN128`（`RLADKR_RUN_N128_LOCAL_BENCH=1`，
EPYC 9754、GOMAXPROCS=4、与线上同一 recover→verify 流水线）：86 个 component
**37.82 s/op**（9.51 GB/op、12.1M allocs/op），即 **1.76 core-s/component**（L=86）。
两个修正：

1. **每 component 成本对 L 次线性**（MSM/Pippinger 规模效应）：L=22/65/86 对应
   ~0.66/~1.5/~1.76 core-s，catalog 总核时随 n 约 `n^1.7` 而非纯 `n^2`；n=128 外推
   从上文 ~58 s 下修为实测 37.8 s（隔离、4 worker）。
2. **in-cluster 32.4 s 含约 35% 主机争用**：n=96 隔离推算 ~24 s（65×1.5/4），集群内
   其余 95 进程的 leaf/recover 与 proposer 验证重叠。AWS 一机一进程没有这项争用，
   但 ARM 单核吞吐低于 EPYC 9754，两者大致相抵，n=96 AWS catalog 验证仍按 ~25-35 s 估。

57.97 s 的构成与压缩路径（n=96、4-worker 口径）：leaf 5.9 + slots 43.0（catalog 验证
32.4 + 流水线填充/中继尾部 ~10.6）+ agreement 2.0 + recover 实际 ~3.2 + 收尾 ~0.5。

| 优化 | 类型 | 预期（集群口径） | 依赖 |
| --- | --- | --- | --- |
| 跨 component 批量验证（一次 MSM 合并全部方程） | 实现层 | 验证 32.4→11-20 s，总 ~37-46 s | soundness loss 分析 + 对抗性测试（沿用既有 batch 工作流程） |
| proposer 分工互验 + f+1 背书交换 | 协议层 | 关键路径 /3：验证 ~11 s，总 ~37 s；与上条叠加 ~28-32 s | 背书语义与 FS transcript 绑定，需安全论证 |
| 验证尾部（更早 prewarm、RS decode 提速） | 实现层 | -3-5 s | 无协议变更 |
| leaf 构建再并行化 | 实现层 | -1-2 s | 边际 |
| 8 vCPU 实例（c7g.2xlarge） | 环境 | 验证减半，总 ~40 s | 实验成本口径改变 |

叠加后合理目标：仅实现层 **~38-45 s**；加 proposer 分工 **~28-32 s**；维持"每个
proposer 独立验完全部 component"语义的下限约低 30 s（24 验证 + 6 leaf + 6 尾部 +
2 agreement + 3 recover）。要进入 30 s 以内必须改验证分工或加每节点核数。以上为单轮
估算，落地前按本仓惯例补齐定向测试、`-race`、全包回归与 soundness 记录。

## 2026-08-23 catalog 验证剖析驱动优化：leaf 级子群批检等四项（本地验证，$0 AWS）

按上节计划实施"跨 component 批量验证"。实现前的 pprof/block/trace/strace/内存剖析
（n=128 门控基准 + n=64 双变体基准 + 自写并行度探针，探针与阶段计时脚手架已删除）把
成本构成彻底改写，实际落地的四项修改与原始"合并 MSM 方程"设想不同，均按证据实施：

**剖析结论**（n=64 hints 单进程，每 component ~721ms 单核"忙时"）：
- **子群批检 487ms/component**：`assertDecodedSubgroup` 按 wire 段触发，每 component
  **194 次**批检（平均仅 67 点/次），每次各付一次小 MSM + 一次 order-r
  `IsInSubGroup` 标量乘（~2ms）——隐藏主因，此前任何口径都没拆出来；
- APVSS 语句验证（evaluation/ownership batch + 签名）133ms；规范化重编码与帧解析
  ~17ms（重编码经 size-hint 修复后仅 3.2ms）；
- 每点 `SetRandom()` 直接打内核 CSPRNG（strace 实测单轮 **277 万次 getrandom**，
  多 verifier 并发时在内核 CRNG 上串行化）；
- 解码缓冲 `bytes.Buffer` 从零倍增（alloc 剖析 57.6% 在 growSlice，2.19GB/op）；
- gnark 内层 MSM/批乘自起 goroutine 扇出（NbTasks 缺省与
  `BatchScalarMultiplicationG1` 固有扇出），与外层 verify worker 池叠加。

**实现**（协议语义不变，`8cee734` 工作树之上，未提交）：
1. **leaf 级一次性子群批检**（`cv_point_hints.go`/`cv_point_subgroup_batch.go`/
   `cv_sapvss_leaf_v2.go`）：`cvDecodeSidechannelV2` 增加 `deferredBatch` 收集器并
   默认物化；各 wire 段 reader 的 `assertDecodedSubgroup` 改为把点移交收集器，
   `cvDecodeLeafV2Sidechannel` 在 unsigned 解码完成后执行**唯一一次**全 leaf 批检
   （先于 dealer 签名与 APVSS 验证拒绝）。独立 ACK 网络路径（side=nil）保持逐段即检。
2. **FS 权重替代 SetRandom**（`cvAssertG1SubgroupBatch`）：challenge 由全部被检点的
   压缩字节哈希导出（域 `CV-V2-SUBGROUP-BATCH-v1`，零值重试，幂次权重），与
   `cvVerifyReceiverEvaluationsBatchV2` 同款 Fiat–Shamir 模式。**Soundness**：敌手
   必须先固定全部点，权重才作为 RO 输出存在，无法比独立随机抽取更可预测；批检失败
   语义与逐点检查一致（任意点在子群外 ⇒ 组合以 ≤ len(points)/r 概率漏检，与原实现
   同界）。内核 CSPRNG 调用从解码路径完全移除。
3. **解码缓冲 size hint**（`cvLeafV2CanonicalBytesSized` 等）：解码路径已知 wire
   精确长度，两个装配缓冲一次 `Grow` 取代对数级倍增；hint 只影响分配策略，
   欠估时回退增量增长，输出字节不变。
4. **内层 MSM 串行化**（`cvG1LinearCombination`/`apvssCompactPointSum` 的
   `NbTasks: cvNestedMSMWorkers`=1）：外层 leaf-verify worker 池已提供并行度，
   消除 gnark 内部 goroutine 扇出与 channel 协调对外层 worker 的踩踏（与
   `cvNestedMSMWorkers` 既有注释意图对齐；独立单次调用场景点数少，无并行损失）。

**验证与结果**：

| 指标 | before | after | 变化 |
| --- | ---: | ---: | ---: |
| n=64 门控基准 legacy（43 comps，4 worker） | 9.53 s | 5.81 s | -39% |
| n=64 门控基准 hints | 7.11 s | **3.29 s** | **-54%** |
| n=128 门控基准（无 hints，86 comps） | 37.82 s | 22.04 s | -42% |
| 每 op 分配次数（n=64） | 3.03M | 1.52M | -50% |
| 本地 n=96 集群 w4（GOMAXPROCS=4）全节点延迟 | 57.97 s | **49.97 s** | -13.8% |
| 同上 proposer catalog 验证 | ~32.4 s | ~26.3 s | -19% |
| 同上完成率 | 95/96 | **96/96（all_success）** | - |
| 同上峰值 RSS | 27.3 GiB | 20.0 GiB | -27% |

正确性：新增对抗性测试 `TestCVLeafWideSubgroupBatchRejectsPlantedOutsider`（真实
leaf 植入 on-curve 非子群点，证明 leaf 级批检先于签名/规范化拒绝）与
`TestCVDecodeSidechannelSubgroupCollector`（跨段收集/重置/拒绝）；既有 hints 回退、
子群拒绝、round-trip 测试全部通过；`go test ./core -count=1`（219.7 s）与定向
`-race` 通过；`go test ./... -run '^$'` 编译检查通过。诊断脚手架（阶段计时、并行度
探针、临时基准）已全部移除。

**遗留**：in-cluster n=96 catalog 验证（~26 s）仍高于隔离基准外推（~9-13 s），差距
指向恢复供料/多进程争用而非本批瓶颈（子群批检已从每 component 194 次降为 1 次）。

## 2026-08-23 dealer/receiver recovery 热路径解耦（本地代码验证，AWS `$0`）

本轮先处理实现层的恢复供料瓶颈，协议 wire、APDB 阈值、dealer payload 认证和 Merkle
root 校验均未改变：

- inbox `dispatch` 对 `APDBRecoverGet` 和完整 payload response 只做轻量入队；hints 生成、
  response canonical encode、payload decode/root re-encode 都移到独立的有界 recovery worker
  pool，不再阻塞同一服务的控制消息、candidate relay 或签名处理。
- dealer 在 `PublishComponent` 缓存 payload 后立即预排一个 response-preparation job；首次
  请求只等待该 job 的完成，后续请求复用同一份完整 `payload+hints` response wire，避免每个
  receiver 重复 encode/copy。`RLADKR_APDB_PAYLOAD_HINTS=0` 仍只关闭 hints，保留单 payload
  response 和相同 root 校验。
- recovery worker 默认按委员会规模取 `max(2, committee/16)`，上限 16；可用
  `RLADKR_APDB_RECOVERY_WORKERS=4|8|12|16` 做 A/B。该旋钮只控制请求/响应重活，不改变
  `RLADKR_COMPONENT_RECOVERY_WORKERS` 的 payload recovery fanout。
- 新增 `E2E_BENCH_RESULT` profile：`mean_dealer_hint_build_ms`、
  `mean_dealer_response_encode_ms`、`mean_receiver_payload_validation_ms`、
  `mean_recovery_queue_wait_ms` 和 `mean_recovery_worker_ms`。其中 queue wait 是入队到
  worker 开始的等待，worker 是实际处理墙钟；不能把多条并发 recovery latency 相加当成端到端
  延迟。

本地验证：`go test ./core ./cmd/rladkrbench` 定向 profile/metrics 测试通过；
`go test -race ./core -run 'TestCV(APDB|Service|PayloadHints|ComponentPipeline)'` 通过。
尚未 AWS 复测，因此不能声称 AWS latency 已改善。下面已完成本地固定-topology worker A/B；
新增 AWS 成本 `$0`，累计量化成本不变。

## 2026-08-23 本地 recovery workers 4/8/12/16 A/B（n=64/n=96）

在同一台 224-vCPU EPYC 主机上顺序运行八个严格 loopback TCP epoch。每个规模内部固定端口布局、
全量 listener barrier、smoke sampling、`GOMAXPROCS=4`、leaf verify workers=4、component
recovery workers=8，只改变 `RLADKR_APDB_RECOVERY_WORKERS`。每 500 ms 从 `/proc` 口径采样
全部 `rladkrbench` 的 RSS，并以 `GODEBUG=gctrace=1` 记录每进程 GC。每档只有一个 epoch，适合
选择并发上限，不作为论文统计样本。

| n | APDB workers | 完成 | adjusted E2E 均值 | queue wait 均值 | worker wall 均值 | sent/recv 每节点 | 簇峰值 RSS | GC live peak 均值/最大 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 | 4 | 63/64 | 18.99 s | 139.73 ms | 1489.83 ms | 30.93/26.95 MB* | 13.02 GiB | 290/600 MB |
| 64 | **8** | **64/64** | **17.64 s** | 135.45 ms | 1296.33 ms | 31.13/31.11 MB | 11.23 GiB | 287/412 MB |
| 64 | 12 | 62/64 | 18.03 s | 115.66 ms | 1353.54 ms | 30.76/31.56 MB* | 12.48 GiB | 288/437 MB |
| 64 | 16 | 63/64 | 17.33 s | 89.26 ms | 1219.52 ms | 29.58/27.09 MB* | 9.00 GiB | 278/438 MB |
| 96 | 4 | 96/96 | 43.05 s | 84.27 ms | 2080.69 ms | 43.96/43.95 MB | 19.25 GiB | 406/686 MB |
| 96 | 8 | 96/96 | 42.47 s | 73.34 ms | 2180.46 ms | 44.46/44.45 MB | 19.67 GiB | 405/703 MB |
| 96 | **12** | **96/96** | **42.05 s** | **57.56 ms** | 2121.65 ms | 42.71/42.69 MB | 19.72 GiB | 408/696 MB |
| 96 | 16 | 95/96 | 45.74 s | 70.29 ms | 2408.77 ms | 43.50/39.28 MB* | 24.67 GiB | 427/780 MB |

`*` 表示 settle 窗口内有节点未完成，recv 均值受结果集合截断，不能解释为通信优化。其余完整轮的
每节点通信差异约 4%，worker 数不改变 wire 或阈值，差异来自候选到达/中继调度和单轮噪声。
GC 每节点平均次数在 n=64 为 36.0--41.8、n=96 为 40.4--51.7；平均累计 GC clock 分别仅
192--208 ms 和 313--373 ms，没有 GC 成为端到端主瓶颈的证据。500-ms RSS 可能漏掉短峰，故同时
给出 gctrace live heap；两种口径都显示 n=96/w16 的内存压力最高。

结论：保留现有规模自适应默认值。service 以 old+new committee 总数计算，恰好得到 n=64 的
8 workers 和 n=96 的 12 workers；前者是 n=64 唯一 all-success 档，后者是 n=96 all-success
档中 E2E 最低且 queue wait 最低。固定 16 没有收益：n=96 慢 3.69 s、丢一个尾节点，并将簇峰值
RSS 提高约 25%。原始产物在 `/tmp/arladkr-recovery-workers-ab-20260823/`，包含每节点日志、
`cluster-results.log`、runner summary 和 RSS CSV。

## 2026-08-23 本地 n=128 严格 TCP smoke 与 AWS 条件预测

使用 `n=128,f=42`、严格 loopback TCP、全量 listener barrier、smoke proposer/validator sample=3、
`GOMAXPROCS=4`、leaf verify workers=4、component recovery workers=8 和规模默认 APDB recovery
workers=16 运行一个 epoch。本机 224 个逻辑 CPU 承载 `128*4=512` 个 Go 执行槽，约 2.29 倍超配；
因此本轮用于功能、完成率和阶段归因，不直接代表一机一节点 AWS latency。

| 指标 | 本地 n=128 结果 |
| --- | ---: |
| 完成 / quorum / 共识 | `127/128` / `86` 达成 / 单一 hash |
| adjusted E2E 均值 | `92515.56 ms` |
| setup / leaf build | `4833.21 / 10074.78 ms` |
| candidate formation / proposer slots | `67679.17 / 67425.80 ms` |
| 实际 proposer catalog verify | `54133--57133 ms`（4 个节点非零） |
| aggregate agreement | `3499.23 ms` |
| recover shard / receipt | `15449.10 / 415.56 ms`（recover 含约 10 s service grace） |
| recovery queue wait / worker wall | `51.73 / 3568.82 ms` |
| sent/recv 每成功节点 | `51.27 / 46.01 MB`* |
| 簇峰值 RSS / 单进程采样峰值 | `52.33 GiB / 1464.7 MiB` |
| GC live peak 均值/最大 | `576 / 1120 MB` |

`*` recv 均值缺少 settle 窗口内未完成的 node 69。该节点在结果清理时仍处于共享主机重负载下的
GC/计算尾部，没有协议错误行；不能把 `127/128` 解释为 Byzantine 或共识分叉。每节点 GC clock
累计均值约 `0.77 s`，不是 92 秒的主因。原始产物为
`/tmp/arladkr-n128-local-w16-20260823/`，runner/RSS 文件在同名前缀 `/tmp` 路径。

**AWS 预测边界（不是实测）。** 私网假设 128 台 `c7g.xlarge`、`us-east-1` 同 AZ、全量 ready 后
启动；公网假设 `us-east-1:64 + eu-west-1:64`、公网地址、无 netem、全部 Spot 保持存活。当前本地
smoke 与 n=128 隔离 catalog 门控基准支持以下工程预算：

| profile | AWS 私网预期 adjusted E2E | AWS 公网两区预期 | 每节点协议字节预期 | 可信度 |
| --- | ---: | ---: | ---: | --- |
| smoke (3/3) | `40--65 s` | 健康 MVBA 下 `120--300 s` | `50--65 MB` | 私网中；公网低 |
| original (proposer=19, validator=85) | `70--120 s` | `300--900 s`，有超时风险 | `0.5--1.0 GB` | 低，需 n64/n96 正式档校准 |

私网下 catalog 从共享主机的 54--57 s 回落到隔离的约 20--35 s 是主要收益；ARM 单核较 EPYC 慢，
故没有直接使用 x86 隔离基准的 12--22 s。公网范围刻意较宽：历史 n=32 美爱公网轮曾在 MVBA
aggregate agreement 放大到约 286 s，而同轮 candidate 仅约 4.6 s；在该 WAN 回归被当前代码于
n=32/n=64 重新证明消失前，不能对 n=128 公网给出窄区间或承诺完成。正式 original 的精确参数为
proposer 19、validator 85、VCert threshold 43；n=64 original 已显示通信比 smoke 高数倍，因此
不能用本轮 51 MB 外推正式公网成本。建议先做 n=128 私网 smoke，再做 n=64/n=96 公网 original，
最后才启动 n=128 公网 original。

## proposer 分工互验证书：协议层设计（待安全评审和小规模实验）

目标是在保持 component payload、Pool、ARC 和 VCert 绑定不变的前提下，避免每个 sampled
proposer 独立验证完整 `L=n-f` 个 component。该设计不是本轮代码实现，不能计入当前 latency
结果。

**责任分区。** eligibility coin `E` 经无放回 PRF 派生一个确定的责任表：对每个 component
`d`，生成至少 `2f+1` 个候选 verifier，并以 `H(domain,E,context,d,verifier)` 排序取前项。
每个 verifier 只验证自己责任窗口内的 component；责任表、版本和窗口摘要写入 transcript。
proposer sample 仅负责发起 candidate，不承担完整覆盖证明。由于正式 original profile 的
n=96/n=128 proposer sample 只有 18/19，而 `f+1` 是 32/43，不能把背书集合错误地限制为
proposer sample。

**分片验证记录。** verifier 对每个 component 产生
`ComponentCheck(component_ref_digest, payload_digest, leaf_digest, verifier, E, epoch, version,
result)`，签名域为 `CV-V2-PROPOSER-CHECK-v1`。记录必须绑定 component ref 的完整 lock/root、
payload digest、receiver/validator registry digest、责任窗口和验证结果；不能只签 component
序号或 proposer ID。相同 component 的冲突结果按签名集合保留并使该 component 不可背书。

**背书证书。** 每个责任分区达到 `f+1` 个不同 verifier 的有效检查后，形成
`ComponentEndorsementCertificate`，包括 canonical responsibility digest、component check
摘要列表、signer bitmap/签名聚合和 transcript digest。proposer 只接受覆盖全部 selected
component 的证书集合，并把其 digest 放入 Pool/VCert statement；任一 component 缺证书、
责任表不一致、registry/context 不一致或聚合签名无效都拒绝 candidate。

**活性。** 仅 `f+1` 个固定 verifier 会被 Byzantine withholding 破坏，因此发送集合必须先取
`2f+1` 候选并允许在超时后按同一 `E` 派生的下一窗口扩展；证书门槛仍为 `f+1`。扩展次数和
失败概率写入 sampling report，并与 proposer/validator sampling union bound 分开计算。不能
通过“收到任意 f+1 个签名”掩盖责任覆盖不足。

**安全边界和迁移。** 先实现 verifier 责任表/证书 codec、签名域、覆盖检查和 Byzantine
withholding/冲突测试，再接入 candidate；旧路径保留为 feature flag fallback。必须完成
soundness/liveness 证明、重放/跨 epoch/跨 context 拒绝测试、多 proposer 共用证书测试后，
才允许进入 AWS A/B。预期收益为 proposer catalog 验证关键路径约除以分区并发数，当前证据
支持的端到端目标约 `32--36 s`；文档中的 `28--32 s` 仍是叠加实现优化后的乐观上限。

## 2026-08-23 PracticalADKR 本地 n=64 ordinary/high-assurance 严格 TCP 对照

用户口述的 `high-assumption` 在代码中没有对应 profile，本节按实际存在的
`high-assurance` 执行。两轮均为 `n=64,f=21`、严格 loopback TCP、单 epoch、
Paillier-3072、`fallback-policy=off`、`PRACTICAL_DXT_FAST_LOCAL_ACKS=0`、
`PRACTICAL_DEALING_DELTA_MS=1000`、`PRACTICAL_DERIVE_WAIT_ALL_MS=0`、每节点 3 核
affinity；二进制 sha256 为 `71960756e6705dd5e1badf275b8411fbd4b561553f29e54907dfef58c03aeb3f`。
两轮唯一的协议参数差异是 `kappa-profile`。每档只跑一轮，以下分位数来自同一轮已完成节点，
用于功能和瓶颈定位，不是论文统计样本。

| profile | 实际 kappa / 安全预算 | 完成 / quorum / 共识 | E2E mean / median / p95 | online median | derive median | sent/recv median 每节点 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `practical-original` | `20`；epoch 35.41-bit；525600 epochs union-bound 16.41-bit | `54/64` / 43 达成 / 单一 hash | `81.85 / 78.32 / 92.07 s` | `40.71 s` | `4.12 s` | `153.75/153.72 MB` |
| `high-assurance` | `22=f+1`；确定性 honest inclusion（failure 0） | `63/64` / 43 达成 / 单一 hash | `190.34 / 190.36 / 190.91 s` | `153.59 s` | `116.26 s` | `155.67/154.66 MB` |

两档 setup median 接近（`37.62 s` 与 `36.82 s`），MVBA median 也接近（`29.43 s` 与
`29.48 s`）；high-assurance 的主要放大集中在 derive。partial verify median 从 `1.96 s`
升至 `2.14 s`，recover 从 `4.57 s` 升至 `5.05 s`，均无法解释约 112.9 秒的 online 差值。
通信量只增加约 1%，因此不是网络字节主导。

代码没有 high-assurance 专用 derive 分支；两档都走 `runCompKeyDerivationMulticast`。
该路径先扫描 selected transcripts，缺少 receiver ACK aux 时执行 3072-bit Paillier 解密，随后
43 份 CompProve share 的逐份验证又各自扫描 selected transcripts。`kappa=22` 相对 20 的
理论线性增量只有 10%，不能单独解释本轮约 28 倍的 derive median；当前最值得验证的假设是新增
selected transcript 的 ACK 覆盖较差，触发了更多昂贵的 Paillier fallback，并被 64 进程同时
计算放大。现有结果没有记录 `ack-hit/paillier-decrypt` 数量，故这只是待 profile 假设，不能写成
已证明根因。下一次无需重复完整 A/B，先在 CompProve 增加 ACK hit、Paillier decrypt count/time、
share verify count/time，再跑单轮 targeted profile 即可。

完成率按停止时已产生 `E2E_BENCH_RESULT` 的节点计算；成功节点在 service grace 后退出，尾节点
可能失去 peer，因此没有等待它们耗尽 600 秒 timeout。第一次 ordinary 预跑误设
`--mem-per-node-mb=3072`，该参数实施的是 `RLIMIT_AS` 而非 RSS 限制，导致实际 RSS 仅几十 MiB
时出现 mmap/pthread OOM，整轮作废；取消虚拟地址空间上限后无同类错误。本轮没有启动 AWS 资源，
新增成本 `$0`，累计 AWS 成本不变。有效产物为
`/tmp/practical-n64-original-r2-20260823/` 和
`/tmp/practical-n64-high-assurance-20260823/`。

## 本地 n=128 original setup 启动诊断与处理建议（2026-08-23）

本地 TCP `n=128,f=42` 使用论文 original sampling `c_prop/c_val/q_val=19/85/43` 时，
128 个节点日志都只写入一行 `WARMUP`，没有 `E2E_BENCH_RESULT`、`EPOCH_RUN_ERROR`、panic
或 timeout。运行约 11 分钟后主动停止，未产生可用 E2E 数据。

这不是已证实的 OOM：运行期间进程 RSS 峰值约 `153 GiB`，机器仍约 `118 GiB` 可用内存，swap
为 0，未发现 OOM killer 或 cgroup kill 记录。`WARMUP` 是 benchmark 在 `--start-at` 前打印的
第一行，不代表进程一直停留在 sleep；warmup 后每个进程会进入 `PrepareConfigRuntime`，在
`RunEpoch` 前加载并验证完整 n=128 receiver/validator registry 和 threshold key bundle。
128 个进程同时重复该 setup，形成 CPU/内存并发启动风暴，最可能导致进程长期未完成 setup，
而不是 ARC、VCert 或 validator 协议阶段失败。

setup 不是本实验主要指标，后续应采用以下处理口径：

1. 将 CV V2 key bundle 作为预生成、带 digest 校验的实验输入；不要在每个 benchmark epoch
   重新生成 key material。
2. 将 `PrepareConfigRuntime` 作为 setup 阶段单独计时并从 E2E 中排除；协议进程只在 setup
   完成后进入统一 start barrier。
3. 本机 n=128 不要 128 路同时做 setup。先分批预热（建议 16--32 个进程一批），或为每个
   进程设置 staggered setup，再统一等待 `n-f` 个 listener/epoch markers 后启动协议。
4. 不要用 `-precompute-runtime=false` 作为性能修复；这只是把同样的加载成本移入协议计时，
   会污染 E2E。若需要快速 smoke，只能明确标注为 setup-inclusive smoke。
5. AWS 一节点一进程时，setup 并发压力通常会分散到多台机器；仍应保留 bundle digest、
   setup-complete 时间和 listener-ready 时间，避免把 setup 卡住误判为协议性能异常。

本次失败不应填写 n=128 的延迟、通信量或 ARC communication share；追踪结果保留为
`0/128`、无有效 E2E，直到采用分批/预热方案重新运行。

### 修复实施状态（2026-08-23）

已在本地 runner 和 benchmark 入口实施 setup/协议解耦：

- `rladkrbench` 现在先执行 `PrepareConfigRuntime`，写入 `RLADKR_SETUP_READY_DIR/node-*.ready`，再等待 `--start-at` 并进入 `RunEpoch`；setup 不再与统一协议起点同时发生。
- `scripts/run_cv_cluster.sh` 默认按 16 个节点一批启动，等待整批 setup-ready marker 后再启动下一批；`n>=96` 默认预留 600 秒 start window，`RLADKR_CV_SETUP_BATCH_SIZE` 和 `RLADKR_CV_SETUP_READY_TIMEOUT` 可调。
- setup marker 只表示本地 runtime/key material 已准备完成，不改变协议 quorum，也不计入 E2E - setup。正式结果仍由 `E2E_BENCH_RESULT` 和 epoch barrier 校验。
- n=4 回归运行通过：4/4 成功、quorum 3、单一 consensus hash；说明新启动顺序不会破坏协议流程。

这相当于跳过 setup 对协议性能的影响，而不是跳过安全校验：key bundle 仍通过 digest 和 registry 校验，`PrepareConfigRuntime` 仍然执行，只是被提前并按批次摊平。下一次 n=128 original 应使用默认 batch=16，并保证 runner 总超时覆盖 setup window + epoch timeout，例如：

```bash
RLADKR_CV_FAILURE_TARGET=original \
RLADKR_CV_SETUP_BATCH_SIZE=16 \
RLADKR_CV_SETUP_READY_TIMEOUT=900s \
RLADKR_CV_EPOCH_TIMEOUT=900s \
RLADKR_CV_RUNNER_TIMEOUT=1800s \
bash scripts/run_cv_cluster.sh 128 42 /tmp/arladkr-n128-original-batched 25000
```

若 setup 仍超过窗口，可将 `RLADKR_CV_SETUP_BATCH_SIZE=8`；不应改用 `-precompute-runtime=false`。

## Candidate fanout 通信审查与后续优化（2026-08-23）

### 结论先行

本地 n=64 original 结果中，每节点 `total sent/recv` 为 `232.76/212.94 MB`，这些总计、
`recovery sent/recv` 和 ARC share 的数值计算没有错误。此前把
`mean_candidate_formation_sent_bytes=204.23 MB` 直接解释成 candidate fanout 是归因错误：
该字段来自全局 `commPhase`，多个 proposer slot 并发运行时，aggregate APDB、proposer/
validator recovery 等流量会混入 candidate formation phase。

按 `CV_V2_CERTIFIED_CANDIDATE` tag 重新归因，candidate relay 实际约为每节点发送 `2.16 MB`、
接收 `1.74 MB`；单个 agreement object wire 约 `21.95 KB`。平均 fanout attempt 为 `96.9`，
其中 retry `39.2`，约 `40.5%`。因此 candidate fanout 不是 n=64 总通信量的主要来源，但存在
明显的重复传播和 ACK 延迟放大。

### 代码审查结果

1. **全量 fanout 加全量 relay 会形成 flooding。** proposer 在
   `core/cv_sapvss_candidate_network_v2.go:247-292` 向完整 `OldRoster` 发送；每个接收并接受
   candidate 的节点又在 `:493-511` 向除发送者外的完整 roster relay。digest cache 只能避免
   重复验证，不能避免重复 payload 已经在线路上传输。
2. **ACK 走共享单 worker 队列。** 接收 candidate 后 ACK 在 `:455-462` 通过 `sendAsync` 入队，
   但 `core/cv_sapvss_apdb_network_v2.go:597-608` 只有一个 outbound worker 串行发送。在
   aggregate/recovery 流量拥塞时，candidate 已送达而 ACK 尚未发出，会触发完整 candidate
   重复发送。
3. **phase byte counter 不是互斥分解。** `setCommPhase` 是 runtime 级全局状态，且 proposer
   slot 并发执行；因此 phase counter 只能用于时间窗口定位，不能替代 tag 级通信统计。

### 优化顺序

1. 增加 `direct-only` feature flag，先保留 proposer 到全 roster 的一次发送，关闭接收后的
   再 relay，验证完成率、candidate tag bytes 和 retry 是否下降。这是安全语义变化最小的
   A/B。
2. 为 candidate ACK 增加优先级队列或专用 ACK writer，避免 ACK 排在大 payload 后面。该项
   比单纯修改 retry delay 更可能减少重复字节。
3. 若 direct-only 仍需故障传播，再实现 deterministic dissemination tree：每个节点只向
   预定 child 转发，并设置备用 parent；禁止全 roster flooding。
4. 评估 validator-sample + digest/pull：先传播 digest/header，validator sample 获取完整
   candidate，其他节点按需拉取。不能直接把目标集合改为 validator sample，因为当前
   `cvVerifyAgreementObjectV2` 要求完整 pool/component refs 可用。
5. 最后再做 pool catalog 缓存、digest 引用和紧凑编码。当前 agreement object 只有约 22 KB，
   这些优化收益低于消除 relay 和 ACK 阻塞。

`RLADKR_CANDIDATE_FANOUT_PARALLEL` 只改变并发度，不直接减少字节；在 ACK 队列未优化前盲目
增大并发可能增加拥塞和 retry。后续 AWS 实验必须同时记录 tag 级 candidate bytes、attempts、
retries、ACK wait、direct/relay mode 和完成率，不能只依赖 `mean_candidate_formation_*`。

### 本地新机器验证结果（32 vCPU / 39 GiB，2026-08-23）

代码已加入 `RLADKR_CANDIDATE_FANOUT_MODE`：`flood`（兼容旧行为）、`direct-only`（源节点
全量发送、接收节点不 relay）和 `tree`（按 candidate proposer 为根的确定性二叉传播树）。ACK
已移入独立 priority outbound queue；candidate tag bytes 与混合 phase counter 也已分离，输出
`mean_candidate_formation_*`（tag-accurate）和 `mean_candidate_phase_counter_*`（原始窗口计数）。

本机 n=32 original（`f=10, c_prop/c_val/q_val=11/21/11`）进行了两档快速验证：

| 模式 | 结果 | 观察 |
| --- | --- | --- |
| `direct-only` | 无有效 E2E；节点最终 `quitpd`/MVBA deadline | 关闭 relay 后，当前 MVBA/候选可用性假设未满足；不能直接设为默认 |
| `tree` | 产生部分结果后停止；多节点在 decision finalization 仅收到 `19/22` shares | 树传播减少冗余但当前决策阶段仍需要完整节点可达性；不能视为成功基准 |

两轮都没有 OOM，测试目录和进程已清理。失败说明 direct-only/tree 不能只改 fanout 目标，
必须同时实现 digest/header 广播、authenticated pull 或 MVBA value fetch，确保未直接收到完整
candidate 的节点仍能参与 predicate 和 decision-share 阶段。

### validator-sample + pull / pool catalog 评估

当前 `cvVerifyAgreementObjectV2` 会验证完整 pool 中的每个 component ref、pool certificate、
VCert 和 ARC；直接把 candidate fanout 限制为 validator sample 会让其他节点缺少 MVBA predicate
所需的完整 object。因此本轮没有启用不完整的 validator-only 路径。

推荐的后续协议改造是：先传播 candidate digest/header，validator sample 验证完整 object；其余
节点通过带 digest、origin 和 proof 的 pull 获取完整 candidate，收到后再进入 predicate。pool
catalog 可以按 `pool digest` 缓存并按需拉取缺失 component refs，但必须保留 pool digest 和
certificate 的绑定验证。当前只做缓存不会减少线上的首次 payload，收益低于 relay/tree 和 ACK
优先级优化，暂不作为默认改动。

### Pull 原型回归（本地 n=4，2026-08-23）

新增 `RLADKR_CANDIDATE_FANOUT_MODE=pull` 原型：源节点向 roster 发送带 origin/digest 的轻量
announce，接收节点通过 priority queue 发送 digest fetch，源节点返回带 digest 绑定的完整
candidate response；接收端再次校验 response digest 后才进入现有 candidate verification queue。

n=4 smoke 回归为 `4/4` 结果、无错误、单一 consensus hash，说明 pull 的基本活性和认证绑定
成立。当前 pull 是全 roster announce + 按需 fetch，还不是 validator-sample-only；n=32 以上仍
需要在 pull 成功后再逐步限制 fetch 目标集合，并补充 source failure/fallback 测试。candidate
relay 统计已包含 announce/fetch/response 三类 tag，避免 pull 模式下漏算完整 response。

### Validator-pull 原型回归（本地 n=4，2026-08-23）

新增 `RLADKR_CANDIDATE_FANOUT_MODE=validator-pull`：announce 仍只携带 origin/digest；validator
sample 节点向 origin 拉取完整 candidate，非 validator 节点向确定的 validator 请求；validator
在尚未缓存时记录 waiter、代 origin 拉取，再把 digest-bound response 转发给 waiter。接收端仍
经过原有 canonical decode/verify，不接受未匹配 digest 的 response。

n=4 smoke 为 `4/4`、无错误、单一 consensus hash。该结果证明 validator-aware pull 的基本
请求链和认证绑定可用，但尚未证明 source failure、validator failure 或 n=32 以上的 quorum
可用性；下一轮应先加入多 validator fallback，再进行 n=32 A/B。

随后补充 origin-set fallback：同一 digest 现在保留已见的多个 proposer origins，validator cache
miss 时按节点 ID 稳定顺序向这些 origins 转发 fetch，不再覆盖早先 origin。这样 source failure
测试可以利用另一个已发布同 digest 的 proposer 作为候选来源；若整个 origin 集合都不可达，仍
会按正常 quorum 失败，不会伪造成功结果。

### Validator-pull fallback n=32 回归（本地新机器，2026-08-23）

加入 validator sample 顺序 fallback：非 validator 会依次向 sample validators 发起 digest fetch，
若仍未缓存再回退 origin；validator 仍会保留 waiter 并代 origin 拉取。`n=32,f=10`、论文
original `11/21/11` 在 32 vCPU/39 GiB 主机上得到 `22/32` 结果，达到 quorum 22，无
`EPOCH_RUN_ERROR`、panic 或 OOM，且结果共享单一 consensus hash。成功节点均值为：

| 指标 | 值 |
| --- | ---: |
| E2E raw / setup-adjusted | `38.88 / 38.47 s` |
| total sent/recv 每节点 | `47.23 / 34.83 MB` |
| candidate relay tag sent | 约 `0.01 MB` |

该轮证明 validator-pull 在 n=32 至少具备 quorum 活性；22/32 不是完整性能基准，仍需补充
source failure、validator failure 和多 origin fallback 后再比较 flood/tree。

### Source failure injection（本地 n=4，2026-08-24）

在 validator-pull 启动完成 setup 后主动停止 node 0。该轮没有有效 E2E；其余节点等待完整
candidate/MVBA value，直到测试窗口结束。原因是单一 candidate digest 只有一个 origin 时，
origin-set fallback 没有可切换的第二份完整 payload；保存 origin 集合只能在多个 proposer 已经
持有同一 digest 时提供替代来源，不能凭空恢复被停止的唯一 source。下一步应先设计 proposer
candidate replication/validator prefetch，再做 source failure 的正式活性测试。

同配置的 origin-set fallback 复跑（r2）在本机资源调度下出现 `22` 个 partial result，但最终
均为 MVBA `quitpd` deadline，未形成有效 E2E 基准；该轮 invalidated，不覆盖前一轮达到 quorum
的结果。当前证据说明 fallback 代码通过单测且不破坏 n=4，但 n=32 的活性仍受本机 32 vCPU
调度和协议 timeout 影响，不能把一次成功或失败外推为正式性能结论。

### Validator prefetch 实施（2026-08-24）

`validator-pull` 现在在 digest announce 之前，先把完整、已 canonicalized 的 candidate wire
发送给 validator sample 并写入其 candidate cache；随后才发送轻量 announce。这样 source 在
candidate 发布后退出时，validator 仍可作为完整 payload 的替代来源。正常 n=4 validator-pull
回归保持 `4/4`、无错误、单一 consensus hash，说明 prefetch 不破坏基本活性。

source failure 注入仍需更精确地杀掉实际 proposer，并确认至少一个 validator 已收到 prefetch；
若唯一 proposer 在 prefetch 完成前退出，协议仍应失败，这是预期的安全行为，而不是 fallback
缺陷。下一轮应增加 prefetch-ready marker 或测试 transport 的按 tag 丢包钩子，再做可重复的
source/validator failure A/B。
