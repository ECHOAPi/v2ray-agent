# v2ray-agent · ECHOAPi 端口管理版

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Port management regression](https://github.com/ECHOAPi/v2ray-agent/actions/workflows/port-management-tests.yml/badge.svg?branch=master)](https://github.com/ECHOAPi/v2ray-agent/actions/workflows/port-management-tests.yml)

基于 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 的 Xray-core / sing-box 管理脚本。本仓库保留原有安装、协议、账户和订阅管理能力，并将主菜单 **12「添加新端口」升级为「端口管理」**。

当前脚本版本：`v3.5.24-port.5`。本轮修正 Xray/sing-box 核心安装、升级及 Xray 回退的先删后下载：核心、内置 Geo 和配置候选在锁外准备，验证通过后才替换，失败返回错误并尝试恢复旧文件；sing-box 合并不再改写原始配置碎片。真实核心、内核规则和客户端验收仍待完成；单端口限速为实验性功能。

## 本版新增

- **安装后更换端口**：修改受支持的独立入口，不重新生成账户、UUID、密码或 Reality 密钥。
- **订阅同步**：核对全部账户及适用的 default、Clash 和 sing-box 输出，保留订阅下载地址与 Salt。客户端需要重新拉取订阅。
- **批量月额度与到期日**：统一或逐项设置额度、截止时间，支持用量查询、续期及人工暂停/恢复。
- **单端口双向限速**：每次只选择一个入口，分别设置上传和下载 Mbps，不提供批量限速。
- **变更恢复**：共享写锁、候选配置校验、私密备份、事务记录及失败补偿；反向改端口保留后续账户变化和已用流量。
- **持续执行策略**：systemd 后台服务核对 nftables 额度/到期规则和 tc 限速对象，退出菜单后继续运行。

原有多协议安装、证书、伪装站、CDN、分流、用户管理等功能继续保留。中文与英文脚本共用同一套端口管理模块。

## 安装与更新

### 运行前提

端口管理的写入适配目标是 Debian / Ubuntu + systemd。实际配置、核心服务和网络规则必须通过本机预检，不能仅凭系统名称判断支持。

基础依赖包括 Python 3.9+、`python3-yaml`、jq、时区数据、`flock`、`ss`、curl 和 GNU coreutils（含 timeout、sha256sum）；额度/到期功能还需要 nftables、同步时钟及后台服务，限速还需要 tc/HTB/flower/IFB 和符合要求的接口、队列结构。

在 Debian / Ubuntu 上可先准备依赖（以 root 执行）：

```bash
apt-get update && apt-get install -y curl ca-certificates python3 python3-yaml jq coreutils tzdata util-linux iproute2 nftables
python3 --version
```

请确认 Python 不低于 3.9。安装 nftables 软件包不等于要求启用它的通用服务；本模块通过自己的后台服务管理专属规则表。

### 中文入口

以下命令下载本仓库的 `master` 脚本，先检查 Bash 语法，再打开菜单：

```bash
curl --fail --location --proto '=https' --tlsv1.2 "https://raw.githubusercontent.com/ECHOAPi/v2ray-agent/master/install.sh" -o /root/install.sh && bash -n /root/install.sh && chmod 700 /root/install.sh && /root/install.sh
```

已有安装也可用此命令更新脚本入口。需要管理现有节点时选择菜单 **12**，不要选择重新安装。之后可以使用快捷命令：

```bash
vasma
```

### 英文入口

```bash
curl --fail --location --proto '=https' --tlsv1.2 "https://raw.githubusercontent.com/ECHOAPi/v2ray-agent/master/shell/install_en.sh" -o /root/install.sh && bash -n /root/install.sh && chmod 700 /root/install.sh && /root/install.sh
```

### 后续更新

主菜单 **17「更新脚本」** 从 `ECHOAPi/v2ray-agent` 获取更新。端口管理模块使用安装器中记录的固定提交，避免混用不同版本；下载或校验失败时保留旧脚本，成功替换时保留 `install.sh.previous`。

脚本和模块下载期间不占用共用写锁，后台可继续核对策略。提交前重新检查配置、已安装脚本和模块指针；发现其他操作已改变这些内容时，本次更新会失败退出，请重新运行。普通脚本替换失败会尝试恢复原模块指针。

首次进入端口管理会安装对应的模块。首次使用额度、到期或限速功能时，菜单会提示确认安装后台服务及核心启动依赖，不需要重装协议或重新创建账户。

### 核心安装、升级与回退

Xray/sing-box 的下载和候选配置检查在随机私有目录中进行，期间不占用共用写锁。核心归档必须匹配 GitHub Release 资产的 SHA-256 摘要，只提取指定的普通二进制文件；版本、Geo 或配置校验失败时，不删除旧核心、不提前停止服务，也不递归重试。旧发布缺少可用摘要、回退核心不支持当前配置时，会拒绝更新。

提交前重新核对配置、脚本、模块指针、二进制、Geo、标准服务文件和 TLS 文件，以及服务状态。已运行的目标核心才执行有超时的重启与活动状态检查，不重启另一核心；原先停止的服务保持停止，首次安装只准备文件，不声称尚未生成的协议配置可用。部分替换、重启失败及可捕获信号会尝试恢复旧文件；文件恢复不等于服务已恢复。

该流程仅适配 Linux amd64/arm64、标准目录和标准 root systemd 服务；OpenRC、动态/非 root 用户、自定义服务来源或启动命令会拒绝自动处理。成功后保留私有 `.core-backup.*` 目录，不自动清理历史备份。若提示 `.core-update.*/KEEP_RECOVERY`，后续安装器写入会被阻止；请按 [核心恢复说明](documents/security-followup-a397ae39-2026-09-08.md#核心备份与恢复) 先核对并恢复一致文件，不能直接删除标记。

sing-box 的 DNS、旧出站和 HTTP client 兼容性转换只处理配置碎片的临时副本，校验通过后才替换合并结果。原始碎片在成功和失败时均保持不变；不覆盖已有 HTTP client 设置，遇到畸形 JSON 或冲突的新旧字段会失败退出。自定义相对资源路径和旧核心的兼容性仍需单独验证。

### Geo 更新与主机维护

Xray 菜单的 Geo 更新及 `UpdateGeo` 定时入口先在私有目录下载两个数据库及 SHA-256 校验文件，并调用已安装核心检查候选数据和配置；准备期间释放共用写锁。取锁复核后仅替换 `geosite.dat`、`geoip.dat`，不删除其他 `geo*` 文件。下载或校验失败保留旧数据；替换、服务重启失败或可捕获信号触发文件补偿，cron 返回失败，不再输出成功时间。

该独立更新入口要求标准目录的 systemd Xray 安装；Alpine/OpenRC 和自定义路径拒绝自动更新。重启等待有超时，成功提示仅代表配置检查和当时的服务状态通过，不代表公网连通性通过。若提示保留恢复目录，请先按 [Geo 恢复说明](documents/security-followup-74a1a73d-2026-09-08.md#geo-恢复与验证边界) 核对，不能仅删除 `KEEP_RECOVERY`。核心安装/升级中的 Geo 下载现已复用候选校验，并与核心一起备份和补偿。

安装器检测到包管理器忙时会退出，请等待已有任务结束后重试；不再强杀 apt 或删除 yum 的 PID 文件。证书 cron 只替换精确匹配的标准续期作业，保留 Geo、其他 ACME、监控及自定义作业，旧表备份为 `backup_crontab.cron`。已修改过命令或时间的续期作业也会保留，需自行检查是否重复。

独立 `shell/ufw_remove.sh` 已停用，只提示并返回失败，不再修改防火墙或服务。历史 Release 和标签不再自动清理；完整的 `-port.*` 版本按预发布发布，不覆盖稳定版 latest。

## 端口管理菜单

运行 `vasma`，选择 **12「端口管理」**：

| 子菜单 | 功能 |
|---|---|
| 1 | 查看入口、端口、监听及策略状态 |
| 2 | 修改一个节点的连接端口 |
| 3 | 检查 TCP / UDP 端口占用 |
| 4 | 查看变更记录，回退最近一次端口变更 |
| 5 | 查看、添加或删除可安全识别的附加端口 |
| 6 | 批量设置月流量额度和到期日 |
| 7 | 查看用量、自然月周期和历史记录 |
| 8 | 批量调整额度/日期、暂停或恢复 |
| 9 | 设置一个入口的上传、下载速度上限 |
| 0 | 返回 |

支持按 `#1,#3`、完整 `port_id`、`port:10001` 或已有端口范围 `10001-10010` 选择。范围只筛选已有入口，不创建新端口；同号多对象或重复选择会要求明确选择。

### 额度、日期与速度的含义

| 设置 | 规则 |
|---|---|
| 月流量 | 同一逻辑入口的上下行合计，多用户共享；GB = 1,000,000,000 字节，GiB 需显式输入 |
| 月周期 | 按管理时区的自然月计算；默认 `Asia/Shanghai`，调整额度不重置当月已用量 |
| 到期日 | 仅填日期表示该日全天有效，次日零点截止；也可输入带时区的明确时刻 |
| 上传 / 下载 | 从客户端视角定义，分别设置 Mbps；匹配到的同入口用户和连接共享对应方向的调度类 |
| 空白 | 保留该字段原值 |
| `unlimited` | 解除额度或对应方向的速度限制；日期使用 `never` 表示永不到期 |
| 0 | 月额度为 0 时阻断；速度为 0 时拒绝，不把它当作不限速 |

到期、超额和人工暂停分别生效。续期、提高额度或解除限速不会绕过仍存在的其他限制，改端口和回退也不会返还已经消耗的流量。

## 支持范围与已知限制

端口修改适配 Xray Reality、独立 XHTTP + Reality，以及 sing-box Reality、Hysteria2、Tuic 的已知配置结构。共享 TLS/Nginx 入口、内部回落、CDN/外部反代、端口跳跃/NAT、Docker/OpenRC 和未知自定义配置只读或拒绝自动写入。

订阅须先通过原有订阅管理完整初始化。端口事务不会临时安装 Nginx、申请证书、重新生成 Salt 或刷新远程模板。成功发布后需在客户端重新拉取；本机检查不代表云安全组或公网连接已验证。

**限速仍有实质边界：** 当前 flower 端口分类不能覆盖非首个 IP 分片，因此尚不能保证严格的端口带宽上限。首次接入只接受空/noqueue 或本模块已拥有的队列结构；`mq`、`fq_codel`、未知 QoS 和多个外部接口会被拒绝。`applied=true` 仅表示对象安装核验通过，不代表真实吞吐验收通过。

**策略刷新仍受旧写入流程影响：** 日志跟随、等待输入、自更新、模块下载、Geo 更新、核心安装/升级及 sing-box 配置合并的慢准备阶段已释放共用写锁；订阅远程模板下载等其他旧流程仍可能长时间持锁。最终文件替换、摘要复核和服务操作仍持锁，文件系统操作没有统一硬超时。超过 30 秒策略有效期后，纳管入口可能被保守阻断；R01 尚未整体关闭。

删除主账户会联动使用相同凭证的辅助入口。如果将删空 SOCKS、HTTP 或 mixed 入站的认证用户列表，整批删除会被拒绝并保留原配置。请先为辅助入口设置独立凭证或禁用该入口，再重新删除。

新生成的 Clash 完整配置默认只允许本机访问代理、管理接口及 DNS；Trojan gRPC 的 sing-box 订阅恢复证书校验。已下载的旧配置需要重新拉取。换 Salt 时先准备新订阅，再撤销五种格式的旧生成地址；普通发布失败尝试补偿，中断后若保留恢复目录会明确提示。订阅生成现在需要 Python 3。

这些改动不代表全部账户、订阅和更新流程已完成整改。R01、A10（历史权限/ACL）、A12（Docker 失败恢复）仍待处理；A11 报告列出的核心及输入碎片路径已按本轮范围修正，但不提供多文件断电原子性，也不代表所有旧重载调用链已完成错误传播。准确范围见 [本轮安全修正记录](documents/security-followup-a397ae39-2026-09-08.md)。此前的认证删空保护不会自动修复已经存在的空认证列表，Clash 回环监听也不等于管理 API 已配置认证。

旧防火墙放行规则采用保留策略，不会清空整机规则。异常断电或计数器代次丢失会保留可信用量并采取保守限制；目前没有完整的全量退役和普通用户故障校正向导，不应直接删除账本、规则表或队列解除限制。

完整范围及恢复方式见 [端口管理使用说明](documents/port-management.md)。

## 测试与验证

本轮 **258 项本地隔离回归全部通过，0 失败、0 跳过**，其中新增 31 项核心安装/升级/回退及候选配置测试；完整结果见 [本轮安全修正记录](documents/security-followup-a397ae39-2026-09-08.md)。云端 CI 状态见页首徽章及对应提交的检查页。测试实际执行 Bash 函数、归档解析、摘要、文件锁和策略模块，核心、网络、服务及内核执行器为替身，没有操作实际代理服务器。真实核心、内核流量、双栈、重启/断电和客户端验收尚待完成。

在仓库目录复现：

```bash
bash -n install.sh
bash -n shell/install_en.sh
bash -n shell/init_tls.sh
bash -n shell/ufw_remove.sh
node --check .github/scripts/release.cjs
PYTHONPATH=shell python3 -m unittest discover -s tests -p 'test_port*.py' -q
```

需要 Python 3.9+、PyYAML、Bash、jq、util-linux、GNU coreutils 和 Node.js 18+；Node.js 仅用于仓库发布回归，不是节点运行依赖。非 root 环境会跳过要求 root 的安装器锁测试。详细结果与待验证项见 [实施验证记录](documents/port-management-validation.md)。

## 文档与反馈

- [端口管理使用说明、支持范围与恢复步骤](documents/port-management.md)
- [端口管理实施验证记录](documents/port-management-validation.md)
- [2026-09-08 复核修正范围与剩余问题](documents/audit-followup-2026-09-08.md)
- [5748474d 后的安全修正与验证](documents/security-followup-5748474d-2026-09-08.md)
- [74a1a73d 后的 Geo、主机操作与发布修正](documents/security-followup-74a1a73d-2026-09-08.md)
- [a397ae39 后的核心升级与配置候选修正](documents/security-followup-a397ae39-2026-09-08.md)
- [提交本修改版的问题](https://github.com/ECHOAPi/v2ray-agent/issues)
- [本仓库 CI](https://github.com/ECHOAPi/v2ray-agent/actions)
- [上游基础使用教程](https://www.v2ray-agent.com/archives/1710141233)
- [上游英文文档](documents/en/README_EN.md)
- [原有 Docker Reality 说明](https://www.v2ray-agent.com/archives/019e1b57-92b3-70ab-8919-cdf8c0bb4fe9)；Docker 独立脚本不包含本版端口管理能力

## 上游与许可证

原始项目由 [mack-a](https://github.com/mack-a) 及上游贡献者维护，ECHOAPi 在其基础上维护本修改版。上游社区：[Telegram 频道](https://t.me/v2rayAgentChannel)、[交流群](https://t.me/technologyshare)、[网站](https://www.v2ray-agent.com/)。

感谢 [JetBrains](https://www.jetbrains.com/?from=v2ray-agent) 提供非商业开源软件开发授权。

本项目遵循 [AGPL-3.0 许可证](LICENSE)。端口管理新增与相关修正不表示原审计报告中的全部问题已解决。
