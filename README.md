# v2ray-agent · ECHOAPi 端口管理版

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Port management regression](https://github.com/ECHOAPi/v2ray-agent/actions/workflows/port-management-tests.yml/badge.svg?branch=master)](https://github.com/ECHOAPi/v2ray-agent/actions/workflows/port-management-tests.yml)

基于 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 的 Xray-core / sing-box 管理脚本。本仓库保留原有安装、协议、账户和订阅管理能力，并将主菜单 **12「添加新端口」升级为「端口管理」**。

当前脚本版本：`v3.5.24-port.1`。端口管理已加入代码，真实核心、内核规则和客户端验收仍待完成；单端口限速为实验性功能，已知限制见下文。

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

基础依赖包括 Python 3.9+、`python3-yaml`、时区数据、`flock`、`ss` 和 curl；额度/到期功能还需要 nftables、同步时钟及后台服务，限速还需要 tc/HTB/flower/IFB 和符合要求的接口、队列结构。

在 Debian / Ubuntu 上可先准备依赖（以 root 执行）：

```bash
apt-get update && apt-get install -y curl ca-certificates python3 python3-yaml tzdata util-linux iproute2 nftables
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

首次进入端口管理会安装对应的模块。首次使用额度、到期或限速功能时，菜单会提示确认安装后台服务及核心启动依赖，不需要重装协议或重新创建账户。

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

旧防火墙放行规则采用保留策略，不会清空整机规则。异常断电或计数器代次丢失会保留可信用量并采取保守限制；目前没有完整的全量退役和普通用户故障校正向导，不应直接删除账本、规则表或队列解除限制。

完整范围及恢复方式见 [端口管理使用说明](documents/port-management.md)。

## 测试与验证

本版已完成 **130 项本地隔离回归测试**，对应开发提交的 GitHub CI 已通过。测试使用临时目录、合成账户和模拟系统执行器，没有操作实际代理服务器。真实核心、内核流量、双栈、重启/断电和客户端验收尚待完成；合并代码不等于这些验收已经通过。

在仓库目录复现：

```bash
bash -n install.sh
bash -n shell/install_en.sh
PYTHONPATH=shell python3 -m unittest discover -s tests -p 'test_port*.py' -q
```

需要 Python 3.9+、PyYAML、Bash、jq 和 util-linux；非 root 环境会跳过要求 root 的安装器锁测试。详细结果与待验证项见 [实施验证记录](documents/port-management-validation.md)。

## 文档与反馈

- [端口管理使用说明、支持范围与恢复步骤](documents/port-management.md)
- [端口管理实施验证记录](documents/port-management-validation.md)
- [提交本修改版的问题](https://github.com/ECHOAPi/v2ray-agent/issues)
- [本仓库 CI](https://github.com/ECHOAPi/v2ray-agent/actions)
- [上游基础使用教程](https://www.v2ray-agent.com/archives/1710141233)
- [上游英文文档](documents/en/README_EN.md)
- [原有 Docker Reality 说明](https://www.v2ray-agent.com/archives/019e1b57-92b3-70ab-8919-cdf8c0bb4fe9)；Docker 独立脚本不包含本版端口管理能力

## 上游与许可证

原始项目由 [mack-a](https://github.com/mack-a) 及上游贡献者维护，ECHOAPi 在其基础上维护本修改版。上游社区：[Telegram 频道](https://t.me/v2rayAgentChannel)、[交流群](https://t.me/technologyshare)、[网站](https://www.v2ray-agent.com/)。

感谢 [JetBrains](https://www.jetbrains.com/?from=v2ray-agent) 提供非商业开源软件开发授权。

本项目遵循 [AGPL-3.0 许可证](LICENSE)。端口管理新增与相关修正不表示原审计报告中的全部问题已解决。
