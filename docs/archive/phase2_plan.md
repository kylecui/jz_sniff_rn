# Phase 2：产品集成开发方案

> 版本：1.3.1
> 日期：2026-03-23
> 状态：待评审（v1.3.1 — 修复 Momus 评审发现的 3 个阻塞问题）
> 前置文档：[design.md](design.md) · [backlog.md](backlog.md)
> *(Note: these are relative links within docs/archive/)*

---

## 目录

1. [架构前提](#1-架构前提)
2. [技术决策](#2-技术决策)
3. [需求逻辑重组](#3-需求逻辑重组)
4. [能力差距分析](#4-能力差距分析)
5. [多网口架构设计](#5-多网口架构设计)
6. [日志格式规范](#6-日志格式规范)
7. [配置体系增强](#7-配置体系增强)
8. [分阶段开发计划](#8-分阶段开发计划)
9. [配置Schema变更](#9-配置schema变更)
10. [API变更清单](#10-api变更清单)
11. [新增文件清单](#11-新增文件清单)
12. [交叉编译与多架构注意事项](#12-交叉编译与多架构注意事项)
13. [风险与待决事项](#13-风险与待决事项)

---

## 1. 架构前提

### 1.1 多架构部署目标

jz_sniff_rn 将部署在以下环境：

| 环境 | 架构 | 内核要求 | 说明 |
|------|------|----------|------|
| 物理设备（当前） | x86_64 | 5.8+ BTF | Ubuntu 22.04/24.04 |
| 嵌入式网关 | aarch64 (ARM64) | 5.10+ BTF | OpenWrt/Debian ARM |
| VPC 云环境 | x86_64 / aarch64 | 5.15+ BTF | AWS/阿里云 VPC，可能无XDP硬件卸载 |

**此前提对所有技术决策产生约束**：

- 所有第三方依赖必须支持交叉编译或为纯C可vendor
- 不依赖特定架构的系统调用（如x86特有的syscall号）
- BPF程序本身架构无关，但 `vmlinux.h` 需按目标内核/架构生成
- 前端为纯静态资源（JS/CSS/HTML），无架构依赖

### 1.2 已有约束（不变）

- 纯 XDP 方案，不引入 TC 或更高层 helper
- 不修改 rSwitch 核心代码
- jz maps pinned 在 `/sys/fs/bpf/jz/` 命名空间下
- jz 模块使用 `rs_ctx` 偏移 192-255 的保留字节
- `jz_config_map_batch_t` 必须堆分配（~800KB+）

---

## 2. 技术决策

### 2.1 MQTT 客户端：Paho Embedded C

| 维度 | 选择 | 理由 |
|------|------|------|
| 库 | [Eclipse Paho Embedded C](https://github.com/eclipse/paho.mqtt.embedded-c) | 纯C、零外部依赖、~50KB编译体积、支持x86/ARM/任意POSIX |
| 集成方式 | vendor 进 `third_party/paho-embed/` | 与 mongoose、cJSON 同等方式管理 |
| 传输层 | 自带 socket 抽象 + 我们提供 TLS 适配层 | 利用已有的 mongoose TLS 或直接用 OpenSSL/mbedTLS |
| QoS | QoS 1（至少一次） | 配合本地 SQLite 离线缓冲，确保不丢 |
| Topic 设计 | `jz/{device_id}/logs/{type}` | type = attack, sniffer, bg, threat, audit, heartbeat |

**注意事项**：
- Paho Embedded C 是同步 API（MQTTClient），不是 Paho C（异步API，依赖pthread）
- 需要我们自己实现 reconnect 逻辑和离线缓冲（SQLite already handles this）
- Broker 地址/端口/认证由配置文件指定。Broker 部署在云端，端侧只做 MQTT client

### 2.2 前端框架：Vue 3

| 维度 | 选择 | 理由 |
|------|------|------|
| 框架 | Vue 3 + Vite | 轻量SPA，构建产物 <500KB gzip，适合嵌入式 |
| UI 库 | 待定（建议 Element Plus 或 Naive UI） | 开箱即用的管理后台组件 |
| 部署方式 | `make frontend` 构建 → 静态文件复制到 `/usr/share/jz/www/` → Mongoose 直接 serve | 无需额外 web server |
| API 通信 | fetch / axios → 已有 31+ REST API | 前端纯消费，不引入 WebSocket（暂时） |

**目录结构**：
```
frontend/              # Vue 3 项目（独立 package.json）
├── src/
│   ├── views/         # 页面组件
│   ├── components/    # 通用组件
│   ├── api/           # API 封装
│   ├── stores/        # Pinia 状态管理
│   └── router/        # Vue Router
├── vite.config.ts
└── package.json
```

### 2.3 其他保持不变

- HTTP 服务器：Mongoose（已有）
- JSON 解析：cJSON（已有）
- 数据持久化：SQLite（已有）
- 进程间通信：Unix domain socket（已有）
- 配置格式：YAML（已有）

---

## 3. 需求逻辑重组

将用户提出的 16 项需求重新组织为 5 个功能域：

### 域A：哨兵生命周期管理

> 产品核心 — 从设备发现到哨兵自动部署、自动退出的完整生命周期

```
网络 → [设备发现] → 在线设备表 → [IP选择] → 动态哨兵 → [冲突检测] → 自动退出
                         ↓                    ↑
                    排除：白名单          约束：比例限制
                    排除：冻结IP          约束：max_entries
                    排除：已在线IP        约束：每VLAN独立
```

| 需求# | 需求描述 | 优先级 |
|--------|----------|--------|
| 1 | 自动探测各二层在线设备（多VLAN） | P0 |
| 2 | 选择未使用IP上线动态哨兵 | P0 |
| 4 | 真实设备占用哨兵IP时自动下线 | P0 |
| 8 | 限制动态哨兵占用比例 | P1 |
| 7 | 可冻结IP（不被动态哨兵使用） | P1 |
| 5 | 可配置静态哨兵 | ✅ 已完成 |
| 6 | 可配置白名单 | ✅ 已完成 |
| 3 | 捕获探测哨兵流量并记录 | ✅ 已完成 |

### 域B：流量编织与蜜罐导流

> 基于攻击事件自动创建流量策略，将可疑流量导入蜜罐做深度分析

```
攻击事件 → [策略引擎] → flow_policy → [traffic_weaver BPF] → REDIRECT/MIRROR → 蜜罐
                ↕
         动态策略调整（升级/降级/过期）
```

| 需求# | 需求描述 | 优先级 |
|--------|----------|--------|
| 9 | 基于rSwitch流量编织导入蜜罐 | P0 |
| 13 | 蜜罐导流动态/自动策略调整 | P1 |

### 域C：日志格式与传输

> 兼容旧系统 syslog 格式 + 设计新 v2 格式，支持多种传输通道

```
事件 → [格式化引擎] → v1 KV 格式 → rsyslog
                     → v2 JSON 格式 → MQTT / HTTPS
```

| 需求# | 需求描述 | 优先级 |
|--------|----------|--------|
| 10 | 兼容早期格式（rsyslog）+ 设计 v2 格式 | P0 |
| 11 | 用户可选格式和传输方式（MQTT/rsyslog/HTTPS） | P0 |

### 域D：配置管理增强

> 在现有基础上增加 UCI 式分阶段修改能力 + 完善云端推送

| 需求# | 需求描述 | 优先级 |
|--------|----------|--------|
| 12 | 保留界面配置 + 云端下发（类似 OpenWrt UCI） | P1 |

### 域E：部署模式与多网口

> 支持旁路/串行两种部署模式，均支持多网口和特定流量抓取

| 需求# | 需求描述 | 优先级 |
|--------|----------|--------|
| 14 | 串行接入（保留交换机基础功能） | P2（可后置） |
| 15 | 旁路/串行都保留抓取特定流量能力 | P1 |

### 补充需求（隐含）

| 补充项 | 说明 | 优先级 |
|--------|------|--------|
| 前端 UI | 管理界面（Vue 3 SPA） | P1 |
| BPF 模块修复 | bg_collector 验证器死循环 + threat_detect/forensics 的 extern .maps 问题 | P0 |
| 多网口架构 | 即使旁路模式也需支持多业务口 + 管理口 | P0 |

---

## 4. 能力差距分析

### 4.1 已完成能力（Phase 1 交付物）

| 能力 | 实现位置 | 状态 |
|------|----------|------|
| 静态哨兵 CRUD | guard_mgr.c + jz_static_guards map + API + CLI | ✅ 完整 |
| 动态哨兵 CRUD | guard_mgr.c + jz_dynamic_guards map + API + CLI | ✅ 完整 |
| 白名单 CRUD | guard_mgr.c + jz_whitelist map + API + CLI | ✅ 完整 |
| ARP 蜜罐响应 | jz_arp_honeypot.bpf.c (XDP_TX) | ✅ 完整 |
| ICMP 蜜罐响应 | jz_icmp_honeypot.bpf.c (XDP_TX) | ✅ 完整 |
| 嗅探器检测 | jz_sniffer_detect.bpf.c + probe_gen.c | ✅ 完整 |
| 流量编织（BPF层） | jz_traffic_weaver.bpf.c (5种动作) | ✅ 完整 |
| 事件采集与持久化 | rs_event_bus → ringbuf.c → collectord → SQLite | ✅ 完整 |
| 配置热重载 | configd (inotify + IPC + BPF map push) | ✅ 完整 |
| 配置版本/回滚 | configd (config_history + config_diff) | ✅ 完整 |
| 远程配置推送 | configd/remote.c (HTTPS + mTLS) | ✅ 完整 |
| REST API (31端点) | sniffd/api.c | ✅ 完整（policies 3端点返回501） |
| 日志上传 | uploadd (HTTPS + gzip + mTLS) | ✅ 完整 |
| CLI 工具 | jzctl, jzguard, jzlog | ✅ 完整 |

### 4.2 需新建能力

| 能力 | 差距描述 | 涉及文件 |
|------|----------|----------|
| 设备发现引擎 | 无。`auto_discover: false` 存在但无实现。probe_gen.c 的 ARP 探测是为嗅探器检测，不是设备发现 | 新建 `discovery.c` |
| 被动设备指纹识别 | 无。bg_collector 捕获 128 字节 payload 但用户空间仅做原始记录，无协议深度解析。需解析 DHCP/mDNS/SSDP/LLDP/CDP 实现设备画像 | 新建 `fingerprint.c` |
| 动态哨兵自动部署 | guard_mgr 有增删，但无"从子网中选择未使用IP"逻辑 | 新建 `guard_auto.c` |
| 哨兵冲突检测/自动退出 | 无检测真实设备上线的机制 | `guard_auto.c` |
| IP 冻结 | 无 frozen_ips 概念 | `guard_auto.c` + 配置 |
| 动态哨兵比例限制 | 仅有 max_entries 绝对限制 | `guard_auto.c` + 配置 |
| 策略管理器 | API 返回 501，无 policy CRUD 到 BPF map 的逻辑 | 新建 `policy_mgr.c` |
| 自动策略引擎 | 无。流量编织 BPF 已就绪，但策略全由配置静态定义 | 新建 `policy_auto.c` |
| V1 日志格式 | 无旧系统兼容格式输出 | 新建 `log_format.c` |
| V2 日志格式 | 当前 JSON 导出格式非标准化 | `log_format.c` |
| MQTT 传输 | 仅有 HTTPS 上传 | 新建 `mqtt.c` (uploadd) |
| rsyslog 输出 | 仅有 syslog(LOG_INFO)，无格式化 | `log_format.c` |
| UCI 式暂存配置 | 修改立即生效，无暂存/提交概念 | 新建 `staged.c` (configd) |
| 多网口管理 | `discover_ifindex()` 只找一个 NIC | 重构 `main.c` 接口发现 |
| 串行模式 L2 转发 | 无 ingress→egress 转发逻辑 | BPF + sniffd 配置 |
| 前端 UI | 零 UI 代码 | 新建 `frontend/` 目录 |

### 4.3 需修复

| 问题 | 描述 | 修复方式 |
|------|------|----------|
| 3个BPF模块加载失败 | bg_collector: 验证器 "infinite loop detected"（已无 extern maps）；threat_detect/forensics: 仍有 extern .maps | bg_collector: 简化循环复杂度；threat_detect/forensics: 移除 extern，改用 LIBBPF_PIN_BY_NAME + reuse_fd |

---

## 5. 多网口架构设计

### 5.1 网口角色模型

```
┌─────────────────────────────────────────────────────────────────┐
│                        jz_sniff_rn 设备                         │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  eth0     │  │  eth1     │  │  eth2     │  │  eth3     │      │
│  │  管理口   │  │ 业务口#1  │  │ 业务口#2  │  │  蜜罐口   │      │
│  │  MGMT     │  │ BUSINESS  │  │ BUSINESS  │  │ HONEYPOT  │      │
│  │           │  │           │  │           │  │           │      │
│  │ REST API  │  │ XDP 管道  │  │ XDP 管道  │  │ redirect  │      │
│  │ SSH 管理  │  │ 诱捕+编织 │  │ 诱捕+编织 │  │ 目标      │      │
│  │ 日志上传  │  │           │  │           │  │           │      │
│  │ 配置下发  │  │           │  │           │  │           │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│       │                                          ▲              │
│       │    ┌─────────────────────────────────────┘              │
│       │    │  bpf_redirect() / rs_ctx.mirror                   │
│       │    │                                                    │
│  ┌────┴────┴────────────────────────────────────────────────┐  │
│  │                    sniffd 守护进程                         │  │
│  │  • 管理口：API 监听 + 日志上传 + 配置接收                  │  │
│  │  • 业务口：XDP attach + BPF 管道 + 事件采集               │  │
│  │  • 蜜罐口：redirect 目标（ifindex 写入 BPF map）          │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 网口角色定义

| 角色 | 标识 | 数量 | XDP附加 | 说明 |
|------|------|------|---------|------|
| `mgmt` | 管理口 | 0-1 | ❌ 不附加 | REST API / SSH / 日志上传 / 配置下发。如不配置，使用第一个业务口兼管理 |
| `business` | 业务口 | 1-N | ✅ 附加 XDP | 诱捕、流量编织、背景收集。每个业务口独立运行完整 BPF 管道 |
| `honeypot` | 蜜罐口 | 0-M | ❌ 不附加 | `bpf_redirect()` 的目标接口。用于欺骗导流 — 将攻击流量重定向到蜜罐进行交互分析。目标可以是物理网口、veth pair（容器）、tap/tun（虚拟机）、bridge port 等 |
| `mirror` | 镜像口 | 0-M | ❌ 不附加 | `rs_ctx.mirror` 的目标接口。用于流量留存/录制 — 复制一份流量到分析器存档。目标同样可以是物理网口或虚拟设备 |

> **端侧 All-in-One 说明**：物理设备应具备端侧一体化能力。honeypot 和 mirror 的目标不限于外部物理设备，也可以是同一物理主机上的容器（Docker/LXC，通过 veth pair 连接）或虚拟机（通过 tap/tun 连接）。sniffd 只关心目标 interface name → ifindex 解析，不关心底层是物理还是虚拟设备。

### 5.3 单网口兼容模式

当设备只有一个网口（或只配置了一个业务口、未配置管理口）时：

- 业务口同时承担管理功能
- REST API 绑定 `0.0.0.0:8443`（包含业务口 IP）
- 日志上传 / 配置接收通过该口的 IP 进行
- XDP 管道正常运行，不影响管理流量（管理流量走 XDP_PASS → 内核协议栈）

### 5.4 串行模式（后置，此处仅做设计预留）

```
上游交换机 → eth1 (ingress) → XDP 管道 → bpf_redirect(eth2) → eth2 (egress) → 下游交换机
                                  │
                            检测/编织/采集
                                  │
                            eth3 (honeypot) ← redirect 分流
```

- 未匹配流量：`XDP_REDIRECT(egress_ifindex)` 代替 `XDP_PASS`
- 需要在管道最后阶段（forwarding stage）添加 redirect 逻辑
- 保留 rSwitch L2 转发能力

### 5.5 配置示例

```yaml
# base.yaml — 多网口配置
system:
  mode: "bypass"           # "bypass" (旁路) 或 "inline" (串行)
  interfaces:
    mgmt: "eth0"           # 管理口（可选，空=业务口兼管理）
    business:              # 业务口列表（至少一个）
      - name: "eth1"
        vlans: [100, 200]  # 该口关注的 VLAN（空=所有）
      - name: "eth2"
        vlans: []
    honeypot:              # 蜜罐接口（可选）
      - name: "eth3"
        type: "full"       # "full" = 全交互蜜罐, "low" = 低交互
    mirror:                # 镜像接口（可选）
      - name: "eth4"
```

---

## 6. 日志格式规范

### 6.1 V1 格式（兼容旧 JZZN 系统）

V1 为逗号分隔的 KV 对，通过 syslog 传输。格式从旧 JZZN `devBase.cpp` 和 `devGuard.cpp` 中提取。

#### 6.1.1 攻击日志（log_type=1）

```
syslog_version=1.10.0,dev_serial={device_id},log_type=1,sub_type=1,attack_mac={src_mac},attack_ip={src_ip},response_ip={guard_ip},response_port={dst_port},line_id={ifindex},Iface_type=1,Vlan_id={vlan_id},log_time={epoch_sec},eth_type={ethertype},ip_type={ip_proto}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| syslog_version | string | 固定 "1.10.0" |
| dev_serial | string | 设备序列号（= system.device_id） |
| log_type | int | 1 = 攻击日志 |
| sub_type | int | 1 = 哨兵攻击 |
| attack_mac | string | 攻击者 MAC (aa:bb:cc:dd:ee:ff) |
| attack_ip | string | 攻击者 IP |
| response_ip | string | 被攻击的哨兵 IP（guard IP） |
| response_port | int | 目标端口（ARP/ICMP 为 0） |
| line_id | int | 接口编号（ifindex） |
| Iface_type | int | 固定 1（以太网） |
| Vlan_id | int | VLAN ID（0 = 无标签） |
| log_time | long | Unix 时间戳（秒） |
| eth_type | int | 以太网类型（0x0806=ARP, 0x0800=IP） |
| ip_type | int | IP 协议号（1=ICMP, 6=TCP, 17=UDP；非IP时为0） |

#### 6.1.2 心跳日志（log_type=2）

```
syslog_version=1.10.0,dev_serial={device_id},log_type=2,sentry_count={total_guards},real_host_count={online_devices},dev_start_time={daemon_start_epoch},dev_end_time={current_epoch},time={datetime_str}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| log_type | int | 2 = 心跳 |
| sentry_count | int | 总哨兵数（静态 + 动态） |
| real_host_count | int | 在线真实设备数 |
| dev_start_time | long | 守护进程启动时间（epoch） |
| dev_end_time | long | 当前时间（epoch） |
| time | string | 当前时间（格式 "YYYY-MM-DD HH:MM:SS"） |

#### 6.1.3 溢出丢包日志（从 devNetCard.cpp 提取，可选实现）

```
DROP_OVERFLOW: ARP line={ifindex} src_mac={mac} src_ip={ip} dst_ip={ip}
DROP_OVERFLOW: IP line={ifindex} proto={proto} src={ip}:{port} dst={ip}:{port} src_mac={mac}
```

### 6.2 V2 格式（新设计）

V2 为结构化 JSON，向后兼容 V1 的所有字段，同时扩展新字段。

#### 6.2.1 通用信封

```json
{
  "v": 2,
  "device_id": "jz-sniff-001",
  "seq": 123456,
  "ts": "2026-03-23T10:15:32.123456789+08:00",
  "type": "attack",
  "data": { ... }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| v | int | 格式版本，固定 2 |
| device_id | string | 设备标识 |
| seq | uint64 | 单调递增序列号（设备级唯一） |
| ts | string | ISO 8601 带时区和纳秒精度 |
| type | string | "attack" / "sniffer" / "threat" / "bg" / "heartbeat" / "audit" / "policy" |
| data | object | 类型特定的数据载荷 |

#### 6.2.2 攻击日志 (type="attack")

```json
{
  "v": 2,
  "device_id": "jz-sniff-001",
  "seq": 100,
  "ts": "2026-03-23T10:15:32.123456789+08:00",
  "type": "attack",
  "data": {
    "src_ip": "10.0.1.100",
    "src_mac": "aa:bb:cc:11:22:33",
    "guard_ip": "10.0.1.50",
    "guard_mac": "aa:bb:cc:dd:ee:01",
    "guard_type": "static",
    "protocol": "arp",
    "dst_port": 0,
    "interface": "eth1",
    "ifindex": 3,
    "vlan_id": 100,
    "threat_level": 2,
    "ethertype": 2054,
    "ip_proto": 0
  }
}
```

#### 6.2.3 心跳日志 (type="heartbeat")

```json
{
  "v": 2,
  "device_id": "jz-sniff-001",
  "seq": 200,
  "ts": "2026-03-23T10:30:00.000000000+08:00",
  "type": "heartbeat",
  "data": {
    "uptime_sec": 86400,
    "static_guards": 10,
    "dynamic_guards": 45,
    "total_guards": 55,
    "online_devices": 120,
    "frozen_ips": 5,
    "whitelist_count": 8,
    "interfaces": {
      "eth1": { "rx_pps": 15000, "tx_pps": 200, "bpf_modules": 8 },
      "eth2": { "rx_pps": 8000, "tx_pps": 100, "bpf_modules": 8 }
    },
    "modules": {
      "loaded": 8,
      "failed": 0
    },
    "db_size_mb": 128,
    "attack_count_total": 5432,
    "attack_count_last_period": 12,
    "network_topology": {
      "total_identified": 95,
      "total_unidentified": 25,
      "by_class": {
        "Computer": 42,
        "Phone": 18,
        "Printer": 5,
        "Switch": 3,
        "IoT": 12,
        "Unknown": 40
      },
      "by_os": {
        "Windows": 30,
        "Linux": 8,
        "iOS": 10,
        "Android": 8,
        "Cisco IOS": 3,
        "Unknown": 61
      },
      "by_vendor": {
        "Apple": 18,
        "Dell": 12,
        "HP": 8,
        "Cisco": 3,
        "VMware": 5,
        "Other": 74
      }
    },
    "devices": [
      {
        "ip": "10.0.1.100",
        "mac": "aa:bb:cc:11:22:33",
        "vlan": 100,
        "vendor": "Dell",
        "os_class": "Windows",
        "device_class": "Computer",
        "hostname": "desktop-01",
        "confidence": 85,
        "first_seen": "2026-03-20T08:00:00+08:00",
        "last_seen": "2026-03-23T10:29:55+08:00"
      }
    ]
  }
}
```

> **心跳 devices 数组大小控制**：MQTT 单条消息大小受 broker 配置限制（默认 256KB）。当在线设备数 > 200 时，仅发送 top-200 设备（按 confidence 降序 + last_seen 降序）。完整设备列表通过 REST API `GET /discovery/devices` 提供。可通过 `log.transports.mqtt.heartbeat_max_devices` 配置（默认 200）。
```

#### 6.2.4 嗅探器检测日志 (type="sniffer")

```json
{
  "v": 2, "device_id": "jz-sniff-001", "seq": 300,
  "ts": "2026-03-23T10:20:00.000000000+08:00",
  "type": "sniffer",
  "data": {
    "suspect_mac": "00:11:22:33:44:55",
    "suspect_ip": "10.0.1.200",
    "probe_ip": "10.0.1.253",
    "interface": "eth1",
    "ifindex": 3,
    "response_count": 3,
    "first_seen": "2026-03-23T09:00:00+08:00",
    "last_seen": "2026-03-23T10:20:00+08:00"
  }
}
```

#### 6.2.5 威胁检测日志 (type="threat")

```json
{
  "v": 2, "device_id": "jz-sniff-001", "seq": 400,
  "ts": "2026-03-23T10:25:00.000000000+08:00",
  "type": "threat",
  "data": {
    "pattern_id": 42,
    "threat_level": 3,
    "action_taken": "log_drop",
    "description": "SMB exploit attempt",
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.1.50",
    "dst_port": 445,
    "protocol": "tcp",
    "interface": "eth1",
    "ifindex": 3,
    "vlan_id": 100
  }
}
```

#### 6.2.6 背景流量日志 (type="bg")

```json
{
  "v": 2, "device_id": "jz-sniff-001", "seq": 500,
  "ts": "2026-03-23T10:30:00.000000000+08:00",
  "type": "bg",
  "data": {
    "period_start": "2026-03-23T10:00:00+08:00",
    "period_end": "2026-03-23T10:30:00+08:00",
    "protocols": {
      "arp": { "count": 1234, "bytes": 56780, "unique_sources": 15 },
      "dhcp": { "count": 56, "bytes": 12340, "unique_sources": 8 },
      "mdns": { "count": 789, "bytes": 34560, "unique_sources": 12 },
      "lldp": { "count": 23, "bytes": 4560, "unique_sources": 3 },
      "stp": { "count": 456, "bytes": 9120, "unique_sources": 2 }
    }
  }
}
```

#### 6.2.7 策略匹配日志 (type="policy")

```json
{
  "v": 2, "device_id": "jz-sniff-001", "seq": 600,
  "ts": "2026-03-23T10:35:00.000000000+08:00",
  "type": "policy",
  "data": {
    "policy_id": 7,
    "action": "redirect_mirror",
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.1.50",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "tcp",
    "redirect_to": "eth3",
    "mirror_to": "eth4",
    "trigger": "auto",
    "reason": "repeated_attack_threshold"
  }
}
```

#### 6.2.8 审计日志 (type="audit")

```json
{
  "v": 2, "device_id": "jz-sniff-001", "seq": 700,
  "ts": "2026-03-23T10:40:00.000000000+08:00",
  "type": "audit",
  "data": {
    "action": "guard_add",
    "actor": "api:token:admin",
    "target": "static_guard:10.0.1.50",
    "result": "success",
    "details": { "ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:01", "vlan": 100 }
  }
}
```

### 6.3 传输通道配置

用户可选择一种或多种传输通道同时工作：

| 通道 | 格式 | 适用场景 |
|------|------|----------|
| rsyslog | V1（KV对） | 兼容旧系统、已有 rsyslog 基础设施 |
| MQTT | V2（JSON） | 实时推送、IoT 风格部署、云平台集成 |
| HTTPS | V2（JSON 批量） | 定时批量上传、高安全性（mTLS） |
| 本地存储 | V2（SQLite） | 离线缓冲、本地查询（始终启用） |

配置方式：
```yaml
log:
  format: "v2"                # 默认格式："v1" 或 "v2"
  transports:
    syslog:
      enabled: true
      format: "v1"            # syslog 强制 v1（兼容旧系统）
      facility: "local0"      # syslog facility
    mqtt:
      enabled: true
      format: "v2"
      broker: "tcp://mqtt.example.com:8883"
      tls: true
      tls_ca: "/etc/jz/tls/mqtt-ca.crt"
      client_id: "{device_id}"
      topic_prefix: "jz/{device_id}/logs"
      qos: 1
      keepalive_sec: 60
    https:
      enabled: false           # 保留，与现有 uploadd 兼容
      url: "https://platform.example.com/api/v1/upload"
      tls_cert: "/etc/jz/tls/client.crt"
      tls_key: "/etc/jz/tls/client.key"
      interval_sec: 60
      batch_size: 1000
```

---

## 7. 配置体系增强

### 7.1 UCI 式分阶段配置

```
                当前                                     目标
        ┌─────────────────┐                    ┌─────────────────┐
        │  修改 → 立即生效  │                    │  修改 → 暂存     │
        │                 │         →          │  提交 → 生效     │
        │                 │                    │  丢弃 → 回滚     │
        └─────────────────┘                    └─────────────────┘
```

#### 新增 IPC 命令

| 命令 | 说明 |
|------|------|
| `config_stage:{section}:{json}` | 暂存修改（不立即生效） |
| `config_staged` | 查看所有暂存修改 |
| `config_commit` | 提交所有暂存修改（原子应用） |
| `config_discard` | 丢弃所有暂存修改 |
| `heartbeat_push:{json}` | sniffd → uploadd：推送心跳 JSON 数据，由 uploadd 通过 MQTT 发布（阶段 3） |

#### 实现方式

- configd 维护一个内存中的 `staged_changes[]` 数组
- 每次 `config_stage` 追加到数组
- `config_commit` 合并所有暂存修改 → 执行当前的 `apply_config_body()` 逻辑
- `config_discard` 清空数组
- 暂存超过 300 秒未提交自动丢弃（防止遗忘）

#### 与云端推送的关系

- 云端推送（`config_push`）仍为即时生效模式（不走暂存）
- 云端推送有 `X-Config-Version` 版本号防重放
- 本地 staged 修改如果与云端推送冲突，云端推送优先（覆盖暂存）

### 7.2 Section 级推送

当前 `config_push` 已支持 `sections` 数组指定需更新的 section，但需验证：
- 只推送 `guards` 时，`policies` 不被清空
- 多次 section 级推送的 version 递增正确
- 部分 section 失败时正确回滚

---

## 8. 分阶段开发计划

### 阶段 0：基础修复（1-2 天）

> 目标：全部 8/8 BPF 模块可加载，解除后续阶段阻塞

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 0.1 | 修复 bg_collector 验证器死循环 | `bpf/jz_bg_collector.bpf.c`, `bpf/include/jz_events.h` | 内核 6.8 验证器在 insn 169 报 "infinite loop detected"。bg_collector 已无 extern maps（此前已修复），问题是循环复杂度超出验证器限制。需简化 protocol 分类逻辑（展开循环或减少分支嵌套）。**同时扩展 DHCP 事件的 payload 捕获**：当前 `jz_event_bg.payload[128]` 从帧头开始捕获，而 DHCP Options 起始于偏移 282（14+20+8+236+4），128 字节远不够。修改方案：(a) 将 `jz_event_bg.payload` 扩大为 `payload[512]`（所有协议统一），或 (b) 新增 `jz_event_bg_dhcp` 专用事件结构 `payload[512]`（仅 DHCP 使用大缓冲区以节省 ringbuf 带宽）。推荐方案 (b)，512 字节足以覆盖绝大多数 DHCP Options。Phase 1 的 DHCP 指纹识别依赖此修改 | `ssh jzzn@10.174.254.136 'sudo /usr/local/sbin/sniffd --daemon --config /etc/jz/base.yaml' && sleep 3 && curl -sk https://10.174.254.136:8443/api/v1/modules \| jq '.modules[] \| select(.name=="jz_bg_collector") \| .loaded'` 输出 `true`。验证 DHCP 捕获：在有 DHCP 流量的网段上，`curl -sk .../logs/bg?limit=10 \| jq '[.logs[] \| select(.bg_proto==2) \| .payload_len] \| max'` 输出 > 282 |
| 0.2 | 修复 threat_detect extern .maps | `bpf/jz_threat_detect.bpf.c` | 第 80-86 行 `extern struct { ... } jz_redirect_config` 导致 libbpf "unrecognized extern section '.maps'"。修复方式：移除 extern，改为自有 map 定义 + `LIBBPF_PIN_BY_NAME`，由 `bpf_loader.c` 的 `bpf_map__reuse_fd()` 在 open→load 之间复用已 pin 的 fd | `ssh jzzn@10.174.254.136 '...' && curl -sk https://10.174.254.136:8443/api/v1/modules \| jq '.modules[] \| select(.name=="jz_threat_detect") \| .loaded'` 输出 `true` |
| 0.3 | 修复 forensics extern .maps | `bpf/jz_forensics.bpf.c` | 第 54-59 行 `extern struct { ... } jz_threat_result_map` 同上问题。同样改为自有定义 + `LIBBPF_PIN_BY_NAME` + loader 端 `reuse_fd()` | `curl -sk https://10.174.254.136:8443/api/v1/modules \| jq '.modules[] \| select(.name=="jz_forensics") \| .loaded'` 输出 `true` |
| 0.4 | 远程部署全量验证 | 远程 10.174.254.136 | rsync → `make user` → `make install` → 重启 sniffd/configd/collectord → 确认 8/8 模块加载 | `curl -sk https://10.174.254.136:8443/api/v1/modules \| jq '[.modules[] \| select(.loaded==true)] \| length'` 输出 `8` |
| 0.5 | 新增模块计数测试 | `tests/integration/test_api.sh` | 当前 test_api.sh 只验证 modules 数组非空和字段存在，不验证加载总数。新增 assertion：`assert_json "all 8 modules loaded" '[.modules[] \| select(.loaded==true)] \| length' "8" "$API/modules"` | `bash tests/integration/test_api.sh` 全部 PASS（含新增的模块计数断言） |

### 阶段 1：哨兵自动化与设备指纹识别（4-6 天）

> 目标：实现动态哨兵全自动生命周期 + 被动设备指纹识别 — 这是产品的核心价值

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 1.1 | 多网口配置与接口发现 | `src/common/config.h`, `src/common/config.c`, `src/sniffd/main.c` | 解析新的 `system.interfaces` 配置，替代单一 `discover_ifindex()` | `make user` 编译成功。在 base.yaml 配置 `system.interfaces` 后启动 sniffd，`journalctl -u sniffd \| grep "interface"` 显示已发现的业务口列表 |
| 1.2 | 设备发现引擎 — 被动监听 | `src/sniffd/discovery.c` (新), `src/sniffd/discovery.h` (新) | 消费 bg_collector 的 ARP reply 和 DHCP 事件，维护 `online_devices` 内存哈希表。value 从简单 `{mac,vlan,last_seen}` 扩展为完整 `device_profile_t`（见 §1.2A 指纹结构），包含 vendor/os_class/device_class/hostname/confidence 等字段 | `curl -sk https://10.174.254.136:8443/api/v1/discovery/devices \| jq '.devices \| length'` 返回 > 0（需有 ARP 流量的网段）。`curl ... \| jq '.devices[0].vendor'` 返回非空字符串（OUI 识别） |
| 1.3 | 设备发现引擎 — 主动扫描 | `src/sniffd/discovery.c` | 定时发送 ARP request 扫描子网（per VLAN），用 raw socket。扫描间隔可配（默认 300s），单次扫描采用随机化延迟避免风暴 | 触发扫描后 `curl -sk .../discovery/devices \| jq '.devices \| length'` 数量增长。`tcpdump -i ens33 arp` 可见 ARP request 序列 |
| 1.4 | 多 VLAN 感知 | `src/sniffd/discovery.c` | 解析 802.1Q 标签，按 VLAN 维护独立的在线设备表和子网范围。从接口配置获取关注的 VLAN 列表 | `curl -sk .../discovery/devices \| jq '[.devices[].vlan] \| unique'` 返回多个 VLAN ID（需多 VLAN 测试环境） |
| 1.2A | 被动指纹识别框架 | `src/common/fingerprint.c` (新), `src/common/fingerprint.h` (新) | 实现 `device_profile_t` 结构体和指纹识别框架。结构定义见下方 §1.2A。实现 `fp_init()` 加载嵌入式指纹数据库、`fp_update_profile(profile, event)` 根据新事件更新设备画像、`fp_get_confidence(profile)` 计算综合置信度。置信度采用多信号叠加模型（OUI +15, DHCP opt55 +35, DHCP opt60 +20, mDNS +25, SSDP +25, LLDP +30, LLDP-MED/CDP +50，上限100） | `make user` 编译成功。单元测试 `tests/unit/test_fingerprint.c` 验证：OUI 查找 `00:50:56` → vendor="VMware"，DHCP opt55 Windows 特征（含 option 249）→ os_class="Windows"，mDNS `_airplay._tcp` → device_class="Phone/Tablet" os_class="iOS" |
| 1.2B | MAC OUI 指纹库 | `src/common/fingerprint.c` | 编译时嵌入 MAC OUI 查找表（前 2000 条覆盖 95%+ 设备，~80KB）。IEEE OUI.txt 精简为 `{oui_prefix[3], vendor_short[24]}` 排序数组，运行时二分查找。`fp_lookup_oui(mac)` → vendor 字符串 | 单元测试验证：`fp_lookup_oui({0x00,0x50,0x56,...})` → "VMware"，`fp_lookup_oui({0xAC,0xDE,0x48,...})` → "Apple"，未知 OUI → "Unknown"。查找 ≤ 11 次比较（log2(2000)） |
| 1.2C | DHCP 指纹解析 | `src/common/fingerprint.c` | **依赖 Phase 0 任务 0.1 的 DHCP payload 扩展**（512 字节捕获）。从 bg_collector 捕获的 DHCP payload 中提取 Option 55（Parameter Request List）、Option 60（Vendor Class）、Option 12（Hostname）。DHCP Options 起始于 BOOTP 固定头之后（帧偏移 282+），需要 512 字节捕获范围。Option 55 的参数请求顺序是 OS 级指纹的金标准：Windows 含 Option 249，Apple 含 121+119 组合，Android 含 33+59。内建 ~200 条 DHCP 指纹签名（来源：Satori dhcp.xml + Fingerbank 精选），~30KB | 单元测试构造 DHCP Discover 包（含 opt55=[1,15,3,6,44,46,47,31,33,249]）→ `fp_parse_dhcp(payload, len, profile)` → os_class="Windows", confidence ≥ 50 |
| 1.2D | mDNS/SSDP/LLDP/CDP 指纹解析 | `src/common/fingerprint.c` | **mDNS**：从 5353/UDP payload 解析 service type（`_airplay._tcp`=Apple, `_googlecast._tcp`=Chromecast, `_hap._tcp`=HomeKit, `_ipp._tcp`=Printer, `_smb._tcp`=Windows）。**SSDP**：从 1900/UDP 的 SERVER/NT header 提取 OS 和设备信息（如 `Windows/10 UPnP/1.0`）。**LLDP**：Type 5 (System Name) + Type 6 (System Description)，LLDP-MED 子类 8/9 (Manufacturer/Model) 提供精确设备标识。**CDP**：Type 0x0006 (Platform) 包含 Cisco 产品标识字符串。每种协议内建 50-100 条匹配规则，mDNS ~5KB, SSDP ~3KB | 单元测试构造 mDNS 响应包含 `_airplay._tcp.local` → device_class="Phone/Tablet", os_class="iOS"。构造 LLDP 帧含 System Description "Cisco IOS..." → vendor="Cisco", os_class="Cisco IOS"。所有解析器对畸形包返回 0（不崩溃） |
| 1.2E | 指纹识别集成到 discovery | `src/sniffd/discovery.c` | bg_collector 事件到达时（通过 sniffd→collectord IPC 或直接 ringbuf 回调），除更新 last_seen 外，调用 `fp_update_profile()` 更新设备画像。ARP 事件触发 OUI 查找；DHCP 事件触发 opt55/60/12 解析；mDNS/SSDP/LLDP/CDP 事件各自触发对应解析器。设备画像在内存中持久维护，重启后从首次观察到的事件重建 | `curl -sk .../discovery/devices \| jq '.devices[] \| select(.confidence > 50) \| {ip, vendor, os_class, device_class}'` 返回已识别设备列表。在有 DHCP 流量的网段中，至少 50% 设备 confidence ≥ 50 |
| 1.5 | 动态哨兵自动部署 | `src/sniffd/guard_auto.c` (新), `src/sniffd/guard_auto.h` (新) | 定时任务（默认 60s）：遍历子网 → 排除在线设备 → 排除白名单 → 排除冻结IP → 按比例限制 → 写入 jz_dynamic_guards map | `curl -sk https://10.174.254.136:8443/api/v1/guards \| jq '[.guards[] \| select(.type=="dynamic")] \| length'` 返回 > 0。等待 60s 后首批动态哨兵出现 |
| 1.6 | 哨兵冲突检测与自动退出 | `src/sniffd/guard_auto.c` | 监听 ARP reply 事件，若来源 MAC ≠ 该 IP 的 fake_mac → 真实设备上线 → 删除 dynamic guard → 记录 audit event | 模拟：在动态哨兵占用的 IP 上启动真实设备（`arping -I ens33 {guard_ip}`），30s 内 `curl .../guards` 中该 guard 消失。`curl .../logs/audit` 包含退出事件 |
| 1.7 | IP 冻结 | `src/sniffd/guard_auto.c`, `config.h` | 新增 `guards.frozen_ips: ["10.0.1.1", "10.0.1.254"]` 配置项。frozen IP 列表加载到内存哈希表，动态哨兵选 IP 时排除 | `curl -sk -X POST -d '{"ip":"10.0.1.100"}' https://10.174.254.136:8443/api/v1/guards/frozen` 返回 201。之后 `curl .../guards` 中不出现 10.0.1.100 作为动态哨兵 |
| 1.8 | 动态哨兵比例限制 | `src/sniffd/guard_auto.c`, `config.h` | 新增 `guards.dynamic.max_ratio: 0.10` 配置项。计算：子网可用 IP 数 × ratio = 最大动态哨兵数。与 max_entries 取较小值 | 配置 `max_ratio: 0.01`（/24 子网 → 最多 2 个动态哨兵），`curl .../guards \| jq '[.guards[] \| select(.type=="dynamic")] \| length'` 输出 ≤ 2 |
| 1.9 | 设备发现 API | `src/sniffd/api.c` | 新增 `GET /api/v1/discovery/devices` — 返回在线设备列表（含 IP、MAC、VLAN、last_seen、vendor、os_class、device_class、hostname、confidence） | `curl -sk https://10.174.254.136:8443/api/v1/discovery/devices` 返回 200 JSON，结构 `{"devices":[{"ip":"...","mac":"...","vlan":0,"last_seen":...,"vendor":"VMware","os_class":"Linux","device_class":"Computer","hostname":"ubuntu-vm","confidence":65}]}` |
| 1.10 | 冻结 IP API | `src/sniffd/api.c` | 新增 `GET/POST/DELETE /api/v1/guards/frozen` — 冻结 IP CRUD | GET 返回 200 `{"frozen":["10.0.1.1"...]}`，POST 返回 201，DELETE 返回 200。`bash tests/integration/test_api.sh` 包含新断言且 PASS |
| 1.11 | 自动部署配置 API | `src/sniffd/api.c` | 新增 `GET/PUT /api/v1/guards/auto/config` — 查看/修改自动部署参数（max_ratio, scan_interval, enabled） | `curl -sk .../guards/auto/config` 返回 200 `{"enabled":true,"max_ratio":0.10,"scan_interval":300}`。PUT 修改后 GET 返回更新值 |

#### §1.2A 被动设备指纹识别设计

**核心数据结构 `device_profile_t`**：

```c
typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
    uint16_t vlan;
    char     vendor[32];        /* OUI 查表 / DHCP opt60 / LLDP source */
    char     os_class[24];      /* "Windows", "Linux", "iOS", "Android", "Cisco IOS" */
    char     device_class[24];  /* "Computer", "Phone", "Printer", "Switch", "IoT" */
    char     device_model[48];  /* LLDP-MED / mDNS TXT 精确型号 */
    char     hostname[48];      /* DHCP Option 12 / LLDP System Name */
    uint8_t  confidence;        /* 0-100, 多信号叠加 */
    uint8_t  signals;           /* bitmask: bit0=OUI, bit1=DHCP, bit2=mDNS, bit3=SSDP, bit4=LLDP, bit5=CDP */
    uint32_t first_seen;
    uint32_t last_seen;
} device_profile_t;
```

**置信度计算模型**（多信号叠加，上限 100）：

| 信号源 | 置信度增量 | 提供信息 |
|--------|-----------|----------|
| MAC OUI | +15 | vendor（设备制造商） |
| DHCP Option 55 | +35 | os_class（操作系统家族） |
| DHCP Option 60 | +20 | os_class + vendor（明确的供应商类标识） |
| DHCP Option 12 | +0（附加信息） | hostname（主机名，不增加置信度但提供有用信息） |
| mDNS Service Type | +25 | device_class + os_class（服务类型 → 设备类型推断） |
| SSDP SERVER/NT | +25 | os_class + device_class（UPnP 设备公告） |
| LLDP Type 5/6 | +30 | hostname + os_class + vendor（交换机/AP 级精确信息） |
| LLDP-MED / CDP | +50 | device_model + vendor（最精确的设备型号标识） |

**嵌入式指纹数据库**（编译时链接，运行时零 I/O）：

| 数据库 | 来源 | 条目数 | 内存占用 | 说明 |
|--------|------|--------|----------|------|
| MAC OUI 表 | IEEE OUI.txt 精选 | ~2000 | ~80KB | `{oui[3], vendor[24]}` 排序数组，二分查找 |
| DHCP 签名 | Satori dhcp.xml + Fingerbank | ~200 | ~30KB | `{opt55_hash, os_class, device_class}` |
| mDNS 服务类型 | Avahi service DB + 手工补充 | ~100 | ~5KB | `{service_type, device_class, os_hint}` |
| SSDP SERVER 模式 | 手工整理 | ~60 | ~3KB | `{pattern, os_class, device_class}` |
| **合计** | | | **~120KB** | 对嵌入式设备友好 |

**最小可行协议栈**：仅 DHCP opt55 + MAC OUI + mDNS 即可达到 ~85-90% 设备分类率。SSDP/LLDP/CDP 为增强信号。

**BPF 层需微调**：ARP/mDNS/SSDP/LLDP/CDP 的关键字段均在 128 字节内，现有捕获足够。但 **DHCP Options 起始于帧偏移 282 字节**（Ethernet 14 + IP 20 + UDP 8 + BOOTP 236 + Magic Cookie 4），超出当前 `payload[128]` 范围。Phase 0 任务 0.1 已包含扩展 DHCP 事件 payload 至 512 字节的修改（见 §8 阶段 0）。除 DHCP 外，无需其他 BPF 代码变更。

### 阶段 2：策略引擎与蜜罐导流（2-3 天）

> 目标：实现 policy CRUD + 基于攻击事件的自动策略生成

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 2.1 | Policy 管理器 | `src/sniffd/policy_mgr.c` (新), `src/sniffd/policy_mgr.h` (新) | 实现 flow policy CRUD → 写入/删除 `jz_flow_policy` BPF map。替换 API 的 501 存根 | `make user` 编译成功。单元测试 `tests/unit/test_policy_mgr.c` PASS |
| 2.2 | Policy API 激活 | `src/sniffd/api.c` | 将 policies 的 3 个 501 存根（POST/PUT/DELETE）替换为调用 policy_mgr 的实际实现。GET /policies 已返回 200 空数组，改为从 BPF map 读取实际数据 | `curl -sk -X POST -H 'Content-Type: application/json' -d '{"name":"test","src_ip":"1.2.3.4","action":"redirect"}' https://10.174.254.136:8443/api/v1/policies` 返回 201。`curl -sk .../policies` 返回包含刚创建 policy 的数组。DELETE 返回 200 |
| 2.3 | 自动策略引擎 | `src/sniffd/policy_auto.c` (新), `src/sniffd/policy_auto.h` (新) | 监听攻击事件（来自 ringbuf callback）。规则：同一 src_ip 在 window 时间内触发 ≥ threshold 次哨兵 → 自动创建 redirect policy 将该 IP 后续 TCP/UDP 流量导入蜜罐接口 | 模拟攻击：连续从同一 IP 发送 ARP 到哨兵 ≥ threshold 次后，`curl -sk .../policies \| jq '[.policies[] \| select(.auto==true)]'` 出现自动生成的 redirect 策略 |
| 2.4 | 策略动态调整 | `src/sniffd/policy_auto.c` | (a) 升级：威胁等级提升时从 log-only 升级到 redirect (b) 降级：超过 TTL 无新事件自动删除策略 (c) 可配置参数：threshold, window_sec, ttl_sec, max_auto_policies | 配置 `ttl_sec: 10`（测试用短 TTL），创建自动策略后等待 15s，`curl .../policies` 中该策略自动消失 |
| 2.5 | 蜜罐接口配置 | `config.h`, `base.yaml` | honeypot/mirror 接口的 ifindex 自动解析并写入 `jz_redirect_config` BPF map | 在 base.yaml 配置 honeypot 接口后重启，`bpftool map dump name jz_redirect_config` 显示正确的 ifindex 值 |

### 阶段 3：日志格式与传输（2-3 天）

> 目标：实现 V1/V2 双格式 + rsyslog/MQTT/HTTPS 三通道

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 3.1 | 日志格式化引擎 | `src/common/log_format.c` (新), `src/common/log_format.h` (新) | 统一格式化接口：`log_format_v1(event, buf)` 和 `log_format_v2(event, buf)`。V1 生成 KV 对字符串，V2 生成 JSON（cJSON） | `make user` 编译成功。单元测试 `tests/unit/test_log_format.c` 验证：V1 输出匹配 `syslog_version=1.10.0,dev_serial=...` 格式，V2 输出为合法 JSON 且包含 `event_type`、`timestamp`、`device_id` 字段 |
| 3.2 | rsyslog 输出 | `src/collectord/syslog_export.c` (新) | 按配置的 facility (local0-local7) 输出 V1 格式日志到 syslog。rsyslog 可通过 `/etc/rsyslog.d/jz.conf` 转发到远端 | 触发攻击事件后，`journalctl -t jz_sniff --since "1 min ago"` 显示 V1 KV 格式日志（`syslog_version=...,log_type=1,...`） |
| 3.3 | Vendor Paho Embedded C | `third_party/paho-embed/` | 从 GitHub 获取 Paho Embedded C 源码，放入 vendor 目录，添加到 Makefile 编译 | `make user 2>&1 \| grep -c error` 输出 0。`ls third_party/paho-embed/MQTTClient-C/src/MQTTClient.h` 存在 |
| 3.4 | MQTT 客户端 | `src/uploadd/mqtt.c` (新), `src/uploadd/mqtt.h` (新) | 实现 MQTT 连接管理（connect/reconnect/disconnect）、TLS 适配、publish 接口。**uploadd 是唯一的 MQTT broker 会话持有者**。connect 时设置 LWT（topic=`jz/{device_id}/status`, payload=`{"online":false}`, retain=true）并发布 retained status `{"online":true,...}`。topic = `jz/{device_id}/logs/{type}` | 启动 `mosquitto_sub -t 'jz/#' -v`，uploadd connect 后立即可见 retained status。触发攻击事件后显示 `jz/{id}/logs/attack {...}` JSON 消息。kill uploadd 后 broker 自动发布 `{"online":false}` |
| 3.5 | MQTT 集成到 uploadd | `src/uploadd/main.c` | 根据 `log.transports.mqtt.enabled` 决定使用 MQTT 还是 HTTPS。两者可同时启用 | base.yaml 配置 `mqtt.enabled: true`，重启 uploadd 后 `mosquitto_sub` 持续收到日志。切换 `mqtt.enabled: false` 后停止 |
| 3.6 | 心跳任务 | `src/sniffd/heartbeat.c` (新), `src/uploadd/main.c` | **数据流**：sniffd 的 `heartbeat.c` 负责定时组装心跳数据（收集 guard 数量、在线设备、BPF 模块状态、network_topology 等），然后：(a) V1 syslog 通道：sniffd 直接调用 `syslog(LOG_INFO, "%s", v1_kv)` 输出到本地 rsyslog，定时 `log.heartbeat_interval_sec`（默认 1800s，与旧 JZZN 一致）；(b) MQTT 通道：sniffd 通过 IPC 发送心跳 JSON 到 uploadd（`heartbeat_push:{json}`），由 uploadd 调用 `mqtt_publish()` 发布到 `jz/{device_id}/heartbeat`。**uploadd 是唯一的 MQTT broker 会话持有者**（LWT/retained status 也由 uploadd 管理，见 3.4）。MQTT 心跳间隔通过 `log.transports.mqtt.heartbeat_interval`（默认 300s）配置。心跳 JSON 包含 §6.2.3 定义的 `network_topology` + `devices[]` 数组（按 confidence 降序取 top-N，N 由 `log.transports.mqtt.heartbeat_max_devices` 配置，默认 200）。两个通道独立定时 | V1 验证：设置 `log.heartbeat_interval_sec: 10`（测试短间隔），`journalctl -t jz_sniff --since "15 sec ago"` 显示 `log_type=2,sentry_count=...`。MQTT 验证：设置 `log.transports.mqtt.heartbeat_interval: 10`（测试短间隔），`mosquitto_sub -t 'jz/+/status' -v` 显示 retained `{"online":true,...}`，`mosquitto_sub -t 'jz/+/heartbeat'` 每 10s 收到含 `network_topology.by_class` 和 `devices[].confidence` 的心跳 JSON |
| 3.7 | 传输通道配置解析 | `src/common/config.h`, `src/common/config.c` | 解析 `log.transports` 配置块 | `make user` 编译成功。配置包含 `log.transports.mqtt/syslog/https` 后 sniffd 启动不报配置错误 |

### 阶段 4：配置系统增强（1-2 天）

> 目标：增加 UCI 式暂存/提交机制

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 4.1 | Staged config 实现 | `src/configd/staged.c` (新), `src/configd/staged.h` (新) | 内存暂存区 + config_stage/config_staged/config_commit/config_discard IPC 命令 | `make user` 编译成功。通过 API 验证（4.2 完成后）：`curl -sk -X POST -H 'Content-Type: application/json' -d '{"guards":{"static":[]}}' https://10.174.254.136:8443/api/v1/config/stage` 返回 200 → `curl -sk .../config/staged` 返回暂存 JSON → `curl -sk -X POST -d "" .../config/commit` 返回 200。4.1 和 4.2 可联合验收 |
| 4.2 | Staged config API | `src/sniffd/api.c` | 新增 `GET /api/v1/config/staged`, `POST /api/v1/config/stage`, `POST /api/v1/config/commit`, `POST /api/v1/config/discard` | `curl -sk -X POST -H 'Content-Type: application/json' -d '{"guards":{"static":[]}}' https://10.174.254.136:8443/api/v1/config/stage` 返回 200。`curl -sk .../config/staged` 返回暂存内容。`curl -sk -X POST -d "" .../config/commit` 返回 200 |
| 4.3 | 自动过期 | `src/configd/staged.c` | 暂存超过 300s 未提交自动丢弃 + 记录 audit | 测试用短 TTL（`staged_ttl: 5`）：stage 后等 8s，`curl .../config/staged` 返回空。`curl .../logs/audit` 包含 staged-expired 事件 |
| 4.4 | Section 级推送验证 | `src/configd/main.c` | 验证并修复 config_push 的 section 级部分更新 | stage `{"guards":{"static":[new_guard]}}` → commit → `curl .../policies` 不变（policies section 未被清空），`curl .../guards` 含 new_guard |

### 阶段 5：部署模式与网口管理（2-3 天）

> 目标：旁路多网口完整支持 + 串行模式设计预留

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 5.1 | 多网口 XDP attach | `src/sniffd/bpf_loader.c`, `src/sniffd/api.c` | 为每个业务口独立 attach XDP 程序。管理口不 attach。在 `/api/v1/modules` 响应中新增 `interfaces` 字段（已 attach 的业务口列表） | `ip link show` 每个业务口有 `prog/xdp` 标志，管理口无。`bpftool net list` 显示每个业务口的 XDP 程序。`curl -sk .../modules \| jq '.modules[0].interfaces'` 返回业务口列表 |
| 5.2 | 蜜罐/镜像口 ifindex 解析 | `src/sniffd/main.c` | 启动时解析 honeypot/mirror 接口名到 ifindex，写入 `jz_redirect_config` BPF map | `bpftool map dump name jz_redirect_config \| jq '.[0].value'` 显示正确的 honeypot_ifindex 和 mirror_ifindex（非0） |
| 5.3 | 管理口兼容模式 | `src/sniffd/main.c` | 无管理口配置时，API 绑定 0.0.0.0（包含业务口 IP）。管理流量走 XDP_PASS → 内核栈 | 单网口环境（ens33 only）：`curl -sk https://10.174.254.136:8443/api/v1/health` 返回 200。SSH 连接正常不断 |
| 5.4 | 串行模式骨架（预留） | `src/sniffd/main.c`, `config.h` | `system.mode: "inline"` 配置解析 + 日志提示 "inline mode not yet implemented"。不实际实现 L2 转发 | base.yaml 设置 `system.mode: inline` → sniffd 启动成功，`journalctl -u sniffd \| grep "inline mode not yet"` 可见提示。切回 `bypass` 正常工作 |
| 5.5 | 守护进程控制 API | `src/sniffd/api.c` | 新增 `POST /api/v1/system/restart/{daemon}` — 通过 systemctl 重启指定守护进程（sniffd/configd/collectord/uploadd）。仅限 sniffd 自身重启用 `exec` 替换进程。安全校验：只允许已知守护进程名 | `curl -sk -X POST -d "" https://10.174.254.136:8443/api/v1/system/restart/collectord` 返回 200，`systemctl is-active collectord` 显示 active |
| 5.6 | 抓包模块验证 | 远程部署 | 确认 forensics 模块在旁路多网口模式下正常工作（sample_flag 触发一致） | 发送攻击流量触发 threat_detect 的 sample_flag。`journalctl -u sniffd --since "1 min ago" \| grep -c "forensic sample"` 输出 > 0（sniffd ringbuf consumer 已有 forensic 事件日志）。`bpftool map dump name jz_sample_config` 确认 sampling 已启用 |

### 阶段 6：前端界面（5-7 天）

> 目标：Vue 3 管理界面 SPA

| # | 任务 | 文件 | 说明 | 验证标准 |
|---|------|------|------|----------|
| 6.1 | 项目初始化 | `frontend/` | Vue 3 + Vite + Vue Router + Pinia。配置 proxy 到 :8443 | `cd frontend && npm install && npm run dev` 启动成功，浏览器 `http://localhost:5173` 显示空白欢迎页 |
| 6.2 | 布局与导航 | `frontend/src/` | 侧边栏导航：仪表盘、哨兵管理、白名单、策略、日志、配置、系统 | 浏览器点击每个导航项均可路由到对应页面（空壳），URL 正确变化（如 `/guards`、`/policies`） |
| 6.3 | 仪表盘页面 | `frontend/src/views/Dashboard.vue` | 系统状态概览：在线设备数、哨兵数、攻击次数、模块状态、心跳图 | 浏览器打开仪表盘，Network 面板显示 `GET /api/v1/status` 和 `GET /api/v1/stats` 请求返回 200，页面显示数值数据 |
| 6.4 | 哨兵管理页面 | `frontend/src/views/Guards.vue` | 静态/动态哨兵列表、添加/删除、冻结IP管理、自动部署参数配置 | 页面加载哨兵列表（调 `GET /guards`）。点击"添加"→ 填入 IP/MAC → 提交 → 列表刷新显示新哨兵 |
| 6.5 | 白名单管理页面 | `frontend/src/views/Whitelist.vue` | 白名单 CRUD | 添加白名单条目 → 列表显示 → 删除 → 列表移除。每步操作 Network 面板对应 POST/DELETE 返回 200/201 |
| 6.6 | 策略管理页面 | `frontend/src/views/Policies.vue` | 手动策略 CRUD + 自动策略列表查看 | 创建策略 → 列表显示 → 编辑 → 删除。自动策略标记 `auto=true` 不可编辑删除 |
| 6.7 | 日志查看页面 | `frontend/src/views/Logs.vue` | 5 种日志分 tab 查看，支持时间范围过滤、分页 | 切换 tab（attack/sniffer/bg/threat/audit），每个 tab 调对应 `GET /logs/{type}` 返回 200。选择时间范围后数据正确过滤 |
| 6.8 | 设备发现页面 | `frontend/src/views/Discovery.vue` | 在线设备表 + VLAN 分组 | 页面调 `GET /discovery/devices` 返回 200，设备以 VLAN 分组展示（或 flat 表格显示 VLAN 列） |
| 6.9 | 配置管理页面 | `frontend/src/views/Config.vue` | 查看当前配置、编辑（staged）、提交/丢弃、版本历史、回滚 | 编辑配置 → stage → 页面显示暂存状态 → commit → 生效。`GET /config/history` 返回包含新版本的历史列表 |
| 6.10 | 系统设置页面 | `frontend/src/views/System.vue` | 模块状态、接口状态、日志传输配置、重启守护进程（调用 Task 5.5 新增的 `POST /system/restart/{daemon}` API） | 页面显示 8 个模块及 loaded 状态。点击"重启 collectord"→ 确认弹窗 → 执行 → Network 面板显示 `POST /api/v1/system/restart/collectord` 返回 200 |
| 6.11 | 构建集成 | `Makefile`, `src/sniffd/api.c` | `make frontend` 构建 → 复制到 `/usr/share/jz/www/`。Mongoose serve 静态文件 + API 同端口 | `make frontend && sudo make install` 后浏览器访问 `https://10.174.254.136:8443/` 直接加载 SPA 界面，API 请求同端口返回数据 |

### 执行顺序与依赖关系

```
阶段0 ──→ 阶段1 ──→ 阶段2 ──→ 阶段6（可在阶段2完成后启动）
  │                    │
  │                    └──→ 阶段3（与阶段2可部分并行）
  │                    └──→ 阶段4（与阶段2可并行）
  │                    └──→ 阶段5（与阶段2可并行）
  │
  └─ 阻塞：bg_collector 修复后才能做被动设备发现和指纹识别

总计预估：18-27 天
```

---

## 9. 配置 Schema 变更

### 9.1 base.yaml 新增/修改项

```yaml
# ===== 新增 =====

system:
  mode: "bypass"                    # 新增："bypass" | "inline"
  interfaces:                       # 新增：替代原来的隐式单网口
    mgmt: ""                        # 新增：管理口（空=业务口兼管理）
    business:                       # 新增：业务口列表
      - name: "eth1"
        vlans: []                   # 关注的 VLAN（空=所有）
    honeypot: []                    # 新增：蜜罐接口列表
    mirror: []                      # 新增：镜像接口列表

guards:
  frozen_ips: []                    # 新增：冻结 IP 列表
  dynamic:
    auto_discover: true             # 修改：默认改为 true
    max_ratio: 0.10                 # 新增：动态哨兵占子网比例上限
    scan_interval_sec: 300          # 新增：主动扫描间隔
    retire_timeout_sec: 30          # 新增：冲突后退出延迟

log:                                # 新增：整个 section
  format: "v2"                      # 默认日志格式
  heartbeat_interval_sec: 1800      # 心跳间隔
  transports:
    syslog:
      enabled: true
      format: "v1"
      facility: "local0"
    mqtt:
      enabled: false
      format: "v2"
      broker: ""
      tls: false
      tls_ca: ""
      client_id: "{device_id}"
      topic_prefix: "jz/{device_id}/logs"
      qos: 1
      keepalive_sec: 60
      heartbeat_interval: 300     # 新增：MQTT 心跳间隔（秒）
      heartbeat_max_devices: 200  # 新增：心跳中 devices[] 数组最大条目数
    https:                          # 移动：从 uploader section 移入
      enabled: false
      url: ""
      tls_cert: ""
      tls_key: ""
      interval_sec: 60
      batch_size: 1000
      compress: true

policy:                             # 新增：策略引擎配置
  auto:
    enabled: true
    threshold: 5                    # 同一 src_ip 触发次数阈值
    window_sec: 300                 # 统计窗口
    ttl_sec: 3600                   # 自动策略过期时间
    max_auto_policies: 256          # 最大自动策略数
    default_action: "redirect"      # 触发后默认动作
    escalation: true                # 是否自动升级（log→redirect→redirect_mirror）

# ===== 废弃 =====
# uploader section 迁移到 log.transports.https
# uploader.enabled → log.transports.https.enabled
# uploader.platform_url → log.transports.https.url
# （保留旧字段解析做向后兼容，日志提示 deprecation）
```

### 9.2 向后兼容

- 旧 base.yaml 中无 `system.interfaces` → 退回到 `discover_ifindex()` 单网口模式
- 旧 base.yaml 中有 `uploader` → 映射到 `log.transports.https`
- 旧 base.yaml 中无 `log` → 使用默认值（syslog v1 enabled, mqtt disabled）
- 所有新配置项有合理默认值，无需手动编辑即可运行

---

## 10. API 变更清单

### 10.1 新增端点

| 方法 | 路径 | 说明 | 阶段 |
|------|------|------|------|
| GET | `/api/v1/discovery/devices` | 在线设备列表 | 1 |
| GET | `/api/v1/guards/frozen` | 冻结 IP 列表 | 1 |
| POST | `/api/v1/guards/frozen` | 添加冻结 IP | 1 |
| DELETE | `/api/v1/guards/frozen/{ip}` | 删除冻结 IP | 1 |
| GET | `/api/v1/guards/auto/config` | 自动部署参数 | 1 |
| PUT | `/api/v1/guards/auto/config` | 修改自动部署参数 | 1 |
| GET | `/api/v1/config/staged` | 查看暂存修改 | 4 |
| POST | `/api/v1/config/stage` | 暂存配置修改 | 4 |
| POST | `/api/v1/config/commit` | 提交暂存修改 | 4 |
| POST | `/api/v1/config/discard` | 丢弃暂存修改 | 4 |
| POST | `/api/v1/system/restart/{daemon}` | 重启指定守护进程 | 5 |

### 10.2 修改端点

| 方法 | 路径 | 变更 | 阶段 |
|------|------|------|------|
| GET | `/api/v1/policies` | 空数组存根 → 从 BPF map 读取实际数据 | 2 |
| POST | `/api/v1/policies` | 501 → 实际实现 | 2 |
| PUT | `/api/v1/policies/{id}` | 501 → 实际实现 | 2 |
| DELETE | `/api/v1/policies/{id}` | 501 → 实际实现 | 2 |

### 10.3 端点总数

- Phase 1 完成：31 端点
- Phase 2 完成后：31 + 11 新增 = 42 端点（3 个 501 变为实际实现，GET /policies 从空数组存根改为实际数据）

---

## 11. 新增文件清单

| 文件 | 阶段 | 说明 |
|------|------|------|
| `src/sniffd/discovery.c` | 1 | 设备发现引擎（被动监听 + 主动扫描 + 指纹识别集成） |
| `src/sniffd/discovery.h` | 1 | 设备发现头文件 |
| `src/common/fingerprint.c` | 1 | 被动设备指纹识别引擎（OUI/DHCP/mDNS/SSDP/LLDP/CDP 解析 + 嵌入式签名库） |
| `src/common/fingerprint.h` | 1 | 指纹识别头文件（`device_profile_t` 定义） |
| `tests/unit/test_fingerprint.c` | 1 | 指纹识别单元测试 |
| `src/sniffd/guard_auto.c` | 1 | 动态哨兵自动部署/退出/冻结/比例限制 |
| `src/sniffd/guard_auto.h` | 1 | 自动部署头文件 |
| `src/sniffd/policy_mgr.c` | 2 | 策略管理器（CRUD → BPF map） |
| `src/sniffd/policy_mgr.h` | 2 | 策略管理头文件 |
| `src/sniffd/policy_auto.c` | 2 | 自动策略引擎（事件驱动） |
| `src/sniffd/policy_auto.h` | 2 | 自动策略头文件 |
| `src/sniffd/heartbeat.c` | 3 | 心跳任务 |
| `src/sniffd/heartbeat.h` | 3 | 心跳头文件 |
| `src/common/log_format.c` | 3 | V1/V2 日志格式化引擎 |
| `src/common/log_format.h` | 3 | 格式化头文件 |
| `src/collectord/syslog_export.c` | 3 | rsyslog V1 格式输出 |
| `src/collectord/syslog_export.h` | 3 | rsyslog 头文件 |
| `src/uploadd/mqtt.c` | 3 | MQTT 客户端实现 |
| `src/uploadd/mqtt.h` | 3 | MQTT 头文件 |
| `third_party/paho-embed/` | 3 | Paho Embedded C 源码 (vendored) |
| `src/configd/staged.c` | 4 | UCI 式暂存配置 |
| `src/configd/staged.h` | 4 | 暂存配置头文件 |
| `frontend/` | 6 | Vue 3 前端项目（完整目录） |

**新增文件总计**：~21 个 C 源文件/头文件 + 1 个 vendor 目录 + 1 个前端项目

---

## 12. 交叉编译与多架构注意事项

### 12.1 BPF 编译

- BPF 字节码架构无关（verifier 在目标内核运行）
- `vmlinux.h` 必须从目标内核生成：`bpftool btf dump file /sys/kernel/btf/vmlinux format c`
- 构建系统需支持：`VMLINUX_H=/path/to/target/vmlinux.h make bpf`

### 12.2 用户空间交叉编译

- 所有 C 代码使用标准 POSIX API，无 x86 特有代码
- Makefile 需支持 `CROSS_COMPILE=aarch64-linux-gnu-` 前缀
- 依赖检查清单：

| 依赖 | ARM64 可用性 | 说明 |
|------|-------------|------|
| libbpf | ✅ | 从源码编译，无架构限制 |
| libelf | ✅ | apt: `libelf-dev:arm64` |
| zlib | ✅ | apt: `zlib1g-dev:arm64` |
| libsqlite3 | ✅ | apt: `libsqlite3-dev:arm64` |
| mongoose (vendored) | ✅ | 纯 C |
| cJSON (vendored) | ✅ | 纯 C |
| Paho Embedded C (vendored) | ✅ | 纯 C |

### 12.3 VPC 环境特殊考虑

- VPC 可能没有 XDP 硬件卸载 → 使用 `XDP_FLAGS_SKB_MODE`（generic XDP）
- VPC 网卡名不固定（可能是 `ens5`, `eth0`, `enp0s3`） → 必须通过配置指定，不能硬编码
- VPC 通常只有 1-2 个网口 → 单网口兼容模式尤其重要
- 安全组/防火墙可能阻止 MQTT 端口 → 配置文档需说明所需端口

---

## 13. 风险与待决事项

### 13.1 已知风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| Paho Embedded C 无异步 API | uploadd 主循环阻塞 | 单独线程运行 MQTT publish，或使用非阻塞 socket + select |
| VPC generic XDP 性能下降 | 吞吐量可能降至 1/10 | 可接受 — VPC 通常网络带宽本身有限 |
| 多业务口 XDP attach 需要每口独立 BPF 程序实例 | 内存占用翻倍 | 共享 pinned maps，只加载程序到不同 ifindex |
| Vue 3 构建工具链（Node.js）可能不在目标设备上 | 无法在目标设备上构建前端 | 前端构建在开发机完成，部署产物为静态文件 |

### 13.2 待决事项（已决）

| # | 事项 | 决定 | 说明 |
|---|------|------|------|
| 1 | Vue 3 UI 组件库 | **Element Plus** | 最成熟的 Vue 3 管理后台组件库，文档完善，组件覆盖齐全 |
| 2 | V1 syslog_version 字段 | **保持 "1.10.0" 不升级** | 与旧系统完全一致 |
| 3 | MQTT broker 归属 | **云端部署，端侧只做 client** | broker 是云端设备，端侧不嵌入 broker |
| 4 | uploadd 保留策略 | **持续保留** | 直到另行通知，不废弃 |
| 5 | 心跳策略 | **V1 syslog: 1800s 不变；MQTT: LWT + retained + 300s** | 详见 §13.3 |
| 6 | 前端国际化 | **需要（中文 + 英文）** | 使用 vue-i18n，默认中文 |

### 13.3 MQTT 心跳策略（新增）

V1 syslog 心跳保持 1800s 不变（与旧 JZZN 系统一致）。MQTT 通道采用三层机制，比固定间隔心跳更优：

| 层级 | 机制 | 间隔 | 说明 |
|------|------|------|------|
| 协议层 | **MQTT keepalive** | 60s | 协议内置，broker 自动检测连接断开 |
| 即时通知 | **LWT (Last Will & Testament)** | 即时 | client 异常断开时 broker 自动发布 `jz/{device_id}/status` → `{"online":false, "ts":...}`。云端秒级感知设备离线 |
| 状态发布 | **Retained status message** | 连接时 | connect 成功后 publish retained 消息到 `jz/{device_id}/status` → `{"online":true, "device_id":"...", "version":"...", "ts":...}` |
| 定时心跳 | **Heartbeat publish** | 300s（可配） | 定期发布详细运行数据到 `jz/{device_id}/heartbeat` → 包含 guard count、online count、stats 等。间隔通过 `log.transports.mqtt.heartbeat_interval` 配置 |

**效果**：
- 云端不需要等 1800s 才知道设备是否在线（LWT 秒级感知断连）
- 300s 定时心跳提供详细运行状态
- V1 syslog 通道仍保持 1800s 心跳，确保旧系统兼容

---

## 14. 部署后修复与增强 (v0.9.0)

部署后通过实际测试发现并修复了多项问题，同时增加了新功能。共计 11 个提交。

### 14.1 Bug 修复

| Commit | 范围 | 描述 |
|--------|------|------|
| `e061fa8` | guards | 静态哨兵 ping 响应、动态哨兵部署、统计计数、冻结功能修复 |
| `d22b701` | events | EVENT_HDR_LEN 从 44 修正为 48（结构体对齐） |
| `d21510c` | bg-logs | 背景流量日志缺失 src/dst IP 和 MAC 字段 |
| `625ca5a` | bpf | L4 端口解析错误及单播 DHCP 报文未捕获 |
| `8c68196` | dhcp | DHCP 客户端误判为服务器、protected 状态查找逻辑错误 |
| `9b6129a` | ui | 配置显示空白、发现页字段缺失、VLAN 子网布局、Dashboard 导航 |

### 14.2 新功能

| Commit | 范围 | 描述 |
|--------|------|------|
| `fd15333` | dhcp | DHCP 服务器自动检测与豁免管理机制 |
| `f4c746d` | discovery | 主动 DHCP 探测（aggressive 模式，可开关） |
| `6fb1962` | config | 接口角色配置（monitor/manage/mirror）、网关、DNS |
| `9173c22` | config | 按接口 VLAN 配置（从全局迁移为逐接口） |
| `86e9a6c` | discovery | 从背景流量自动检测 VLAN |

### 14.3 关键设计决策

1. **DHCP 保护流程**: bg_collector BPF → collectord → SQLite dhcp_servers 表 → sniffd API → Dashboard 告警 → 一键添加豁免
2. **接口角色模型**: 每个网络接口分配角色 (monitor/manage/mirror)，manage 接口额外配置网关和 DNS
3. **VLAN 配置迁移**: 从全局 VLAN 列表迁移到按接口 VLAN 配置，每个接口卡片内嵌 VLAN 表格
4. **主动探测开关**: aggressive_mode 默认关闭，开启后定期发送 DHCP Discovery 探测网络中的 DHCP 服务器

### 14.4 版本发布

- Draft release v0.9.0 已创建
- 所有 11 个提交已推送至 origin/master
- 前端已部署到实验机 (10.174.254.139)

---

*文档结束 — v0.9.0 部署后修复与增强完成*
