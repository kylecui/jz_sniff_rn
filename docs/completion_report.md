# jz_sniff_rn Phase 2 项目完成报告

> 日期：2026-03-24
> 基线文档：[phase2_plan.md](../phase2_plan.md) v1.3.1
> 部署环境：10.174.254.136（Ubuntu 24.04 / x86_64 / kernel 6.8）

---

## 目录

1. [项目概述](#1-项目概述)
2. [阶段完成总览](#2-阶段完成总览)
3. [各阶段详情](#3-各阶段详情)
4. [差距分析与修复](#4-差距分析与修复)
5. [实验室部署结果](#5-实验室部署结果)
6. [代码统计](#6-代码统计)
7. [Git 提交历史](#7-git-提交历史)
8. [已知限制](#8-已知限制)
9. [后续工作建议](#9-后续工作建议)

---

## 1. 项目概述

jz_sniff_rn（Sniff Reborn）是基于 rSwitch XDP 平台的网络安全固件，实现基于欺骗的威胁检测、流量分析和取证能力。Phase 2 集成开发在 Phase 1 基础上新增 16 项需求，涵盖哨兵自动化、设备指纹识别、策略引擎、日志格式与传输、配置增强、多网口支持和前端管理界面。

### 核心架构

```
BPF 管道（内核空间，XDP）：
  guard_classifier(21) → arp_honeypot(22) / icmp_honeypot(23)
                       → sniffer_detect(24)
                       → traffic_weaver(25)
                       → bg_collector(26)
                       → threat_detect(27)
                       → forensics(28)

用户空间守护进程：
  sniffd      — BPF 加载器、事件消费者、探针生成器、REST API、设备发现、哨兵自动化
  configd     — 配置监视、远程推送、BPF map 应用、暂存配置
  collectord  — 事件去重、SQLite 持久化、syslog 导出
  uploadd     — 批量上传、MQTT 客户端、HTTPS 上传

CLI 工具：
  jzctl       — 系统管理
  jzguard     — 哨兵表管理
  jzlog       — 日志查看

前端：
  Vue 3 + Vite + Element Plus + vue-i18n（中英双语）
```

---

## 2. 阶段完成总览

| 阶段 | 描述 | 状态 | 提交 |
|------|------|------|------|
| Phase 0 | BPF 基础修复（bg_collector / threat_detect / forensics） | ✅ 完成 | `4362b49` |
| Phase 1 | 哨兵自动化 + 设备指纹识别 | ✅ 完成 | `35332fc` |
| Phase 2 | 策略引擎 + 蜜罐导流 | ✅ 完成 | `c9729d7` |
| Phase 3 | 日志格式（V1/V2）+ 传输（rsyslog/MQTT/HTTPS） | ✅ 完成 | `5f4fc2c` |
| Phase 4 | UCI 式暂存配置 + 自动过期 | ✅ 完成 | `f86f95a` |
| Phase 5 | 多网口 XDP attach + 守护进程控制 | ✅ 完成 | `fe53ed3` |
| Phase 6 | Vue 3 前端管理 SPA | ✅ 完成 | `f3d05c2` |
| 差距修复 | 5 个对照方案差距修补 | ✅ 完成 | `e2e44f2` |
| 部署 | 安装脚本 + systemd 服务修复 | ✅ 完成 | `c72ffa8` |

**整体完成度：100%（全部 7 个阶段 + 差距修复 + 部署）**

---

## 3. 各阶段详情

### 3.1 Phase 0 — BPF 基础修复

**目标**：8/8 BPF 模块全部可加载

| 任务 | 说明 | 完成状态 |
|------|------|----------|
| 0.1 bg_collector 验证器修复 | 简化循环复杂度；DHCP payload 扩展至 512 字节 | ✅ |
| 0.2 threat_detect extern .maps | 移除 extern，改 LIBBPF_PIN_BY_NAME + reuse_fd | ✅ |
| 0.3 forensics extern .maps | 同 0.2 方式修复 | ✅ |
| 0.4 远程部署验证 | rsync → make → install → 8/8 模块加载 | ✅ |
| 0.5 模块计数测试 | test_api.sh 新增 8 模块 loaded 断言 | ✅ |

### 3.2 Phase 1 — 哨兵自动化与设备指纹识别

**目标**：动态哨兵全自动生命周期 + 被动设备指纹识别

**新建文件**：
- `src/sniffd/discovery.c / .h` — 设备发现引擎（被动监听 + 主动扫描 + 多 VLAN）
- `src/common/fingerprint.c / .h` — 被动指纹识别框架（OUI/DHCP/mDNS/SSDP/LLDP/CDP）
- `src/sniffd/guard_auto.c / .h` — 动态哨兵自动部署/冲突检测/退出/冻结/比例限制

**核心能力**：
- MAC OUI 查找表（~2000 条，二分查找）
- DHCP Option 55/60/12 指纹签名（~200 条）
- mDNS/SSDP/LLDP/CDP 协议解析
- 多信号叠加置信度模型（上限 100 分）
- 冲突检测（ARP reply 的 MAC ≠ guard fake_mac → 自动退出）
- IP 冻结列表
- 子网比例限制（`max_ratio`）

**新增 API**：
- `GET /api/v1/discovery/devices` — 在线设备列表
- `GET/POST/DELETE /api/v1/guards/frozen` — 冻结 IP CRUD
- `GET/PUT /api/v1/guards/auto/config` — 自动部署参数配置

### 3.3 Phase 2 — 策略引擎与蜜罐导流

**新建文件**：
- `src/sniffd/policy_mgr.c / .h` — 策略 CRUD → BPF map
- `src/sniffd/policy_auto.c / .h` — 自动策略引擎（事件驱动）

**核心能力**：
- Policy CRUD 替换 501 存根
- 基于攻击事件的自动 redirect 策略生成
- 策略动态调整（升级/降级/过期）
- 蜜罐接口 ifindex 自动解析

### 3.4 Phase 3 — 日志格式与传输

**新建文件**：
- `src/common/log_format.c / .h` — V1（KV 对）/ V2（JSON）格式化引擎
- `src/collectord/syslog_export.c / .h` — rsyslog V1 格式输出
- `src/uploadd/mqtt.c / .h` — MQTT 客户端（Paho Embedded C）
- `src/sniffd/heartbeat.c / .h` — 心跳任务
- `third_party/paho-embed/` — Paho Embedded C vendor

**核心能力**：
- V1 格式：兼容旧 JZZN 系统（`syslog_version=1.10.0,...` KV 对）
- V2 格式：结构化 JSON（7 种日志类型：attack/sniffer/threat/bg/heartbeat/audit/policy）
- rsyslog 输出（V1 格式，按 facility 分类）
- MQTT 传输（QoS 1 + LWT + retained status + 定时心跳）
- HTTPS 批量上传（保留原有 uploadd 能力）
- 心跳双通道：V1 syslog 1800s + MQTT 300s
- 心跳包含 `network_topology`（by_class/by_os/by_vendor 统计）+ `devices[]` 数组

### 3.5 Phase 4 — 配置系统增强

**新建文件**：
- `src/configd/staged.c / .h` — UCI 式暂存配置

**核心能力**：
- `config_stage` / `config_staged` / `config_commit` / `config_discard` IPC 命令
- 暂存超过 300s 自动丢弃
- Section 级部分更新
- 云端推送仍为即时生效模式

**新增 API**：
- `GET /api/v1/config/staged` — 查看暂存
- `POST /api/v1/config/stage` — 暂存修改
- `POST /api/v1/config/commit` — 提交暂存
- `POST /api/v1/config/discard` — 丢弃暂存

### 3.6 Phase 5 — 部署模式与网口管理

**核心能力**：
- 多网口 XDP attach（每个业务口独立 attach）
- 管理口不 attach XDP
- 蜜罐/镜像口 ifindex 自动解析 → `jz_redirect_config` BPF map
- 单网口兼容模式（API 绑定 0.0.0.0）
- 串行模式骨架预留（`system.mode: "inline"` 解析 + 日志提示）
- 守护进程控制 API：`POST /api/v1/system/restart/{daemon}`

### 3.7 Phase 6 — 前端管理界面

**技术栈**：Vue 3 + Vite + Element Plus + Vue Router + vue-i18n

**页面列表**（8 个视图）：

| 页面 | 文件 | 功能 |
|------|------|------|
| 仪表盘 | Dashboard.vue | 系统状态概览、在线设备数、哨兵数、攻击次数、模块状态 |
| 哨兵管理 | Guards.vue | 静态/动态哨兵列表、添加/删除、冻结 IP、自动部署参数 |
| 白名单 | Whitelist.vue | 白名单 CRUD |
| 策略管理 | Policies.vue | 手动/自动策略列表、CRUD |
| 日志查看 | Logs.vue | attack/sniffer/bg/threat/audit 分 tab、时间范围过滤、分页 |
| 设备发现 | Discovery.vue | 在线设备表、VLAN 分组、指纹信息 |
| 配置管理 | Config.vue | 当前配置查看、暂存编辑、提交/丢弃、版本历史 |
| 系统设置 | System.vue | 模块状态、接口状态、日志传输配置、守护进程重启 |

**国际化**：中英双语（`locales/zh-cn.json` + `locales/en.json`），默认中文。

**构建**：`bun run build` → 静态文件 → Mongoose 同端口 serve（:8443）。

---

## 4. 差距分析与修复

对照 `phase2_plan.md` v1.3.1 进行逐项验证，发现并修复 5 个差距：

| # | 差距描述 | 修复内容 | 涉及文件 |
|---|----------|----------|----------|
| 1 | guard_auto.c 缺少冲突检测 | 新增 `jz_guard_auto_check_conflict()`：当 ARP reply 的 MAC ≠ guard fake_mac 时自动删除动态哨兵 | guard_auto.c/h, discovery.c/h |
| 2 | API 路由是 `/guards/auto/status`，但方案要求 `/guards/auto/config` GET+PUT | 重命名路由 + 新增 PUT handler（max_ratio / enabled / scan_interval 配置） | api.c |
| 3 | heartbeat.c 缺少 `network_topology` 块 | 新增 `by_class` / `by_os` / `by_vendor` 统计 + `devices[]` 数组（按 confidence 降序 top-N） | heartbeat.c |
| 4 | heartbeat.c 缺少 V1 syslog 输出 | 新增 `jz_log_v1_heartbeat()` → `jz_syslog_send()` | heartbeat.c |
| 5 | test_api.sh 缺少 staged config 和 system restart 测试 | 新增 Section 12（staged config）和 Section 13（system restart），更新 auto/config 测试 | test_api.sh |

**提交**：`e2e44f2 fix(gaps): close 5 plan gaps`

---

## 5. 实验室部署结果

### 5.1 部署环境

| 项目 | 值 |
|------|-----|
| 目标主机 | 10.174.254.136 |
| 操作系统 | Ubuntu 24.04 LTS |
| 架构 | x86_64 |
| 内核 | 6.8（带 BTF 支持） |
| 用户 | jzzn |
| 部署方式 | rsync + install.sh |

### 5.2 部署流程

1. 本地构建前端：`cd frontend && /snap/bin/bun run build`
2. rsync 项目到远程（排除 build/、.git/、vmlinux.h、node_modules/）
3. 远程编译：`make user -j$(nproc)`
4. 运行安装脚本：`sudo scripts/install.sh --skip-build --skip-deps`

### 5.3 验证结果

| 检查项 | 结果 |
|--------|------|
| sniffd 服务 | ✅ active (running)，enabled |
| configd 服务 | ✅ active (running)，enabled |
| collectord 服务 | ✅ active (running)，enabled |
| uploadd 服务 | ✅ active (running)，enabled |
| API 健康检查 | ✅ `{"status":"ok","version":"0.8.0"}` |
| BPF 模块 | ✅ 8/8 loaded，全部 enabled |
| 前端访问 | ✅ https://10.174.254.136:8443/ 正常加载 |
| 自动部署 API | ✅ GET/PUT `/guards/auto/config` 正常 |

### 5.4 systemd 服务配置

| 服务 | 依赖关系 | 说明 |
|------|----------|------|
| sniffd.service | Wants=rswitch.service | 核心守护进程（软依赖 rSwitch，无 rSwitch 也可启动） |
| configd.service | BindsTo=sniffd.service | 配置管理（随 sniffd 启停） |
| collectord.service | BindsTo=sniffd.service | 事件采集（随 sniffd 启停） |
| uploadd.service | Wants=collectord.service | 上传代理（可选） |

所有服务均：
- `Restart=on-failure`（失败自动重启）
- `NoNewPrivileges=yes`（安全加固）
- `ProtectSystem=strict`（只读文件系统，白名单写入路径）
- 已 `enable`，开机自动启动

### 5.5 安装脚本

`scripts/install.sh` 支持以下选项：

| 选项 | 说明 |
|------|------|
| （无参数） | 完整安装：编译 + 部署 + 启动 |
| `--skip-build` | 跳过编译（使用预编译二进制） |
| `--skip-deps` | 跳过依赖检查 |
| `--skip-frontend` | 跳过前端安装 |
| `--no-start` | 仅安装，不启动服务 |
| `--uninstall` | 停止服务并卸载 |

脚本自动处理：
- 依赖安装（apt）
- 构建（make all）
- 二进制安装（make install）
- bpffs 挂载 + fstab 持久化
- TLS 证书生成（EC P-256，10 年有效期）
- 运行时目录创建
- systemd daemon-reload + enable + start
- 部署验证（服务状态、API 健康、模块加载、前端可达）

---

## 6. 代码统计

### 6.1 源码规模

| 组件 | 文件数 | 行数 | 说明 |
|------|--------|------|------|
| BPF 管道 | 11 | ~2,423 | 8 模块 + 3 头文件 |
| 通用库 | 16 | ~6,889 | db, config, ipc, log, mac_pool, fingerprint, log_format 等 |
| sniffd | 15+ | ~6,500+ | 含 api, guard_mgr, discovery, guard_auto, policy_mgr, policy_auto, heartbeat 等 |
| configd | 5 | ~1,700+ | 含 staged config, remote |
| collectord | 3 | ~1,200+ | 含 syslog_export |
| uploadd | 3 | ~1,400+ | 含 MQTT 客户端 |
| CLI 工具 | 3 | ~2,157 | jzctl, jzguard, jzlog |
| 测试 | 17+ | ~4,600+ | BPF/unit/integration/perf |
| 前端 | 20+ | ~3,000+ | Vue 3 SPA |
| systemd | 4 | ~170 | 服务定义 |
| 脚本 | 2 | ~450+ | install.sh, gen_vmlinux.sh |
| vendor | 4+ | ~33,781 | mongoose, cJSON, Paho MQTT |

**总计**：25,000+ 行 C 代码 + 3,000+ 行前端代码（不含 vendor）

### 6.2 REST API 端点

Phase 2 完成后共 **42 个端点**：

| 分类 | 端点数 | 说明 |
|------|--------|------|
| Health & Status | 4 | health, status, modules, module reload |
| Guards | 6 | 静态/动态哨兵 CRUD |
| Whitelist | 3 | 白名单 CRUD |
| Policies | 4 | 策略 CRUD |
| Logs | 5 | 5 类日志查询 |
| Stats | 5 | 统计聚合 |
| Config | 4 | 配置查看/推送/历史/回滚 |
| Discovery | 1 | 设备发现 |
| Frozen IPs | 3 | 冻结 IP CRUD |
| Auto Config | 2 | 自动部署参数 GET/PUT |
| Staged Config | 4 | 暂存/查看/提交/丢弃 |
| System | 1 | 守护进程重启 |
| **总计** | **42** | |

---

## 7. Git 提交历史

Phase 2 相关提交（按时间正序）：

```
4362b49 fix(bpf): Phase 0 — BPF fixes
35332fc feat(discovery): Phase 1 — guard automation and device fingerprinting
c9729d7 feat(policy): Phase 2 — policy engine and honeypot redirect
5f4fc2c feat(log): Phase 3 — V1/V2 log formats, rsyslog export, MQTT client, heartbeat
f86f95a feat(config): Phase 4 — UCI-style staged config with auto-expiry
fe53ed3 feat(deploy): Phase 5 — multi-NIC XDP attach and daemon control
f3d05c2 feat(frontend): Phase 6 — Vue 3 management SPA with Element Plus
e2e44f2 fix(gaps): close 5 plan gaps — guard conflict, auto/config API, heartbeat topology, V1 syslog, test coverage
c72ffa8 feat(deploy): add install script and fix sniffd service deps
```

---

## 8. 已知限制

| 限制 | 说明 | 影响 |
|------|------|------|
| 串行模式未实现 | `system.mode: "inline"` 仅做配置解析和日志提示 | P2 优先级，暂不影响旁路部署 |
| rSwitch 依赖 | 无 rSwitch 时降级运行（BPF 加载但不 attach XDP） | 实验室环境无 rSwitch，功能验证通过 API |
| 单网口限制 | 单网口时管理流量和业务流量共用 | 生产环境建议 2+ 网口 |
| MQTT broker | 端侧仅为 client，需外部 broker | 实验室未配置 MQTT broker |
| VPC generic XDP | 无硬件卸载时性能下降至 1/10 | VPC 带宽本身有限，可接受 |

---

## 9. 后续工作建议

| 优先级 | 建议 | 说明 |
|--------|------|------|
| P1 | 生产环境 MQTT broker 部署 | 配置实际 broker 地址，验证端到端日志传输 |
| P1 | API Token 更换 | 当前使用默认 `changeme`，生产环境必须更换 |
| P1 | TLS 证书替换 | 当前为自签名，生产环境应使用 CA 签发证书 |
| P2 | 串行模式实现 | `system.mode: "inline"` 的 L2 转发逻辑 |
| P2 | 交叉编译验证 | ARM64（aarch64）平台构建测试 |
| P2 | 前端功能增强 | WebSocket 实时推送、图表可视化 |
| P3 | 性能基准测试 | 完整 XDP 管道在 rSwitch 上的 PPS 测试 |
| P3 | CI/CD 管道 | 自动构建、测试、打包、部署 |

---

*报告结束*
