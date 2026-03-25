# jz_sniff_rn 运维与用户手册

> 版本：1.0.0
> 更新日期：2026-03-24
> 适用版本：jz_sniff_rn 0.9.0+（Phase 2 集成完成）

---

## 目录

1. [系统概述](#1-系统概述)
2. [硬件与软件要求](#2-硬件与软件要求)
3. [安装部署](#3-安装部署)
4. [配置参考](#4-配置参考)
5. [服务管理](#5-服务管理)
6. [CLI 命令行工具](#6-cli-命令行工具)
7. [REST API 参考](#7-rest-api-参考)
8. [前端管理界面](#8-前端管理界面)
9. [日志系统](#9-日志系统)
10. [故障排查](#10-故障排查)
11. [卸载](#11-卸载)
12. [附录](#12-附录)

---

## 1. 系统概述

### 1.1 产品简介

jz_sniff_rn（Sniff Reborn）是基于 rSwitch XDP 平台的网络安全固件，提供基于欺骗的威胁检测、流量分析和取证能力。系统运行于 Linux 内核的 XDP（eXpress Data Path）层，在网络数据包到达内核栈之前就完成处理，实现线速安全检测。

### 1.2 核心功能

| 功能 | 描述 |
|------|------|
| 动态蜜罐陷阱 | 自动部署 ARP/ICMP 哨兵，检测网络扫描和攻击行为 |
| 设备指纹识别 | 被动识别网络设备类型（OUI/DHCP/mDNS/SSDP/LLDP/CDP） |
| 嗅探器检测 | 通过 ARP 探针技术检测混杂模式设备 |
| 流量编织 | 基于策略的流量导流（pass/drop/redirect/mirror） |
| 威胁检测 | 快速路径头部/载荷模式匹配 |
| 取证采样 | 可疑数据包捕获供离线分析 |
| 背景采集 | 广播/组播协议基线监控 |
| 策略引擎 | 基于攻击事件的自动策略生成与管理 |

### 1.3 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│                    BPF 管道（内核空间，XDP）                     │
│                                                             │
│  guard_classifier(21) → arp_honeypot(22) / icmp_honeypot(23)│
│                       → sniffer_detect(24)                  │
│                       → traffic_weaver(25)                  │
│                       → bg_collector(26)                    │
│                       → threat_detect(27)                   │
│                       → forensics(28)                       │
└─────────────────────────────────────────────────────────────┘
                              │
                         ring buffer
                              │
┌─────────────────────────────────────────────────────────────┐
│                    用户空间守护进程                             │
│                                                             │
│  sniffd      BPF 加载器 / 事件消费 / REST API / 设备发现       │
│  configd     配置监视 / 远程推送 / BPF map 应用                │
│  collectord  事件去重 / SQLite 持久化 / syslog 导出            │
│  uploadd     批量上传 / MQTT 客户端 / HTTPS 上传               │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  CLI 工具：jzctl / jzguard / jzlog                           │
│  前端界面：Vue 3 + Element Plus（https://<host>:8443/）       │
└─────────────────────────────────────────────────────────────┘
```

### 1.4 组件说明

#### 守护进程

| 守护进程 | 职责 | 端口/接口 |
|----------|------|-----------|
| sniffd | 核心进程：BPF 模块加载、事件消费、探针生成、哨兵管理、设备发现、REST API 服务 | HTTPS :8443 |
| configd | 配置管理：文件监视、远程推送、BPF map 同步、暂存配置 | IPC socket |
| collectord | 事件采集：去重、限速、SQLite 持久化、rsyslog V1 格式输出 | IPC socket |
| uploadd | 上传代理：MQTT 发布、HTTPS 批量上传、心跳传输 | MQTT/HTTPS 出站 |

#### BPF 模块（8 个）

| 模块 | 阶段 | 功能 |
|------|------|------|
| guard_classifier | 21 | 哨兵 IP 分类网关，查找静态/动态哨兵表和白名单 |
| arp_honeypot | 22 | 对哨兵 IP 的 ARP 请求生成伪造回复（XDP_TX） |
| icmp_honeypot | 23 | 对哨兵 IP 的 ICMP echo 请求生成伪造回复（XDP_TX） |
| sniffer_detect | 24 | 监控 ARP 探针回复以检测混杂模式嗅探器 |
| traffic_weaver | 25 | 基于五元组的流量导流（pass/drop/redirect/mirror） |
| bg_collector | 26 | 捕获广播/组播协议基线（ARP/DHCP/mDNS/LLDP 等） |
| threat_detect | 27 | 快速路径威胁头部模式匹配 |
| forensics | 28 | 取证采样，捕获可疑数据包载荷 |

#### CLI 工具

| 工具 | 用途 |
|------|------|
| jzctl | 系统管理（状态查看、模块控制、配置管理、统计信息） |
| jzguard | 哨兵表管理（添加/删除哨兵、白名单、探针控制） |
| jzlog | 日志查看（攻击、嗅探、背景、威胁、审计日志） |

---

## 2. 硬件与软件要求

### 2.1 硬件要求

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | x86_64 或 ARM64 | 2+ 核心 |
| 内存 | 512 MB | 2 GB+ |
| 存储 | 2 GB 可用空间 | 10 GB+（日志存储） |
| 网卡 | 1 块（降级模式） | 2+ 块（业务口 + 管理口） |

> **单网卡警告**：如果仅有一块网卡（如 `ens33`），不要将 rSwitch XDP attach 到该接口——这会丢弃所有流量（包括 SSH）。守护进程仍可加载 BPF 对象并以"降级模式"运行。

### 2.2 操作系统要求

| 项目 | 要求 |
|------|------|
| 发行版 | Ubuntu 22.04+ 或 Debian 12+ |
| 内核版本 | 5.8+（带 BTF 支持） |
| 已验证环境 | Ubuntu 24.04 LTS / kernel 6.8 / x86_64 |

### 2.3 内核检查

```bash
# 验证 BTF 支持（CO-RE BPF 必须）
ls /sys/kernel/btf/vmlinux

# 验证 BPF 文件系统已挂载
mount | grep bpf
# 预期输出：bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,...)
```

### 2.4 构建依赖

```bash
sudo apt update
sudo apt install -y \
    clang llvm \
    gcc make pkg-config \
    libelf-dev zlib1g-dev \
    libsqlite3-dev \
    libyaml-dev \
    libcmocka-dev \
    linux-headers-$(uname -r)
```

| 包名 | 用途 |
|------|------|
| clang, llvm | BPF 编译（target bpf） |
| libelf-dev, zlib1g-dev | BPF 加载器和 ELF 解析 |
| libsqlite3-dev | 日志、配置历史、审计存储 |
| libyaml-dev | YAML 配置解析 |
| libcmocka-dev | 单元测试框架（可选） |
| linux-headers | 内核头文件（BPF 类型信息） |

### 2.5 rSwitch 平台（可选）

rSwitch 为完整 XDP 管道运行提供支持。无 rSwitch 时，sniffd 以降级模式运行：
- BPF 对象加载并 pin maps，但不 attach 到 XDP
- CLI 工具和 REST API 正常工作
- 无事件产生（无 XDP 管道）

---

## 3. 安装部署

### 3.1 自动安装（推荐）

使用 `scripts/install.sh` 一键安装：

```bash
# 完整安装：检查依赖 → 编译 → 部署 → 启动服务
sudo scripts/install.sh

# 跳过编译（使用预编译二进制）
sudo scripts/install.sh --skip-build

# 跳过编译和依赖检查
sudo scripts/install.sh --skip-build --skip-deps

# 仅安装，不启动服务
sudo scripts/install.sh --no-start

# 跳过前端安装
sudo scripts/install.sh --skip-frontend
```

#### 安装脚本功能

安装脚本自动完成以下任务：

1. **依赖检查与安装**：检测 clang/llvm/libs，缺失时自动 apt 安装
2. **编译项目**：`make clean && make all -j$(nproc)`
3. **安装二进制**：`make install`（守护进程、CLI、BPF 模块、配置、systemd 服务）
4. **挂载 bpffs**：确保 `/sys/fs/bpf` 已挂载并写入 `/etc/fstab`
5. **生成 TLS 证书**：自签名 ECC P-256 证书（10 年有效期）
6. **创建运行时目录**：`/var/lib/jz`、`/var/run/jz`、`/etc/jz`
7. **安装前端**：复制预编译的 Vue 3 SPA 到 `/usr/share/jz/www/`
8. **配置 systemd**：daemon-reload + enable 全部 4 个服务
9. **启动服务**：按依赖顺序启动
10. **部署验证**：检查服务状态、API 健康、BPF 模块加载数、前端可达性

#### 安装脚本选项一览

| 选项 | 说明 |
|------|------|
| （无参数） | 完整安装：依赖 + 编译 + 部署 + 启动 + 验证 |
| `--skip-build` | 跳过编译步骤，使用 `build/` 目录中的预编译产物 |
| `--skip-deps` | 跳过依赖检查 |
| `--skip-frontend` | 跳过前端安装 |
| `--no-start` | 仅安装，不启动服务 |
| `--uninstall` | 停止并卸载（见[第 11 节](#11-卸载)） |
| `-h, --help` | 显示帮助 |

### 3.2 手动安装

如果需要更精细的控制，可按以下步骤手动安装：

#### 步骤一：编译

```bash
cd ~/jz_sniff_rn

# 生成 vmlinux.h（首次或内核更新后需要）
./scripts/gen_vmlinux.sh

# 编译全部组件
make all -j$(nproc)
```

构建目标：

| 目标 | 说明 |
|------|------|
| `make all` | 编译全部（BPF + 用户空间 + CLI） |
| `make bpf` | 仅 BPF 模块 |
| `make user` | 仅用户空间守护进程 |
| `make cli` | 仅 CLI 工具 |
| `make test` | 运行测试 |
| `make clean` | 清理构建产物 |

#### 步骤二：安装

```bash
sudo make install
```

安装路径：

| 组件 | 安装位置 |
|------|----------|
| 守护进程（sniffd 等） | `/usr/local/sbin/` |
| CLI 工具（jzctl 等） | `/usr/local/bin/` |
| BPF 模块（*.bpf.o） | `/etc/jz/bpf/` |
| 配置文件（base.yaml） | `/etc/jz/` |
| systemd 服务 | `/etc/systemd/system/` |
| 数据目录 | `/var/lib/jz/` |
| 运行时目录 | `/var/run/jz/` |
| 前端文件 | `/usr/share/jz/www/` |

#### 步骤三：创建系统用户

```bash
sudo groupadd --system jz 2>/dev/null || true
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g jz jz 2>/dev/null || true
```

#### 步骤四：创建目录

```bash
sudo mkdir -p /var/lib/jz /var/run/jz /sys/fs/bpf/jz /etc/jz/tls
sudo chown jz:jz /var/lib/jz /var/run/jz
sudo chmod 0750 /var/lib/jz /var/run/jz
```

#### 步骤五：挂载 bpffs

```bash
# 挂载 BPF 文件系统
sudo mount -t bpf bpf /sys/fs/bpf

# 持久化到 fstab
echo "bpf /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab
```

#### 步骤六：生成 TLS 证书

REST API 使用 Mongoose 内置 TLS（`MG_TLS_BUILTIN`），**仅支持 ECC 证书**，不支持 RSA。

```bash
sudo mkdir -p /etc/jz/tls

# 生成 ECC P-256 私钥
sudo openssl ecparam -name prime256v1 -genkey -noout -out /etc/jz/tls/server.key

# 生成自签名证书（10 年有效）
sudo openssl req -new -x509 -key /etc/jz/tls/server.key \
    -out /etc/jz/tls/server.crt -days 3650 \
    -subj "/CN=jz-sniff/O=JZZN/C=CN"

# 设置权限
sudo chown root:jz /etc/jz/tls/server.key /etc/jz/tls/server.crt
sudo chmod 0640 /etc/jz/tls/server.key
sudo chmod 0644 /etc/jz/tls/server.crt
```

验证证书类型：

```bash
openssl x509 -in /etc/jz/tls/server.crt -text -noout | grep "Public Key Algorithm"
# 必须显示：id-ecPublicKey（不能是 rsaEncryption）
```

#### 步骤七：启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable sniffd configd collectord uploadd
sudo systemctl start sniffd configd collectord uploadd
```

### 3.3 前端构建与部署

前端为 Vue 3 SPA，构建后为纯静态文件，由 Mongoose 同端口（:8443）serve。

```bash
# 在开发机上构建（需要 bun）
cd frontend
bun install
bun run build
# 产物在 frontend/dist/

# 部署到目标机器
sudo install -d /usr/share/jz/www
sudo cp -r frontend/dist/* /usr/share/jz/www/
```

> **注意**：目标嵌入式设备可能没有 Node.js/bun，前端必须在开发机上预编译。

### 3.4 远程部署流程

从开发机部署到远程服务器的典型流程：

```bash
# 1. 本地构建前端
cd frontend && bun run build && cd ..

# 2. 同步代码到远程
rsync -avz --delete \
    --exclude='build/' --exclude='.git/' \
    --exclude='vmlinux.h' --exclude='node_modules/' \
    --exclude='frontend/dist/' \
    ./ user@remote:~/jz_sniff_rn/

# 3. 远程编译用户空间
ssh user@remote 'cd ~/jz_sniff_rn && make user -j$(nproc)'

# 4. 远程安装
ssh user@remote 'cd ~/jz_sniff_rn && sudo scripts/install.sh --skip-build --skip-deps'
```

### 3.5 部署验证

```bash
# 检查服务状态
systemctl status sniffd configd collectord uploadd

# API 健康检查
curl -sk https://localhost:8443/api/v1/health
# 预期：{"status":"ok","version":"0.9.0"}

# BPF 模块加载
curl -sk https://localhost:8443/api/v1/modules | python3 -m json.tool
# 预期：8 个模块，loaded=true

# 前端访问
curl -sk https://localhost:8443/ | head -1
# 预期：<!DOCTYPE html>
```

---

## 4. 配置参考

主配置文件路径：`/etc/jz/base.yaml`

### 4.1 完整配置 Schema

#### system — 系统设置

```yaml
system:
  device_id: "jz-sniff-001"       # 设备唯一标识符
  log_level: "info"                # 日志级别：debug, info, warn, error
  mode: "bypass"                   # 部署模式：bypass（旁路）, inline（串行，暂未实现）
  data_dir: "/var/lib/jz"         # 数据目录（SQLite 数据库等）
  run_dir: "/var/run/jz"          # 运行时目录（PID 文件、IPC socket）
  interfaces:                      # 网络接口配置
    - name: "ens33"                #   接口名
      role: "monitor"             #   角色：monitor（监听）, manage（管理）, mirror（镜像）
      vlans: [100, 200]           #   该接口关联的 VLAN 列表
      gateway: "10.0.1.1"         #   网关（仅 manage 角色有效）
      dns: ["8.8.8.8"]            #   DNS（仅 manage 角色有效）
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| device_id | string | "jz-sniff-001" | 设备标识，用于日志、MQTT topic 等 |
| log_level | string | "info" | 日志级别：debug/info/warn/error |
| mode | string | "bypass" | 部署模式。bypass=旁路，inline=串行（P2 预留） |
| data_dir | string | "/var/lib/jz" | SQLite 数据库和导出文件存放路径 |
| run_dir | string | "/var/run/jz" | PID 文件和 IPC socket 存放路径 |
| interfaces | array | - | 网络接口列表 |
| interfaces[].name | string | - | 接口名称（如 eth0, ens33） |
| interfaces[].role | string | "monitor" | monitor=监听, manage=管理, mirror=镜像 |
| interfaces[].vlans | array | [] | 关联的 VLAN ID 列表 |
| interfaces[].gateway | string | - | 网关 IP（仅 manage 角色有效） |
| interfaces[].dns | array | [] | DNS 服务器列表（仅 manage 角色有效） |

#### modules — BPF 模块配置

```yaml
modules:
  guard_classifier:
    enabled: true
    stage: 21
  arp_honeypot:
    enabled: true
    stage: 22
    rate_limit_pps: 100            # ARP 回复限速（包/秒）
    log_all: false                 # 是否记录所有 ARP 事件
  icmp_honeypot:
    enabled: true
    stage: 23
    ttl: 64                        # 伪造回复的 TTL 值
    rate_limit_pps: 100
  sniffer_detect:
    enabled: true
    stage: 24
    probe_interval_sec: 30         # 探针发送间隔（秒）
    probe_count: 5                 # 每轮探针数量
  traffic_weaver:
    enabled: true
    stage: 25
    default_action: "pass"         # 默认流量动作
  bg_collector:
    enabled: true
    stage: 26
    sample_rate: 1                 # 采样率（1=全量）
    protocols:                     # 监控的协议开关
      arp: true
      dhcp: true
      mdns: true
      ssdp: true
      lldp: true
      cdp: true
      stp: true
      igmp: true
  threat_detect:
    enabled: true
    stage: 27
  forensics:
    enabled: true
    stage: 28
    max_payload_bytes: 256         # 最大捕获载荷字节数
    sample_rate: 0                 # 0=仅捕获标记包
```

#### guards — 哨兵配置

```yaml
guards:
  static: []                       # 静态哨兵列表
  #  - ip: "10.0.1.50"
  #    mac: "aa:bb:cc:dd:ee:01"   # 可选，省略则从 MAC 池分配
  #    vlan: 0                     # 0=所有 VLAN

  dynamic:
    auto_discover: false           # 是否自动发现部署
    max_entries: 16384             # 动态哨兵最大数量
    ttl_hours: 24                  # 动态哨兵过期时间（小时）
    max_ratio: 30                  # 动态哨兵占子网 IP 百分比上限

  whitelist: []                    # 白名单列表
  #  - ip: "10.0.1.1"
  #    mac: "00:11:22:33:44:55"
  #    match_mac: true

  frozen_ips: []                   # 冻结 IP 列表（不被动态哨兵使用）
  #  - ip: "10.0.1.1"
  #    reason: "gateway"
```

#### fake_mac_pool — 伪造 MAC 池

```yaml
fake_mac_pool:
  prefix: "aa:bb:cc"              # OUI 前缀
  count: 64                        # 池大小
```

#### policies — 流量策略

```yaml
policies: []
  # - src_ip: "0.0.0.0"           # 0.0.0.0=通配
  #   dst_ip: "10.0.1.50"
  #   src_port: 0                  # 0=通配
  #   dst_port: 22
  #   proto: "tcp"
  #   action: "redirect"           # pass, drop, redirect, mirror
  #   redirect_port: 8             # 重定向接口索引
  #   mirror_port: 0
```

#### policy_auto — 自动策略引擎

```yaml
policy_auto:
  enabled: true                    # 启用自动策略
  threshold: 5                     # 触发阈值（同一 src_ip 攻击次数）
  window_sec: 300                  # 统计窗口（秒）
  ttl_sec: 3600                    # 自动策略过期时间（秒）
  max_auto_policies: 256           # 最大自动策略数
  default_action: "redirect"       # 默认动作：redirect/drop/mirror
  escalation: true                 # 自动升级（log→redirect）
```

#### threats — 威胁检测

```yaml
threats:
  blacklist_file: "/etc/jz/blacklist.txt"  # IP 黑名单（每行一个 IP）
  patterns: []
  #  - id: 1
  #    dst_port: 445
  #    proto: "tcp"
  #    threat_level: "high"
  #    action: "log_drop"
  #    description: "SMB exploit attempt"
```

#### collector — 事件采集器

```yaml
collector:
  db_path: "/var/lib/jz/jz.db"    # SQLite 数据库路径
  max_db_size_mb: 512              # 数据库最大体积（MB），超出自动裁剪
  dedup_window_sec: 10             # 去重窗口（秒）
  rate_limit_eps: 1000             # 最大事件速率（事件/秒）
```

#### uploader — 上传代理（旧版，已迁移至 log.https）

```yaml
uploader:
  enabled: false
  platform_url: ""
  interval_sec: 60
  batch_size: 1000
  tls_cert: ""
  tls_key: ""
  compress: true
```

> **注意**：`uploader` 配置节保留向后兼容，但建议使用 `log.https` 替代。

#### log — 日志系统

```yaml
log:
  format: "v2"                     # 默认日志格式：v1（KV 对）或 v2（JSON）
  heartbeat_interval_sec: 1800     # V1 syslog 心跳间隔（秒）
  syslog:
    enabled: false                 # 启用 rsyslog 输出
    format: "v1"                   # 传输格式覆盖
    facility: "local0"             # syslog facility
  mqtt:
    enabled: false                 # 启用 MQTT 传输
    format: "v2"
    broker: ""                     # Broker 地址，如 "tcp://10.0.1.100:1883"
    tls: false                     # 启用 TLS
    tls_ca: ""                     # CA 证书路径
    client_id: ""                  # MQTT 客户端 ID（空=使用 device_id）
    topic_prefix: ""               # Topic 前缀，如 "jz/{device_id}/logs"
    qos: 1                         # QoS 级别
    keepalive_sec: 60              # MQTT keepalive 间隔
    heartbeat_interval_sec: 300    # MQTT 心跳发布间隔
    heartbeat_max_devices: 200     # 心跳中 devices[] 最大设备数
  https:
    enabled: false                 # 启用 HTTPS 批量上传
    url: ""
    tls_cert: ""
    tls_key: ""
    interval_sec: 60
    batch_size: 1000
    compress: true                 # gzip 压缩
```

#### api — REST API

```yaml
api:
  enabled: true                    # 启用 REST API
  listen: "0.0.0.0:8443"          # 监听地址和端口
  tls_cert: "/etc/jz/tls/server.crt"
  tls_key: "/etc/jz/tls/server.key"
  auth_tokens:                     # 认证令牌列表
    - token: "changeme"            # ⚠️ 生产环境必须更换！
      role: "admin"
```

### 4.2 配置热重载

修改 `base.yaml` 后无需重启服务：

```bash
# 方法一：通过 CLI
sudo jzctl config reload

# 方法二：通过信号
sudo kill -HUP $(cat /var/run/jz/sniffd.pid)

# 方法三：通过 API
curl -sk -X POST https://localhost:8443/api/v1/system/restart/configd
```

### 4.3 安全建议

| 项目 | 建议 |
|------|------|
| API Token | 使用 `openssl rand -hex 32` 生成随机令牌替换 `changeme` |
| TLS 证书 | 生产环境使用 CA 签发的 ECC 证书替换自签名证书 |
| 文件权限 | TLS 私钥 0640（root:jz），配置文件 0644 |
| 网络隔离 | API 端口（8443）仅允许管理网段访问 |

---

## 5. 服务管理

### 5.1 服务依赖关系

```
sniffd ←── configd    (BindsTo：随 sniffd 启停)
       ←── collectord (BindsTo：随 sniffd 启停)
       ←── uploadd    (Wants collectord：可选)

sniffd ───→ rswitch.service (Wants：软依赖，无 rSwitch 也可启动)
```

### 5.2 常用操作

```bash
# 启动全部服务
sudo systemctl start sniffd
# configd 和 collectord 因 BindsTo 自动跟随启动

# 停止全部服务
sudo systemctl stop sniffd
# configd 和 collectord 因 BindsTo 自动跟随停止

# 重启全部
sudo systemctl restart sniffd

# 查看状态
sudo systemctl status sniffd configd collectord uploadd

# 查看日志
sudo journalctl -u sniffd -f                     # 实时跟踪
sudo journalctl -u sniffd --since "1 hour ago"   # 最近一小时
sudo journalctl -u sniffd --no-pager -n 50       # 最近 50 行

# 启用/禁用开机自启
sudo systemctl enable sniffd configd collectord uploadd
sudo systemctl disable uploadd   # 可选禁用 uploadd
```

### 5.3 服务安全加固

所有 systemd 服务包含以下安全措施：

| 配置项 | 说明 |
|--------|------|
| `Restart=on-failure` | 异常退出自动重启 |
| `NoNewPrivileges=yes` | 禁止提升权限 |
| `ProtectSystem=strict` | 只读文件系统（白名单写入路径） |
| `ProtectHome=yes` | 禁止访问 /home |
| `PrivateTmp=yes` | 独立 /tmp |
| `LimitMEMLOCK=infinity` | 允许 BPF map 内存锁定 |
| `WatchdogSec=60` | sniffd 60 秒无响应自动重启 |

### 5.4 前台调试模式

```bash
# 前台运行 sniffd（带详细日志）
sudo sniffd --verbose --config /etc/jz/base.yaml

# 不启动 REST API
sudo sniffd --verbose --no-api --config /etc/jz/base.yaml

# 指定 BPF 目录
sudo sniffd --verbose --bpf-dir /etc/jz/bpf --config /etc/jz/base.yaml
```

#### sniffd 命令行选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-c, --config PATH` | `/etc/jz/base.yaml` | 配置文件路径 |
| `-d, --daemon` | 关 | 后台守护进程模式 |
| `-p, --pidfile PATH` | `/var/run/jz/sniffd.pid` | PID 文件 |
| `-b, --bpf-dir PATH` | `/etc/jz/bpf` | BPF 模块目录 |
| `-v, --verbose` | 关 | 调试级别日志 |
| `--api-port PORT` | 8443 | REST API 端口 |
| `--api-cert PATH` | `/etc/jz/tls/server.crt` | TLS 证书 |
| `--api-key PATH` | `/etc/jz/tls/server.key` | TLS 私钥 |
| `--api-token TOKEN` | 来自配置 | Bearer 认证令牌覆盖 |
| `--no-api` | 关 | 禁用 REST API |

---

## 6. CLI 命令行工具

> 所有 CLI 工具需要 root 权限（通过 IPC socket 与 sniffd 通信）。

### 6.1 jzctl — 系统管理

#### 查看状态

```bash
# 查看 sniffd 状态
sudo jzctl status

# 查看指定守护进程状态
sudo jzctl status configd
sudo jzctl status collectord
```

#### 模块管理

```bash
# 列出所有 BPF 模块及状态
sudo jzctl module list

# 启用/禁用模块
sudo jzctl module enable threat_detect
sudo jzctl module disable forensics
```

#### 配置管理

```bash
# 查看当前配置
sudo jzctl config show

# 热重载配置
sudo jzctl config reload

# 查看配置版本
sudo jzctl config version
```

#### 统计信息

```bash
# 查看采集统计
sudo jzctl stats

# 重置统计计数器
sudo jzctl stats reset
```

### 6.2 jzguard — 哨兵管理

#### 添加哨兵

```bash
# 添加静态哨兵（自动分配 MAC）
sudo jzguard add static --ip 10.0.1.50

# 添加静态哨兵（指定 MAC）
sudo jzguard add static --ip 10.0.1.51 --mac aa:bb:cc:dd:ee:01

# 添加静态哨兵（指定 VLAN）
sudo jzguard add static --ip 10.0.1.52 --vlan 100
```

#### 查看和删除

```bash
# 列出所有哨兵
sudo jzguard list

# 按类型过滤
sudo jzguard list --type static
sudo jzguard list --type dynamic

# JSON 格式输出
sudo jzguard list --format json

# 删除哨兵
sudo jzguard del --ip 10.0.1.50
```

#### 白名单管理

```bash
# 添加白名单
sudo jzguard whitelist add --ip 10.0.1.1 --mac 00:11:22:33:44:55

# 列出白名单
sudo jzguard whitelist list

# 删除白名单
sudo jzguard whitelist del --ip 10.0.1.1
```

#### 探针控制

```bash
# 触发嗅探器检测探针
sudo jzguard probe
```

### 6.3 jzlog — 日志查看

#### 按类型查看

```bash
# 攻击日志
sudo jzlog attack

# 嗅探器检测日志
sudo jzlog sniffer

# 背景采集日志
sudo jzlog background

# 威胁检测日志
sudo jzlog threat

# 审计日志
sudo jzlog audit
```

#### 过滤选项

```bash
# 限制条数
sudo jzlog attack --limit 50

# 时间过滤
sudo jzlog attack --since 2026-03-01

# 实时跟踪（类似 tail -f）
sudo jzlog tail
```

---

## 7. REST API 参考

### 7.1 基本信息

| 项目 | 值 |
|------|-----|
| 基础 URL | `https://<host>:8443` |
| 协议 | HTTPS（TLS 1.3，ECC 证书） |
| 认证 | Bearer Token（`Authorization: Bearer <token>`） |
| 响应格式 | JSON |
| 端点总数 | 50+ |

> **注意**：根路径 `/` 返回 `{"error":"not found"}`，所有 API 端点位于 `/api/v1/` 下。

### 7.2 认证

配置文件中设置了 `auth_tokens` 时，除 `/api/v1/health` 外的所有端点均需要认证：

```bash
# 每个请求需添加认证头
curl -sk https://localhost:8443/api/v1/guards \
    -H "Authorization: Bearer changeme"
```

`/api/v1/health` 始终无需认证。

### 7.3 端点总览

#### 健康与状态（4 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/health` | 健康检查（无需认证） |
| GET | `/api/v1/status` | 系统状态概览 |
| GET | `/api/v1/modules` | BPF 模块列表 |
| POST | `/api/v1/modules/{name}/reload` | 重新加载指定 BPF 模块 |

#### 哨兵管理（6 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/guards` | 所有哨兵列表（静态+动态） |
| GET | `/api/v1/guards/static` | 静态哨兵列表 |
| GET | `/api/v1/guards/dynamic` | 动态哨兵列表 |
| POST | `/api/v1/guards/static` | 添加静态哨兵 |
| DELETE | `/api/v1/guards/static/{ip}` | 删除静态哨兵 |
| DELETE | `/api/v1/guards/dynamic/{ip}` | 删除动态哨兵 |

#### 白名单（3 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/whitelist` | 白名单列表 |
| POST | `/api/v1/whitelist` | 添加白名单条目 |
| DELETE | `/api/v1/whitelist/{ip}` | 删除白名单条目 |

#### 策略管理（4 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/policies` | 策略列表 |
| POST | `/api/v1/policies` | 创建策略 |
| PUT | `/api/v1/policies/{id}` | 更新策略 |
| DELETE | `/api/v1/policies/{id}` | 删除策略 |

#### 日志查询（6 个）

| 方法 | 路径 | 说明 | 依赖 |
|------|------|------|------|
| GET | `/api/v1/logs/attacks` | 攻击日志 | collectord |
| GET | `/api/v1/logs/sniffers` | 哨兵日志 | collectord |
| GET | `/api/v1/logs/background` | 背景流量日志 | collectord |
| GET | `/api/v1/logs/threats` | 威胁检测日志 | collectord |
| GET | `/api/v1/logs/audit` | 审计日志 | collectord |
| GET | `/api/v1/logs/heartbeat` | 心跳日志 | collectord |

> 日志端点需要 collectord 运行，否则返回 `"database unavailable (is collectord running?)"` 。

#### 统计（5 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/stats` | 聚合统计 |
| GET | `/api/v1/stats/guards` | 哨兵统计 |
| GET | `/api/v1/stats/traffic` | 流量统计 |
| GET | `/api/v1/stats/threats` | 威胁统计 |
| GET | `/api/v1/stats/background` | 背景采集统计 |

#### 配置管理（10 个）

| 方法 | 路径 | 说明 | 依赖 |
|------|------|------|------|
| GET | `/api/v1/config` | 当前运行配置 | - |
| POST | `/api/v1/config` | 推送新配置 | configd |
| GET | `/api/v1/config/history` | 配置变更历史 | collectord |
| POST | `/api/v1/config/rollback` | 回滚到指定版本 | configd |
| GET | `/api/v1/config/staged` | 查看暂存配置 | configd |
| POST | `/api/v1/config/stage` | 暂存配置修改 | configd |
| POST | `/api/v1/config/commit` | 提交暂存配置 | configd |
| POST | `/api/v1/config/discard` | 丢弃暂存配置 | configd |
| GET | `/api/v1/config/interfaces` | 接口配置 | configd |
| PUT | `/api/v1/config/interfaces` | 更新接口配置 | configd |

#### 设备发现（2 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/discovery/devices` | 在线设备列表（含指纹信息） |
| GET | `/api/v1/discovery/vlans` | VLAN 自动发现 |

#### DHCP 告警与豁免（4 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/dhcp/alerts` | DHCP 服务器告警 |
| GET | `/api/v1/dhcp/exceptions` | DHCP 豁免列表 |
| POST | `/api/v1/dhcp/exceptions` | 添加 DHCP 豁免 |
| DELETE | `/api/v1/dhcp/exceptions/{id}` | 删除 DHCP 豁免 |

#### 冻结 IP（3 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/guards/frozen` | 冻结 IP 列表 |
| POST | `/api/v1/guards/frozen` | 添加冻结 IP |
| DELETE | `/api/v1/guards/frozen/{ip}` | 删除冻结 IP |

#### 自动部署配置（2 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/guards/auto/config` | 自动部署参数 |
| PUT | `/api/v1/guards/auto/config` | 修改自动部署参数 |

#### 系统控制（1 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/system/restart/{daemon}` | 重启指定守护进程 |

### 7.4 curl 示例

以下所有示例使用 `-k` 跳过自签名证书验证。如启用了认证，需添加 `-H "Authorization: Bearer <token>"`。

```bash
HOST=10.174.254.139
TOKEN="changeme"
AUTH="-H \"Authorization: Bearer $TOKEN\""

# ===== 健康与状态 =====

# 健康检查（无需认证）
curl -sk https://$HOST:8443/api/v1/health

# 系统状态
curl -sk https://$HOST:8443/api/v1/status

# BPF 模块列表
curl -sk https://$HOST:8443/api/v1/modules

# 重新加载模块
curl -sk -X POST -d "" https://$HOST:8443/api/v1/modules/guard_classifier/reload

# ===== 哨兵管理 =====

# 列出所有哨兵
curl -sk https://$HOST:8443/api/v1/guards

# 列出静态/动态哨兵
curl -sk https://$HOST:8443/api/v1/guards/static
curl -sk https://$HOST:8443/api/v1/guards/dynamic

# 添加静态哨兵
curl -sk -X POST https://$HOST:8443/api/v1/guards/static \
    -H "Content-Type: application/json" \
    -d '{"ip":"10.0.1.50","mac":"aa:bb:cc:dd:ee:01"}'

# 删除静态哨兵
curl -sk -X DELETE https://$HOST:8443/api/v1/guards/static/10.0.1.50

# ===== 白名单 =====

# 列出白名单
curl -sk https://$HOST:8443/api/v1/whitelist

# 添加白名单
curl -sk -X POST https://$HOST:8443/api/v1/whitelist \
    -H "Content-Type: application/json" \
    -d '{"ip":"10.0.1.100"}'

# 删除白名单
curl -sk -X DELETE https://$HOST:8443/api/v1/whitelist/10.0.1.100

# ===== 策略管理 =====

# 列出策略
curl -sk https://$HOST:8443/api/v1/policies

# 创建策略
curl -sk -X POST https://$HOST:8443/api/v1/policies \
    -H "Content-Type: application/json" \
    -d '{"name":"block-scanner","src_ip":"1.2.3.4","action":"redirect"}'

# 删除策略
curl -sk -X DELETE https://$HOST:8443/api/v1/policies/1

# ===== 日志查询 =====

curl -sk https://$HOST:8443/api/v1/logs/attacks
curl -sk https://$HOST:8443/api/v1/logs/sniffers
curl -sk https://$HOST:8443/api/v1/logs/background
curl -sk https://$HOST:8443/api/v1/logs/threats
curl -sk https://$HOST:8443/api/v1/logs/audit

# 带分页参数
curl -sk "https://$HOST:8443/api/v1/logs/attacks?limit=20&offset=0"

# ===== 统计 =====

curl -sk https://$HOST:8443/api/v1/stats
curl -sk https://$HOST:8443/api/v1/stats/guards
curl -sk https://$HOST:8443/api/v1/stats/traffic
curl -sk https://$HOST:8443/api/v1/stats/threats
curl -sk https://$HOST:8443/api/v1/stats/background

# ===== 配置管理 =====

# 查看当前配置
curl -sk https://$HOST:8443/api/v1/config

# 查看配置历史
curl -sk https://$HOST:8443/api/v1/config/history

# 推送新配置
curl -sk -X POST https://$HOST:8443/api/v1/config \
    -H "Content-Type: application/json" \
    -d '{"guard":{"probe_interval":30}}'

# 回滚
curl -sk -X POST https://$HOST:8443/api/v1/config/rollback \
    -H "Content-Type: application/json" \
    -d '{"version":1}'

# ===== 暂存配置（UCI 式） =====

# 暂存修改
curl -sk -X POST https://$HOST:8443/api/v1/config/stage \
    -H "Content-Type: application/json" \
    -d '{"guards":{"static":[{"ip":"10.0.1.50"}]}}'

# 查看暂存
curl -sk https://$HOST:8443/api/v1/config/staged

# 提交暂存
curl -sk -X POST -d "" https://$HOST:8443/api/v1/config/commit

# 丢弃暂存
curl -sk -X POST -d "" https://$HOST:8443/api/v1/config/discard

# ===== 设备发现 =====

curl -sk https://$HOST:8443/api/v1/discovery/devices

# ===== 冻结 IP =====

# 列出冻结 IP
curl -sk https://$HOST:8443/api/v1/guards/frozen

# 添加冻结 IP
curl -sk -X POST https://$HOST:8443/api/v1/guards/frozen \
    -H "Content-Type: application/json" \
    -d '{"ip":"10.0.1.1"}'

# 删除冻结 IP
curl -sk -X DELETE https://$HOST:8443/api/v1/guards/frozen/10.0.1.1

# ===== 自动部署配置 =====

# 查看自动部署参数
curl -sk https://$HOST:8443/api/v1/guards/auto/config

# 修改自动部署参数
curl -sk -X PUT https://$HOST:8443/api/v1/guards/auto/config \
    -H "Content-Type: application/json" \
    -d '{"enabled":true,"max_ratio":10,"scan_interval":300}'

# ===== 系统控制 =====

# 重启指定守护进程
curl -sk -X POST -d "" https://$HOST:8443/api/v1/system/restart/collectord
curl -sk -X POST -d "" https://$HOST:8443/api/v1/system/restart/configd
curl -sk -X POST -d "" https://$HOST:8443/api/v1/system/restart/uploadd
```

### 7.5 守护进程依赖说明

部分 API 端点需要其他守护进程运行才能正常响应：

| API 分组 | 所需守护进程 | 缺失时的表现 |
|----------|-------------|-------------|
| health, status, modules | 仅 sniffd | 始终可用 |
| guards, whitelist, stats | 仅 sniffd | 始终可用 |
| logs/* | sniffd + collectord | 返回 `"database unavailable"` |
| config/history | sniffd + collectord | 返回 `"database unavailable"` |
| config (POST), config/rollback | sniffd + configd | 返回 `"configd unavailable"` |
| config/stage, staged, commit, discard | sniffd + configd | 返回 `"configd unavailable"` |

---

## 8. 前端管理界面

### 8.1 访问方式

前端通过与 API 相同的 HTTPS 端口访问：

```
https://<host>:8443/
```

首次访问时浏览器会提示证书不信任（自签名证书），选择"继续访问"即可。

### 8.2 技术栈

| 组件 | 说明 |
|------|------|
| Vue 3 | 前端框架（Composition API，`<script setup lang="ts">`） |
| Vite | 构建工具 |
| Element Plus | UI 组件库（自动导入） |
| Vue Router | 路由管理 |
| vue-i18n | 国际化（中文/英文，默认中文） |

### 8.3 页面功能

前端共有 8 个主要页面：
Dashboard, Guards, Discovery, Logs, Config, Whitelist, Policies, About

#### 仪表盘（Dashboard）

系统状态总览页面，显示：
- 在线设备数
- 哨兵数量（静态/动态）
- 攻击事件计数
- BPF 模块状态一览（8 个模块的 loaded 状态）
- 系统版本信息
- **DHCP 告警面板**：显示未受保护的 DHCP 服务器，支持一键"添加豁免"

**快捷导航**：
- 点击"攻击次数"卡片跳转至日志页攻击标签页
- 点击"哨兵数量"卡片跳转至哨兵管理页
- 点击"嗅探器数量"卡片跳转至设备发现页
- 点击"威胁数量"卡片跳转至日志页威胁标签页

数据来源：`GET /api/v1/status`、`GET /api/v1/stats`、`GET /api/v1/dhcp/alerts`

#### 哨兵管理（Guards）

完整的哨兵生命周期管理：
- 静态哨兵列表（IP、MAC、VLAN、状态）
- 动态哨兵列表（自动发现部署的哨兵）
- 添加/删除静态哨兵
- 冻结 IP 管理（防止特定 IP 被动态哨兵使用）
- 自动部署参数配置（启用/禁用、比例限制、扫描间隔）

数据来源：`GET /api/v1/guards`、`GET/POST/DELETE /api/v1/guards/frozen`、`GET/PUT /api/v1/guards/auto/config`

#### 设备发现（Discovery）

在线设备视图，支持：
- **设备列表**：IP、MAC、VLAN、厂商、OS 类型、设备类型、主机名、置信度
- **VLAN 自动发现**：从背景流量中自动识别网络中的 VLAN (新增)
- **设备指纹识别**：基于 OUI + DHCP option 55/60 + mDNS/SSDP/LLDP 的多维指纹识别
- **VLAN 分组展示**
- **指纹信息详情**

数据来源：`GET /api/v1/discovery/devices`、`GET /api/v1/discovery/vlans`

#### 日志查看（Logs）

多类型日志浏览器，包含 6 个标签页：
- **攻击日志** (attacks)：ARP/ICMP 蜜罐触发事件
- **哨兵日志** (sniffers)：混杂模式检测结果
- **背景流量** (background)：广播/组播协议捕获
- **威胁检测** (threats)：威胁模式匹配告警（attack_log 中威胁等级 > 0 的子集）
- **审计日志** (audit)：管理员操作审计记录
- **心跳日志** (heartbeat)：守护进程运行状态记录 (新增)

支持功能：
- 时间范围过滤
- 分页浏览
- 数据表格展示

数据来源：`GET /api/v1/logs/{type}`、`GET /api/v1/logs/heartbeat`

#### 配置管理（Config）

重新设计的配置界面，支持：
- **接口角色配置**：监听 (monitor)、管理 (manage)、镜像 (mirror)
- **按接口 VLAN 配置**：每个网卡卡片内嵌独立的 VLAN 表格
- **管理口增强**：为 manage 类型接口配置网关和 DNS
- **配置显示**：同时提供原始 YAML 和结构化表单视图
- **UCI 式分阶段管理**：
  - 查看当前运行配置
  - 编辑配置（暂存模式）
  - 提交 (commit) / 丢弃 (discard) 暂存修改
  - 配置版本历史与回滚 (rollback)

数据来源：`GET/POST /api/v1/config`、`GET/POST /api/v1/config/staged`、`POST /api/v1/config/commit`、`POST /api/v1/config/discard`、`GET /api/v1/config/history`、`GET/PUT /api/v1/config/interfaces`

> **暂存过期**：暂存配置超过 300 秒未提交将自动丢弃。

#### 白名单（Whitelist）

管理不受哨兵检查的设备：
- 白名单条目列表
- 添加/删除白名单（IP + MAC）

数据来源：`GET/POST/DELETE /api/v1/whitelist`

#### 策略管理（Policies）

流量策略的查看和管理：
- 手动创建的策略（可编辑、可删除）
- 自动生成的策略（标记为 `auto=true`，仅可查看）
- 策略 CRUD 操作

数据来源：`GET/POST/PUT/DELETE /api/v1/policies`

#### 关于（About）

系统级管理与信息展示：
- BPF 模块状态（8 个模块的 loaded/enabled 状态）
- 网络接口状态
- 日志传输配置（syslog/MQTT/HTTPS 的启用状态）
- 守护进程重启（sniffd/configd/collectord/uploadd）
- 系统版本与版权信息

数据来源：`GET /api/v1/modules`、`GET /api/v1/status`、`POST /api/v1/system/restart/{daemon}`

### 8.4 国际化

前端支持中文和英文双语切换：
- 默认语言：中文（zh-cn）
- 切换方式：前端界面内切换
- 翻译文件：`frontend/src/locales/zh-cn.json`、`frontend/src/locales/en.json`
- 所有 UI 文本通过 `$t()` / `t()` 函数调用，无硬编码字符串

---

## 9. 日志系统

### 9.1 日志格式

系统支持两种日志格式：

#### V1 格式（KV 键值对）

兼容旧 JZZN 系统的 rsyslog 格式：

```
syslog_version=1.10.0,dev_serial=jz-sniff-001,log_type=1,timestamp=1711296000,...
```

适用场景：rsyslog 转发、旧系统对接。

#### V2 格式（结构化 JSON）

新设计的结构化 JSON 格式，支持 7 种日志类型：

```json
{
  "event_type": "attack",
  "timestamp": 1711296000,
  "device_id": "jz-sniff-001",
  "src_ip": "10.0.1.100",
  "dst_ip": "10.0.1.50",
  "attack_type": "arp_request",
  "guard_ip": "10.0.1.50",
  "...": "..."
}
```

支持的日志类型：attack、sniffer、threat、bg（背景）、heartbeat、audit、policy。

适用场景：MQTT 传输、HTTPS 上传、结构化分析。

### 9.2 传输通道

| 通道 | 默认格式 | 说明 |
|------|----------|------|
| rsyslog | V1 | 输出到本地 syslog，rsyslog 可按 facility 分类转发 |
| MQTT | V2 | 发布到 MQTT broker，Topic: `jz/{device_id}/logs/{type}` |
| HTTPS | V2 | 批量上传到管理平台（gzip 压缩） |

三种通道可同时启用。配置位于 `base.yaml` 的 `log` 节。

### 9.3 心跳机制

系统支持双通道心跳：

| 通道 | 间隔 | 格式 | 内容 |
|------|------|------|------|
| V1 syslog | 1800 秒（默认） | KV 对 | 基本设备状态 |
| MQTT | 300 秒（默认） | JSON | 详细运行数据 |

MQTT 心跳包含：
- 设备状态（在线、版本号等）
- 哨兵计数
- 在线设备数
- `network_topology`：按设备类别/操作系统/厂商分组统计
- `devices[]`：按置信度降序排列的 top-N 设备列表

MQTT 还提供额外机制：
- **LWT（Last Will & Testament）**：设备异常断线时，broker 自动发布 offline 状态
- **Retained Status**：连接成功时发布 online 状态（retained），新订阅者立即获取

### 9.4 日志存储

| 存储位置 | 格式 | 说明 |
|----------|------|------|
| SQLite 数据库 | 结构化 | `/var/lib/jz/jz.db`，collectord 负责写入 |
| syslog/journald | V1 文本 | 通过 rsyslog 转发或 journald 记录 |

数据库自动裁剪：超过 `collector.max_db_size_mb`（默认 512MB）时自动删除旧记录。

```bash
# 直接查询数据库
sqlite3 /var/lib/jz/jz.db ".tables"
sqlite3 /var/lib/jz/jz.db "SELECT COUNT(*) FROM events;"
```

### 9.5 日志级别

在 `base.yaml` 中通过 `system.log_level` 设置：

| 级别 | 说明 |
|------|------|
| debug | 所有消息（非常详细，仅用于调试） |
| info | 正常运行信息（默认） |
| warn | 仅警告 |
| error | 仅错误 |

运行时覆盖：`sniffd --verbose` 强制使用 debug 级别。

---

## 10. 故障排查

### 10.1 sniffd 启动失败

#### "Failed to initialize BPF loader"

```bash
# 检查 BPF 模块文件是否存在
ls /etc/jz/bpf/*.bpf.o
# 预期：8 个 .bpf.o 文件

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 检查 BPF 文件系统
mount | grep bpf

# 使用详细日志启动
sudo sniffd --verbose --config /etc/jz/base.yaml
```

#### "Failed to load config"

```bash
# 验证 YAML 语法
python3 -c "import yaml; yaml.safe_load(open('/etc/jz/base.yaml'))"

# 检查文件权限
ls -la /etc/jz/base.yaml
```

#### "REST API init failed"

```bash
# 验证 TLS 证书类型（必须是 ECC，不能是 RSA）
openssl x509 -in /etc/jz/tls/server.crt -text -noout | grep "Public Key Algorithm"
# 必须显示：id-ecPublicKey

# 如果证书是 RSA，重新生成 ECC 证书
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/jz/tls/server.key \
    -out /etc/jz/tls/server.crt \
    -days 3650 -nodes \
    -subj "/CN=jz-sniff/O=JZZN/C=CN"

# 或禁用 REST API 启动
sudo sniffd --no-api --verbose --config /etc/jz/base.yaml
```

#### "Ring buffer init failed"

这表示 `/sys/fs/bpf/rs_event_bus` 未 pin（rSwitch 未运行）。sniffd 将以降级模式继续运行——**这是无 rSwitch 时的预期行为**。

### 10.2 权限错误

```bash
# 确保 BPF 文件系统可写
sudo mount -o remount,rw /sys/fs/bpf

# 确保 jz 用户拥有所需目录
sudo chown -R jz:jz /var/lib/jz /var/run/jz

# sniffd 必须以 root 启动（初始化后降权）
sudo sniffd --verbose --config /etc/jz/base.yaml
```

### 10.3 BPF 状态异常

代码更新或异常崩溃后，如出现意外行为：

```bash
# 清理 pinned BPF maps
sudo rm -rf /sys/fs/bpf/jz
sudo rm -f /sys/fs/bpf/jz_*

# 清理残留的 PID/socket 文件
sudo rm -f /var/run/jz/*.pid /var/run/jz/*.sock

# 重启 sniffd（会重新 pin 新的 maps）
sudo systemctl restart sniffd
```

### 10.4 IPC 连接失败

```bash
# 验证 socket 存在
ls -la /var/run/jz/sniffd.sock

# 验证 sniffd 在运行
ps aux | grep sniffd

# CLI 工具需要 root 权限
sudo jzctl status
```

### 10.5 API 无响应

```bash
# 检查服务状态
sudo systemctl status sniffd

# 检查端口占用
ss -tlnp | grep 8443

# 检查证书有效性
openssl s_client -connect localhost:8443 </dev/null 2>/dev/null | head -5

# 直接测试 API
curl -sk -v https://localhost:8443/api/v1/health
```

### 10.6 日志查询返回空

```bash
# 确认 collectord 在运行
sudo systemctl status collectord

# 确认数据库文件存在
ls -la /var/lib/jz/jz.db

# 直接查询数据库
sqlite3 /var/lib/jz/jz.db "SELECT COUNT(*) FROM events;"
```

### 10.7 编译错误

```bash
# 始终先清理再编译
sudo rm -rf build
make all

# 检查 clang 版本（需要 14+）
clang --version

# 检查库依赖
dpkg -l | grep -E 'libelf|libsqlite3|libyaml|libbpf'
```

### 10.8 前端无法访问

```bash
# 确认前端文件存在
ls /usr/share/jz/www/index.html

# 确认 sniffd 在 serve 静态文件
curl -sk https://localhost:8443/ | head -5

# 如果返回 404 或 API JSON，检查前端安装
sudo install -d /usr/share/jz/www
sudo cp -r frontend/dist/* /usr/share/jz/www/
sudo systemctl restart sniffd
```

---

## 11. 卸载

### 11.1 使用安装脚本卸载

```bash
sudo scripts/install.sh --uninstall
```

此操作会：
- 停止全部 4 个服务
- 禁用开机自启
- 执行 `make uninstall` 移除二进制和服务文件
- 删除前端文件（`/usr/share/jz/www`）
- **保留**配置（`/etc/jz`）和数据（`/var/lib/jz`）

### 11.2 手动完整卸载

```bash
# 1. 停止并禁用服务
sudo systemctl stop sniffd configd collectord uploadd
sudo systemctl disable sniffd configd collectord uploadd

# 2. 移除安装文件
sudo make uninstall

# 3. 清理运行时状态
sudo rm -rf /var/run/jz
sudo rm -rf /sys/fs/bpf/jz
sudo rm -f /sys/fs/bpf/jz_*

# 4. 可选：删除数据和配置（⚠️ 不可恢复）
sudo rm -rf /var/lib/jz     # 删除事件数据库
sudo rm -rf /etc/jz          # 删除配置文件和 TLS 证书
sudo rm -rf /usr/share/jz    # 删除前端文件

# 5. 可选：删除系统用户
sudo userdel jz
sudo groupdel jz 2>/dev/null
```

---

## 12. 附录

### 12.1 文件路径速查

| 路径 | 说明 |
|------|------|
| `/etc/jz/base.yaml` | 主配置文件 |
| `/etc/jz/bpf/` | BPF 模块目录（8 个 .bpf.o 文件） |
| `/etc/jz/tls/server.crt` | TLS 证书 |
| `/etc/jz/tls/server.key` | TLS 私钥 |
| `/etc/jz/blacklist.txt` | IP 黑名单文件 |
| `/usr/local/sbin/sniffd` | sniffd 守护进程 |
| `/usr/local/sbin/configd` | configd 守护进程 |
| `/usr/local/sbin/collectord` | collectord 守护进程 |
| `/usr/local/sbin/uploadd` | uploadd 守护进程 |
| `/usr/local/bin/jzctl` | 系统管理 CLI |
| `/usr/local/bin/jzguard` | 哨兵管理 CLI |
| `/usr/local/bin/jzlog` | 日志查看 CLI |
| `/var/lib/jz/jz.db` | SQLite 事件数据库 |
| `/var/run/jz/sniffd.pid` | sniffd PID 文件 |
| `/var/run/jz/sniffd.sock` | IPC socket |
| `/sys/fs/bpf/jz/` | BPF pinned maps |
| `/usr/share/jz/www/` | 前端静态文件 |
| `/etc/systemd/system/sniffd.service` | systemd 服务文件 |

### 12.2 端口与协议

| 端口 | 协议 | 方向 | 说明 |
|------|------|------|------|
| 8443 | HTTPS | 入站 | REST API + 前端界面 |
| 1883/8883 | MQTT/MQTTS | 出站 | 日志上传（如已配置 MQTT） |
| 514 | UDP/syslog | 出站 | rsyslog 转发（如已配置） |

### 12.3 BPF Map 列表

| Map 名称 | 类型 | 说明 |
|----------|------|------|
| jz_static_guards | Hash | 静态哨兵表（key=IP, value=guard_entry） |
| jz_dynamic_guards | Hash | 动态哨兵表 |
| jz_whitelist | Hash | 白名单 |
| jz_guard_result_map | Per-CPU Array | 分类结果传递 |
| jz_arp_config | Array | ARP 蜜罐配置 |
| jz_arp_rate | Per-CPU Hash | ARP 限速计数 |
| jz_icmp_config | Array | ICMP 蜜罐配置 |
| jz_icmp_rate | Per-CPU Hash | ICMP 限速计数 |
| jz_fake_mac_pool | Array | 伪造 MAC 地址池 |
| jz_probe_targets | Hash | 嗅探器探针目标 |
| jz_sniffer_suspects | Hash | 嗅探器嫌疑设备 |
| jz_flow_policy | Hash | 流量策略表（五元组匹配） |
| jz_redirect_config | Array | 重定向/镜像接口配置 |
| jz_flow_stats | Per-CPU Hash | 流量统计 |
| jz_bg_filter | Hash | 背景采集过滤配置 |
| jz_bg_stats | Per-CPU Array | 背景协议统计 |
| jz_threat_patterns | Array | 威胁匹配模式 |
| jz_threat_blacklist | Hash | IP 黑名单 |
| jz_threat_stats | Per-CPU Array | 威胁统计 |
| jz_sample_config | Array | 取证采样配置 |

### 12.4 快速冒烟测试

一行命令验证部署是否成功：

```bash
curl -sk https://localhost:8443/api/v1/health && echo " ✓ API OK"
```

完整冒烟测试：

```bash
#!/bin/bash
HOST=localhost
echo "=== jz_sniff_rn 冒烟测试 ==="

# 1. API 健康
health=$(curl -sk https://$HOST:8443/api/v1/health)
echo "[1] 健康检查: $health"

# 2. 模块加载
modules=$(curl -sk https://$HOST:8443/api/v1/modules)
loaded=$(echo "$modules" | grep -o '"loaded":true' | wc -l)
echo "[2] BPF 模块: $loaded/8 已加载"

# 3. 服务状态
for svc in sniffd configd collectord uploadd; do
    status=$(systemctl is-active $svc 2>/dev/null)
    echo "[3] $svc: $status"
done

# 4. 前端
frontend=$(curl -sk -o /dev/null -w "%{http_code}" https://$HOST:8443/)
echo "[4] 前端访问: HTTP $frontend"

echo "=== 测试完成 ==="
```

---

*手册结束 — jz_sniff_rn 运维与用户手册 v1.0.0*
