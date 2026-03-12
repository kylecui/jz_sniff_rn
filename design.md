# jz_sniff_rn (嗅探重生 / Sniff Reborn) — Design Document

> Version: 1.0.0-draft
> Date: 2026-03-12
> Status: Design Phase

---

## Table of Contents

1. [Project Overview (项目概述)](#1-project-overview-项目概述)
2. [System Architecture (系统架构)](#2-system-architecture-系统架构)
3. [BPF Module Design (BPF 模块设计)](#3-bpf-module-design-bpf-模块设计)
4. [User-space Design (用户空间设计)](#4-user-space-design-用户空间设计)
5. [Data Model (数据模型)](#5-data-model-数据模型)
6. [Configuration System (配置系统)](#6-configuration-system-配置系统)
7. [Security Design (安全设计)](#7-security-design-安全设计)
8. [Deployment Architecture (部署架构)](#8-deployment-architecture-部署架构)
9. [Performance Targets (性能目标)](#9-performance-targets-性能目标)
10. [TDD Strategy & Atomic Commit Plan](#10-tdd-strategy--atomic-commit-plan)

---

## 1. Project Overview (项目概述)

### 1.1 Project Identity

- **Project Name**: jz_sniff_rn (嗅探重生 / Sniff Reborn)
- **Codename**: Sniff Reborn
- **Type**: Network security appliance firmware — deception, traffic analysis, and threat detection
- **Platform**: rSwitch XDP/eBPF network switch
- **Lineage**: Redesign of legacy JZZN (金盾智能网络) honeypot system

### 1.2 Project Goals

The jz_sniff_rn project reimagines the legacy JZZN honeypot system for the XDP/eBPF era. Where JZZN relied on libpcap-based user-space packet capture (C++14 sniff daemon), jz_sniff_rn performs all hot-path operations directly in the kernel via XDP programs, achieving orders-of-magnitude improvements in throughput and latency while preserving the core deception and detection concepts.

**Primary goals:**

1. **Dynamic Trapping (动态诱捕)** — Detect and deceive network attackers using ARP/ICMP honeypot responses for guarded IP addresses. Support static guards (pre-configured honeypot IPs), dynamic guards (auto-discovered IPs), and whitelists (trusted devices).

2. **Traffic Weaving (流量编织)** — Dynamically steer suspicious traffic to honeypot interfaces, mirror selected flows for deep inspection, and apply per-flow granular control policies — all with hot-reload capability.

3. **Data Collation (数据整理)** — Perform fast-path threat pattern matching in BPF, generate structured attack event logs, capture forensic packet samples, and export data to an analysis platform.

4. **Configuration Delivery (配置信息下发)** — Accept configuration from a centralized management platform, support hot-reload of guard policies / ACL rules / mirror configs, and maintain config versioning with rollback.

5. **Background Collection (背景收集)** — Capture broadcast (ARP, DHCP), multicast (mDNS, SSDP, IGMP), and protocol announcement traffic (STP, LLDP, CDP) for baseline building and anomaly detection.

### 1.3 JZZN-to-rSwitch Concept Mapping

| JZZN Concept | JZZN Implementation | jz_sniff_rn Implementation |
|---|---|---|
| Packet capture | libpcap in sniff daemon (user-space) | XDP BPF programs (kernel) |
| ARP honeypot | sniff daemon crafts raw ARP replies | `jz_arp_honeypot` BPF module (XDP_TX) |
| ICMP honeypot | sniff daemon crafts raw ICMP replies | `jz_icmp_honeypot` BPF module (XDP_TX) |
| Static guards | `guard_static_config` table in PostgreSQL | `jz_static_guards` BPF hash map |
| Dynamic guards | `dynamic_guard` table + auto-discovery | `jz_dynamic_guards` BPF LRU hash map |
| Whitelist | `guard_white_list` table | `jz_whitelist` BPF hash map |
| Attack logging | `log_attack` table + pg_notify CDC | `rs_event_bus` ring buffer → collectord → SQLite |
| REST API | Java/Jersey/Jetty backend | mgmtd extension (Mongoose HTTP in C) |
| Config management | Angular frontend + PostgreSQL | YAML profiles + configd daemon |
| RBAC | 280+ permissions in PostgreSQL | Simplified 3-role model (admin/operator/viewer) |

### 1.4 Scope

**In scope:**
- All 5 core capabilities listed above
- 8 new BPF modules for the rSwitch pipeline
- 4 user-space daemons (sniffd, configd, collectord, uploadd)
- CLI tools (jzctl, jzguard, jzlog)
- REST API for management
- SQLite persistence for attack logs, config history, audit trail
- Single-device standalone and platform-managed deployment modes

**Out of scope:**
- Modifying rSwitch core code (all integration via module system and shared maps)
- Full web UI (management platform provides this)
- Multi-tenant support (each device is single-tenant)
- High-interaction honeypot VMs (jz_sniff_rn redirects traffic to them but doesn't manage them)
- DPI engine (offloaded to analysis platform)

### 1.5 Terminology

| Term | Definition |
|---|---|
| Guard | A protected IP address that triggers honeypot responses when accessed |
| Static guard | A guard IP manually configured by an administrator |
| Dynamic guard | A guard IP auto-discovered via network scanning or DHCP observation |
| Whitelist entry | A trusted device (IP+MAC) exempt from guard checks |
| Fake MAC | A synthetic MAC address used in honeypot ARP replies |
| Probe | An ARP request sent to a non-existent IP to detect promiscuous-mode sniffers |
| Stage | A numbered slot in the rSwitch BPF pipeline (ingress 10-99, egress 100-199) |
| Tail call | BPF mechanism for chaining program execution across pipeline stages |

---

## 2. System Architecture (系统架构)

### 2.1 Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Management Platform (远程管理平台)                  │
│                  ┌─────────────────────────┐                    │
│                  │  Config Push / Log Collect   │                    │
│                  └──────────┬──────────────┘                    │
│                             │ HTTPS/TLS                             │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│ jz_sniff_rn Device          │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              Management Plane (管理面)                         │   │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐            │   │
│  │  │ REST API │ │  jzctl   │ │jzguard │ │ jzlog  │            │   │
│  │  │(Mongoose)│ │  (CLI)   │ │ (CLI)  │ │ (CLI)  │            │   │
│  │  └────┬─────┘ └────┬─────┘ └───┬────┘ └───┬────┘            │   │
│  └───────┼─────────────┼──────────┼───────────┼─────────────────┘   │
│          │ Unix Socket │          │           │                      │
│  ┌───────┼─────────────┼──────────┼───────────┼─────────────────┐   │
│  │       ▼     Control Plane (控制面)          ▼                  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐       │   │
│  │  │  sniffd  │ │ configd  │ │ collectord│ │ uploadd  │       │   │
│  │  │(主守护)  │ │(配置管理) │ │(数据收集)  │ │(上传代理) │       │   │
│  │  └────┬─────┘ └────┬─────┘ └─────┬─────┘ └────┬─────┘       │   │
│  │       │  libbpf    │  BPF map     │  ringbuf   │  HTTPS      │   │
│  └───────┼────────────┼─────────────┼────────────┼──────────────┘   │
│          │            │             │            │                   │
│  ┌───────┼────────────┼─────────────┼────────────┼──────────────┐   │
│  │       ▼    Data Plane (数据面) — XDP/eBPF     ▼               │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │              rSwitch BPF Pipeline                      │  │   │
│  │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │  │   │
│  │  │  │ S:10 │→│ S:18 │→│ S:19 │→│ S:22 │→│ S:23 │→ ...   │  │   │
│  │  │  │parser│ │src_gd│ │dhcp_s│ │guard │ │arp_hp│        │  │   │
│  │  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │  │   │
│  │  │                                                        │  │   │
│  │  │  ... →┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │  │   │
│  │  │       │ S:30 │→│ S:35 │→│ S:40 │→│ S:45 │→│ S:50 │→  │  │   │
│  │  │       │ ACL  │ │weaver│ │bg_col│ │mirror│ │threat│   │  │   │
│  │  │       └──────┘ └──────┘ └──────┘ └──────┘ └──────┘   │  │   │
│  │  │                                                        │  │   │
│  │  │  ... →┌──────┐ ┌──────┐ ┌──────┐                      │  │   │
│  │  │       │ S:55 │→│ S:85 │→│ S:99 │                      │  │   │
│  │  │       │foren.│ │sflow │ │ fwd  │                      │  │   │
│  │  │       └──────┘ └──────┘ └──────┘                      │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Persistence (持久层)                                         │   │
│  │  ┌───────────┐  ┌────────────────┐  ┌────────────────────┐  │   │
│  │  │  SQLite   │  │  YAML Configs  │  │  BPF Pinned Maps   │  │   │
│  │  │(attack_log│  │ (profiles/)    │  │(/sys/fs/bpf/jz/)   │  │   │
│  │  │ audit_log)│  │                │  │                    │  │   │
│  │  └───────────┘  └────────────────┘  └────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 rSwitch Integration Model

jz_sniff_rn integrates with rSwitch exclusively through the standard module interface:

1. **Module declaration**: Each BPF module uses `RS_DECLARE_MODULE()` macro with a `.rodata.mod` ELF section for auto-discovery by `rswitch_loader`.
2. **Shared maps**: jz modules reference rSwitch shared maps (`rs_progs`, `rs_ctx_map`, `rs_mac_table`, `rs_event_bus`, `rs_stats_map`) via pinned BPF maps at `/sys/fs/bpf/rswitch/`.
3. **Custom maps**: jz modules define their own maps pinned under `/sys/fs/bpf/jz/` for isolation.
4. **Tail-call chaining**: Each jz module ends with `bpf_tail_call(ctx, &rs_progs, NEXT_STAGE)` to continue the pipeline.
5. **Context passing**: Modules communicate per-packet state via `rs_ctx` (256-byte per-CPU array).

**Integration constraints:**
- No modification to rSwitch core source code
- All jz maps pinned under `/sys/fs/bpf/jz/` namespace (not `/sys/fs/bpf/rswitch/`)
- jz modules must not alter `rs_ctx` fields used by rSwitch core modules
- jz modules use a reserved range of `rs_ctx` bytes (offset 192-255) for custom state

### 2.3 BPF Module Pipeline

```
INGRESS PIPELINE (入站管道)
═══════════════════════════════════════════════════════════════════

 Packet In
     │
     ▼
┌─────────┐   ┌───────────┐   ┌───────────┐
│ Stage 10 │──▶│  Stage 18  │──▶│  Stage 19  │
│  parser  │   │source_guard│   │ dhcp_snoop │
│(rSwitch) │   │ (rSwitch)  │   │ (rSwitch)  │
└─────────┘   └───────────┘   └───────────┘
                                      │
                    ┌─────────────────┘
                    ▼
  ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
  │         jz_sniff_rn DECEPTION BLOCK              │
  │                                                   │
  │  ┌───────────────┐   Packet matches   ┌────────────────┐
  │  │   Stage 22     │──guard table?──▶  │   Stage 23      │
  │  │guard_classifier│   YES (ARP)       │ arp_honeypot    │
  │  │                │                   │ Craft fake ARP  │
  │  │ Lookup static, │                   │ reply → XDP_TX  │
  │  │ dynamic guards │                   └────────────────┘
  │  │ Check whitelist│
  │  │                │   YES (ICMP)  ┌────────────────┐
  │  │                │──────────────▶│   Stage 24      │
  │  │                │               │ icmp_honeypot   │
  │  │                │               │ Craft fake echo │
  │  │                │               │ reply → XDP_TX  │
  │  │                │               └────────────────┘
  │  │                │
  │  │                │   PROBE      ┌────────────────┐
  │  │                │─────────────▶│   Stage 25      │
  │  └───────────────┘               │ sniffer_detect  │
  │         │ NO match               │ Log response to │
  │         │ (pass-through)         │ probe targets   │
  │         ▼                        └────────────────┘
  └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
            │
            ▼
     ┌───────────┐
     │  Stage 30  │
     │    ACL     │
     │ (rSwitch)  │
     └───────────┘
            │
            ▼
  ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
  │       jz_sniff_rn TRAFFIC BLOCK                   │
  │                                                    │
  │  ┌────────────────┐                               │
  │  │   Stage 35      │  REDIRECT → bpf_redirect()  │
  │  │ traffic_weaver  │  MIRROR   → clone + redirect │
  │  │                 │  PASS     → continue pipeline │
  │  │ Per-flow policy │  DROP     → XDP_DROP          │
  │  └────────────────┘                               │
  └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
            │
            ▼
  ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
  │       jz_sniff_rn COLLECTION BLOCK                │
  │                                                    │
  │  ┌────────────────┐                               │
  │  │   Stage 40      │  Capture broadcast/multicast │
  │  │  bg_collector   │  ARP, DHCP, mDNS, SSDP,     │
  │  │                 │  STP, LLDP, CDP, IGMP        │
  │  │                 │  → ringbuf event             │
  │  └────────────────┘                               │
  └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
            │
            ▼
     ┌───────────┐
     │  Stage 45  │
     │   mirror   │
     │ (rSwitch)  │
     └───────────┘
            │
            ▼
  ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
  │       jz_sniff_rn ANALYSIS BLOCK                  │
  │                                                    │
  │  ┌────────────────┐   ┌────────────────┐          │
  │  │   Stage 50      │──▶│   Stage 55      │         │
  │  │ threat_detect   │   │   forensics     │         │
  │  │                 │   │                 │         │
  │  │ Pattern match   │   │ Sample packets  │         │
  │  │ known threats   │   │ to ringbuf for  │         │
  │  │ → ringbuf alert │   │ forensic review │         │
  │  └────────────────┘   └────────────────┘          │
  └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
            │
            ▼
     ┌───────────┐   ┌───────────┐
     │  Stage 85  │──▶│  Stage 99  │──▶ Packet Out
     │   sflow   │   │ forwarding │
     │ (rSwitch) │   │ (rSwitch)  │
     └───────────┘   └───────────┘
```

### 2.4 User-space Daemon Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User-space Daemons                        │
│                                                              │
│  ┌──────────────────────┐    ┌──────────────────────┐       │
│  │       sniffd          │    │      configd          │       │
│  │  (Main Orchestrator)  │    │  (Config Manager)     │       │
│  │                       │    │                       │       │
│  │ • Load/unload BPF     │    │ • Watch YAML files    │       │
│  │   modules via libbpf  │    │ • Receive remote cfg  │       │
│  │ • Consume rs_event_bus│    │   via TLS endpoint    │       │
│  │   ring buffer         │    │ • Validate configs    │       │
│  │ • Manage guard tables │    │ • Update BPF maps     │       │
│  │   (static/dynamic/wl) │    │ • Version history     │       │
│  │ • Generate ARP probes │    │ • Rollback support    │       │
│  │ • Timer-based tasks   │    │                       │       │
│  │                       │    │                       │       │
│  │ IPC: /var/run/jz/     │    │ IPC: /var/run/jz/     │       │
│  │      sniffd.sock      │    │      configd.sock     │       │
│  └───────────┬───────────┘    └───────────┬───────────┘       │
│              │                            │                   │
│              │  ┌─────────────────────┐   │                   │
│              │  │   Unix Domain IPC   │   │                   │
│              │  │   (JSON messages)   │   │                   │
│              │  └─────────────────────┘   │                   │
│              │                            │                   │
│  ┌───────────┴───────────┐    ┌───────────┴───────────┐       │
│  │     collectord        │    │      uploadd          │       │
│  │  (Data Collector)     │    │  (Upload Agent)       │       │
│  │                       │    │                       │       │
│  │ • Aggregate events    │    │ • Batch collected     │       │
│  │   from ring buffer    │    │   data for upload     │       │
│  │ • Deduplicate/rate    │    │ • HTTPS POST to       │       │
│  │   limit events        │    │   management platform │       │
│  │ • Write to SQLite     │    │ • Retry with backoff  │       │
│  │ • Structure bg noise  │    │ • Compress payloads   │       │
│  │   capture data        │    │ • Certificate auth    │       │
│  │                       │    │                       │       │
│  │ IPC: /var/run/jz/     │    │ IPC: /var/run/jz/     │       │
│  │      collectord.sock  │    │      uploadd.sock     │       │
│  └───────────────────────┘    └───────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### 2.5 Data Flow Diagrams

#### 2.5.1 Dynamic Trapping Flow (动态诱捕流程)

```
Attacker                 jz_sniff_rn Device              Admin
   │                          │                            │
   │  ARP Request for         │                            │
   │  guarded IP (10.0.1.50)  │                            │
   │─────────────────────────▶│                            │
   │                          │                            │
   │              ┌───────────┴───────────┐                │
   │              │ Stage 22: guard_class │                │
   │              │ Lookup 10.0.1.50 in   │                │
   │              │ jz_static_guards map  │                │
   │              │ → MATCH (guard type:  │                │
   │              │   static, proto: ARP) │                │
   │              └───────────┬───────────┘                │
   │                          │                            │
   │              ┌───────────┴───────────┐                │
   │              │ Stage 23: arp_honeypot│                │
   │              │ 1. Get fake MAC from  │                │
   │              │    jz_fake_mac_pool   │                │
   │              │ 2. Craft ARP reply    │                │
   │              │    (swap src/dst,     │                │
   │              │     set fake MAC)     │                │
   │              │ 3. Emit ATTACK event  │                │
   │              │    to rs_event_bus    │                │
   │              │ 4. Return XDP_TX      │                │
   │              └───────────┬───────────┘                │
   │                          │                            │
   │  Fake ARP Reply          │                            │
   │  (MAC: aa:bb:cc:dd:ee:01)│                            │
   │◀─────────────────────────│                            │
   │                          │                            │
   │                ┌─────────┴─────────┐                  │
   │                │ sniffd (ringbuf)  │                  │
   │                │ Consume event     │                  │
   │                │ → collectord      │                  │
   │                └─────────┬─────────┘                  │
   │                          │                            │
   │                ┌─────────┴─────────┐                  │
   │                │ collectord        │                  │
   │                │ Write attack_log  │                  │
   │                │ to SQLite DB      │──notify──────────▶│
   │                └─────────┬─────────┘                  │
   │                          │                            │
   │                ┌─────────┴─────────┐                  │
   │                │ uploadd           │                  │
   │                │ Batch upload to   │                  │
   │                │ management platform│                 │
   │                └───────────────────┘                  │
```

#### 2.5.2 Traffic Weaving Flow (流量编织流程)

```
Suspicious            jz_sniff_rn              Honeypot VM        Mirror
 Client                 Device                  (Port 8)         Analyzer
    │                     │                        │                 │
    │  TCP SYN to         │                        │                 │
    │  suspicious port    │                        │                 │
    │────────────────────▶│                        │                 │
    │                     │                        │                 │
    │         ┌───────────┴───────────┐            │                 │
    │         │ Stage 35: traffic_    │            │                 │
    │         │ weaver                │            │                 │
    │         │                       │            │                 │
    │         │ Lookup flow in        │            │                 │
    │         │ jz_flow_policy map    │            │                 │
    │         │                       │            │                 │
    │         │ Policy match:         │            │                 │
    │         │ action = REDIRECT +   │            │                 │
    │         │          MIRROR       │            │                 │
    │         └───┬───────────┬───────┘            │                 │
    │             │           │                    │                 │
    │             │ REDIRECT  │ MIRROR (clone)     │                 │
    │             │           │                    │                 │
    │             │  bpf_redirect(port=8)          │                 │
    │             │───────────────────────────────▶│                 │
    │             │           │                    │                 │
    │             │           │  bpf_clone_redirect(port=mirror)    │
    │             │           │────────────────────────────────────▶│
    │             │           │                    │                 │
```

#### 2.5.3 Configuration Delivery Flow (配置下发流程)

```
Management                   configd                BPF Maps
Platform                       │                       │
    │                          │                       │
    │  HTTPS POST              │                       │
    │  /api/v1/config/push     │                       │
    │  { version: 42,          │                       │
    │    guards: [...],        │                       │
    │    policies: [...] }     │                       │
    │─────────────────────────▶│                       │
    │                          │                       │
    │              ┌───────────┴───────────┐           │
    │              │ 1. Validate schema    │           │
    │              │ 2. Diff with current  │           │
    │              │ 3. Save to history    │           │
    │              │    (SQLite)           │           │
    │              │ 4. Write YAML file    │           │
    │              └───────────┬───────────┘           │
    │                          │                       │
    │                          │  bpf_map_update_elem  │
    │                          │──────────────────────▶│
    │                          │  (atomic per-entry    │
    │                          │   update to guard     │
    │                          │   maps, policy maps)  │
    │                          │                       │
    │              ┌───────────┴───────────┐           │
    │              │ 5. Verify maps updated│           │
    │              │ 6. Log audit event    │           │
    │              │ 7. ACK to platform    │           │
    │              └───────────┬───────────┘           │
    │                          │                       │
    │  200 OK { version: 42,   │                       │
    │    status: "applied" }   │                       │
    │◀─────────────────────────│                       │
```

#### 2.5.4 Background Collection Flow (背景收集流程)

```
Network Devices             jz_sniff_rn             Analysis Platform
    │                          │                          │
    │  ARP Broadcast           │                          │
    │─────────────────────────▶│                          │
    │                          │                          │
    │  DHCP Discover           │                          │
    │─────────────────────────▶│                          │
    │                          │                          │
    │  mDNS Query              │                          │
    │─────────────────────────▶│                          │
    │                          │                          │
    │  LLDP Announcement       │                          │
    │─────────────────────────▶│                          │
    │                          │                          │
    │         ┌────────────────┴────────────────┐         │
    │         │ Stage 40: bg_collector          │         │
    │         │                                 │         │
    │         │ Check jz_bg_filter map:         │         │
    │         │ • ETH_P_ARP → CAPTURE           │         │
    │         │ • UDP:67/68 (DHCP) → CAPTURE    │         │
    │         │ • UDP:5353 (mDNS) → CAPTURE     │         │
    │         │ • LLDP ethertype → CAPTURE      │         │
    │         │                                 │         │
    │         │ Emit BG_CAPTURE event to        │         │
    │         │ rs_event_bus with:              │         │
    │         │ • protocol type                 │         │
    │         │ • source MAC/IP                 │         │
    │         │ • packet summary (first 128B)   │         │
    │         │ • timestamp                     │         │
    │         └────────────────┬────────────────┘         │
    │                          │                          │
    │              ┌───────────┴───────────┐              │
    │              │ collectord            │              │
    │              │ • Aggregate by proto  │              │
    │              │ • Build baseline stats│              │
    │              │ • Write to SQLite     │              │
    │              └───────────┬───────────┘              │
    │                          │                          │
    │              ┌───────────┴───────────┐              │
    │              │ uploadd               │              │
    │              │ • Batch bg captures   │──────────────▶│
    │              │ • Compress + upload   │  HTTPS POST   │
    │              └───────────────────────┘              │
```

---

## 3. BPF Module Design (BPF 模块设计)

### 3.1 Common Definitions

All jz modules share a common header `jz_common.h`:

```c
/* jz_common.h — Shared definitions for all jz_sniff_rn BPF modules */

#ifndef __JZ_COMMON_H
#define __JZ_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── Stage Numbers ── */
#define JZ_STAGE_GUARD_CLASSIFIER   22
#define JZ_STAGE_ARP_HONEYPOT       23
#define JZ_STAGE_ICMP_HONEYPOT      24
#define JZ_STAGE_SNIFFER_DETECT     25
#define JZ_STAGE_TRAFFIC_WEAVER     35
#define JZ_STAGE_BG_COLLECTOR       40
#define JZ_STAGE_THREAT_DETECT      50
#define JZ_STAGE_FORENSICS          55

/* ── rs_ctx Offsets (jz reserved: 192-255) ── */
#define JZ_CTX_OFFSET               192
#define JZ_CTX_GUARD_RESULT         192  /* __u8: 0=no-match, 1=static, 2=dynamic */
#define JZ_CTX_GUARD_PROTO          193  /* __u8: matched protocol (ARP/ICMP/TCP/UDP) */
#define JZ_CTX_GUARD_FLAGS          194  /* __u16: flags (whitelist_bypass, probe, etc.) */
#define JZ_CTX_WEAVER_ACTION        196  /* __u8: PASS/DROP/REDIRECT/MIRROR */
#define JZ_CTX_WEAVER_PORT          197  /* __u8: redirect target port */
#define JZ_CTX_THREAT_LEVEL         198  /* __u8: 0=none, 1=low, 2=med, 3=high, 4=crit */
#define JZ_CTX_SAMPLE_FLAG          199  /* __u8: 1=sample this packet */

/* ── Guard Types ── */
#define JZ_GUARD_NONE               0
#define JZ_GUARD_STATIC             1
#define JZ_GUARD_DYNAMIC            2

/* ── Guard Flags ── */
#define JZ_FLAG_WHITELIST_BYPASS    (1 << 0)
#define JZ_FLAG_IS_PROBE_RESPONSE  (1 << 1)
#define JZ_FLAG_ARP_REQUEST        (1 << 2)
#define JZ_FLAG_ICMP_REQUEST       (1 << 3)

/* ── Weaver Actions ── */
#define JZ_ACTION_PASS              0
#define JZ_ACTION_DROP              1
#define JZ_ACTION_REDIRECT          2
#define JZ_ACTION_MIRROR            3
#define JZ_ACTION_REDIRECT_MIRROR   4  /* both redirect + mirror */

/* ── Event Types ── */
#define JZ_EVENT_ATTACK_ARP         1
#define JZ_EVENT_ATTACK_ICMP        2
#define JZ_EVENT_SNIFFER_DETECTED   3
#define JZ_EVENT_POLICY_MATCH       4
#define JZ_EVENT_THREAT_DETECTED    5
#define JZ_EVENT_BG_CAPTURE         6
#define JZ_EVENT_CONFIG_CHANGE      7
#define JZ_EVENT_SYSTEM_STATUS      8

/* ── Event Header (common to all events) ── */
struct jz_event_hdr {
    __u32 type;           /* JZ_EVENT_* */
    __u32 len;            /* total event length */
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() */
    __u32 ifindex;        /* ingress interface */
    __u8  src_mac[6];     /* source MAC */
    __u8  dst_mac[6];     /* destination MAC */
    __u32 src_ip;         /* source IP (0 if not applicable) */
    __u32 dst_ip;         /* destination IP (0 if not applicable) */
};

/* ── Map Size Limits ── */
#define JZ_MAX_STATIC_GUARDS       4096
#define JZ_MAX_DYNAMIC_GUARDS      16384
#define JZ_MAX_WHITELIST           4096
#define JZ_MAX_FAKE_MACS           256
#define JZ_MAX_FLOW_POLICIES       8192
#define JZ_MAX_PROBE_TARGETS       1024
#define JZ_MAX_THREAT_PATTERNS     2048
#define JZ_MAX_BG_FILTERS          64

#endif /* __JZ_COMMON_H */
```

### 3.2 Module: jz_guard_classifier (Stage 22)

**Purpose**: Classify incoming packets against guard tables (static guards, dynamic guards, whitelists). Sets guard result in `rs_ctx` for downstream modules. This is the gatekeeper — all deception logic depends on its classification.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_guard_classifier, 22,
    .description = "Guard IP classifier for honeypot deception",
    .flags = RS_MOD_INGRESS | RS_MOD_REQUIRED,
    .priority = 0);
```

**BPF Maps**:

```c
/* Static guard entries — manually configured honeypot IPs */
struct jz_guard_entry {
    __u32 ip_addr;        /* guarded IP address */
    __u8  fake_mac[6];    /* associated fake MAC (or 0 for pool) */
    __u8  guard_type;     /* JZ_GUARD_STATIC or JZ_GUARD_DYNAMIC */
    __u8  enabled;        /* 0=disabled, 1=enabled */
    __u16 vlan_id;        /* VLAN scope (0=all VLANs) */
    __u16 flags;          /* reserved */
    __u64 created_at;     /* timestamp */
    __u64 last_hit;       /* last time this guard was triggered */
    __u64 hit_count;      /* total hits */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                    /* IP address */
    __type(value, struct jz_guard_entry);
    __uint(max_entries, JZ_MAX_STATIC_GUARDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_static_guards SEC(".maps");

/* Dynamic guard entries — auto-discovered IPs */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   /* LRU: auto-evict stale entries */
    __type(key, __u32);
    __type(value, struct jz_guard_entry);
    __uint(max_entries, JZ_MAX_DYNAMIC_GUARDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_dynamic_guards SEC(".maps");

/* Whitelist — trusted devices exempt from guard checks */
struct jz_whitelist_entry {
    __u32 ip_addr;
    __u8  mac[6];
    __u8  match_mac;      /* 1=must match both IP+MAC, 0=IP only */
    __u8  enabled;
    __u64 created_at;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                      /* IP address */
    __type(value, struct jz_whitelist_entry);
    __uint(max_entries, JZ_MAX_WHITELIST);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_whitelist SEC(".maps");

/* Guard classification result — per-CPU scratch for passing to next stage */
struct jz_guard_result {
    __u8  guard_type;     /* JZ_GUARD_NONE / STATIC / DYNAMIC */
    __u8  proto;          /* detected protocol needing response */
    __u16 flags;          /* JZ_FLAG_* */
    __u32 guarded_ip;     /* the IP that was matched */
    __u8  fake_mac[6];    /* MAC to use for response (from entry or pool) */
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_guard_result);
    __uint(max_entries, 1);
} jz_guard_result SEC(".maps");
```

**Core Logic**:
```
1. Parse packet: extract src_ip, src_mac, dst_ip, protocol
2. Check whitelist: if src_ip in jz_whitelist AND mac matches → set WHITELIST_BYPASS flag → tail_call(NEXT)
3. Check static guards: lookup dst_ip in jz_static_guards
4. If no static match, check dynamic guards: lookup dst_ip in jz_dynamic_guards
5. If match found:
   a. Determine protocol (ARP request? ICMP echo? TCP SYN?)
   b. Set guard_result in per-CPU map
   c. Write classification into rs_ctx[192..199]
   d. Update hit_count and last_hit on the guard entry
   e. Tail call to appropriate honeypot stage (23 for ARP, 24 for ICMP)
6. If no match: tail_call to next stage (30 = ACL)
```

### 3.3 Module: jz_arp_honeypot (Stage 23)

**Purpose**: Craft and send fake ARP replies for guarded IP addresses. Responds to ARP requests that target guard IPs with synthetic MAC addresses, making the guarded IPs appear "alive" to attackers.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_arp_honeypot, 23,
    .description = "ARP honeypot response generator",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* ARP honeypot configuration */
struct jz_arp_config {
    __u8  enabled;           /* global enable/disable */
    __u8  log_all;           /* log every ARP response (vs. first-only) */
    __u16 rate_limit_pps;    /* max responses per second (0=unlimited) */
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_arp_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_arp_config SEC(".maps");

/* Fake MAC address pool — rotating pool of synthetic MACs */
struct jz_fake_mac {
    __u8  mac[6];
    __u8  in_use;
    __u8  _pad;
    __u32 assigned_ip;      /* which guard IP this is assigned to */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);                  /* index 0..255 */
    __type(value, struct jz_fake_mac);
    __uint(max_entries, JZ_MAX_FAKE_MACS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_fake_mac_pool SEC(".maps");

/* Rate limiter — per-CPU token bucket */
struct jz_rate_state {
    __u64 last_refill_ns;
    __u32 tokens;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_rate_state);
    __uint(max_entries, 1);
} jz_arp_rate SEC(".maps");
```

**Core Logic**:
```
1. Read guard_result from per-CPU map (set by stage 22)
2. Verify this is an ARP request (opcode = ARP_REQUEST)
3. Check rate limiter — if over limit, drop silently
4. Get fake MAC:
   a. If guard entry has a specific fake_mac → use it
   b. Else → allocate from jz_fake_mac_pool (round-robin)
5. Craft ARP reply in-place:
   a. Swap ETH src/dst MACs
   b. Set ETH src to fake_mac
   c. Set ARP opcode = ARP_REPLY
   d. Set ARP sender MAC = fake_mac
   e. Set ARP sender IP = guarded_ip
   f. Set ARP target MAC = original sender MAC
   g. Set ARP target IP = original sender IP
6. Emit JZ_EVENT_ATTACK_ARP to rs_event_bus ring buffer
7. Return XDP_TX (send reply back out same port)
```

### 3.4 Module: jz_icmp_honeypot (Stage 24)

**Purpose**: Craft and send fake ICMP echo replies for guarded IP addresses.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_icmp_honeypot, 24,
    .description = "ICMP honeypot echo reply generator",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* ICMP honeypot configuration */
struct jz_icmp_config {
    __u8  enabled;
    __u8  ttl;              /* TTL value in fake reply (e.g., 64 for Linux, 128 for Windows) */
    __u16 rate_limit_pps;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_icmp_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_icmp_config SEC(".maps");
```

**Core Logic**:
```
1. Read guard_result from per-CPU map
2. Verify this is ICMP echo request (type=8, code=0)
3. Check rate limiter
4. Craft ICMP echo reply in-place:
   a. Swap ETH src/dst MACs (use fake_mac for src)
   b. Swap IP src/dst
   c. Set IP TTL from config (OS fingerprint spoofing)
   d. Set ICMP type = 0 (echo reply)
   e. Recalculate ICMP checksum
   f. Recalculate IP checksum
5. Emit JZ_EVENT_ATTACK_ICMP to rs_event_bus
6. Return XDP_TX
```

### 3.5 Module: jz_sniffer_detect (Stage 25)

**Purpose**: Detect network sniffers using ARP probe techniques. Monitors responses to ARP probes sent to non-existent IPs — only a device in promiscuous mode would respond.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_sniffer_detect, 25,
    .description = "Network sniffer detection via ARP probes",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* Probe targets — IPs we've sent ARP probes to (non-existent IPs) */
struct jz_probe_target {
    __u32 probe_ip;         /* non-existent IP we probed */
    __u64 probe_sent_ns;    /* when the probe was sent */
    __u32 probe_ifindex;    /* interface the probe was sent on */
    __u8  status;           /* 0=pending, 1=response_received, 2=expired */
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                     /* probe IP */
    __type(value, struct jz_probe_target);
    __uint(max_entries, JZ_MAX_PROBE_TARGETS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_probe_targets SEC(".maps");

/* Sniffer suspects — devices that responded to probes */
struct jz_sniffer_suspect {
    __u8  mac[6];
    __u16 _pad;
    __u32 ip_addr;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 response_count;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);                       /* MAC as __u64 */
    __type(value, struct jz_sniffer_suspect);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_sniffer_suspects SEC(".maps");
```

**Core Logic**:
```
1. Check if packet is ARP reply
2. Extract sender IP from ARP reply
3. Lookup sender IP in jz_probe_targets
4. If match found (someone replied to our probe for a non-existent IP):
   a. This device is likely in promiscuous mode (sniffer!)
   b. Record in jz_sniffer_suspects map
   c. Emit JZ_EVENT_SNIFFER_DETECTED to rs_event_bus
   d. Mark probe_target status = response_received
5. Tail call to next stage (30 = ACL)

NOTE: Probe generation (sending ARP requests to non-existent IPs)
is done by sniffd in user-space via raw sockets on a timer.
The BPF module only monitors for responses.
```

### 3.6 Module: jz_traffic_weaver (Stage 35)

**Purpose**: Per-flow traffic steering engine. Looks up flow policies and applies actions: pass-through, drop, redirect to honeypot interface, or mirror to analyzer.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_traffic_weaver, 35,
    .description = "Per-flow traffic steering and mirroring",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* Flow policy key — 5-tuple match */
struct jz_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;         /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    __u8  _pad[3];
};

/* Flow policy value — action to take */
struct jz_flow_policy {
    __u8  action;         /* JZ_ACTION_* */
    __u8  redirect_port;  /* ifindex for redirect target */
    __u8  mirror_port;    /* ifindex for mirror target */
    __u8  priority;       /* higher = checked first */
    __u32 flags;          /* reserved */
    __u64 created_at;
    __u64 hit_count;
    __u64 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct jz_flow_key);
    __type(value, struct jz_flow_policy);
    __uint(max_entries, JZ_MAX_FLOW_POLICIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_flow_policy SEC(".maps");

/* Redirect port configuration */
struct jz_redirect_config {
    __u32 honeypot_ifindex;    /* default honeypot VM interface */
    __u32 mirror_ifindex;      /* default mirror analyzer interface */
    __u8  enabled;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_redirect_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_redirect_config SEC(".maps");

/* Per-flow statistics */
struct jz_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct jz_flow_key);
    __type(value, struct jz_flow_stats);
    __uint(max_entries, JZ_MAX_FLOW_POLICIES);
} jz_flow_stats SEC(".maps");
```

**Core Logic**:
```
1. Parse 5-tuple from packet (src_ip, dst_ip, src_port, dst_port, proto)
2. Build flow_key
3. Lookup in jz_flow_policy map
4. If match found:
   a. Update flow_stats (packets, bytes, last_seen)
   b. Execute action:
      - PASS: tail_call to next stage
      - DROP: return XDP_DROP
      - REDIRECT: bpf_redirect(redirect_port) → return XDP_REDIRECT
      - MIRROR: bpf_clone_redirect(mirror_port) → continue pipeline
      - REDIRECT_MIRROR: bpf_clone_redirect(mirror) then bpf_redirect(honeypot)
   c. Emit JZ_EVENT_POLICY_MATCH if logging enabled
5. If no match: tail_call to next stage (40 = bg_collector)
```

### 3.7 Module: jz_bg_collector (Stage 40)

**Purpose**: Capture broadcast, multicast, and protocol announcement traffic for baseline building. Non-intrusive — always passes packets through after sampling.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_bg_collector, 40,
    .description = "Background broadcast/multicast traffic collector",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* Background capture filter — which protocols to capture */
struct jz_bg_filter_entry {
    __u16 ethertype;        /* ETH_P_ARP, ETH_P_LLDP, etc. (0=match by port) */
    __u16 udp_port;         /* UDP dest port (67=DHCP, 5353=mDNS, 1900=SSDP) */
    __u8  capture;          /* 1=capture, 0=ignore */
    __u8  sample_rate;      /* 1=every packet, N=1-in-N sampling */
    __u8  include_payload;  /* 1=include first 128B of payload */
    __u8  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                       /* filter_id */
    __type(value, struct jz_bg_filter_entry);
    __uint(max_entries, JZ_MAX_BG_FILTERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_bg_filter SEC(".maps");

/* Background capture statistics */
struct jz_bg_stats {
    __u64 arp_count;
    __u64 dhcp_count;
    __u64 mdns_count;
    __u64 ssdp_count;
    __u64 lldp_count;
    __u64 cdp_count;
    __u64 stp_count;
    __u64 igmp_count;
    __u64 other_count;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_bg_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_bg_stats SEC(".maps");
```

**Core Logic**:
```
1. Check if packet is broadcast (dst_mac = ff:ff:ff:ff:ff:ff) or multicast (bit 0 of byte 0 set)
2. Classify protocol:
   a. ETH_P_ARP → arp_count++
   b. ETH_P_LLDP (0x88cc) → lldp_count++
   c. STP (dst_mac 01:80:c2:00:00:00) → stp_count++
   d. IP + UDP:67/68 → dhcp_count++
   e. IP + UDP:5353 → mdns_count++
   f. IP + UDP:1900 → ssdp_count++
   g. IGMP (IP proto 2) → igmp_count++
   h. CDP (SNAP + OUI 00:00:0c) → cdp_count++
3. Check jz_bg_filter for this protocol
4. If capture enabled:
   a. Apply sample_rate (skip N-1 out of N packets)
   b. Emit JZ_EVENT_BG_CAPTURE to rs_event_bus:
      - protocol type
      - src MAC/IP
      - packet summary (first 128B if include_payload=1)
      - timestamp
5. Always tail_call to next stage (45 = mirror) — non-blocking
```

### 3.8 Module: jz_threat_detect (Stage 50)

**Purpose**: Fast-path threat pattern matching. Matches packet headers and partial payloads against known threat signatures. Heavy analysis is offloaded to user-space; this module catches obvious threats at line rate.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_threat_detect, 50,
    .description = "Fast-path threat pattern matching",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* Threat pattern — header-based matching */
struct jz_threat_pattern {
    __u32 src_ip;           /* 0 = wildcard */
    __u32 dst_ip;           /* 0 = wildcard */
    __u16 dst_port;         /* 0 = wildcard */
    __u8  proto;            /* 0 = wildcard */
    __u8  threat_level;     /* 1=low, 2=medium, 3=high, 4=critical */
    __u32 pattern_id;       /* unique ID for this pattern */
    __u8  action;           /* 0=log-only, 1=log+drop, 2=log+redirect */
    __u8  _pad[3];
    char  description[32];  /* human-readable description */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                      /* pattern_id */
    __type(value, struct jz_threat_pattern);
    __uint(max_entries, JZ_MAX_THREAT_PATTERNS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_patterns SEC(".maps");

/* Known malicious source IPs (blacklist) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);           /* IP address */
    __type(value, __u64);         /* first seen timestamp */
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_blacklist SEC(".maps");

/* Threat detection statistics */
struct jz_threat_stats {
    __u64 total_checked;
    __u64 threats_low;
    __u64 threats_medium;
    __u64 threats_high;
    __u64 threats_critical;
    __u64 dropped;
    __u64 redirected;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_stats SEC(".maps");
```

**Core Logic**:
```
1. Quick check: lookup src_ip in jz_threat_blacklist
   a. If blacklisted → threat_level=HIGH, skip pattern matching
2. For each relevant threat pattern (iterated via array index):
   a. Match against packet headers (src_ip, dst_ip, dst_port, proto)
   b. Wildcards (0) match anything
   c. First match wins (patterns ordered by priority)
3. If threat detected:
   a. Set threat_level in rs_ctx
   b. Update threat_stats
   c. Emit JZ_EVENT_THREAT_DETECTED to rs_event_bus
   d. Execute action: log-only (continue), log+drop (XDP_DROP), log+redirect
4. Set JZ_CTX_SAMPLE_FLAG if threat_level >= medium (trigger forensics stage)
5. Tail call to next stage (55 = forensics)
```

### 3.9 Module: jz_forensics (Stage 55)

**Purpose**: Packet sampling for forensic analysis. Captures full or partial packet contents to the ring buffer for user-space forensic review. Triggered by upstream modules setting the sample flag.

**Module Declaration**:
```c
RS_DECLARE_MODULE(jz_forensics, 55,
    .description = "Packet sampling for forensic analysis",
    .flags = RS_MOD_INGRESS,
    .priority = 0);
```

**BPF Maps**:
```c
/* Forensic sample configuration */
struct jz_sample_config {
    __u8  enabled;
    __u8  _pad;
    __u16 max_payload_bytes;  /* how many bytes of payload to capture (128/256/512) */
    __u32 sample_rate;        /* 1-in-N sampling for non-flagged packets (0=only flagged) */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_sample_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_sample_config SEC(".maps");

/* Forensic sample ring buffer — dedicated ringbuf for large payloads */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  /* 4MB dedicated forensics ringbuf */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_sample_ringbuf SEC(".maps");
```

**Core Logic**:
```
1. Read JZ_CTX_SAMPLE_FLAG from rs_ctx
2. If flag not set AND sample_rate > 0:
   a. Apply random sampling (1-in-N)
3. If sampling this packet:
   a. Reserve space in jz_sample_ringbuf
   b. Copy event header (type, timestamp, IPs, MACs)
   c. Copy packet payload (up to max_payload_bytes)
   d. Include threat_level from rs_ctx
   e. Submit to ringbuf
4. Tail call to next stage (85 = sflow)
```

---

## 4. User-space Design (用户空间设计)

### 4.1 sniffd — Main Orchestrator Daemon

**Responsibilities**:
- Load/unload all jz BPF modules via libbpf
- Initialize and pin BPF maps under `/sys/fs/bpf/jz/`
- Consume events from `rs_event_bus` ring buffer
- Dispatch events to collectord via IPC
- Generate ARP probes for sniffer detection (timer-based)
- Manage guard table lifecycle (populate maps from config)
- Health monitoring (watchdog heartbeat)

**Interface**:
```c
/* sniffd command-line interface */
sniffd [options]
  -c, --config <path>     Config file (default: /etc/jz/sniffd.yaml)
  -d, --daemon            Run as daemon (fork to background)
  -p, --pidfile <path>    PID file (default: /var/run/jz/sniffd.pid)
  -v, --verbose           Verbose logging
  -V, --version           Print version and exit

/* sniffd IPC socket protocol (Unix domain, /var/run/jz/sniffd.sock) */
/* JSON-based request/response */

/* Commands: */
{ "cmd": "status" }                          /* → system status */
{ "cmd": "reload" }                          /* → reload config */
{ "cmd": "guard_add", "type": "static",      /* → add guard */
  "ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:01" }
{ "cmd": "guard_del", "type": "static",      /* → remove guard */
  "ip": "10.0.1.50" }
{ "cmd": "guard_list", "type": "all" }       /* → list guards */
{ "cmd": "whitelist_add",                    /* → add whitelist entry */
  "ip": "10.0.1.1", "mac": "00:11:22:33:44:55" }
{ "cmd": "probe_start" }                     /* → start sniffer probing */
{ "cmd": "probe_stop" }                      /* → stop sniffer probing */
{ "cmd": "module_status" }                   /* → BPF module load status */
```

**Internal Architecture**:
```
┌──────────────────────────────────────────────┐
│                     sniffd                        │
│                                                   │
│  ┌─────────────┐  ┌────────────┐  ┌───────────┐ │
│  │ Main Thread  │  │ Ring Buffer│  │  Probe    │ │
│  │              │  │ Consumer   │  │ Generator │ │
│  │ • Init libbpf│  │ Thread     │  │ Thread    │ │
│  │ • Load mods  │  │            │  │           │ │
│  │ • IPC listen │  │ • Poll     │  │ • Timer   │ │
│  │ • Signal     │  │   ringbuf  │  │   (30s)   │ │
│  │   handler    │  │ • Parse    │  │ • Send ARP│ │
│  │ • Watchdog   │  │   events   │  │   probes  │ │
│  │              │  │ • Dispatch │  │   to non- │ │
│  │              │  │   to IPC   │  │   existent│ │
│  │              │  │            │  │   IPs     │ │
│  └──────┬───────┘  └─────┬──────┘  └─────┬─────┘ │
│         │                │               │        │
│         └────────────────┼───────────────┘        │
│                          │                         │
│                   ┌──────┴──────┐                  │
│                   │  IPC Router │                  │
│                   │  (to CLI,   │                  │
│                   │  collectord,│                  │
│                   │  REST API)  │                  │
│                   └─────────────┘                  │
└──────────────────────────────────────────────────┘
```

### 4.2 configd — Configuration Manager Daemon

**Responsibilities**:
- Watch YAML config files for changes (inotify)
- Receive remote config pushes via TLS endpoint
- Validate config schemas
- Apply config changes to BPF maps atomically
- Maintain config version history in SQLite
- Support rollback to previous config versions

**Interface**:
```c
/* configd command-line interface */
configd [options]
  -c, --config <path>     Config file (default: /etc/jz/configd.yaml)
  -d, --daemon            Run as daemon
  -p, --pidfile <path>    PID file
  --tls-cert <path>       TLS certificate for remote config endpoint
  --tls-key <path>        TLS private key
  --tls-ca <path>         CA certificate for client auth

/* configd IPC socket protocol (/var/run/jz/configd.sock) */
{ "cmd": "config_get", "section": "guards" }
{ "cmd": "config_set", "section": "guards", "data": {...} }
{ "cmd": "config_version" }                  /* → current version */
{ "cmd": "config_history", "limit": 10 }     /* → last 10 versions */
{ "cmd": "config_rollback", "version": 41 }  /* → rollback to v41 */
{ "cmd": "config_diff", "from": 40, "to": 42 }
```

**Remote Config Endpoint**:
```
POST /api/v1/config/push
  Headers: Content-Type: application/json
           X-Config-Version: 42
  Body: { "guards": {...}, "policies": {...}, ... }
  Response: { "status": "applied", "version": 42 }

GET /api/v1/config/current
  Response: { "version": 42, "guards": {...}, ... }
```

### 4.3 collectord — Data Collector Daemon

**Responsibilities**:
- Receive events from sniffd via IPC
- Deduplicate and rate-limit events
- Write structured events to SQLite database
- Maintain rotating log files
- Export data in JSON format for uploadd

**Interface**:
```c
/* collectord command-line interface */
collectord [options]
  -c, --config <path>     Config file
  -d, --daemon
  -p, --pidfile <path>
  --db <path>             SQLite database path (default: /var/lib/jz/jz.db)
  --max-db-size <MB>      Max database size before rotation (default: 512)

/* collectord IPC socket protocol (/var/run/jz/collectord.sock) */
{ "cmd": "event", "data": { <jz_event_hdr fields> } }  /* receive event */
{ "cmd": "query", "type": "attack_log",                 /* query logs */
  "filter": { "since": "2026-03-01", "limit": 100 } }
{ "cmd": "stats" }                                       /* collection stats */
{ "cmd": "export", "format": "json",                    /* export data */
  "since": "2026-03-01", "until": "2026-03-12" }
```

### 4.4 uploadd — Upload Agent Daemon

**Responsibilities**:
- Poll collectord for new data batches
- Compress data (gzip/zstd)
- Upload to management platform via HTTPS
- Handle retry with exponential backoff
- Track upload state (last successful upload timestamp)

**Interface**:
```c
/* uploadd command-line interface */
uploadd [options]
  -c, --config <path>
  -d, --daemon
  --platform-url <URL>    Management platform API URL
  --batch-size <N>        Events per upload batch (default: 1000)
  --interval <seconds>    Upload interval (default: 60)
  --tls-cert <path>       Client certificate for platform auth
  --tls-key <path>        Client private key

/* uploadd IPC socket protocol (/var/run/jz/uploadd.sock) */
{ "cmd": "status" }                      /* → upload stats, queue depth */
{ "cmd": "force_upload" }                /* → trigger immediate upload */
{ "cmd": "set_platform", "url": "..." }  /* → change platform URL */
```

### 4.5 CLI Tools

#### jzctl — Main Management CLI

```
jzctl status                          # System status overview
jzctl module list                     # List loaded BPF modules
jzctl module reload <name>            # Reload a specific module
jzctl stats [--reset]                 # Show/reset statistics
jzctl config show                     # Show current configuration
jzctl config reload                   # Trigger config reload
jzctl config rollback <version>       # Rollback to config version
jzctl daemon restart <name>           # Restart a daemon
```

#### jzguard — Guard Management CLI

```
jzguard list [--type static|dynamic|whitelist]
jzguard add static --ip 10.0.1.50 [--mac aa:bb:cc:dd:ee:01] [--vlan 100]
jzguard add dynamic --ip 10.0.1.60
jzguard del static --ip 10.0.1.50
jzguard whitelist add --ip 10.0.1.1 --mac 00:11:22:33:44:55
jzguard whitelist del --ip 10.0.1.1
jzguard probe start                  # Start sniffer detection probing
jzguard probe stop
jzguard probe results                # Show detected sniffers
```

#### jzlog — Log Viewer CLI

```
jzlog attack [--since 2026-03-01] [--limit 100] [--format json|table]
jzlog sniffer                         # Show detected sniffers
jzlog background [--proto arp|dhcp|mdns|lldp]
jzlog audit [--since 2026-03-01]      # Admin action audit log
jzlog threat [--level high|critical]
jzlog tail [-f]                       # Follow live events
```

### 4.6 Management REST API

Built into sniffd using the Mongoose HTTP library, listening on port 8443 (HTTPS) by default.

```
Base URL: https://<device-ip>:8443/api/v1

Authentication: Bearer token (JWT) or client certificate

Endpoints:

GET    /api/v1/status                     # System status
GET    /api/v1/modules                    # BPF module status
POST   /api/v1/modules/{name}/reload      # Reload module

GET    /api/v1/guards                     # List all guards
GET    /api/v1/guards/static              # List static guards
POST   /api/v1/guards/static              # Add static guard
DELETE /api/v1/guards/static/{ip}         # Remove static guard
GET    /api/v1/guards/dynamic             # List dynamic guards
DELETE /api/v1/guards/dynamic/{ip}        # Remove dynamic guard

GET    /api/v1/whitelist                  # List whitelist
POST   /api/v1/whitelist                  # Add whitelist entry
DELETE /api/v1/whitelist/{ip}             # Remove whitelist entry

GET    /api/v1/policies                   # List flow policies
POST   /api/v1/policies                   # Add flow policy
PUT    /api/v1/policies/{id}              # Update flow policy
DELETE /api/v1/policies/{id}              # Remove flow policy

GET    /api/v1/logs/attacks               # Query attack logs
GET    /api/v1/logs/sniffers              # Detected sniffers
GET    /api/v1/logs/background            # Background captures
GET    /api/v1/logs/threats               # Threat detections
GET    /api/v1/logs/audit                 # Audit log

GET    /api/v1/stats                      # All statistics
GET    /api/v1/stats/guards               # Guard hit stats
GET    /api/v1/stats/traffic              # Traffic stats
GET    /api/v1/stats/threats              # Threat stats
GET    /api/v1/stats/background           # Background capture stats

GET    /api/v1/config                     # Current config
POST   /api/v1/config                     # Push new config
GET    /api/v1/config/history             # Config version history
POST   /api/v1/config/rollback            # Rollback to version

GET    /api/v1/health                     # Health check (for load balancer)
```

---

## 5. Data Model (数据模型)

### 5.1 BPF Map Summary

| Map Name | Type | Key | Value | Max Entries | Pin Path |
|---|---|---|---|---|---|
| jz_static_guards | HASH | __u32 (IP) | jz_guard_entry | 4096 | /sys/fs/bpf/jz/ |
| jz_dynamic_guards | LRU_HASH | __u32 (IP) | jz_guard_entry | 16384 | /sys/fs/bpf/jz/ |
| jz_whitelist | HASH | __u32 (IP) | jz_whitelist_entry | 4096 | /sys/fs/bpf/jz/ |
| jz_guard_result | PERCPU_ARRAY | __u32 | jz_guard_result | 1 | (not pinned) |
| jz_arp_config | ARRAY | __u32 | jz_arp_config | 1 | /sys/fs/bpf/jz/ |
| jz_fake_mac_pool | ARRAY | __u32 | jz_fake_mac | 256 | /sys/fs/bpf/jz/ |
| jz_arp_rate | PERCPU_ARRAY | __u32 | jz_rate_state | 1 | (not pinned) |
| jz_icmp_config | ARRAY | __u32 | jz_icmp_config | 1 | /sys/fs/bpf/jz/ |
| jz_probe_targets | HASH | __u32 (IP) | jz_probe_target | 1024 | /sys/fs/bpf/jz/ |
| jz_sniffer_suspects | HASH | __u64 (MAC) | jz_sniffer_suspect | 1024 | /sys/fs/bpf/jz/ |
| jz_flow_policy | HASH | jz_flow_key | jz_flow_policy | 8192 | /sys/fs/bpf/jz/ |
| jz_redirect_config | ARRAY | __u32 | jz_redirect_config | 1 | /sys/fs/bpf/jz/ |
| jz_flow_stats | PERCPU_HASH | jz_flow_key | jz_flow_stats | 8192 | (not pinned) |
| jz_bg_filter | HASH | __u32 | jz_bg_filter_entry | 64 | /sys/fs/bpf/jz/ |
| jz_bg_stats | PERCPU_ARRAY | __u32 | jz_bg_stats | 1 | /sys/fs/bpf/jz/ |
| jz_threat_patterns | HASH | __u32 | jz_threat_pattern | 2048 | /sys/fs/bpf/jz/ |
| jz_threat_blacklist | LRU_HASH | __u32 (IP) | __u64 | 65536 | /sys/fs/bpf/jz/ |
| jz_threat_stats | PERCPU_ARRAY | __u32 | jz_threat_stats | 1 | /sys/fs/bpf/jz/ |
| jz_sample_config | ARRAY | __u32 | jz_sample_config | 1 | /sys/fs/bpf/jz/ |
| jz_sample_ringbuf | RINGBUF | — | — | 4MB | /sys/fs/bpf/jz/ |

**Total: 20 custom BPF maps + references to rSwitch shared maps (rs_progs, rs_ctx_map, rs_event_bus, rs_mac_table, rs_stats_map)**

### 5.2 SQLite Database Schema

**Database file**: `/var/lib/jz/jz.db`

```sql
-- Attack log — records every honeypot interaction
CREATE TABLE attack_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      INTEGER NOT NULL,       -- JZ_EVENT_ATTACK_ARP, _ICMP, etc.
    timestamp       TEXT NOT NULL,           -- ISO 8601
    timestamp_ns    INTEGER NOT NULL,        -- nanosecond precision
    src_ip          TEXT NOT NULL,
    src_mac         TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,           -- the guarded IP
    dst_mac         TEXT,                    -- fake MAC used in response
    guard_type      TEXT NOT NULL,           -- 'static' or 'dynamic'
    protocol        TEXT NOT NULL,           -- 'arp', 'icmp', 'tcp', 'udp'
    ifindex         INTEGER NOT NULL,
    threat_level    INTEGER DEFAULT 0,
    packet_sample   BLOB,                   -- optional raw packet bytes
    details         TEXT,                   -- JSON with extra details
    uploaded        INTEGER DEFAULT 0,      -- 0=pending, 1=uploaded
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_attack_log_timestamp ON attack_log(timestamp);
CREATE INDEX idx_attack_log_src_ip ON attack_log(src_ip);
CREATE INDEX idx_attack_log_uploaded ON attack_log(uploaded);

-- Sniffer detection log
CREATE TABLE sniffer_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL,
    ip              TEXT,
    ifindex         INTEGER NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    response_count  INTEGER NOT NULL,
    probe_ip        TEXT NOT NULL,           -- the non-existent IP that was probed
    uploaded        INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_sniffer_log_mac ON sniffer_log(mac);

-- Background capture summary (aggregated, not per-packet)
CREATE TABLE bg_capture (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start    TEXT NOT NULL,           -- aggregation period start
    period_end      TEXT NOT NULL,
    protocol        TEXT NOT NULL,           -- 'arp', 'dhcp', 'mdns', 'lldp', etc.
    packet_count    INTEGER NOT NULL,
    byte_count      INTEGER NOT NULL,
    unique_sources  INTEGER NOT NULL,        -- distinct source MACs
    sample_data     TEXT,                   -- JSON array of sample entries
    uploaded        INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_bg_capture_period ON bg_capture(period_start);
CREATE INDEX idx_bg_capture_protocol ON bg_capture(protocol);

-- Configuration version history
CREATE TABLE config_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL UNIQUE,
    config_data     TEXT NOT NULL,           -- full YAML config as text
    source          TEXT NOT NULL,           -- 'local', 'remote', 'cli'
    applied_at      TEXT NOT NULL,
    applied_by      TEXT,                   -- user or system
    rollback_from   INTEGER,                -- if this was a rollback, from which version
    status          TEXT DEFAULT 'applied',  -- 'applied', 'rolled_back', 'failed'
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_config_history_version ON config_history(version);

-- Audit trail — all administrative actions
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    action          TEXT NOT NULL,           -- 'guard_add', 'config_push', 'rollback', etc.
    actor           TEXT NOT NULL,           -- 'cli:admin', 'api:token:xyz', 'system'
    target          TEXT,                   -- what was affected
    details         TEXT,                   -- JSON details
    result          TEXT NOT NULL,           -- 'success', 'failure'
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_action ON audit_log(action);

-- System state — persistent key-value store for daemon state
CREATE TABLE system_state (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT DEFAULT (datetime('now'))
);
```

### 5.3 Event Types and Formats

```c
/* Event structures emitted to rs_event_bus ring buffer */

/* Attack event (ARP/ICMP honeypot triggered) */
struct jz_event_attack {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_ATTACK_ARP or _ICMP */
    __u8  guard_type;           /* static or dynamic */
    __u8  protocol;             /* ARP=1, ICMP=2 */
    __u8  fake_mac[6];          /* MAC used in honeypot response */
    __u32 guarded_ip;           /* the guard IP that was triggered */
};

/* Sniffer detected event */
struct jz_event_sniffer {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_SNIFFER_DETECTED */
    __u8  suspect_mac[6];
    __u16 _pad;
    __u32 suspect_ip;
    __u32 probe_ip;             /* the non-existent IP that was probed */
    __u32 response_count;
};

/* Policy match event */
struct jz_event_policy {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_POLICY_MATCH */
    __u8  action;               /* JZ_ACTION_* */
    __u8  _pad[3];
    __u32 policy_id;
    struct jz_flow_key flow;
};

/* Threat detected event */
struct jz_event_threat {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_THREAT_DETECTED */
    __u32 pattern_id;
    __u8  threat_level;
    __u8  action_taken;         /* log-only, drop, redirect */
    __u16 _pad;
    char  description[32];
};

/* Background capture event */
struct jz_event_bg {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_BG_CAPTURE */
    __u8  bg_proto;             /* internal protocol classification */
    __u8  _pad[3];
    __u32 payload_len;          /* actual payload captured */
    __u8  payload[128];         /* first 128 bytes of packet */
};

/* Forensic sample event (emitted to jz_sample_ringbuf, not rs_event_bus) */
struct jz_event_sample {
    struct jz_event_hdr hdr;
    __u8  threat_level;
    __u8  _pad[3];
    __u32 payload_len;
    __u8  payload[];            /* variable-length payload (up to 512B) */
};
```

### 5.4 JSON Export Format

```json
{
  "device_id": "jz-sniff-001",
  "export_version": 1,
  "export_timestamp": "2026-03-12T10:30:00Z",
  "data": {
    "attacks": [
      {
        "id": 1234,
        "event_type": "ATTACK_ARP",
        "timestamp": "2026-03-12T10:15:32.123456789Z",
        "src_ip": "10.0.1.100",
        "src_mac": "aa:bb:cc:11:22:33",
        "guarded_ip": "10.0.1.50",
        "fake_mac": "aa:bb:cc:dd:ee:01",
        "guard_type": "static",
        "protocol": "arp",
        "interface": "eth0",
        "threat_level": 2
      }
    ],
    "sniffers": [...],
    "threats": [...],
    "background": {
      "period": { "start": "...", "end": "..." },
      "arp": { "count": 1234, "unique_sources": 15 },
      "dhcp": { "count": 56, "unique_sources": 8 },
      "mdns": { "count": 789, "unique_sources": 12 }
    }
  }
}
```

---

## 6. Configuration System (配置系统)

### 6.1 YAML Profile Hierarchy

```
/etc/jz/
├── base.yaml           # Default base profile (shipped with package)
├── device.yaml         # Device-specific overrides (user-edited)
├── runtime/            # Runtime overrides (applied by configd)
│   ├── guards.yaml
│   ├── policies.yaml
│   └── bg_filters.yaml
└── profiles/           # Named profiles for quick switching
    ├── aggressive.yaml
    ├── passive.yaml
    └── monitor-only.yaml
```

**Merge order**: `base.yaml` ← `device.yaml` ← `runtime/*.yaml` ← remote push

### 6.2 Base Profile Schema

```yaml
# /etc/jz/base.yaml — Base configuration profile
---
version: 1

system:
  device_id: "jz-sniff-001"
  log_level: "info"                  # debug, info, warn, error
  data_dir: "/var/lib/jz"
  run_dir: "/var/run/jz"

modules:
  guard_classifier:
    enabled: true
    stage: 22
  arp_honeypot:
    enabled: true
    stage: 23
    rate_limit_pps: 100
    log_all: false
  icmp_honeypot:
    enabled: true
    stage: 24
    ttl: 64                          # Emulate Linux
    rate_limit_pps: 100
  sniffer_detect:
    enabled: true
    stage: 25
    probe_interval_sec: 30
    probe_count: 5                   # Number of probe IPs per cycle
  traffic_weaver:
    enabled: true
    stage: 35
    default_action: "pass"
  bg_collector:
    enabled: true
    stage: 40
    sample_rate: 1                   # 1 = every packet
    protocols:
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
    stage: 50
  forensics:
    enabled: true
    stage: 55
    max_payload_bytes: 256
    sample_rate: 0                   # 0 = only sample flagged packets

guards:
  static: []
  #  - ip: "10.0.1.50"
  #    mac: "aa:bb:cc:dd:ee:01"     # Optional, use pool if omitted
  #    vlan: 0                       # 0 = all VLANs

  dynamic:
    auto_discover: false
    max_entries: 16384
    ttl_hours: 24                    # Auto-expire after 24h

  whitelist: []
  #  - ip: "10.0.1.1"
  #    mac: "00:11:22:33:44:55"
  #    match_mac: true

fake_mac_pool:
  prefix: "aa:bb:cc"                # OUI prefix for fake MACs
  count: 64                          # Number of fake MACs to generate

policies: []
  # - src_ip: "0.0.0.0"              # 0.0.0.0 = wildcard
  #   dst_ip: "10.0.1.50"
  #   src_port: 0                     # 0 = wildcard
  #   dst_port: 22
  #   proto: "tcp"
  #   action: "redirect"
  #   redirect_port: 8               # Interface index
  #   mirror_port: 0

threats:
  blacklist_file: "/etc/jz/blacklist.txt"  # One IP per line
  patterns: []
  #  - id: 1
  #    dst_port: 445
  #    proto: "tcp"
  #    threat_level: "high"
  #    action: "log_drop"
  #    description: "SMB exploit attempt"

collector:
  db_path: "/var/lib/jz/jz.db"
  max_db_size_mb: 512
  dedup_window_sec: 10
  rate_limit_eps: 1000               # Max events per second

uploader:
  enabled: false
  platform_url: ""
  interval_sec: 60
  batch_size: 1000
  tls_cert: ""
  tls_key: ""
  compress: true                     # gzip compression

api:
  enabled: true
  listen: "0.0.0.0:8443"
  tls_cert: "/etc/jz/tls/server.crt"
  tls_key: "/etc/jz/tls/server.key"
  auth_tokens:
    - token: ""                      # Generated on first boot
      role: "admin"
```

### 6.3 Remote Configuration Protocol

```
Platform → Device:
  POST https://<device>:8443/api/v1/config
  Headers:
    Content-Type: application/json
    Authorization: Bearer <platform-token>
    X-Config-Version: <monotonic version number>
  Body:
    {
      "version": 42,
      "timestamp": "2026-03-12T10:00:00Z",
      "sections": ["guards", "policies", "threats"],
      "guards": {
        "static": [
          { "ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:01", "vlan": 0 }
        ],
        "whitelist": [
          { "ip": "10.0.1.1", "mac": "00:11:22:33:44:55" }
        ]
      },
      "policies": [...],
      "threats": { "blacklist": [...], "patterns": [...] }
    }

Device → Platform:
  Response:
    {
      "status": "applied",     // or "rejected", "partial"
      "version": 42,
      "applied_sections": ["guards", "policies", "threats"],
      "errors": []             // empty if all succeeded
    }
```

### 6.4 Hot-Reload Sequence

```
1. configd receives new config (file change or remote push)
2. Parse and validate schema (reject on error)
3. Diff against current config (identify changed sections)
4. Save current config to config_history (rollback point)
5. For each changed section:
   a. Build new map entries from config
   b. Apply to BPF maps atomically:
      - For HASH maps: delete removed entries, update/add new entries
      - For ARRAY maps: overwrite entire value
   c. Verify map contents match config (read-back check)
6. If any step fails:
   a. Attempt rollback (restore previous map state)
   b. Log failure in audit_log
   c. Return error to caller
7. On success:
   a. Update version counter in system_state
   b. Write YAML file to disk (for persistence across restarts)
   c. Log in audit_log
   d. Notify sniffd via IPC (for in-memory state refresh)
   e. Return success to caller
```

---

## 7. Security Design (安全设计)

### 7.1 Authentication

| Interface | Auth Method | Details |
|---|---|---|
| REST API | Bearer token (JWT) | Tokens generated by jzctl, stored in config |
| REST API | Client certificate | mTLS with platform CA |
| Remote config | Mutual TLS | Device cert + platform CA |
| CLI tools | Unix socket permissions | Root or `jz` group only |
| IPC (inter-daemon) | Unix socket + PID verification | `/var/run/jz/*.sock` owned by `jz` user |

### 7.2 Authorization (RBAC)

Three roles (simplified from JZZN's 280+ permissions):

| Role | Capabilities |
|---|---|
| admin | Full access: config changes, guard management, log access, system control |
| operator | Guard management, log access, statistics. No config changes. |
| viewer | Read-only: log access, statistics, status queries |

### 7.3 Secure Configuration Delivery

- All remote config uses TLS 1.3
- Device authenticates platform via CA-signed certificate
- Platform authenticates device via client certificate
- Config payloads include HMAC signature for integrity
- Config version is monotonically increasing (reject stale/replayed configs)

### 7.4 Audit Logging

All administrative actions are logged to `audit_log` table:
- Guard additions/removals
- Config changes (with before/after diff)
- Config rollbacks
- Module reloads
- Daemon restarts
- Authentication failures
- API access (read and write operations)

### 7.5 Data Protection

- SQLite database: file permissions 0600, owned by `jz` user
- TLS certificates: file permissions 0600, directory permissions 0700
- BPF maps: kernel memory, not directly accessible from user-space except via bpf syscall (requires CAP_BPF)
- Config files: file permissions 0640, owned by `root:jz`
- Upload data: encrypted in transit (TLS), compressed (gzip/zstd)

---

## 8. Deployment Architecture (部署架构)

### 8.1 Single Device Standalone Mode

```
                    ┌─────────────────────┐
                    │   Admin Workstation  │
                    │   (jzctl / browser)  │
                    └──────────┬──────────┘
                               │ SSH / HTTPS
                               │
┌──────────────────────────────┼──────────────────────────────┐
│  jz_sniff_rn Device          │                               │
│  (Standalone Mode)           │                               │
│                              │                               │
│  ┌────────┐  ┌────────┐  ┌──┴─────┐  ┌────────┐           │
│  │ sniffd │  │configd │  │REST API│  │uploadd │ (disabled) │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
│                                                              │
│  ┌──────────────────────────────────────────────┐           │
│  │         Network Interfaces                    │           │
│  │  eth0 (mgmt)   eth1..N (monitored ports)     │           │
│  └──────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────┘
```

- Config managed locally via `jzctl` / `jzguard` CLI
- REST API available for local browser access
- uploadd disabled (no platform to upload to)
- SQLite stores all data locally

### 8.2 Multi-Device Managed Mode

```
┌──────────────────────────────────────────────────────────────┐
│                 Management Platform (管理平台)                 │
│                                                               │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐     │
│  │  Config    │  │  Log         │  │  Dashboard /      │     │
│  │  Manager   │  │  Aggregator  │  │  Analytics        │     │
│  └──────┬─────┘  └──────┬───────┘  └──────────────────┘     │
│         │               │                                     │
└─────────┼───────────────┼─────────────────────────────────────┘
          │               │
          │ Config Push   │ Log Upload
          │ (HTTPS)       │ (HTTPS)
          │               │
    ┌─────┼───────────────┼─────┐
    │     │               │     │
    ▼     ▼               ▼     ▼
┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
│Dev 1 │ │Dev 2 │ │Dev 3 │ │Dev N │
│      │ │      │ │      │ │      │
│sniffd│ │sniffd│ │sniffd│ │sniffd│
│confgd│ │confgd│ │confgd│ │confgd│
│colctd│ │colctd│ │colctd│ │colctd│
│upldd │ │upldd │ │upldd │ │upldd │
└──────┘ └──────┘ └──────┘ └──────┘
```

- Platform pushes config to all devices
- Each device uploads logs/events to platform
- Devices operate independently if platform is unreachable (local buffering)
- Platform provides centralized dashboard, analytics, alerting

### 8.3 Network Topology — Inline Mode

```
    ┌──────────┐                          ┌──────────┐
    │  Switch  │                          │  Switch  │
    │  (上游)   │                          │  (下游)   │
    └────┬─────┘                          └────┬─────┘
         │ eth1                           eth2 │
         │                                     │
    ┌────┴─────────────────────────────────────┴────┐
    │              jz_sniff_rn Device                │
    │                                                │
    │  eth1 (ingress) ──▶ XDP Pipeline ──▶ eth2      │
    │                        │                       │
    │                   ┌────┴────┐                  │
    │                   │ guard   │                  │
    │                   │ check   │                  │
    │                   └────┬────┘                  │
    │                        │                       │
    │              ┌─────────┼─────────┐             │
    │              │ REDIRECT│ MIRROR  │             │
    │              ▼         ▼         │             │
    │           eth3      eth4         │             │
    │         (honeypot) (analyzer)    │             │
    │              │         │         │             │
    │  eth0 (mgmt) │         │         │             │
    └──────────────┘─────────┘─────────┘─────────────┘
```

### 8.4 Installation and Provisioning

```
1. Install base OS (Linux 5.8+ with BTF support)
2. Install rSwitch package (provides BPF pipeline, loader, mgmtd)
3. Install jz_sniff_rn package:
   a. BPF modules → /usr/lib/jz/bpf/
   b. Daemons → /usr/sbin/ (sniffd, configd, collectord, uploadd)
   c. CLI tools → /usr/bin/ (jzctl, jzguard, jzlog)
   d. Config → /etc/jz/ (base.yaml, TLS certs)
   e. Systemd units → /etc/systemd/system/
   f. Data directory → /var/lib/jz/
4. First-boot provisioning:
   a. Generate device ID
   b. Generate API auth token
   c. Generate self-signed TLS cert (or provision from platform)
   d. Initialize SQLite database
   e. Start daemons: sniffd → configd → collectord → uploadd
```

---

## 9. Performance Targets (性能目标)

### 9.1 Throughput

| Metric | Target | Measurement |
|---|---|---|
| Base rSwitch throughput | 10+ Gbps per core | pktgen 64B packets |
| jz overhead (all modules enabled) | <10% reduction | <1 Gbps loss at 10 Gbps |
| Guard classification lookup | <100ns per packet | BPF hash map lookup |
| ARP honeypot response | <500ns total | Parse + craft + TX |
| Max events per second | 100,000 eps | Ring buffer throughput |

### 9.2 Latency

| Operation | Budget | Notes |
|---|---|---|
| Guard classification | <200ns | Hash map lookup |
| ARP honeypot response | <1μs | Including XDP_TX |
| ICMP honeypot response | <1μs | Including checksum recalc |
| Traffic weaver decision | <300ns | Flow policy lookup |
| Background collector | <100ns | Simple ethertype/port check |
| Threat detection | <500ns | Pattern scan |
| Forensic sampling | <200ns | When not sampling; <1μs when sampling |
| Total pipeline (all jz modules) | <3μs added | Cumulative budget |

### 9.3 Memory

| Resource | Budget | Notes |
|---|---|---|
| BPF map memory (total) | <64 MB | All 20 custom maps |
| Ring buffer (event bus) | 16 MB | Shared with rSwitch |
| Ring buffer (forensics) | 4 MB | Dedicated |
| sniffd RSS | <64 MB | Including libbpf overhead |
| configd RSS | <32 MB | YAML parsing, TLS |
| collectord RSS | <32 MB | SQLite, event buffering |
| uploadd RSS | <16 MB | HTTP client, compression |
| Total daemon RSS | <144 MB | All 4 daemons |

### 9.4 Storage

| Resource | Budget | Notes |
|---|---|---|
| SQLite database | <1 GB | With rotation |
| Config files | <10 MB | YAML + history |
| BPF object files | <5 MB | 8 modules |
| Log files | <500 MB | Rotated daily |
| Total disk | <2 GB | All persistent data |

### 9.5 Startup

| Operation | Target | Notes |
|---|---|---|
| Cold start (all daemons) | <5s | Including BPF module load |
| Config hot-reload | <100ms | BPF map update + verify |
| Module reload (single) | <500ms | Unload + reload one BPF module |
| Database query (100 rows) | <50ms | SQLite indexed query |

---

## 10. TDD Strategy & Atomic Commit Plan

### 10.1 Test Pyramid

```
                    ┌─────────┐
                    │ System  │  ← 5-10 tests: Full device integration
                    │  Tests  │    (requires hardware or VM)
                    ├─────────┤
                  ┌─┤Integr.  ├─┐  ← 20-30 tests: Multi-component
                  │ │  Tests  │ │    (BPF + daemon interaction)
                  │ ├─────────┤ │
                ┌─┤ │  Unit   │ ├─┐  ← 100+ tests: Individual functions
                │ │ │  Tests  │ │ │    (BPF map logic, daemon handlers)
                │ │ ├─────────┤ │ │
                │ │ │  Build  │ │ │  ← Compile checks, static analysis
                │ │ │ Checks  │ │ │    (clang-tidy, sparse, verifier)
                └─┴─┴─────────┴─┴─┘
```

### 10.2 Test Tooling

| Layer | Tool | Purpose |
|---|---|---|
| BPF unit tests | `bpf_prog_test_run_opts()` | Run BPF programs with synthetic packets |
| BPF verifier | clang + kernel verifier | Verify BPF programs pass verifier |
| C unit tests | cmocka | Unit test daemon logic (parsers, IPC, DB) |
| Integration tests | Python + scapy | Send real packets, verify behavior |
| API tests | Python + requests | REST API endpoint testing |
| Performance | pktgen + bpftool | Throughput and latency benchmarks |
| Static analysis | clang-tidy, sparse | Code quality, potential bugs |

### 10.3 Atomic Commit Convention

```
Commit message format:
  <type>(<scope>): <description>

  [optional body]

  [optional footer: Refs #<story-id>]

Types:
  feat     — New feature (maps to a user story)
  test     — Add or update tests (TDD: test-first commits)
  fix      — Bug fix
  refactor — Code restructuring without behavior change
  docs     — Documentation only
  build    — Build system, CI, dependencies
  chore    — Maintenance (formatting, tooling config)

Scopes:
  bpf/guard    — guard_classifier module
  bpf/arp      — arp_honeypot module
  bpf/icmp     — icmp_honeypot module
  bpf/sniffer  — sniffer_detect module
  bpf/weaver   — traffic_weaver module
  bpf/bgcol    — bg_collector module
  bpf/threat   — threat_detect module
  bpf/forensic — forensics module
  bpf/common   — shared headers, common maps
  sniffd       — sniffd daemon
  configd      — configd daemon
  collectord   — collectord daemon
  uploadd      — uploadd daemon
  cli          — CLI tools
  api          — REST API
  db           — SQLite schema and queries
  config       — YAML config system
  build        — Build system
  test         — Test infrastructure

Examples:
  test(bpf/guard): add unit tests for static guard lookup
  feat(bpf/guard): implement static guard hash map lookup
  feat(bpf/guard): integrate guard_classifier into pipeline at stage 22
  test(bpf/arp): add tests for ARP reply crafting
  feat(bpf/arp): implement ARP honeypot response generation
  fix(bpf/arp): correct checksum calculation for ARP replies
```

### 10.4 TDD Commit Sequence Per Story

Each user story follows a 3-commit TDD cycle:

```
Story: S2.1 Guard classifier — static guard lookup

Commit 1 (RED):
  test(bpf/guard): add unit tests for static guard lookup
  - Test: packet to guarded IP → guard_result set to STATIC
  - Test: packet to non-guarded IP → guard_result set to NONE
  - Test: empty guard map → all packets pass through
  - Tests fail (module not implemented yet)

Commit 2 (GREEN):
  feat(bpf/guard): implement static guard hash map lookup
  - Implement jz_guard_classifier BPF program
  - Define jz_static_guards map
  - Lookup logic with rs_ctx integration
  - All tests from Commit 1 now pass

Commit 3 (INTEGRATE):
  feat(bpf/guard): integrate guard_classifier into pipeline at stage 22
  - RS_DECLARE_MODULE with stage 22
  - Tail call to stage 23/24/30 based on result
  - Add to build system
  - Integration test: send ARP to guarded IP, verify classification
```

### 10.5 CI Pipeline

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  Build   │──▶│  Verify  │──▶│  Unit    │──▶│  Integ.  │──▶│  Perf    │
│          │   │          │   │  Test    │   │  Test    │   │  Bench   │
│ clang    │   │ BPF      │   │ cmocka + │   │ Python + │   │ pktgen   │
│ compile  │   │ verifier │   │ prog_run │   │ scapy    │   │ (nightly)│
│ all mods │   │ check    │   │          │   │          │   │          │
└──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
```

### 10.6 Directory Structure

```
jz_sniff_rn/
├── design.md                    # This document
├── backlog.md                   # Product backlog
├── Makefile                     # Top-level build
├── bpf/                         # BPF modules (kernel-space)
│   ├── Makefile
│   ├── include/
│   │   ├── jz_common.h          # Shared definitions
│   │   ├── jz_maps.h            # All map declarations
│   │   └── jz_events.h          # Event type definitions
│   ├── jz_guard_classifier.bpf.c
│   ├── jz_arp_honeypot.bpf.c
│   ├── jz_icmp_honeypot.bpf.c
│   ├── jz_sniffer_detect.bpf.c
│   ├── jz_traffic_weaver.bpf.c
│   ├── jz_bg_collector.bpf.c
│   ├── jz_threat_detect.bpf.c
│   └── jz_forensics.bpf.c
├── src/                         # User-space daemons and libs
│   ├── common/                  # Shared daemon code
│   │   ├── ipc.c / ipc.h        # Unix domain socket IPC
│   │   ├── config.c / config.h  # YAML config parser
│   │   ├── db.c / db.h          # SQLite wrapper
│   │   ├── log.c / log.h        # Logging
│   │   └── util.c / util.h      # Utilities
│   ├── sniffd/
│   │   ├── main.c
│   │   ├── bpf_loader.c / .h    # BPF module lifecycle
│   │   ├── ringbuf.c / .h       # Ring buffer consumer
│   │   ├── probe.c / .h         # ARP probe generator
│   │   └── guard_mgr.c / .h     # Guard table manager
│   ├── configd/
│   │   ├── main.c
│   │   ├── watcher.c / .h       # inotify file watcher
│   │   ├── remote.c / .h        # TLS config receiver
│   │   ├── applier.c / .h       # Config-to-BPF-map applier
│   │   └── versioning.c / .h    # Version history
│   ├── collectord/
│   │   ├── main.c
│   │   ├── aggregator.c / .h    # Event aggregation
│   │   ├── dedup.c / .h         # Deduplication
│   │   └── exporter.c / .h      # JSON export
│   └── uploadd/
│       ├── main.c
│       ├── batcher.c / .h       # Batch assembly
│       ├── sender.c / .h        # HTTPS upload
│       └── retry.c / .h         # Retry logic
├── cli/                         # CLI tools
│   ├── jzctl.c
│   ├── jzguard.c
│   └── jzlog.c
├── config/                      # Default config files
│   ├── base.yaml
│   └── profiles/
├── systemd/                     # Systemd service files
│   ├── sniffd.service
│   ├── configd.service
│   ├── collectord.service
│   └── uploadd.service
├── tests/                       # All tests
│   ├── bpf/                     # BPF unit tests
│   │   ├── test_guard_classifier.c
│   │   ├── test_arp_honeypot.c
│   │   ├── test_icmp_honeypot.c
│   │   ├── test_sniffer_detect.c
│   │   ├── test_traffic_weaver.c
│   │   ├── test_bg_collector.c
│   │   ├── test_threat_detect.c
│   │   └── test_forensics.c
│   ├── unit/                    # C unit tests (cmocka)
│   │   ├── test_config_parser.c
│   │   ├── test_ipc.c
│   │   ├── test_db.c
│   │   └── test_dedup.c
│   ├── integration/             # Integration tests (Python)
│   │   ├── conftest.py
│   │   ├── test_arp_honeypot.py
│   │   ├── test_guard_workflow.py
│   │   ├── test_traffic_weaver.py
│   │   ├── test_api.py
│   │   └── test_config_reload.py
│   └── perf/                    # Performance benchmarks
│       ├── bench_guard_lookup.c
│       └── bench_pipeline.sh
├── scripts/                     # Build and deploy scripts
│   ├── install.sh
│   ├── gen_vmlinux.sh
│   └── gen_fake_macs.py
└── third_party/                 # Vendored dependencies
    ├── mongoose/                # HTTP server
    ├── cjson/                   # JSON parser
    └── libyaml/                 # YAML parser
```

---

*End of Design Document*
