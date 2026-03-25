# jz_sniff_rn (嗅探重生) — Product Backlog

> Version: 1.0.0-draft
> Date: 2026-03-12
> Total Stories: 67
> Total Epics: 10

---

## Table of Contents

- [Epic E1: Platform Foundation (平台基础)](#epic-e1-platform-foundation-平台基础)
- [Epic E2: Dynamic Trapping Engine (动态诱捕引擎)](#epic-e2-dynamic-trapping-engine-动态诱捕引擎)
- [Epic E3: Traffic Weaving Engine (流量编织引擎)](#epic-e3-traffic-weaving-engine-流量编织引擎)
- [Epic E4: Data Collation Engine (数据整理引擎)](#epic-e4-data-collation-engine-数据整理引擎)
- [Epic E5: Configuration Management (配置管理系统)](#epic-e5-configuration-management-配置管理系统)
- [Epic E6: Background Collection Engine (背景收集引擎)](#epic-e6-background-collection-engine-背景收集引擎)
- [Epic E7: User-space Daemons (用户空间守护进程)](#epic-e7-user-space-daemons-用户空间守护进程)
- [Epic E8: Management Interface (管理接口)](#epic-e8-management-interface-管理接口)
- [Epic E9: Testing & Quality (测试与质量)](#epic-e9-testing--quality-测试与质量)
- [Epic E10: Deployment & Operations (部署与运维)](#epic-e10-deployment--operations-部署与运维)
- [Development Phase Map](#development-phase-map)
- [Priority Legend](#priority-legend)

---

## Priority Legend

| Priority | Meaning | Guidance |
|----------|---------|----------|
| **P0** | Must-have | Core functionality. System unusable without this. |
| **P1** | Should-have | Important feature. System functional but incomplete without this. |
| **P2** | Nice-to-have | Enhancement. Improves quality/usability but not essential. |
| **P3** | Future | Deferred. Planned for future iteration. |

## Complexity Legend

| Size | Effort | Typical Duration |
|------|--------|-----------------|
| **S** | Small | 1-2 days |
| **M** | Medium | 3-5 days |
| **L** | Large | 1-2 weeks |
| **XL** | Extra Large | 2-3 weeks |

---

## Epic E1: Platform Foundation (平台基础)

> Establish the project scaffold, build system, rSwitch integration, and shared infrastructure.
> This epic must be completed first — all other epics depend on it.

### S1.1: Project Scaffold and Build System

**Description**: As a developer, I want a well-organized project directory structure with a working Makefile, so that I can build all BPF modules and user-space components with a single command.

**Acceptance Criteria**:
- [ ] Directory structure matches design.md Section 10.6
- [ ] `make all` compiles BPF modules (clang -target bpf) and user-space programs (gcc/clang)
- [ ] `make clean` removes all build artifacts
- [ ] `make install` installs to correct system paths
- [ ] `.gitignore` covers build artifacts, editor files, and secrets
- [ ] `git init` with initial commit structure

**Priority**: P0 | **Complexity**: S | **Dependencies**: None

**TDD Commits**:
1. `build: initialize project scaffold with directory structure`
2. `build: add Makefile with BPF and user-space build targets`
3. `test(build): add CI build smoke test`

---

### S1.2: rSwitch SDK Integration

**Description**: As a developer, I want rSwitch headers and libbpf properly integrated into the build system, so that BPF modules can reference rSwitch shared maps and data structures.

**Acceptance Criteria**:
- [ ] rSwitch headers available in include path (rs_ctx, rs_layers, rs_port_config)
- [ ] libbpf linked correctly for user-space programs
- [ ] Shared map references compile without errors (rs_progs, rs_ctx_map, rs_event_bus, rs_mac_table, rs_stats_map)
- [ ] A skeleton BPF module compiles and passes the BPF verifier
- [ ] vmlinux.h generated from target kernel BTF (script provided)

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.1

**TDD Commits**:
1. `build: integrate rSwitch headers and libbpf into build system`
2. `test(bpf/common): verify skeleton module compiles and passes verifier`
3. `build: add vmlinux.h generation script for CO-RE`

---

### S1.3: CO-RE Build Infrastructure

**Description**: As a developer, I want CO-RE (Compile Once, Run Everywhere) support, so that BPF modules are portable across kernel versions 5.8+.

**Acceptance Criteria**:
- [ ] BPF modules compile with `-g -O2 -target bpf` and include BTF debug info
- [ ] vmlinux.h generation script works on target kernel
- [ ] BPF objects contain proper CO-RE relocations (verified via `bpftool btf dump`)
- [ ] Modules load correctly on at least 2 different kernel versions

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.2

**TDD Commits**:
1. `build: add CO-RE compile flags and BTF generation`
2. `test(build): verify BTF relocations in compiled BPF objects`

---

### S1.4: Shared Header Definitions (jz_common.h)

**Description**: As a developer, I want all shared constants, data structures, and map declarations in common headers, so that BPF modules and user-space programs share the same definitions.

**Acceptance Criteria**:
- [ ] `jz_common.h` defines all stage numbers, ctx offsets, guard types, flags, event types
- [ ] `jz_maps.h` declares all BPF map structs (key/value types)
- [ ] `jz_events.h` defines all event structures
- [ ] Headers compile cleanly in both BPF and user-space contexts
- [ ] All constants match design.md Section 3.1

**Priority**: P0 | **Complexity**: S | **Dependencies**: S1.2

**TDD Commits**:
1. `feat(bpf/common): add jz_common.h with stage numbers, constants, event types`
2. `feat(bpf/common): add jz_maps.h with all BPF map struct definitions`
3. `feat(bpf/common): add jz_events.h with event structure definitions`

---

### S1.5: BPF Module Skeleton Template

**Description**: As a developer, I want a working BPF module skeleton that follows rSwitch conventions, so that I can use it as a template for all 8 jz modules.

**Acceptance Criteria**:
- [ ] Skeleton uses RS_DECLARE_MODULE() macro with .rodata.mod section
- [ ] Skeleton includes tail-call chaining to next stage via rs_progs
- [ ] Skeleton reads from rs_ctx_map (per-CPU context)
- [ ] Skeleton emits events to rs_event_bus ring buffer
- [ ] Skeleton compiles, passes BPF verifier, and loads via libbpf

**Priority**: P0 | **Complexity**: S | **Dependencies**: S1.4

**TDD Commits**:
1. `test(bpf/common): add test for skeleton module load and tail-call`
2. `feat(bpf/common): implement BPF module skeleton with rSwitch conventions`

---

### S1.6: Base YAML Configuration Profile

**Description**: As a developer, I want a base YAML configuration file with sensible defaults, so that the system can start with a known-good configuration.

**Acceptance Criteria**:
- [ ] `base.yaml` matches design.md Section 6.2 schema
- [ ] All module enable/disable flags present with defaults
- [ ] Guard, policy, and threat sections present (empty by default)
- [ ] API, collector, and uploader sections with defaults
- [ ] File validates against a schema (tested by config parser)

**Priority**: P0 | **Complexity**: S | **Dependencies**: S1.1

**TDD Commits**:
1. `feat(config): add base.yaml with default configuration profile`

---

### S1.7: Unit Test Framework Setup

**Description**: As a developer, I want BPF test infrastructure (bpf_prog_test_run) and C unit test framework (cmocka) set up, so that I can write TDD-style tests for all components.

**Acceptance Criteria**:
- [ ] cmocka integrated into build system (`make test` runs all unit tests)
- [ ] BPF test harness using `bpf_prog_test_run_opts()` works for synthetic packet injection
- [ ] Example test for skeleton module passes
- [ ] Test output in TAP or JUnit format for CI integration
- [ ] Test coverage report generation (gcov/lcov)

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.5

**TDD Commits**:
1. `test(build): integrate cmocka unit test framework`
2. `test(bpf/common): add BPF prog_test_run harness with example test`
3. `build: add test coverage reporting with gcov/lcov`

---

### S1.8: SQLite Database Schema and Wrapper

**Description**: As a developer, I want the SQLite database schema initialized with all tables and a C wrapper library, so that daemons can persist data with a clean API.

**Acceptance Criteria**:
- [ ] All 6 tables from design.md Section 5.2 created on first run
- [ ] C wrapper provides functions: `jz_db_open()`, `jz_db_close()`, `jz_db_insert_attack()`, `jz_db_query_attacks()`, `jz_db_insert_audit()`, etc.
- [ ] Schema migration support (version tracking in system_state)
- [ ] Unit tests for all wrapper functions
- [ ] WAL mode enabled for concurrent read/write

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.1

**TDD Commits**:
1. `test(db): add unit tests for SQLite schema creation and CRUD operations`
2. `feat(db): implement SQLite schema and C wrapper library`
3. `feat(db): add schema migration and WAL mode support`

---

## Epic E2: Dynamic Trapping Engine (动态诱捕引擎)

> Core deception capability: classify packets against guard tables,
> generate honeypot ARP/ICMP responses, and detect network sniffers.

### S2.1: Guard Classifier — Static Guard Lookup

**Description**: As a security operator, I want the system to classify packets destined for statically-configured guard IPs, so that honeypot responses can be triggered for known decoy addresses.

**Acceptance Criteria**:
- [ ] BPF module `jz_guard_classifier` loads at stage 22
- [ ] Packets with dst_ip matching `jz_static_guards` map → guard_result set to STATIC
- [ ] Packets with no match → guard_result set to NONE, tail-call to stage 30 (ACL)
- [ ] Guard entry `hit_count` and `last_hit` updated on each match
- [ ] Classification result written to rs_ctx[192..199]
- [ ] Handles empty map gracefully (all packets pass through)

**Priority**: P0 | **Complexity**: L | **Dependencies**: S1.4, S1.5, S1.7

**TDD Commits**:
1. `test(bpf/guard): add tests for static guard lookup — match, no-match, empty-map`
2. `feat(bpf/guard): implement static guard hash map lookup in guard_classifier`
3. `feat(bpf/guard): write classification result to rs_ctx and tail-call`

---

### S2.2: Guard Classifier — Dynamic Guard Lookup

**Description**: As a security operator, I want the system to also check dynamically-discovered guard IPs, so that auto-discovered decoy addresses trigger honeypot responses.

**Acceptance Criteria**:
- [ ] If no static match, lookup dst_ip in `jz_dynamic_guards` LRU hash map
- [ ] Dynamic guard match → guard_result set to DYNAMIC
- [ ] LRU eviction works correctly when map is full
- [ ] Dynamic entries can be added from user-space (sniffd populates via DHCP observation or scanning)
- [ ] TTL-based expiry enforced by user-space cleanup (not in BPF)

**Priority**: P0 | **Complexity**: L | **Dependencies**: S2.1

**TDD Commits**:
1. `test(bpf/guard): add tests for dynamic guard LRU lookup`
2. `feat(bpf/guard): implement dynamic guard lookup with LRU hash map`
3. `test(bpf/guard): add test for static-then-dynamic lookup ordering`

---

### S2.3: Guard Classifier — Whitelist Bypass

**Description**: As a security operator, I want trusted devices in the whitelist to bypass guard checks, so that legitimate devices are not caught by the honeypot.

**Acceptance Criteria**:
- [ ] Whitelist checked BEFORE guard lookup (src_ip + optional MAC match)
- [ ] Whitelisted packets → WHITELIST_BYPASS flag set, skip guard classification
- [ ] MAC-matching mode works (require both IP and MAC match)
- [ ] IP-only mode works (match IP regardless of MAC)
- [ ] Whitelist miss → proceed to guard lookup as normal

**Priority**: P0 | **Complexity**: M | **Dependencies**: S2.1

**TDD Commits**:
1. `test(bpf/guard): add tests for whitelist bypass — IP-only, IP+MAC, miss`
2. `feat(bpf/guard): implement whitelist check with MAC-match option`

---

### S2.4: ARP Honeypot — Fake ARP Reply Generation

**Description**: As a security system, I want to automatically generate fake ARP replies for guarded IPs, so that attackers believe the decoy IPs are real hosts on the network.

**Acceptance Criteria**:
- [ ] BPF module `jz_arp_honeypot` loads at stage 23
- [ ] When guard_result = STATIC|DYNAMIC and protocol = ARP:
  - Crafts valid ARP reply with fake MAC in the packet buffer
  - Swaps Ethernet src/dst correctly
  - Uses guard-specific fake MAC or allocates from pool
  - Returns XDP_TX to send reply back on ingress port
- [ ] Rate limiting prevents ARP flood (configurable PPS)
- [ ] Non-ARP packets or non-guard packets pass through (tail-call to next stage)
- [ ] Emits JZ_EVENT_ATTACK_ARP to rs_event_bus

**Priority**: P0 | **Complexity**: XL | **Dependencies**: S2.1, S2.2

**TDD Commits**:
1. `test(bpf/arp): add tests for ARP reply packet crafting — valid reply structure`
2. `test(bpf/arp): add tests for rate limiting and fake MAC pool allocation`
3. `feat(bpf/arp): implement ARP reply crafting with in-place packet modification`
4. `feat(bpf/arp): add rate limiter and fake MAC pool integration`
5. `feat(bpf/arp): emit attack event to ring buffer and return XDP_TX`

---

### S2.5: ICMP Honeypot — Fake Echo Reply Generation

**Description**: As a security system, I want to generate fake ICMP echo replies for guarded IPs, so that attackers who ping decoy IPs get realistic responses.

**Acceptance Criteria**:
- [ ] BPF module `jz_icmp_honeypot` loads at stage 24
- [ ] Crafts valid ICMP echo reply (type=0) from echo request (type=8)
- [ ] Configurable TTL for OS fingerprint emulation (64=Linux, 128=Windows)
- [ ] Correct IP and ICMP checksum recalculation
- [ ] Rate limiting (configurable PPS)
- [ ] Emits JZ_EVENT_ATTACK_ICMP to rs_event_bus
- [ ] Returns XDP_TX

**Priority**: P1 | **Complexity**: L | **Dependencies**: S2.1

**TDD Commits**:
1. `test(bpf/icmp): add tests for ICMP echo reply crafting and checksum`
2. `feat(bpf/icmp): implement ICMP honeypot with configurable TTL`
3. `feat(bpf/icmp): add rate limiting and event emission`

---

### S2.6: Sniffer Detection — ARP Probe Response Monitoring

**Description**: As a security operator, I want the system to detect network sniffers by monitoring responses to ARP probes sent to non-existent IPs, so that I can identify compromised or unauthorized monitoring devices.

**Acceptance Criteria**:
- [ ] BPF module `jz_sniffer_detect` loads at stage 25
- [ ] Monitors ARP replies and checks if sender IP matches `jz_probe_targets` map
- [ ] If match → device is in promiscuous mode (sniffer suspect)
- [ ] Records suspect in `jz_sniffer_suspects` map (MAC, IP, count, timestamps)
- [ ] Emits JZ_EVENT_SNIFFER_DETECTED to rs_event_bus
- [ ] Non-matching ARP replies pass through normally

**Priority**: P1 | **Complexity**: L | **Dependencies**: S1.4, S1.5

**TDD Commits**:
1. `test(bpf/sniffer): add tests for probe response matching`
2. `feat(bpf/sniffer): implement ARP probe response monitor at stage 25`
3. `feat(bpf/sniffer): add suspect tracking and event emission`

---

### S2.7: Sniffer Detection — ARP Probe Generation (User-space)

**Description**: As a security operator, I want sniffd to periodically generate ARP probes to non-existent IPs, so that the sniffer detection BPF module can detect promiscuous-mode responses.

**Acceptance Criteria**:
- [ ] sniffd generates ARP requests to random non-existent IPs on configured subnets
- [ ] Probe IPs registered in `jz_probe_targets` BPF map before sending
- [ ] Configurable probe interval (default 30 seconds) and count (default 5 per cycle)
- [ ] Expired probes cleaned up (no response within timeout)
- [ ] Probe generation can be started/stopped via IPC command

**Priority**: P1 | **Complexity**: L | **Dependencies**: S2.6, S7.1

**TDD Commits**:
1. `test(sniffd): add unit tests for ARP probe generation and map population`
2. `feat(sniffd): implement timer-based ARP probe generator`
3. `feat(sniffd): add probe target map management and expiry cleanup`

---

### S2.8: Fake MAC Pool Management

**Description**: As a security operator, I want a configurable pool of synthetic MAC addresses, so that honeypot responses use realistic but identifiable fake MACs.

**Acceptance Criteria**:
- [ ] Fake MAC pool initialized on daemon startup with configurable OUI prefix (default aa:bb:cc)
- [ ] Configurable pool size (default 64)
- [ ] Round-robin allocation for guards that don't specify a MAC
- [ ] MAC-to-guard assignment tracked (so same guard always gets same MAC)
- [ ] Pool populated into `jz_fake_mac_pool` BPF map

**Priority**: P1 | **Complexity**: M | **Dependencies**: S2.4, S7.1

**TDD Commits**:
1. `test(sniffd): add unit tests for fake MAC pool generation and allocation`
2. `feat(sniffd): implement fake MAC pool with configurable OUI and round-robin`

---

## Epic E3: Traffic Weaving Engine (流量编织引擎)

> Dynamic traffic steering: redirect suspicious flows to honeypot interfaces,
> mirror selected traffic for deep inspection, apply per-flow granular policies.

### S3.1: Flow Policy Map and Classification

**Description**: As a security operator, I want to define per-flow traffic policies (5-tuple match), so that I can control which flows are redirected, mirrored, or dropped.

**Acceptance Criteria**:
- [ ] BPF module `jz_traffic_weaver` loads at stage 35
- [ ] 5-tuple flow key (src_ip, dst_ip, src_port, dst_port, proto) with wildcards (0)
- [ ] Policy map lookup with first-match semantics
- [ ] Flow statistics tracked (packets, bytes, last_seen) in per-CPU map
- [ ] Unmatched flows pass through (tail-call to stage 40)

**Priority**: P1 | **Complexity**: L | **Dependencies**: S1.4, S1.5

**TDD Commits**:
1. `test(bpf/weaver): add tests for 5-tuple flow matching with wildcards`
2. `feat(bpf/weaver): implement flow policy lookup at stage 35`
3. `feat(bpf/weaver): add per-flow statistics tracking`

---

### S3.2: Traffic Redirect to Honeypot Interface

**Description**: As a security operator, I want suspicious traffic redirected to a honeypot VM interface, so that attackers interact with a controlled environment while being observed.

**Acceptance Criteria**:
- [ ] `action = REDIRECT` → `bpf_redirect(honeypot_ifindex, 0)` → XDP_REDIRECT
- [ ] Redirect target configured per-policy or from global default (`jz_redirect_config`)
- [ ] Ethernet headers rewritten if needed (dst MAC set to honeypot MAC)
- [ ] Original packet is NOT forwarded through the normal pipeline
- [ ] Emits JZ_EVENT_POLICY_MATCH event

**Priority**: P1 | **Complexity**: XL | **Dependencies**: S3.1

**TDD Commits**:
1. `test(bpf/weaver): add tests for bpf_redirect to honeypot interface`
2. `feat(bpf/weaver): implement REDIRECT action with bpf_redirect()`
3. `feat(bpf/weaver): add redirect config map and MAC rewriting`

---

### S3.3: Selective Traffic Mirroring

**Description**: As a security analyst, I want selected traffic mirrored to an analyzer interface, so that I can perform deep packet inspection on suspicious flows without disrupting them.

**Acceptance Criteria**:
- [ ] `action = MIRROR` → `bpf_clone_redirect(mirror_ifindex, 0)` → original continues pipeline
- [ ] Mirror target configured per-policy or from global default
- [ ] Original packet continues through pipeline unmodified
- [ ] Mirror port statistics tracked
- [ ] Works in combination with REDIRECT (REDIRECT_MIRROR action)

**Priority**: P1 | **Complexity**: L | **Dependencies**: S3.1

**TDD Commits**:
1. `test(bpf/weaver): add tests for traffic mirroring with clone_redirect`
2. `feat(bpf/weaver): implement MIRROR action with bpf_clone_redirect()`
3. `feat(bpf/weaver): implement combined REDIRECT_MIRROR action`

---

### S3.4: Traffic Drop Action

**Description**: As a security operator, I want to drop traffic matching specific flow policies, so that I can block known-malicious flows at line rate.

**Acceptance Criteria**:
- [ ] `action = DROP` → XDP_DROP
- [ ] Drop counters tracked in flow_stats
- [ ] Drop event emitted to rs_event_bus (if logging enabled for policy)
- [ ] No downstream processing for dropped packets

**Priority**: P1 | **Complexity**: M | **Dependencies**: S3.1

**TDD Commits**:
1. `test(bpf/weaver): add tests for DROP action`
2. `feat(bpf/weaver): implement DROP action with statistics and logging`

---

### S3.5: Policy Hot-Reload Without Flow Disruption

**Description**: As a security operator, I want to update flow policies without disrupting active flows, so that I can adjust security posture in real-time.

**Acceptance Criteria**:
- [ ] New policy entries added to map without clearing existing entries
- [ ] Removed policy entries deleted from map individually
- [ ] Active flows using updated policies see new action on next packet
- [ ] No packet loss during policy update (map operations are atomic per-entry)
- [ ] configd applies policy changes via bpf_map_update_elem / bpf_map_delete_elem

**Priority**: P1 | **Complexity**: M | **Dependencies**: S3.1, S5.2

**TDD Commits**:
1. `test(configd): add tests for policy map update without flow disruption`
2. `feat(configd): implement incremental policy map updates`

---

### S3.6: Flow Statistics and Counters

**Description**: As a security analyst, I want per-flow statistics (packets, bytes, timestamps), so that I can analyze traffic patterns and evaluate policy effectiveness.

**Acceptance Criteria**:
- [ ] Per-CPU flow stats map tracks packets, bytes, last_seen per flow
- [ ] User-space can read and aggregate per-CPU stats
- [ ] Stats exposed via REST API (`GET /api/v1/stats/traffic`)
- [ ] Stats reset capability via API and CLI
- [ ] Periodic stats collection by collectord (configurable interval)

**Priority**: P2 | **Complexity**: M | **Dependencies**: S3.1, S8.1

**TDD Commits**:
1. `test(sniffd): add tests for per-CPU flow stats aggregation`
2. `feat(sniffd): implement flow stats reader with per-CPU aggregation`
3. `feat(api): expose flow statistics endpoint`

---

## Epic E4: Data Collation Engine (数据整理引擎)

> Fast-path threat detection, structured event logging, forensic packet sampling,
> and data export for the analysis platform.

### S4.1: Threat Pattern Matching Engine

**Description**: As a security system, I want to match packet headers against known threat patterns at line rate, so that obvious threats are detected and flagged immediately in the data plane.

**Acceptance Criteria**:
- [ ] BPF module `jz_threat_detect` loads at stage 50
- [ ] Pattern matching on src_ip, dst_ip, dst_port, proto (with wildcards)
- [ ] Configurable threat level per pattern (low/medium/high/critical)
- [ ] Configurable action per pattern (log-only, log+drop, log+redirect)
- [ ] Blacklist map for known malicious IPs (fast O(1) lookup)
- [ ] Statistics: total_checked, threats by level, dropped, redirected

**Priority**: P1 | **Complexity**: XL | **Dependencies**: S1.4, S1.5

**TDD Commits**:
1. `test(bpf/threat): add tests for threat pattern matching with wildcards`
2. `test(bpf/threat): add tests for blacklist IP lookup`
3. `feat(bpf/threat): implement threat pattern matching engine at stage 50`
4. `feat(bpf/threat): add IP blacklist and threat statistics`

---

### S4.2: Attack Event Ring Buffer Emission

**Description**: As a data pipeline, I want all attack events emitted to the rs_event_bus ring buffer with structured headers, so that user-space daemons can consume and process them efficiently.

**Acceptance Criteria**:
- [ ] All event types use common `jz_event_hdr` (type, len, timestamp, IPs, MACs)
- [ ] Events emitted via `bpf_ringbuf_reserve()` + `bpf_ringbuf_submit()`
- [ ] Ring buffer overflow handled gracefully (event dropped, counter incremented)
- [ ] Event timestamp uses `bpf_ktime_get_ns()` for nanosecond precision
- [ ] Events verified readable by user-space consumer

**Priority**: P0 | **Complexity**: L | **Dependencies**: S1.4

**TDD Commits**:
1. `test(bpf/common): add tests for event emission to ring buffer`
2. `feat(bpf/common): implement event emission helpers with common header`

---

### S4.3: Attack Log SQLite Persistence

**Description**: As a security operator, I want attack events persisted to SQLite database, so that I can query historical attack data and build forensic reports.

**Acceptance Criteria**:
- [ ] collectord writes attack events to `attack_log` table
- [ ] All fields from `jz_event_attack` mapped to table columns
- [ ] Index on timestamp and src_ip for fast queries
- [ ] Upload tracking (uploaded=0/1) for uploadd consumption
- [ ] Query API: by time range, source IP, guard type, event type

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.8, S4.2

**TDD Commits**:
1. `test(collectord): add tests for attack event SQLite persistence and query`
2. `feat(collectord): implement attack log writer with indexed queries`

---

### S4.4: Forensic Packet Sampling

**Description**: As a security analyst, I want to capture packet payloads for suspicious traffic, so that I can perform forensic analysis of attack tools and techniques.

**Acceptance Criteria**:
- [ ] BPF module `jz_forensics` loads at stage 55
- [ ] Samples packets when JZ_CTX_SAMPLE_FLAG is set by upstream modules
- [ ] Optional random sampling for non-flagged packets (1-in-N, configurable)
- [ ] Captures up to configurable bytes of payload (128/256/512)
- [ ] Dedicated 4MB ring buffer (`jz_sample_ringbuf`) to avoid contention with event bus
- [ ] User-space stores samples as BLOBs in attack_log.packet_sample

**Priority**: P1 | **Complexity**: L | **Dependencies**: S4.1

**TDD Commits**:
1. `test(bpf/forensic): add tests for packet sampling with flag and random modes`
2. `feat(bpf/forensic): implement forensic sampling module at stage 55`
3. `feat(collectord): consume forensic ring buffer and store packet samples`

---

### S4.5: Event Deduplication and Rate Limiting

**Description**: As a data pipeline, I want events deduplicated and rate-limited in user-space, so that repeated attacks from the same source don't flood the database and upload channel.

**Acceptance Criteria**:
- [ ] collectord deduplicates events within a configurable window (default 10 seconds)
- [ ] Same source IP + same event type within window → increment count, don't create new row
- [ ] Rate limit: max configurable events per second (default 1000 eps)
- [ ] Excess events counted but not stored (overflow counter in stats)
- [ ] Dedup window and rate limit configurable via YAML

**Priority**: P1 | **Complexity**: M | **Dependencies**: S4.3

**TDD Commits**:
1. `test(collectord): add tests for event deduplication and rate limiting`
2. `feat(collectord): implement sliding-window dedup and token-bucket rate limiter`

---

### S4.6: Structured JSON Export

**Description**: As an analysis platform, I want attack data exported in structured JSON format, so that the platform can ingest and correlate data from multiple devices.

**Acceptance Criteria**:
- [ ] JSON export format matches design.md Section 5.4
- [ ] Includes device_id, export_version, timestamp
- [ ] Sections: attacks, sniffers, threats, background
- [ ] Export API: by time range, by event type, all-pending
- [ ] cJSON library used for serialization
- [ ] Output validated against schema

**Priority**: P1 | **Complexity**: M | **Dependencies**: S4.3

**TDD Commits**:
1. `test(collectord): add tests for JSON export format and schema validation`
2. `feat(collectord): implement structured JSON export with cJSON`

---

### S4.7: Real-time Attack Statistics

**Description**: As a security operator, I want real-time attack statistics (by type, by source, by guard), so that I can monitor the current threat landscape on this device.

**Acceptance Criteria**:
- [ ] Guard hit statistics: per-guard hit count and last_hit (read from BPF maps)
- [ ] Attack statistics: by event type (ARP, ICMP, sniffer, threat) with counts and rates
- [ ] Top-N attackers: most active source IPs in last hour
- [ ] Stats available via CLI (`jzctl stats`) and REST API (`GET /api/v1/stats`)
- [ ] Stats include both BPF-level counters and SQLite aggregate queries

**Priority**: P2 | **Complexity**: M | **Dependencies**: S4.3, S8.1

**TDD Commits**:
1. `test(sniffd): add tests for BPF map stats aggregation`
2. `feat(sniffd): implement real-time attack statistics collector`
3. `feat(api): expose attack statistics endpoints`

---

## Epic E5: Configuration Management (配置管理系统)

> YAML configuration parsing, remote config delivery, hot-reload,
> versioning, and rollback.

### S5.1: YAML Configuration Parser

**Description**: As a daemon, I want to parse YAML configuration files using libyaml, so that I can read the device configuration on startup and reload.

**Acceptance Criteria**:
- [ ] Parse all sections of base.yaml (system, modules, guards, policies, threats, etc.)
- [ ] Profile inheritance: device.yaml overrides base.yaml, runtime/ overrides both
- [ ] Validation: reject invalid YAML, missing required fields, invalid values
- [ ] Error reporting: line numbers and clear error messages
- [ ] C API: `jz_config_load(path)`, `jz_config_get_guards()`, `jz_config_get_modules()`, etc.

**Priority**: P0 | **Complexity**: L | **Dependencies**: S1.6

**TDD Commits**:
1. `test(config): add tests for YAML parsing — valid, invalid, missing fields`
2. `test(config): add tests for profile inheritance and merge`
3. `feat(config): implement YAML parser with libyaml and validation`
4. `feat(config): implement profile inheritance with merge semantics`

---

### S5.2: Config-to-BPF-Map Translator

**Description**: As a daemon, I want to translate parsed YAML configuration into BPF map entries, so that configuration changes are applied to the data plane.

**Acceptance Criteria**:
- [ ] Guards section → jz_static_guards, jz_dynamic_guards, jz_whitelist maps
- [ ] Policies section → jz_flow_policy map
- [ ] Threats section → jz_threat_patterns, jz_threat_blacklist maps
- [ ] Module configs → jz_arp_config, jz_icmp_config, jz_sample_config maps
- [ ] Fake MAC pool → jz_fake_mac_pool map
- [ ] Background filters → jz_bg_filter map
- [ ] Incremental updates (only changed entries modified)
- [ ] Read-back verification after update

**Priority**: P0 | **Complexity**: XL | **Dependencies**: S5.1

**TDD Commits**:
1. `test(configd): add tests for guard config → BPF map translation`
2. `test(configd): add tests for policy and threat config translation`
3. `feat(configd): implement config-to-map translator for guard maps`
4. `feat(configd): implement config-to-map translator for policy and threat maps`
5. `feat(configd): add read-back verification and incremental updates`

---

### S5.3: Remote Configuration Receiver

**Description**: As a management platform, I want to push configuration to devices via a TLS endpoint, so that fleet-wide policy changes can be applied remotely.

**Acceptance Criteria**:
- [ ] configd listens on HTTPS endpoint for config push (POST /api/v1/config/push)
- [ ] Mutual TLS authentication (device cert + platform CA)
- [ ] Config payload: JSON with version, sections, data
- [ ] Monotonic version check (reject stale configs)
- [ ] Response includes status (applied/rejected) and any errors
- [ ] Endpoint can be disabled for standalone mode

**Priority**: P1 | **Complexity**: L | **Dependencies**: S5.2

**TDD Commits**:
1. `test(configd): add tests for remote config receiver — valid, stale, auth failure`
2. `feat(configd): implement TLS config endpoint with mbedTLS`
3. `feat(configd): add version validation and error reporting`

---

### S5.4: Configuration Version History

**Description**: As a security operator, I want all configuration changes tracked with version numbers, so that I can see what changed and when.

**Acceptance Criteria**:
- [ ] Every config change creates a new version entry in config_history table
- [ ] Version number is monotonically increasing
- [ ] Full config snapshot stored per version (for rollback)
- [ ] Source tracked (local, remote, cli)
- [ ] Last N versions retained (configurable, default 50)
- [ ] Query API: list versions, get specific version

**Priority**: P1 | **Complexity**: M | **Dependencies**: S5.2, S1.8

**TDD Commits**:
1. `test(configd): add tests for config version tracking and history`
2. `feat(configd): implement config versioning with SQLite history`

---

### S5.5: Configuration Rollback

**Description**: As a security operator, I want to rollback to a previous configuration version, so that I can recover from bad config changes.

**Acceptance Criteria**:
- [ ] `jzctl config rollback <version>` restores a previous config
- [ ] Rollback creates a new version entry (with rollback_from reference)
- [ ] BPF maps updated to match rolled-back config
- [ ] Rollback logged in audit_log
- [ ] Rollback available via CLI and REST API

**Priority**: P1 | **Complexity**: M | **Dependencies**: S5.4

**TDD Commits**:
1. `test(configd): add tests for config rollback — success and invalid version`
2. `feat(configd): implement config rollback with version restoration`

---

### S5.6: Configuration Validation Engine

**Description**: As a system, I want all configuration validated before applying, so that invalid configs never reach the BPF data plane.

**Acceptance Criteria**:
- [ ] IP address format validation
- [ ] MAC address format validation
- [ ] Port range validation (0-65535)
- [ ] Stage number range validation (must be valid jz stages)
- [ ] Cross-reference validation (redirect port must exist, etc.)
- [ ] Dry-run mode: validate without applying

**Priority**: P1 | **Complexity**: M | **Dependencies**: S5.1

**TDD Commits**:
1. `test(configd): add tests for config validation — valid, each error type`
2. `feat(configd): implement config validation with per-field rules`

---

### S5.7: Configuration Diff and Audit Logging

**Description**: As a security auditor, I want all configuration changes logged with before/after diffs, so that I can audit who changed what and when.

**Acceptance Criteria**:
- [ ] Every config change logged in audit_log table
- [ ] Diff computed between old and new config (sections changed, entries added/removed)
- [ ] Actor tracked (cli:admin, api:token:xyz, remote:platform)
- [ ] Result tracked (success, failure with reason)
- [ ] Audit log queryable by time range, action, actor

**Priority**: P2 | **Complexity**: M | **Dependencies**: S5.4, S1.8

**TDD Commits**:
1. `test(configd): add tests for config diff computation and audit logging`
2. `feat(configd): implement config diff and audit log writer`

---

## Epic E6: Background Collection Engine (背景收集引擎)

> Capture broadcast, multicast, and protocol announcement traffic
> for baseline building and anomaly detection.

### S6.1: Broadcast Traffic Capture (ARP, DHCP)

**Description**: As an analysis platform, I want ARP and DHCP broadcast traffic captured and summarized, so that I can build a baseline of normal network behavior.

**Acceptance Criteria**:
- [ ] BPF module `jz_bg_collector` loads at stage 40
- [ ] ARP requests/replies (ETH_P_ARP) captured with src MAC, src IP, target IP
- [ ] DHCP packets (UDP 67/68) captured with client MAC, requested IP, DHCP message type
- [ ] Events emitted to rs_event_bus as JZ_EVENT_BG_CAPTURE
- [ ] Statistics updated in jz_bg_stats (arp_count, dhcp_count)
- [ ] Always passes packets through (non-blocking, tail-call to next stage)

**Priority**: P1 | **Complexity**: L | **Dependencies**: S1.4, S1.5

**TDD Commits**:
1. `test(bpf/bgcol): add tests for ARP and DHCP broadcast capture`
2. `feat(bpf/bgcol): implement broadcast capture for ARP and DHCP at stage 40`
3. `feat(bpf/bgcol): add per-protocol statistics tracking`

---

### S6.2: Multicast Traffic Capture (mDNS, SSDP, IGMP)

**Description**: As an analysis platform, I want multicast traffic (mDNS, SSDP, IGMP) captured, so that I can identify services and devices on the network.

**Acceptance Criteria**:
- [ ] mDNS (UDP 5353, dst 224.0.0.251) captured with query/response type
- [ ] SSDP (UDP 1900, dst 239.255.255.250) captured with service type
- [ ] IGMP (IP proto 2) captured with group address
- [ ] Statistics updated in jz_bg_stats
- [ ] Non-blocking (always pass through)

**Priority**: P2 | **Complexity**: L | **Dependencies**: S6.1

**TDD Commits**:
1. `test(bpf/bgcol): add tests for mDNS, SSDP, IGMP multicast capture`
2. `feat(bpf/bgcol): implement multicast capture for mDNS, SSDP, IGMP`

---

### S6.3: Protocol Announcement Capture (STP, LLDP, CDP)

**Description**: As an analysis platform, I want network protocol announcements (STP, LLDP, CDP) captured, so that I can map the network topology.

**Acceptance Criteria**:
- [ ] STP (dst MAC 01:80:c2:00:00:00) captured
- [ ] LLDP (ETH_P_LLDP = 0x88cc) captured with chassis ID, port ID
- [ ] CDP (SNAP + OUI 00:00:0c, type 0x2000) captured
- [ ] Statistics updated in jz_bg_stats
- [ ] Non-blocking

**Priority**: P2 | **Complexity**: L | **Dependencies**: S6.1

**TDD Commits**:
1. `test(bpf/bgcol): add tests for STP, LLDP, CDP capture`
2. `feat(bpf/bgcol): implement protocol announcement capture`

---

### S6.4: Background Noise Baseline Statistics

**Description**: As a security analyst, I want aggregated background noise statistics, so that I can establish normal network behavior and detect anomalies.

**Acceptance Criteria**:
- [ ] collectord aggregates bg events into periodic summaries (e.g., 5-minute windows)
- [ ] Summary includes: packet count, byte count, unique sources per protocol
- [ ] Summaries stored in `bg_capture` SQLite table
- [ ] Anomaly flag: alert if current period deviates significantly from baseline
- [ ] Statistics available via CLI and REST API

**Priority**: P2 | **Complexity**: M | **Dependencies**: S6.1, S4.3

**TDD Commits**:
1. `test(collectord): add tests for background noise aggregation`
2. `feat(collectord): implement periodic background noise summarization`

---

### S6.5: Background Data Structured Export

**Description**: As a management platform, I want background capture data exported in structured format, so that I can aggregate baselines from multiple devices.

**Acceptance Criteria**:
- [ ] JSON export includes per-protocol packet/byte counts and unique source counts
- [ ] Export includes sample entries (configurable N per protocol per period)
- [ ] Export format matches design.md Section 5.4 `background` schema
- [ ] uploadd includes background data in batch uploads

**Priority**: P2 | **Complexity**: M | **Dependencies**: S6.4, S4.6

**TDD Commits**:
1. `test(collectord): add tests for background data JSON export`
2. `feat(collectord): implement background data export for uploadd`

---

### S6.6: Background Capture Filter Configuration

**Description**: As a security operator, I want to configure which background protocols to capture and at what sample rate, so that I can control the noise level and storage usage.

**Acceptance Criteria**:
- [ ] Per-protocol enable/disable in YAML config (`modules.bg_collector.protocols`)
- [ ] Per-protocol sample rate (1=every packet, N=1-in-N)
- [ ] Include payload flag (capture first 128B or not)
- [ ] Configuration applied to `jz_bg_filter` BPF map
- [ ] Hot-reload supported (change filters without restart)

**Priority**: P2 | **Complexity**: S | **Dependencies**: S6.1, S5.2

**TDD Commits**:
1. `test(configd): add tests for bg_filter config-to-map translation`
2. `feat(configd): implement bg_filter configuration and hot-reload`

---

## Epic E7: User-space Daemons (用户空间守护进程)

> Core daemon infrastructure: lifecycle management, IPC, BPF interaction.

### S7.1: sniffd Core — Daemon Lifecycle

**Description**: As a system administrator, I want sniffd to run as a proper Unix daemon with signal handling, PID file, and clean shutdown, so that it integrates with systemd and standard process management.

**Acceptance Criteria**:
- [ ] Daemonize with `-d` flag (fork, setsid, redirect stdio)
- [ ] PID file creation and cleanup (`/var/run/jz/sniffd.pid`)
- [ ] Signal handling: SIGTERM→clean shutdown, SIGHUP→config reload, SIGUSR1→dump stats
- [ ] Logging to syslog and/or file (configurable)
- [ ] Clean shutdown: unpin maps, close sockets, remove PID file
- [ ] Drop privileges after initialization (run as `jz` user)

**Priority**: P0 | **Complexity**: M | **Dependencies**: S1.1

**TDD Commits**:
1. `test(sniffd): add tests for daemon lifecycle — startup, signals, shutdown`
2. `feat(sniffd): implement daemon lifecycle with signal handling and PID file`

---

### S7.2: sniffd — BPF Module Loader Integration

**Description**: As a daemon, I want sniffd to load all jz BPF modules into the rSwitch pipeline on startup, so that the data plane is operational.

**Acceptance Criteria**:
- [ ] Load all 8 BPF module object files via libbpf
- [ ] Pin maps under `/sys/fs/bpf/jz/`
- [ ] Register programs in rs_progs prog_array at correct stage numbers
- [ ] Verify all modules pass BPF verifier
- [ ] Support per-module enable/disable from config
- [ ] Module reload capability (unload + load without stopping other modules)
- [ ] Graceful degradation: if a module fails to load, continue with others

**Priority**: P0 | **Complexity**: XL | **Dependencies**: S7.1, S1.5

**TDD Commits**:
1. `test(sniffd): add tests for BPF module loading and map pinning`
2. `feat(sniffd): implement BPF module loader with libbpf`
3. `feat(sniffd): add module enable/disable and reload capability`
4. `feat(sniffd): add graceful degradation for module load failures`

---

### S7.3: sniffd — Ring Buffer Consumer

**Description**: As a daemon, I want sniffd to consume events from the rs_event_bus ring buffer and dispatch them to collectord, so that BPF events reach persistent storage.

**Acceptance Criteria**:
- [ ] Dedicated consumer thread polling rs_event_bus and jz_sample_ringbuf
- [ ] Parse event header to determine type
- [ ] Dispatch events to collectord via IPC (Unix domain socket)
- [ ] Handle ring buffer overflow gracefully (log warning, increment counter)
- [ ] Configurable poll interval and batch size
- [ ] Consumer stats: events consumed, dispatched, dropped

**Priority**: P0 | **Complexity**: L | **Dependencies**: S7.1, S4.2

**TDD Commits**:
1. `test(sniffd): add tests for ring buffer consumption and event dispatch`
2. `feat(sniffd): implement ring buffer consumer thread`
3. `feat(sniffd): add IPC dispatch to collectord`

---

### S7.4: sniffd — Guard Table Manager

**Description**: As a daemon, I want sniffd to manage the guard table lifecycle (populate from config, handle additions/removals), so that guard maps are always in sync with configuration.

**Acceptance Criteria**:
- [ ] On startup: populate guard maps from YAML config
- [ ] IPC commands: guard_add, guard_del, guard_list, whitelist_add, whitelist_del
- [ ] Validate entries before map insertion (IP format, MAC format, no duplicates)
- [ ] Sync state to configd (persist changes to YAML)
- [ ] Dynamic guard cleanup: expire entries older than TTL

**Priority**: P1 | **Complexity**: L | **Dependencies**: S7.1, S5.2

**TDD Commits**:
1. `test(sniffd): add tests for guard table CRUD operations`
2. `feat(sniffd): implement guard table manager with IPC interface`
3. `feat(sniffd): add dynamic guard TTL expiry`

---

### S7.5: configd Core — Config Watcher and Reload Orchestrator

**Description**: As a daemon, I want configd to watch for config file changes and orchestrate hot-reloads, so that config changes are applied without restarting services.

**Acceptance Criteria**:
- [ ] inotify watcher on `/etc/jz/` directory for YAML file changes
- [ ] On change: parse → validate → diff → apply to BPF maps → verify → log
- [ ] Reload sequence follows design.md Section 6.4
- [ ] Failure recovery: rollback map changes, log error
- [ ] IPC interface for CLI-triggered reloads
- [ ] Daemon lifecycle (pidfile, signals, logging)

**Priority**: P1 | **Complexity**: L | **Dependencies**: S5.1, S5.2, S7.1

**TDD Commits**:
1. `test(configd): add tests for file watcher and reload orchestration`
2. `feat(configd): implement inotify config watcher`
3. `feat(configd): implement reload orchestrator with rollback on failure`

---

### S7.6: collectord Core — Event Aggregator and SQLite Writer

**Description**: As a daemon, I want collectord to receive events via IPC, aggregate them, and write to SQLite, so that all security events are persisted.

**Acceptance Criteria**:
- [ ] IPC listener accepts events from sniffd
- [ ] Events routed to correct handler by type (attack, sniffer, background, threat)
- [ ] Dedup and rate limiting applied (from S4.5)
- [ ] Batch SQLite writes for performance (transaction per N events or per interval)
- [ ] Database size monitoring with rotation when limit reached
- [ ] Daemon lifecycle (pidfile, signals, logging)

**Priority**: P1 | **Complexity**: L | **Dependencies**: S4.3, S7.1

**TDD Commits**:
1. `test(collectord): add tests for IPC event reception and SQLite batch writing`
2. `feat(collectord): implement event aggregator with batch SQLite writer`
3. `feat(collectord): add database size monitoring and rotation`

---

### S7.7: uploadd Core — Batch Upload Agent

**Description**: As a daemon, I want uploadd to batch collected data and upload to the management platform, so that centralized analysis and alerting are possible.

**Acceptance Criteria**:
- [ ] Poll collectord (or query SQLite directly) for un-uploaded events
- [ ] Batch events (configurable batch size, default 1000)
- [ ] Compress payload (gzip or zstd)
- [ ] HTTPS POST to platform URL with client certificate auth
- [ ] Retry with exponential backoff on failure (1s, 2s, 4s, 8s, max 5min)
- [ ] Mark events as uploaded on success
- [ ] Daemon lifecycle (pidfile, signals, logging)
- [ ] Graceful degradation: buffer locally if platform unreachable

**Priority**: P2 | **Complexity**: L | **Dependencies**: S4.6, S7.1

**TDD Commits**:
1. `test(uploadd): add tests for batch assembly, compression, retry logic`
2. `feat(uploadd): implement batch upload with HTTPS and retry`
3. `feat(uploadd): add compression and upload tracking`

---

### S7.8: Inter-Daemon IPC Framework

**Description**: As a developer, I want a reusable IPC framework (Unix domain sockets + JSON messages), so that all daemons communicate consistently.

**Acceptance Criteria**:
- [ ] Shared library: `ipc.c/ipc.h` with server and client APIs
- [ ] JSON message format: `{"cmd": "...", "data": {...}}`
- [ ] Non-blocking I/O with epoll
- [ ] Connection timeout and reconnect logic
- [ ] Socket permissions restricted to `jz` group
- [ ] Unit tests for all IPC operations

**Priority**: P1 | **Complexity**: M | **Dependencies**: S1.1

**TDD Commits**:
1. `test(common): add unit tests for IPC server/client with JSON messages`
2. `feat(common): implement Unix domain socket IPC framework`
3. `feat(common): add epoll-based non-blocking I/O and reconnect logic`

---

## Epic E8: Management Interface (管理接口)

> REST API, CLI tools, and management endpoints for security operators.

### S8.1: REST API Framework (Mongoose HTTP Server)

**Description**: As a developer, I want the Mongoose HTTP server integrated into sniffd with route registration, so that all REST endpoints have a common framework.

**Acceptance Criteria**:
- [ ] Mongoose HTTP server runs in sniffd (separate thread)
- [ ] HTTPS with TLS (configurable cert/key)
- [ ] Route registration: `jz_api_register(method, path, handler)`
- [ ] JSON request/response handling (cJSON)
- [ ] Bearer token authentication middleware
- [ ] CORS headers for browser access
- [ ] Health endpoint (`GET /api/v1/health`) returns 200

**Priority**: P1 | **Complexity**: M | **Dependencies**: S7.1

**TDD Commits**:
1. `test(api): add tests for HTTP server startup and health endpoint`
2. `feat(api): integrate Mongoose HTTP server with route registration`
3. `feat(api): add JWT authentication middleware`

---

### S8.2: Guard Management API Endpoints

**Description**: As a security operator, I want REST API endpoints to manage guards (static, dynamic, whitelist), so that I can manage decoy addresses remotely.

**Acceptance Criteria**:
- [ ] `GET /api/v1/guards` — list all guards (static + dynamic + whitelist)
- [ ] `GET /api/v1/guards/static` — list static guards
- [ ] `POST /api/v1/guards/static` — add static guard `{"ip":"...","mac":"...","vlan":0}`
- [ ] `DELETE /api/v1/guards/static/{ip}` — remove static guard
- [ ] `GET /api/v1/guards/dynamic` — list dynamic guards
- [ ] `DELETE /api/v1/guards/dynamic/{ip}` — remove dynamic guard
- [ ] `GET /api/v1/whitelist` — list whitelist
- [ ] `POST /api/v1/whitelist` — add whitelist entry
- [ ] `DELETE /api/v1/whitelist/{ip}` — remove whitelist entry
- [ ] All mutations trigger BPF map update and audit log entry

**Priority**: P1 | **Complexity**: L | **Dependencies**: S8.1, S7.4

**TDD Commits**:
1. `test(api): add tests for guard CRUD endpoints`
2. `feat(api): implement guard management endpoints`
3. `feat(api): add whitelist management endpoints`

---

### S8.3: Policy Management API Endpoints

**Description**: As a security operator, I want REST API endpoints to manage flow policies, so that I can control traffic steering remotely.

**Acceptance Criteria**:
- [ ] `GET /api/v1/policies` — list all flow policies
- [ ] `POST /api/v1/policies` — add policy with 5-tuple + action
- [ ] `PUT /api/v1/policies/{id}` — update existing policy
- [ ] `DELETE /api/v1/policies/{id}` — remove policy
- [ ] Validation: IP/port/proto format, valid action, redirect port exists
- [ ] All mutations trigger BPF map update and audit log

**Priority**: P1 | **Complexity**: L | **Dependencies**: S8.1, S3.1

**TDD Commits**:
1. `test(api): add tests for policy CRUD endpoints`
2. `feat(api): implement policy management endpoints`

---

### S8.4: Log Query API Endpoints

**Description**: As a security operator, I want REST API endpoints to query attack logs, sniffer detections, and threats, so that I can investigate incidents remotely.

**Acceptance Criteria**:
- [ ] `GET /api/v1/logs/attacks?since=...&until=...&src_ip=...&limit=100`
- [ ] `GET /api/v1/logs/sniffers`
- [ ] `GET /api/v1/logs/threats?level=high`
- [ ] `GET /api/v1/logs/background?proto=arp`
- [ ] `GET /api/v1/logs/audit?since=...&action=...`
- [ ] Pagination support (offset + limit)
- [ ] JSON response with array of log entries

**Priority**: P1 | **Complexity**: M | **Dependencies**: S8.1, S4.3

**TDD Commits**:
1. `test(api): add tests for log query endpoints with pagination`
2. `feat(api): implement log query endpoints with SQLite queries`

---

### S8.5: System Status and Statistics Endpoints

**Description**: As a security operator, I want REST API endpoints for system status and statistics, so that I can monitor device health and security posture.

**Acceptance Criteria**:
- [ ] `GET /api/v1/status` — system status (uptime, module status, daemon status)
- [ ] `GET /api/v1/modules` — BPF module load status per stage
- [ ] `GET /api/v1/stats` — all statistics aggregated
- [ ] `GET /api/v1/stats/guards` — guard hit counts
- [ ] `GET /api/v1/stats/traffic` — flow statistics
- [ ] `GET /api/v1/stats/threats` — threat detection counts by level
- [ ] `GET /api/v1/stats/background` — background capture counts by protocol

**Priority**: P2 | **Complexity**: M | **Dependencies**: S8.1

**TDD Commits**:
1. `test(api): add tests for status and statistics endpoints`
2. `feat(api): implement system status and statistics endpoints`

---

### S8.6: jzctl CLI Tool

**Description**: As a system administrator, I want a comprehensive CLI tool (`jzctl`) for system management, so that I can manage the device from the command line.

**Acceptance Criteria**:
- [ ] `jzctl status` — system overview (daemons, modules, config version)
- [ ] `jzctl module list` — loaded modules and their stages
- [ ] `jzctl module reload <name>` — reload specific module
- [ ] `jzctl stats [--reset]` — show/reset statistics
- [ ] `jzctl config show` — dump current config
- [ ] `jzctl config reload` — trigger reload
- [ ] `jzctl config rollback <version>` — rollback
- [ ] `jzctl daemon restart <name>` — restart daemon
- [ ] Communicates with sniffd/configd via IPC sockets
- [ ] Colored terminal output, table formatting

**Priority**: P1 | **Complexity**: L | **Dependencies**: S7.1, S7.8

**TDD Commits**:
1. `test(cli): add tests for jzctl command parsing and IPC communication`
2. `feat(cli): implement jzctl with status, module, config, and stats commands`

---

### S8.7: jzguard and jzlog CLI Tools

**Description**: As a security operator, I want dedicated CLI tools for guard management (`jzguard`) and log viewing (`jzlog`), so that I have quick access to the most common operations.

**Acceptance Criteria**:
- [ ] `jzguard list`, `jzguard add`, `jzguard del` — guard operations
- [ ] `jzguard whitelist add/del` — whitelist operations
- [ ] `jzguard probe start/stop/results` — sniffer probing
- [ ] `jzlog attack`, `jzlog sniffer`, `jzlog threat` — log queries
- [ ] `jzlog background --proto arp` — background capture logs
- [ ] `jzlog audit` — audit trail
- [ ] `jzlog tail -f` — live event following
- [ ] Communicate via IPC or direct SQLite query (read-only)

**Priority**: P2 | **Complexity**: M | **Dependencies**: S7.8, S4.3

**TDD Commits**:
1. `test(cli): add tests for jzguard command parsing`
2. `feat(cli): implement jzguard CLI tool`
3. `test(cli): add tests for jzlog command parsing and formatting`
4. `feat(cli): implement jzlog CLI tool with tail -f support`

---

## Epic E9: Testing & Quality (测试与质量)

> Comprehensive test suites, performance benchmarks, and CI pipeline.

### S9.1: BPF Module Unit Tests

**Description**: As a developer, I want comprehensive unit tests for all 8 BPF modules using bpf_prog_test_run, so that I can verify correctness of data-plane logic.

**Acceptance Criteria**:
- [ ] Test file per module (8 files in tests/bpf/)
- [ ] Each test creates synthetic packets (ARP, ICMP, TCP, UDP) and runs through module
- [ ] Tests verify: correct XDP return value, map state after processing, event emission
- [ ] Minimum test cases per module:
  - guard_classifier: static match, dynamic match, whitelist bypass, no match (4 tests)
  - arp_honeypot: valid reply, rate limit, non-ARP passthrough (3 tests)
  - icmp_honeypot: valid reply, checksum, TTL, non-ICMP passthrough (4 tests)
  - sniffer_detect: probe match, no match, suspect recording (3 tests)
  - traffic_weaver: each action type, wildcard match, no match (5 tests)
  - bg_collector: each protocol type, sample rate, passthrough (4 tests)
  - threat_detect: pattern match, blacklist, no match (3 tests)
  - forensics: flagged sample, random sample, no sample (3 tests)
- [ ] Total: 29+ BPF unit tests, all passing

**Priority**: P0 | **Complexity**: XL | **Dependencies**: All E2, E3, E4, E6 BPF modules

**TDD Commits**:
1. `test(bpf/guard): comprehensive unit test suite for guard_classifier`
2. `test(bpf/arp): comprehensive unit test suite for arp_honeypot`
3. `test(bpf/icmp): comprehensive unit test suite for icmp_honeypot`
4. `test(bpf/sniffer): comprehensive unit test suite for sniffer_detect`
5. `test(bpf/weaver): comprehensive unit test suite for traffic_weaver`
6. `test(bpf/bgcol): comprehensive unit test suite for bg_collector`
7. `test(bpf/threat): comprehensive unit test suite for threat_detect`
8. `test(bpf/forensic): comprehensive unit test suite for forensics`

---

### S9.2: Daemon Unit Tests (cmocka)

**Description**: As a developer, I want unit tests for all daemon logic (config parser, IPC, database, dedup), so that I can verify correctness of control-plane code.

**Acceptance Criteria**:
- [ ] test_config_parser: YAML parsing, validation, inheritance (10+ tests)
- [ ] test_ipc: server/client communication, JSON message format (5+ tests)
- [ ] test_db: SQLite CRUD operations, schema migration (8+ tests)
- [ ] test_dedup: event deduplication, rate limiting (5+ tests)
- [ ] Total: 28+ C unit tests, all passing
- [ ] All tests run via `make test`

**Priority**: P1 | **Complexity**: L | **Dependencies**: All E5, E7 daemon code

**TDD Commits**:
1. `test(unit): comprehensive config parser test suite`
2. `test(unit): comprehensive IPC framework test suite`
3. `test(unit): comprehensive SQLite wrapper test suite`
4. `test(unit): comprehensive dedup/rate-limit test suite`

---

### S9.3: Integration Tests (Python + scapy)

**Description**: As a QA engineer, I want end-to-end integration tests that send real packets and verify system behavior, so that I can validate the full data-plane + control-plane pipeline.

**Acceptance Criteria**:
- [ ] Python test harness with scapy for packet generation
- [ ] Test: Send ARP request for guarded IP → verify ARP reply with correct fake MAC
- [ ] Test: Send ICMP echo to guarded IP → verify ICMP echo reply with configured TTL
- [ ] Test: Send packet matching flow policy → verify redirect/mirror/drop
- [ ] Test: Push new config via API → verify guards updated (send ARP, get reply)
- [ ] Test: Config rollback → verify previous guards restored
- [ ] Test: REST API CRUD operations for guards, policies, logs
- [ ] Tests run in isolated network namespace (veth pairs)
- [ ] Total: 15+ integration tests

**Priority**: P1 | **Complexity**: XL | **Dependencies**: All E2-E8

**TDD Commits**:
1. `test(integration): add Python test harness with scapy and veth setup`
2. `test(integration): add ARP and ICMP honeypot end-to-end tests`
3. `test(integration): add traffic weaver redirect/mirror tests`
4. `test(integration): add config push and rollback tests`
5. `test(integration): add REST API integration tests`

---

### S9.4: Performance Benchmarks

**Description**: As a performance engineer, I want automated benchmarks that measure throughput, latency, and resource usage, so that I can verify the system meets design.md Section 9 targets.

**Acceptance Criteria**:
- [ ] Benchmark: BPF pipeline throughput (pktgen, measure packets/sec with all modules)
- [ ] Benchmark: Guard lookup latency (bpf_prog_test_run with timing)
- [ ] Benchmark: Ring buffer throughput (events per second)
- [ ] Benchmark: SQLite write throughput (inserts per second)
- [ ] Results compared against targets from design.md Section 9
- [ ] Benchmark results logged for tracking regression

**Priority**: P2 | **Complexity**: L | **Dependencies**: S9.1

**TDD Commits**:
1. `test(perf): add pktgen-based throughput benchmark`
2. `test(perf): add BPF lookup latency microbenchmark`
3. `test(perf): add ring buffer and SQLite throughput benchmarks`

---

### S9.5: CI Pipeline Configuration

**Description**: As a developer, I want a CI pipeline that builds, verifies, and tests on every commit, so that regressions are caught immediately.

**Acceptance Criteria**:
- [ ] Build step: compile all BPF modules and user-space programs
- [ ] Verify step: BPF verifier check for all modules
- [ ] Unit test step: run cmocka and bpf_prog_test_run tests
- [ ] Lint step: clang-tidy, sparse (optional)
- [ ] Integration test step: Python tests with network namespaces (nightly)
- [ ] Performance benchmark step (nightly, results tracked)
- [ ] Pipeline defined as Makefile targets (CI-agnostic)

**Priority**: P2 | **Complexity**: M | **Dependencies**: S9.1, S9.2

**TDD Commits**:
1. `build: add CI Makefile targets — build, verify, test, lint`
2. `build: add nightly integration and performance test targets`

---

## Epic E10: Deployment & Operations (部署与运维)

> Packaging, installation, systemd integration, monitoring, upgrades.

### S10.1: Systemd Service Files

**Description**: As a system administrator, I want systemd service files for all daemons, so that they start automatically on boot with proper dependency ordering.

**Acceptance Criteria**:
- [ ] `sniffd.service` — starts after network-online.target and rswitch.service
- [ ] `configd.service` — starts after sniffd.service
- [ ] `collectord.service` — starts after sniffd.service
- [ ] `uploadd.service` — starts after collectord.service
- [ ] Restart=on-failure with configurable delay
- [ ] Resource limits (LimitMEMLOCK=infinity for BPF maps)
- [ ] Proper shutdown ordering (WantedBy, After, Requires)

**Priority**: P1 | **Complexity**: S | **Dependencies**: S7.1

**TDD Commits**:
1. `feat(deploy): add systemd service files with dependency ordering`

---

### S10.2: Installation Script and Packaging

**Description**: As a system administrator, I want an installation script that sets up the jz_sniff_rn system from scratch, so that deployment is repeatable and reliable.

**Acceptance Criteria**:
- [ ] `make install` copies files to correct system paths
- [ ] Installation script:
  - Creates `jz` system user and group
  - Creates data directories (`/var/lib/jz/`, `/var/run/jz/`)
  - Installs BPF modules, daemons, CLI tools, configs
  - Generates initial auth token
  - Generates self-signed TLS cert (if none provided)
  - Initializes SQLite database
  - Enables and starts systemd services
- [ ] Uninstall script removes everything
- [ ] Optional: DEB/RPM package generation

**Priority**: P1 | **Complexity**: M | **Dependencies**: S10.1

**TDD Commits**:
1. `feat(deploy): add installation script with user/directory/cert setup`
2. `build: add packaging targets for install/uninstall`

---

### S10.3: Log Rotation and Storage Management

**Description**: As a system administrator, I want automatic log rotation and storage management, so that the device doesn't run out of disk space.

**Acceptance Criteria**:
- [ ] SQLite database rotation when exceeding max_db_size_mb (archive old, create new)
- [ ] Syslog integration for daemon logs (logrotate compatible)
- [ ] Data directory size monitoring with alerts at 80% capacity
- [ ] Configurable retention policy (keep last N days of data)
- [ ] Old archives auto-deleted when space is needed

**Priority**: P2 | **Complexity**: S | **Dependencies**: S4.3

**TDD Commits**:
1. `feat(collectord): add database rotation and retention policy`
2. `feat(deploy): add logrotate configuration`

---

### S10.4: Health Monitoring and Watchdog

**Description**: As a system administrator, I want automatic health monitoring with watchdog capability, so that failed daemons are automatically restarted.

**Acceptance Criteria**:
- [ ] sniffd publishes heartbeat to systemd watchdog (sd_notify)
- [ ] Health checks: BPF modules loaded, ring buffer consuming, IPC responsive
- [ ] Systemd WatchdogSec configured (restart on heartbeat timeout)
- [ ] Health status exposed via REST API (`GET /api/v1/health`)
- [ ] Health includes: daemon uptime, module status, map sizes, event rates

**Priority**: P2 | **Complexity**: M | **Dependencies**: S7.1, S8.1

**TDD Commits**:
1. `feat(sniffd): add systemd watchdog heartbeat and health checks`
2. `feat(api): implement health endpoint with comprehensive status`

---

### S10.5: Upgrade and Rollback Procedure

**Description**: As a system administrator, I want a documented and tested upgrade procedure with rollback capability, so that firmware updates don't cause downtime.

**Acceptance Criteria**:
- [ ] Upgrade script: stop daemons → backup current → install new → start daemons
- [ ] BPF module hot-swap: load new modules without unloading old ones first (prog_array update)
- [ ] Config migration: detect schema changes, apply migrations
- [ ] Rollback: restore backup if new version fails health check
- [ ] Version tracking in system_state table
- [ ] Zero-downtime upgrade for BPF modules (atomic prog_array swap)

**Priority**: P2 | **Complexity**: M | **Dependencies**: S10.2

**TDD Commits**:
1. `feat(deploy): add upgrade script with backup and rollback`
2. `feat(sniffd): implement atomic BPF module hot-swap via prog_array`

---

## v0.9.0 已完成项目 (Post-Deployment Fixes & Enhancements)

> 部署后通过实际测试完成的修复和增强，共 11 个提交。

### DHCP 保护子系统 (新增)

**已完成功能**:
- [x] DHCP 服务器自动检测（从背景流量 bg_collector 识别 DHCP Offer/ACK）
- [x] DHCP 服务器豁免管理 API（GET/POST/DELETE /api/v1/dhcp/exceptions）
- [x] DHCP 告警 API（GET /api/v1/dhcp/alerts）
- [x] Dashboard 告警面板（未受保护的 DHCP 服务器，一键添加豁免）
- [x] 主动 DHCP 探测（aggressive 模式，可开关，定期发送 DHCP Discovery）
- [x] 区分 DHCP 服务器与客户端（通过消息类型 Offer/ACK vs Discover/Request）
- [x] Protected 状态正确查找（匹配 IP 而非 ID）

**相关提交**: fd15333, f4c746d, 8c68196, 625ca5a

### 配置界面重新设计 (新增)

**已完成功能**:
- [x] 接口角色配置：monitor（监听）、manage（管理）、mirror（镜像）
- [x] 按接口 VLAN 配置（从全局列表迁移到每接口卡片内 VLAN 表格）
- [x] 管理接口额外字段：网关 (gateway)、DNS 服务器
- [x] 当前配置显示：原始 YAML + 结构化表单
- [x] 接口配置 API（GET/PUT /api/v1/config/interfaces）

**相关提交**: 6fb1962, 9173c22, 9b6129a

### VLAN 自动检测 (新增)

**已完成功能**:
- [x] 从背景流量自动检测 VLAN ID
- [x] VLAN 发现 API（GET /api/v1/discovery/vlans）
- [x] Discovery 页面展示已发现的 VLAN

**相关提交**: 86e9a6c

### Dashboard 增强

**已完成功能**:
- [x] 统计卡片点击导航（攻击数→日志攻击标签页，哨兵数→哨兵页，嗅探器→发现页，威胁数→日志威胁标签页）
- [x] DHCP 告警面板（显示未保护的 DHCP 服务器）

**相关提交**: 9b6129a

### Bug 修复

- [x] 静态哨兵 ping 无响应 (e061fa8)
- [x] 动态哨兵部署失败 (e061fa8)
- [x] 统计计数和冻结功能异常 (e061fa8)
- [x] EVENT_HDR_LEN 44→48 结构体对齐 (d22b701)
- [x] 背景流量日志 src/dst IP 和 MAC 字段为空 (d21510c)
- [x] L4 端口解析错误 (625ca5a)
- [x] 单播 DHCP 报文未捕获 (625ca5a)
- [x] 配置显示空白 (9b6129a)
- [x] 发现页字段缺失 (9b6129a)
- [x] VLAN 子网布局问题 (9b6129a)

---

## Development Phase Map

```
Phase 1: Foundation (Weeks 1-2)
├── E1: S1.1 → S1.2 → S1.3 → S1.4 → S1.5 → S1.6 → S1.7 → S1.8
│
Phase 2: Core Deception (Weeks 3-6)
├── E2: S2.1 → S2.2 → S2.3 → S2.4 → S2.5 → S2.6 → S2.7 → S2.8
├── E7: S7.1 → S7.2 → S7.3 (parallel with E2)
│
Phase 3: Data Pipeline (Weeks 7-8)
├── E4: S4.1 → S4.2 → S4.3 → S4.4 → S4.5 → S4.6 → S4.7
├── E7: S7.6 (parallel with E4)
│
Phase 4: Traffic Engine (Weeks 9-10)
├── E3: S3.1 → S3.2 → S3.3 → S3.4 → S3.5 → S3.6
│
Phase 5: Config System (Weeks 11-12)
├── E5: S5.1 → S5.2 → S5.3 → S5.4 → S5.5 → S5.6 → S5.7
├── E7: S7.5 (parallel with E5)
│
Phase 6: Background Collection (Week 13)
├── E6: S6.1 → S6.2 → S6.3 → S6.4 → S6.5 → S6.6
│
Phase 7: Management Interface (Weeks 14-15)
├── E8: S8.1 → S8.2 → S8.3 → S8.4 → S8.5 → S8.6 → S8.7
├── E7: S7.4, S7.7, S7.8 (parallel with E8)
│
Phase 8: Quality & Deployment (Weeks 16-18)
├── E9: S9.1 → S9.2 → S9.3 → S9.4 → S9.5
├── E10: S10.1 → S10.2 → S10.3 → S10.4 → S10.5
```

### Dependency Graph (Critical Path)

```
S1.1 ──▶ S1.2 ──▶ S1.4 ──▶ S1.5 ──▶ S2.1 ──▶ S2.4 ──▶ S4.2 ──▶ S7.3
  │        │        │                   │                     │
  │        │        ▼                   ▼                     ▼
  │        │      S1.7               S2.2                   S4.3
  │        │                          │                      │
  │        ▼                          ▼                      ▼
  │      S1.3                       S2.3                   S4.6
  │                                                          │
  ▼                                                          ▼
S1.6 ──▶ S5.1 ──▶ S5.2 ──▶ S5.3                          S7.7
           │
           ▼
         S1.8 ──▶ S4.3 ──▶ S7.6
```

**Critical path**: S1.1 → S1.2 → S1.4 → S1.5 → S2.1 → S2.4 → S4.2 → S7.3 → Integration tests

---

## Story Count Summary

| Epic | Stories | P0 | P1 | P2 | P3 |
|------|---------|----|----|----|----|
| E1: Platform Foundation | 8 | 8 | 0 | 0 | 0 |
| E2: Dynamic Trapping | 8 | 4 | 4 | 0 | 0 |
| E3: Traffic Weaving | 6 | 0 | 5 | 1 | 0 |
| E4: Data Collation | 7 | 2 | 4 | 1 | 0 |
| E5: Configuration Mgmt | 7 | 2 | 4 | 1 | 0 |
| E6: Background Collection | 6 | 0 | 1 | 5 | 0 |
| E7: User-space Daemons | 8 | 3 | 4 | 1 | 0 |
| E8: Management Interface | 7 | 0 | 5 | 2 | 0 |
| E9: Testing & Quality | 5 | 1 | 2 | 2 | 0 |
| E10: Deployment & Ops | 5 | 0 | 2 | 3 | 0 |
| **Total** | **67** | **20** | **31** | **16** | **0** |

---

*End of Product Backlog*
