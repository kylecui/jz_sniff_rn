# jz_sniff_rn Development Guide

This document provides a comprehensive overview of the jz_sniff_rn project, its development history, architecture, and instructions for building and extending the system.

## 1. Project Overview

jz_sniff_rn (Sniff Reborn) is a network security appliance firmware built on the rSwitch XDP platform. It reimagines legacy honeypot concepts for the eBPF era, moving hot-path operations directly into the kernel for high-performance deception and detection.

The primary goal is to provide deception-based threat detection, granular traffic analysis, and forensic capabilities. It uses a pipeline of eBPF modules to identify and respond to suspicious network activity at line rate.

For detailed specifications, refer to the following documents:
- [design.md](design.md): Canonical system architecture and design.
- [backlog.md](backlog.md): Product roadmap and task tracking.

## 2. Development History

The project has progressed through seven major phases, documented in the following commits:

1.  **67a905e** feat(scaffold): Phase 1. Established the project structure, BPF headers, build system, and test framework. (~1,800 lines)
2.  **aa9d365** chore(config): Added .editorconfig and .gitattributes to ensure consistent LF line endings across environments. (~30 lines)
3.  **205eac3** feat(bpf): Phase 2. Implemented the dynamic trapping engine, including ARP/ICMP honeypots, sniffer detection, and the fake MAC pool. (~1,300 lines)
4.  **f1858ab** feat(bpf): Phase 3. Developed the traffic weaving engine with per-flow steering capabilities. (~530 lines)
5.  **20cff53** feat(bpf): Phase 4. Added threat detection, forensic sampling, and background collection modules. (~1,600 lines)
6.  **c020696** feat(config): Phase 5. Implemented the configuration management system, including the parser, translator, history, and diff modules. (~5,985 lines)
7.  **Phase 6**: Implemented IPC and logging common modules, all four user-space daemons (sniffd, configd, collectord, uploadd), and additional unit tests. (~6,235 lines)

8.  **Phase 7**: Completed daemon gaps — uploadd table name bug fix, collectord DB auto-pruning, configd remote TLS endpoint with mTLS support via vendored mongoose v7.20. Vendored cJSON v1.7.18 and mongoose v7.20 into third_party/. (~2,400 lines new code + 33,781 lines vendored)

9.  **Phase 8**: Implemented all three CLI tools — jzctl (604 lines, system management), jzlog (847 lines, log viewer with SQLite queries), jzguard (706 lines, guard table management with IPC). (~2,157 lines)

10. **Phase 9**: REST API & Deployment — 31-endpoint HTTPS management API (api.h/api.c, 2,153 lines) integrated into sniffd with bearer token auth, guard/whitelist CRUD, log queries with pagination, config IPC, stats endpoints. Four systemd service files with dependency ordering, security hardening, and watchdog support (167 lines). sniffd main.c updated with API init/poll/destroy lifecycle and 6 new CLI options. (~2,393 lines)

Total implementation: ~24,287 lines of C across 66 source files (plus 33,781 lines vendored).

## 3. Architecture Overview

### BPF Pipeline
The data plane consists of a series of BPF modules executed in the rSwitch pipeline. Each module handles a specific security or deception task:

- **guard_classifier (21)**: Identifies if a packet targets a guarded IP address.
- **arp_honeypot (22)**: Generates fake ARP replies for guarded IPs.
- **icmp_honeypot (23)**: Generates fake ICMP echo replies for guarded IPs.
- **sniffer_detect (24)**: Monitors responses to ARP probes to detect sniffers.
- **traffic_weaver (25)**: Applies per-flow steering (pass, drop, redirect, mirror).
- **bg_collector (26)**: Captures broadcast and multicast traffic for baselining.
- **threat_detect (27)**: Performs fast-path pattern matching for known threats.
- **forensics (28)**: Samples suspicious packets for offline analysis.

### User-Space Library Modules
The common library provides shared functionality for the daemons:

- **db**: SQLite wrapper for persisting logs and history.
- **mac_pool**: Manages the synthetic MAC address pool.
- **config**: YAML parser and in-memory configuration schema.
- **config_map**: Translates configuration into BPF map entries.
- **config_history**: Tracks configuration versions and snapshots.
- **config_diff**: Computes differences between configuration versions.
- **ipc**: Unix domain socket IPC with epoll and length-prefix framing (server + client).
- **log**: Structured logging with syslog integration and configurable levels.

### User-Space Daemons
Four daemons are implemented with core functionality:

- **sniffd** (src/sniffd/): Main orchestrator — BPF module loader, event ring buffer consumer, ARP probe generator, guard table manager, REST API server, signal handling. Sub-modules: bpf_loader.c/.h (429 lines), ringbuf.c/.h (318 lines), probe_gen.c/.h (472 lines), guard_mgr.c/.h (557 lines), api.c/.h (2,153 lines), main.c (800 lines).
- **configd** (src/configd/): Configuration manager — inotify file watcher, hot-reload orchestration, config validation pipeline, BPF map push, remote TLS config endpoint with mTLS. Sub-modules: remote.c/.h (425 lines), main.c (888 lines). Uses vendored mongoose v7.20 for HTTPS server.
- **collectord** (src/collectord/): Event collector — deduplication via MAC+type+window, token-bucket rate limiter, SQLite batch writes, full JSON record export via cJSON, DB auto-pruning of uploaded records. main.c (1,021 lines).
- **uploadd** (src/uploadd/): Upload agent — batch assembly from pending DB records, gzip compression, retry with exponential backoff, native HTTPS client via vendored mongoose v7.20 with mTLS support. main.c (1,102 lines).

### Build System
A top-level Makefile handles auto-discovery of BPF modules and user-space components. It supports CO-RE (Compile Once, Run Everywhere) for BPF portability.

## 4. Complete File Inventory

The project consists of 66 implemented source files (~24,287 lines of C), organized as follows:

### BPF Modules and Headers (11 files, ~2,420 lines)
- **bpf/include/jz_common.h**: Shared constants and stage numbers. (80 lines)
- **bpf/include/jz_events.h**: Event structure definitions. (67 lines)
- **bpf/include/jz_maps.h**: BPF map definitions. (216 lines)
- **bpf/jz_arp_honeypot.bpf.c**: ARP response logic. (251 lines)
- **bpf/jz_bg_collector.bpf.c**: Background traffic capture. (312 lines)
- **bpf/jz_forensics.bpf.c**: Packet sampling logic. (194 lines)
- **bpf/jz_guard_classifier.bpf.c**: Guard lookup and classification. (236 lines)
- **bpf/jz_icmp_honeypot.bpf.c**: ICMP response logic. (257 lines)
- **bpf/jz_sniffer_detect.bpf.c**: Sniffer detection logic. (181 lines)
- **bpf/jz_threat_detect.bpf.c**: Pattern matching engine. (344 lines)
- **bpf/jz_traffic_weaver.bpf.c**: Traffic steering engine. (282 lines)

### User-Space Common Library (16 files, ~6,889 lines)
- **config.c / .h**: YAML configuration management. (2,509 lines)
- **config_diff.c / .h**: Configuration diffing. (674 lines)
- **config_history.c / .h**: Version history management. (591 lines)
- **config_map.c / .h**: BPF map translation. (990 lines)
- **db.c / .h**: SQLite database wrapper with query and pruning APIs. (936 lines)
- **mac_pool.c / .h**: Fake MAC management. (250 lines)
- **ipc.c / .h**: Unix domain socket IPC (server + client). (695 lines)
- **log.c / .h**: Structured logging with syslog integration. (244 lines)

### User-Space Daemons (14 files, ~7,985 lines)
- **src/sniffd/main.c**: Orchestrator daemon main loop. (800 lines)
- **src/sniffd/bpf_loader.c / .h**: BPF module lifecycle manager (8 slots). (429 lines)
- **src/sniffd/ringbuf.c / .h**: Dual ring buffer consumer (events + forensic samples). (318 lines)
- **src/sniffd/probe_gen.c / .h**: ARP probe generator with timerfd scheduling. (472 lines)
- **src/sniffd/guard_mgr.c / .h**: Guard table manager (CRUD, TTL, IPC). (557 lines)
- **src/sniffd/api.c / .h**: REST API server (31 HTTPS endpoints, bearer auth, mongoose). (2,153 lines)
- **src/configd/main.c**: Configuration manager daemon with BPF map push. (888 lines)
- **src/configd/remote.c / .h**: Remote TLS config endpoint (mTLS, mongoose). (425 lines)
- **src/collectord/main.c**: Event collector daemon with DB auto-pruning. (1,021 lines)
- **src/uploadd/main.c**: Upload agent daemon with native HTTPS. (1,102 lines)

### Tests (16 files, ~3,698 lines)
- **tests/bpf/test_*.c**: 8 BPF module tests using prog_test_run. (~1,800 lines)
- **tests/unit/test_*.c**: 7 unit tests (config, config_diff, config_history, config_map, db, ipc, log). (~1,866 lines)
- **tests/unit/test_helpers.h**: Shared test utilities. (32 lines)

### CLI Tools (3 files, ~2,157 lines)
- **cli/jzctl.c**: System management CLI — status, module list/reload, stats, config show/reload/rollback, daemon restart. (604 lines)
- **cli/jzlog.c**: Log viewer CLI — attack, sniffer, background, audit, threat subcommands with SQLite direct queries, table/JSON output, tail -f mode. (847 lines)
- **cli/jzguard.c**: Guard table management CLI — add/del static/dynamic guards, whitelist add/del, probe start/stop/results, list with type filter and JSON output. (706 lines)

### Systemd Services (4 files, ~167 lines)
- **systemd/sniffd.service**: Main orchestrator — After=network-online.target rswitch.service, LimitMEMLOCK=infinity, WatchdogSec=60. (48 lines)
- **systemd/configd.service**: Config manager — After=sniffd.service, BindsTo=sniffd.service. (41 lines)
- **systemd/collectord.service**: Data collector — After=sniffd.service, BindsTo=sniffd.service. (38 lines)
- **systemd/uploadd.service**: Upload agent — After=collectord.service, Wants=network-online.target. (40 lines)

All services include: Restart=on-failure, NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes.

### Configuration and Scripts
- **config/base.yaml**: Default system configuration. (118 lines)
- **scripts/gen_vmlinux.sh**: Vmlinux.h generation script. (152 lines)

### Vendored Headers (include/rswitch/)
- **map_defs.h, module_abi.h, rswitch_bpf.h, uapi.h**: rSwitch SDK. (954 lines)

### Vendored Libraries (third_party/)
- **cjson/cJSON.c, cJSON.h**: cJSON v1.7.18 -- JSON parser/generator. (3,443 lines)
- **mongoose/mongoose.c, mongoose.h**: mongoose v7.20 -- Embedded HTTP/TLS server and client. (30,338 lines)

### Build and Project Files
- **Makefile, .gitignore, .editorconfig, .gitattributes, README.md, LICENSE**: Project metadata and build config.

## 5. Step-by-Step Build Instructions for Ubuntu

Follow these steps to build the project on Ubuntu 22.04 or newer.

### 1. System Requirements
- Ubuntu 22.04 LTS or newer
- Kernel 5.8+ with BTF support (verify: `ls /sys/kernel/btf/vmlinux`)
- rSwitch platform installed (provides the XDP pipeline framework)
- Root access for BPF map operations and installation

### 2. Install Build Dependencies
Run the following command to install all necessary tools and libraries:

```bash
sudo apt update
sudo apt install -y \
    clang llvm \
    libbpf-dev libelf-dev zlib1g-dev \
    libsqlite3-dev libcmocka-dev libyaml-dev \
    pkg-config \
    linux-tools-generic linux-headers-$(uname -r) \
    cppcheck lcov gcc make
```

Package purposes:
- `clang`, `llvm` -- BPF compilation (target bpf)
- `libbpf-dev`, `libelf-dev`, `zlib1g-dev` -- BPF loader and ELF parsing
- `libsqlite3-dev` -- Database for logs, config history, audit trail
- `libcmocka-dev` -- Unit test framework
- `libyaml-dev` -- YAML configuration parser
- `linux-tools-generic` -- Provides bpftool for vmlinux.h generation
- `linux-headers-$(uname -r)` -- Kernel headers for BPF type information
- `cppcheck` -- Static analysis (optional, for `make lint`)
- `lcov` -- Code coverage reporting (optional, for `make coverage`)

### 3. Clone the Repository

```bash
git clone <repository-url> jz_sniff_rn
cd jz_sniff_rn
```

### 4. Generate vmlinux.h
Generate the kernel type definitions required for CO-RE (Compile-Once, Run-Everywhere) BPF programs. This must be done on the target machine (or a machine with matching kernel BTF):

```bash
./scripts/gen_vmlinux.sh
```

The script:
- Checks for bpftool and kernel BTF support
- Generates `vmlinux.h` in the project root (~5-10MB)
- Skips regeneration if the file is already up-to-date
- Use `--force` to regenerate: `./scripts/gen_vmlinux.sh --force`

### 5. Build BPF Modules
Compile all 8 eBPF programs to BPF bytecode:

```bash
make bpf
```

Output: `build/bpf/*.bpf.o` (8 object files)

### 6. Build Common Library
Compile the shared user-space library:

```bash
make -j$(nproc) $(ls src/common/*.c | sed 's|src/common/|build/common/|;s|\.c$|.o|')
```

Or simply build everything (daemons depend on common):

```bash
make user
```

Note: All four daemons (sniffd, configd, collectord, uploadd) have core implementations. The `make user` target builds the common library and all daemon binaries. CLI tools (`cli/`) are built separately with `make cli`.

### 7. Run Tests

```bash
# Run all tests (unit + BPF)
make test

# Run only unit tests (config, db, mac_pool, etc.)
make test-unit

# Run only BPF tests (requires root for prog_test_run)
sudo make test-bpf
```

### 8. Generate Coverage Report

```bash
make coverage
# Open build/coverage/index.html in a browser
```

### 9. Static Analysis

```bash
make lint
```

### 10. Install to System

```bash
# Install to /usr/local (default)
sudo make install

# Install to /usr for system-wide
sudo make install PREFIX=/usr

# Stage for packaging (e.g., Debian package build)
make install DESTDIR=/tmp/jz-pkg PREFIX=/usr

# Uninstall
sudo make uninstall
```

### 11. Clean Build Artifacts

```bash
make clean
```

## 6. Configuration Reference

The system uses YAML profiles for configuration. The base configuration is located at `config/base.yaml` and is installed to `/etc/jz/base.yaml`.

### Key Sections
- **system**: Device identity, logging levels, and directory paths.
- **modules**: Enable/disable flags and stage assignments for BPF modules.
- **guards**: Static and dynamic guard IP definitions and whitelist entries.
- **fake_mac_pool**: OUI prefix and size for the synthetic MAC pool.
- **policies**: Per-flow traffic steering rules (5-tuple matches).
- **threats**: Header-based threat patterns and IP blacklists.
- **collector**: SQLite database settings, deduplication windows, and rate limits.
- **uploader**: Remote management platform URL and upload intervals.
- **api**: REST API listener settings and authentication tokens.

## 7. BPF Module Reference

### jz_guard_classifier (Stage 21)
- **Purpose**: Gatekeeper for the deception engine.
- **Maps**: `jz_static_guards`, `jz_dynamic_guards`, `jz_whitelist`.
- **Events**: None.
- **Operation**: Performs lookups in guard and whitelist maps. Sets classification results in a per-CPU map for downstream modules.

### jz_arp_honeypot (Stage 22)
- **Purpose**: Responds to ARP requests for guarded IPs.
- **Maps**: `jz_arp_config`, `jz_fake_mac_pool`, `jz_arp_rate`.
- **Events**: `JZ_EVENT_ATTACK_ARP`.
- **Operation**: Crafts a fake ARP reply in-place and uses `XDP_TX` to transmit it.

### jz_icmp_honeypot (Stage 23)
- **Purpose**: Responds to ICMP echo requests for guarded IPs.
- **Maps**: `jz_icmp_config`, `jz_icmp_rate`.
- **Events**: `JZ_EVENT_ATTACK_ICMP`.
- **Operation**: Crafts a fake ICMP echo reply and transmits it via `XDP_TX`.

### jz_sniffer_detect (Stage 24)
- **Purpose**: Detects promiscuous-mode sniffers.
- **Maps**: `jz_probe_targets`, `jz_sniffer_suspects`.
- **Events**: `JZ_EVENT_SNIFFER_DETECTED`.
- **Operation**: Monitors ARP replies to identify responses to non-existent IP probes.

### jz_traffic_weaver (Stage 25)
- **Purpose**: Per-flow traffic steering.
- **Maps**: `jz_flow_policy`, `jz_redirect_config`, `jz_flow_stats`.
- **Events**: `JZ_EVENT_POLICY_MATCH`.
- **Operation**: Matches flows against a 5-tuple and applies steering actions.

### jz_bg_collector (Stage 26)
- **Purpose**: Captures background network traffic.
- **Maps**: `jz_bg_filter`, `jz_bg_stats`.
- **Events**: `JZ_EVENT_BG_CAPTURE`.
- **Operation**: Identifies broadcast/multicast protocols and emits capture events.

### jz_threat_detect (Stage 27)
- **Purpose**: Fast-path threat detection.
- **Maps**: `jz_threat_patterns`, `jz_threat_blacklist`, `jz_threat_stats`.
- **Events**: `JZ_EVENT_THREAT_DETECTED`.
- **Operation**: Matches packet headers against known malicious patterns.

### jz_forensics (Stage 28)
- **Purpose**: Forensic packet sampling.
- **Maps**: `jz_sample_config`.
- **Events**: None (emits raw samples to a dedicated ring buffer).
- **Operation**: Captures packet payloads based on flags or random sampling.

## 8. User-Space Library API Reference

### db (db.h / db.c)
- **Purpose**: SQLite wrapper for attack logs, sniffer records, bg captures, config history, audit trail, and system state.
- **Key Functions**:
  - `jz_db_open(jz_db_t *ctx, const char *path)` -- Open database, create schema if needed.
  - `jz_db_close(jz_db_t *ctx)` -- Close database handle.
  - `jz_db_insert_attack(...)` -- Insert attack log record with packet sample.
  - `jz_db_insert_sniffer(...)` -- Insert sniffer detection record.
  - `jz_db_insert_bg_capture(...)` -- Insert background capture statistics.
  - `jz_db_insert_config(...)` -- Insert config version record.
  - `jz_db_insert_audit(...)` -- Insert audit trail entry.
  - `jz_db_set_state / jz_db_get_state` -- Key-value system state storage.
  - `jz_db_mark_uploaded / jz_db_pending_count` -- Upload sync tracking.
- **Dependencies**: libsqlite3.

### mac_pool (mac_pool.h / mac_pool.c)
- **Purpose**: Generate and manage synthetic MAC addresses for guard IPs, with BPF map sync.
- **Key Functions**:
  - `jz_mac_pool_init(pool, config)` -- Initialize pool with OUI prefix and size.
  - `jz_mac_pool_destroy(pool)` -- Free resources (does NOT unpin BPF map).
  - `jz_mac_pool_alloc(pool, guard_ip)` -- Allocate/lookup MAC for a guard IP (round-robin).
  - `jz_mac_pool_release(pool, guard_ip)` -- Release MAC assignment.
  - `jz_mac_pool_sync_bpf(pool)` -- Write pool state to pinned BPF map.
  - `jz_mac_pool_sync_bpf_fd(pool, map_fd)` -- Write pool state to specific map FD.
- **Dependencies**: None (BPF map interaction via bpf syscall).

### config (config.h / config.c)
- **Purpose**: YAML configuration parsing, validation, defaults, profile merging, and serialization.
- **Key Types**: `jz_config_t` (master config struct), `jz_config_errors_t` (validation errors).
- **Key Functions**:
  - `jz_config_load(cfg, path, errors)` -- Parse YAML file into jz_config_t.
  - `jz_config_load_merged(cfg, base_path, overlay_path, errors)` -- Load base + overlay merge.
  - `jz_config_validate(cfg, errors)` -- Validate loaded config (IP formats, ranges, stages).
  - `jz_config_defaults(cfg)` -- Initialize config to base.yaml defaults.
  - `jz_config_serialize(cfg)` -- Serialize config back to YAML string (caller frees).
  - `jz_config_free(cfg)` -- Free dynamically allocated resources.
- **Dependencies**: libyaml.
- **Note**: Uses event-based libyaml parser (yaml_parser_parse loop), not document API.

### config_map (config_map.h / config_map.c)
- **Purpose**: Translate `jz_config_t` into BPF map entry payloads ready for bpf_map_update_elem.
- **Key Types**: `jz_config_map_batch_t` (~800KB+ -- MUST be heap-allocated).
- **Key Functions**:
  - `jz_config_to_maps(cfg, batch)` -- Translate full config to map batch.
  - `jz_config_load_blacklist(path, batch)` -- Load IP blacklist file, append to batch.
  - `jz_config_generate_macs(prefix, count, batch)` -- Generate fake MAC entries.
- **Dependencies**: config.h (forward-declared jz_config_t).

### config_history (config_history.h / config_history.c)
- **Purpose**: Configuration version history tracking with rollback support.
- **Key Types**: `jz_config_version_t`, `jz_config_version_list_t`.
- **Key Functions**:
  - `jz_config_history_init(db)` -- Create config_history table if not exists.
  - `jz_config_history_current_version(db)` -- Get latest version number.
  - `jz_config_history_save(db, version, yaml, source, actor)` -- Save new version.
  - `jz_config_history_get(db, version, out)` -- Retrieve specific version.
  - `jz_config_history_list(db, limit, out)` -- List versions (newest first).
  - `jz_config_history_rollback(db, target, actor, yaml, buflen)` -- Rollback to version.
  - `jz_config_history_prune(db, keep_count)` -- Prune old versions.
  - `jz_config_version_list_free(list)` -- Free query results.
- **Dependencies**: db.h (jz_db_t).

### config_diff (config_diff.h / config_diff.c)
- **Purpose**: Compute section-level diffs between configs and maintain JSON audit logs.
- **Key Types**: `jz_config_diff_t` (up to 256 diff entries), `jz_audit_entry_t`.
- **Key Functions**:
  - `jz_config_diff(old_cfg, new_cfg, diff)` -- Compute diff (old_cfg can be NULL).
  - `jz_config_audit_log(db, action, actor, diff, result)` -- Write audit entry to DB.
  - `jz_config_audit_query(db, since, until, filter, results, count)` -- Query audit log.
  - `jz_config_audit_free(results)` -- Free query results.
- **Dependencies**: db.h (jz_db_t), config.h (jz_config_t, forward-declared).

### ipc (ipc.h / ipc.c)
- **Purpose**: Unix domain socket IPC for inter-daemon communication with epoll event loop and length-prefix framing.
- **Key Types**: `jz_ipc_server_t` (server with multi-client epoll), `jz_ipc_client_t` (blocking client).
- **Key Functions**:
  - `jz_ipc_server_init(srv, path, handler, user_data)` -- Create server socket, bind, listen.
  - `jz_ipc_server_destroy(srv)` -- Close server and all client connections.
  - `jz_ipc_server_poll(srv, timeout_ms)` -- Epoll wait + dispatch to handler callback.
  - `jz_ipc_server_broadcast(srv, msg, len)` -- Send message to all connected clients.
  - `jz_ipc_client_connect(cli, path)` -- Connect to server socket.
  - `jz_ipc_client_send(cli, msg, len)` -- Send length-prefixed message.
  - `jz_ipc_client_recv(cli, buf, buflen, timeout_ms)` -- Receive with timeout.
  - `jz_ipc_client_close(cli)` -- Disconnect.
- **Protocol**: 4-byte big-endian length prefix + payload. Max message: 64KB.
- **Dependencies**: None (POSIX sockets + epoll).

### log (log.h / log.c)
- **Purpose**: Structured logging with syslog integration and configurable per-module levels.
- **Key Functions**:
  - `jz_log_init(ident, facility, min_level)` -- Open syslog and set minimum level.
  - `jz_log_close()` -- Close syslog.
  - `jz_log(level, fmt, ...)` -- Log with level (DEBUG, INFO, WARN, ERROR, FATAL).
  - `JZ_LOG_DEBUG/INFO/WARN/ERROR/FATAL(fmt, ...)` -- Convenience macros with file:line.
- **Dependencies**: syslog.h (POSIX).

## 9. Key Technical Decisions & Discoveries

1.  **Tail Call Mechanism**: rSwitch uses auto-incrementing slots for tail calls. Modules do not use stage numbers directly for the `bpf_tail_call` index.
2.  **Context Limitations**: The `rs_ctx` reserved area is limited to 16 bytes. Use per-CPU maps to pass complex state between pipeline modules.
3.  **Memory Alignment**: ARP packets often have unaligned IP fields. Use `__builtin_memcpy` helpers for all IP field access in ARP modules to avoid verifier errors.
4.  **Checksum Updates**: ICMP honeypot uses incremental checksum updates when changing the type from 8 (request) to 0 (reply).
5.  **Map References**: Use `extern` map declarations in BPF modules to reference maps defined in other modules or the core platform.
6.  **Heap Allocation**: The `config_map_batch_t` structure exceeds 800KB. It must be allocated on the heap to avoid stack overflow.
7.  **Config Schema**: The configuration library uses nested anonymous structs to handle modules with extra parameters while maintaining a clean hierarchy.
8.  **Threat IDs**: Threat pattern IDs are strings in the YAML config but are parsed into `uint32_t` for efficient BPF map lookups.
9.  **IPC Protocol**: Inter-daemon communication uses Unix domain sockets with a 4-byte big-endian length prefix. Max message size is 64KB. The server uses epoll for non-blocking multi-client handling.
10. **Daemon Architecture**: All four daemons follow a common pattern: signal-driven main loop with `signalfd`, epoll for I/O multiplexing, graceful shutdown via SIGTERM/SIGINT, and PID file management.
11. **REST API Design**: The REST API runs inside sniffd (not as a separate daemon) per design.md §4.6. It uses mongoose for HTTPS with bearer token auth. Guard/whitelist endpoints read BPF maps directly via bpf_map_get_next_key/lookup_elem. Config endpoints use IPC client to communicate with configd. Policy endpoints are stubbed (501) pending a policy manager module.
12. **Mongoose Routing**: mg_match() does exact pattern matching, not prefix matching. `/api/v1/guards` does NOT match `/api/v1/guards/static` — each route needs its own handler entry.

## 10. Remaining Work

### Overall: ~5% remaining

### ~~Critical: rSwitch Integration Bugs~~ (All Fixed)
1. ✅ ~~RS_FLAG_MAY_REDIRECT undefined~~ -- Added to `module_abi.h`.
2. ✅ ~~bpf_loader slot indexing~~ -- Consecutive slot assignment with proper lifecycle.
3. ✅ ~~Stage number conflicts~~ -- Remapped to 21-28 (VLAN-to-ACL gap).
4. ✅ ~~Guard cap mismatch~~ -- `config_map.h` arrays increased to 4096.
5. ✅ ~~Threat loop bound~~ -- Increased to 128 iterations (verifier-safe bounded loop).

### ~~Daemon Gaps~~ (All Complete)
- **sniffd**: ✅ Complete — probe_gen, guard_mgr, REST API, main.c integration all done.
- **configd**: ✅ Complete — BPF map push, remote TLS endpoint (mTLS via mongoose), CLI options for TLS cert/key/CA.
- **collectord**: ✅ Complete — Full JSON record export (cJSON), DB auto-pruning (uploaded + age-based).
- **uploadd**: ✅ Bug fixed (bg_captures → bg_capture table name). ✅ Native HTTPS client (mongoose, replaced curl shell-out).

### Vendored Dependencies
- **cJSON v1.7.18** (third_party/cjson/) — JSON serialization for collectord export. (3,443 lines)
- **mongoose v7.20** (third_party/mongoose/) — HTTPS server/client with built-in TLS 1.3. (30,338 lines)

### ~~Phase 7.5: uploadd Native HTTPS~~ (Complete)
- **uploadd**: ✅ Replaced curl shell-out with mongoose-based HTTPS client. mTLS support, 10s connect / 30s response timeout, graceful shutdown aware. Version bumped to 0.8.0.

### ~~Phase 8: CLI Tools~~ (Complete)
Three CLI tools in `cli/` directory:
- **jzctl** (604 lines): ✅ System management — status, module list/reload, stats, config show/reload/rollback, daemon restart via PID+SIGHUP.
- **jzguard** (706 lines): ✅ Guard table management — add/del static/dynamic guards, whitelist add/del, probe start/stop/results, list with --type filter and --format json output. Graceful handling of unimplemented sniffd commands.
- **jzlog** (847 lines): ✅ Log viewer — attack, sniffer, background, audit, threat subcommands with direct SQLite queries, prepared statements, table/JSON output, tail -f mode with configurable interval.

### ~~Phase 9: REST API & Deployment~~ (Complete)
- **REST API** (api.h + api.c, 2,153 lines): ✅ 31 HTTPS endpoints via mongoose, bearer token auth, guard/whitelist CRUD (direct BPF map iteration), log queries with pagination (SQLite LIMIT/OFFSET), config get/set via IPC to configd, stats from guard_mgr and bpf_loader, health/status/modules endpoints. Policy endpoints stubbed as 501.
- **Systemd services** (4 files, 167 lines): ✅ sniffd/configd/collectord/uploadd with proper dependency ordering (After/BindsTo/Wants), security hardening (NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp), watchdog (sniffd WatchdogSec=60), LimitMEMLOCK=infinity for BPF.
- **sniffd integration**: ✅ main.c updated (727→800 lines) with API lifecycle (init/poll/destroy), 6 new CLI options (--api-port, --api-cert, --api-key, --api-ca, --api-token, --no-api), version bumped to 0.8.0.

### Phase 10: Integration & Validation
- End-to-end integration tests with rSwitch pipeline.
- Performance benchmarks (PPS, latency at line rate).
- Final documentation and deployment guide.

## 11. Development Guidelines

### Commit Convention
Use the following format for all commits: `<type>(<scope>): <description>`
Types: `feat`, `fix`, `chore`, `test`, `docs`, `refactor`.

### BPF Module Template
All BPF modules follow this standard boilerplate:

```c
// SPDX-License-Identifier: GPL-2.0
#include "rswitch_bpf.h"
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

RS_DECLARE_MODULE("jz_module_name",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_NUMBER,       /* e.g. 21, 22, 23... */
                  RS_MODULE_F_NONE,
                  "Module description");

SEC("xdp")
int jz_module_name(struct xdp_md *ctx)
{
    struct rs_ctx *rs = rs_ctx_get(ctx);
    if (!rs)
        return XDP_PASS;

    /* --- module logic here --- */

    /* Continue to next module in pipeline */
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Testing
- BPF module tests go in `tests/bpf/test_<module>.c` -- use cmocka + BPF prog_test_run pattern.
- Unit tests go in `tests/unit/test_<module>.c` -- use cmocka with standard setup/teardown.
- Shared test utilities in `tests/unit/test_helpers.h`.
- All test files are auto-discovered by the Makefile (wildcard on `test_*.c`).

### Map Pinning
All jz-specific maps must be pinned under the `/sys/fs/bpf/jz/` namespace to avoid collisions with rSwitch core maps.

### Integration Rules
- Do not modify rSwitch core source code. All integration must happen through the module system and shared maps.
- rSwitch headers are vendored in `include/rswitch/` -- include `rswitch_bpf.h` to get everything.
- Use `extern` map declarations to reference maps defined in other modules.

### Install Paths

| Component | Default Path |
|---|---|
| Daemons (sniffd, configd, ...) | `/usr/local/sbin/` |
| CLI tools (jzctl, jzguard, jzlog) | `/usr/local/bin/` |
| BPF objects (.bpf.o) | `/etc/jz/bpf/` |
| Configuration (base.yaml) | `/etc/jz/` |
| Config profiles | `/etc/jz/profiles/` |
| Database and data | `/var/lib/jz/` |
| Runtime (PID, sockets) | `/var/run/jz/` |
| Systemd services | `/etc/systemd/system/` |

Override with `PREFIX=`, `DESTDIR=`, or individual path variables in the Makefile.
