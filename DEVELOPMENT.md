# jz_sniff_rn Development Guide

This document provides a comprehensive overview of the jz_sniff_rn project, its development history, architecture, and instructions for building and extending the system.

## 1. Project Overview

jz_sniff_rn (Sniff Reborn) is a network security appliance firmware built on the rSwitch XDP platform. It reimagines legacy honeypot concepts for the eBPF era, moving hot-path operations directly into the kernel for high-performance deception and detection.

The primary goal is to provide deception-based threat detection, granular traffic analysis, and forensic capabilities. It uses a pipeline of eBPF modules to identify and respond to suspicious network activity at line rate.

For detailed specifications, refer to the following documents:
- [design.md](design.md): Canonical system architecture and design.
- [backlog.md](backlog.md): Product roadmap and task tracking.

## 2. Development History

The project has progressed through five major phases, documented in the following commits:

1.  **67a905e** feat(scaffold): Phase 1. Established the project structure, BPF headers, build system, and test framework. (~1,800 lines)
2.  **aa9d365** chore(config): Added .editorconfig and .gitattributes to ensure consistent LF line endings across environments. (~30 lines)
3.  **205eac3** feat(bpf): Phase 2. Implemented the dynamic trapping engine, including ARP/ICMP honeypots, sniffer detection, and the fake MAC pool. (~1,300 lines)
4.  **f1858ab** feat(bpf): Phase 3. Developed the traffic weaving engine with per-flow steering capabilities. (~530 lines)
5.  **20cff53** feat(bpf): Phase 4. Added threat detection, forensic sampling, and background collection modules. (~1,600 lines)
6.  **c020696** feat(config): Phase 5. Implemented the configuration management system, including the parser, translator, history, and diff modules. (~5,985 lines)

Total implementation: ~11,245 lines across 42 files.

## 3. Architecture Overview

### BPF Pipeline
The data plane consists of a series of BPF modules executed in the rSwitch pipeline. Each module handles a specific security or deception task:

- **guard_classifier (22)**: Identifies if a packet targets a guarded IP address.
- **arp_honeypot (23)**: Generates fake ARP replies for guarded IPs.
- **icmp_honeypot (24)**: Generates fake ICMP echo replies for guarded IPs.
- **sniffer_detect (25)**: Monitors responses to ARP probes to detect sniffers.
- **traffic_weaver (35)**: Applies per-flow steering (pass, drop, redirect, mirror).
- **bg_collector (40)**: Captures broadcast and multicast traffic for baselining.
- **threat_detect (50)**: Performs fast-path pattern matching for known threats.
- **forensics (55)**: Samples suspicious packets for offline analysis.

### User-Space Library Modules
The common library provides shared functionality for the daemons:

- **db**: SQLite wrapper for persisting logs and history.
- **mac_pool**: Manages the synthetic MAC address pool.
- **config**: YAML parser and in-memory configuration schema.
- **config_map**: Translates configuration into BPF map entries.
- **config_history**: Tracks configuration versions and snapshots.
- **config_diff**: Computes differences between configuration versions.

### Build System
A top-level Makefile handles auto-discovery of BPF modules and user-space components. It supports CO-RE (Compile Once, Run Everywhere) for BPF portability.

## 4. Complete File Inventory

The project consists of 42 implemented files, organized as follows:

### BPF Modules and Headers
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

### User-Space Library (src/common/)
- **config.c / .h**: YAML configuration management. (2,509 lines)
- **config_diff.c / .h**: Configuration diffing. (674 lines)
- **config_history.c / .h**: Version history management. (591 lines)
- **config_map.c / .h**: BPF map translation. (990 lines)
- **db.c / .h**: SQLite database wrapper. (600 lines)
- **mac_pool.c / .h**: Fake MAC management. (250 lines)

### Tests
- **tests/bpf/test_*.c**: 8 BPF module tests using prog_test_run. (1,666 lines)
- **tests/unit/test_*.c**: 5 unit tests for library modules. (1,463 lines)
- **tests/unit/test_helpers.h**: Shared test utilities. (32 lines)

### Configuration and Scripts
- **config/base.yaml**: Default system configuration. (118 lines)
- **scripts/gen_vmlinux.sh**: Vmlinux.h generation script. (152 lines)

### Vendored Headers (include/rswitch/)
- **map_defs.h, module_abi.h, rswitch_bpf.h, uapi.h**: rSwitch SDK. (954 lines)

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

Note: Daemon source files (`src/sniffd/`, `src/configd/`, etc.) are not yet implemented (Phase 7). The `make user` target will succeed for the common library but will fail for daemons until their source is created.

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

### jz_guard_classifier (Stage 22)
- **Purpose**: Gatekeeper for the deception engine.
- **Maps**: `jz_static_guards`, `jz_dynamic_guards`, `jz_whitelist`.
- **Events**: None.
- **Operation**: Performs lookups in guard and whitelist maps. Sets classification results in a per-CPU map for downstream modules.

### jz_arp_honeypot (Stage 23)
- **Purpose**: Responds to ARP requests for guarded IPs.
- **Maps**: `jz_arp_config`, `jz_fake_mac_pool`, `jz_arp_rate`.
- **Events**: `JZ_EVENT_ATTACK_ARP`.
- **Operation**: Crafts a fake ARP reply in-place and uses `XDP_TX` to transmit it.

### jz_icmp_honeypot (Stage 24)
- **Purpose**: Responds to ICMP echo requests for guarded IPs.
- **Maps**: `jz_icmp_config`, `jz_icmp_rate`.
- **Events**: `JZ_EVENT_ATTACK_ICMP`.
- **Operation**: Crafts a fake ICMP echo reply and transmits it via `XDP_TX`.

### jz_sniffer_detect (Stage 25)
- **Purpose**: Detects promiscuous-mode sniffers.
- **Maps**: `jz_probe_targets`, `jz_sniffer_suspects`.
- **Events**: `JZ_EVENT_SNIFFER_DETECTED`.
- **Operation**: Monitors ARP replies to identify responses to non-existent IP probes.

### jz_traffic_weaver (Stage 35)
- **Purpose**: Per-flow traffic steering.
- **Maps**: `jz_flow_policy`, `jz_redirect_config`, `jz_flow_stats`.
- **Events**: `JZ_EVENT_POLICY_MATCH`.
- **Operation**: Matches flows against a 5-tuple and applies steering actions.

### jz_bg_collector (Stage 40)
- **Purpose**: Captures background network traffic.
- **Maps**: `jz_bg_filter`, `jz_bg_stats`.
- **Events**: `JZ_EVENT_BG_CAPTURE`.
- **Operation**: Identifies broadcast/multicast protocols and emits capture events.

### jz_threat_detect (Stage 50)
- **Purpose**: Fast-path threat detection.
- **Maps**: `jz_threat_patterns`, `jz_threat_blacklist`, `jz_threat_stats`.
- **Events**: `JZ_EVENT_THREAT_DETECTED`.
- **Operation**: Matches packet headers against known malicious patterns.

### jz_forensics (Stage 55)
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

## 9. Key Technical Decisions & Discoveries

1.  **Tail Call Mechanism**: rSwitch uses auto-incrementing slots for tail calls. Modules do not use stage numbers directly for the `bpf_tail_call` index.
2.  **Context Limitations**: The `rs_ctx` reserved area is limited to 16 bytes. Use per-CPU maps to pass complex state between pipeline modules.
3.  **Memory Alignment**: ARP packets often have unaligned IP fields. Use `__builtin_memcpy` helpers for all IP field access in ARP modules to avoid verifier errors.
4.  **Checksum Updates**: ICMP honeypot uses incremental checksum updates when changing the type from 8 (request) to 0 (reply).
5.  **Map References**: Use `extern` map declarations in BPF modules to reference maps defined in other modules or the core platform.
6.  **Heap Allocation**: The `config_map_batch_t` structure exceeds 800KB. It must be allocated on the heap to avoid stack overflow.
7.  **Config Schema**: The configuration library uses nested anonymous structs to handle modules with extra parameters while maintaining a clean hierarchy.
8.  **Threat IDs**: Threat pattern IDs are strings in the YAML config but are parsed into `uint32_t` for efficient BPF map lookups.

## 10. Remaining Work (Phases 6-8)

### Phase 6: Background Collection Engine (User-Space)
BPF module `jz_bg_collector.bpf.c` is already complete (implemented in Phase 4). Remaining work is user-space processing:
- **S6.4**: Baseline statistics aggregation -- compute protocol distribution baselines from bg_collector events.
- **S6.5**: Anomaly detection -- detect deviations from established baselines.
- **S6.6**: Structured JSON export -- export baseline data for upload to management platform.

### Phase 7: User-Space Daemons
Four daemon directories exist but contain no source yet: `src/sniffd/`, `src/configd/`, `src/collectord/`, `src/uploadd/`.
- **S7.1**: `sniffd` -- BPF loader, event ring buffer consumer, ARP probe generator.
- **S7.2**: `configd` -- Config file watcher (inotify), hot-reload, BPF map applier via config_map.
- **S7.3**: `collectord` -- Event deduplication, SQLite persistence via db.h, rate limiting.
- **S7.4**: `uploadd` -- Batch upload to management platform (gzip + HTTPS).
- **S7.5-S7.8**: IPC (Unix sockets), signal handling, systemd integration, graceful shutdown.

### Phase 8: Management and Deployment
- **S8.1-S8.3**: CLI tools (`jzctl`, `jzguard`, `jzlog`) in `cli/` directory.
- **S8.4-S8.5**: REST API via mongoose (vendored in `third_party/mongoose/`), JWT/mTLS auth.
- **S8.6-S8.7**: Systemd service files, install/deploy scripts.
- **S10.1-S10.5**: Integration tests, performance benchmarks, documentation.

### Deferred Items (Blocked on Daemon Phase)
These stories were deferred from earlier phases because they require daemon infrastructure:
- **S2.7**: User-space ARP probe generation (needs sniffd S7.1).
- **S3.5**: Hot-reload without flow disruption (needs configd S7.2).
- **S3.6**: Advanced flow statistics aggregation (needs sniffd + REST API).
- **S4.3**: SQLite persistence for attack logs (needs collectord S7.3).
- **S4.5**: Event deduplication logic (needs collectord S7.3).
- **S5.3**: Remote configuration receiver (TLS endpoint -- needs configd S7.2).

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
                  JZ_STAGE_NUMBER,       /* e.g. 22, 23, 24... */
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
