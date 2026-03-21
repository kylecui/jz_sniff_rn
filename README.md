# jz_sniff_rn (Sniff Reborn)

Network security appliance firmware built on the [rSwitch](https://github.com/kylecui/rswitch) XDP platform. Implements deception-based threat detection, traffic analysis, and forensic capabilities using eBPF.

## Features

- **Dynamic Trapping** -- ARP/ICMP honeypot responses for guard IPs (static & auto-discovered)
- **Sniffer Detection** -- Detect promiscuous-mode devices via ARP probe techniques
- **Traffic Weaving** -- Per-flow traffic steering: pass, drop, redirect, mirror
- **Background Collection** -- Broadcast/multicast protocol baseline (ARP, DHCP, mDNS, LLDP, STP, etc.)
- **Threat Detection** -- Fast-path header/payload pattern matching at line rate
- **Forensic Sampling** -- Packet capture to ring buffer for offline analysis
- **Configuration Management** -- YAML profiles with hot-reload, versioning, and remote push
- **REST API** -- HTTPS management interface with JWT/mTLS auth

## Architecture

```
BPF Pipeline (kernel-space, XDP):
  guard_classifier (21) -> arp_honeypot (22) / icmp_honeypot (23)
                         -> sniffer_detect (24)
                         -> traffic_weaver (25)
                         -> bg_collector (26)
                         -> threat_detect (27)
                         -> forensics (28)
  Stages 21-28 sit in the gap between rSwitch VLAN(20) and ACL(30).
  Actual rs_progs slots are consecutive (0,1,2,...) — stage numbers are for ordering only.

User-space Daemons:
  sniffd      -- BPF loader, event consumer, probe generator
  configd     -- Config watcher, remote config receiver, map applier
  collectord  -- Event dedup, SQLite persistence, JSON export
  uploadd     -- Batch upload to management platform

CLI Tools:
  jzctl       -- System management (status, config, module, daemon control)
  jzguard     -- Guard table management (add/del/list, whitelist, probe)
  jzlog       -- Log viewer (attack, sniffer, bg, audit, threat, tail)
```

## Requirements

- Ubuntu 22.04+ (kernel 5.8+ with BTF support)
- rSwitch platform installed
- Build dependencies:
  ```
  apt install clang llvm libbpf-dev libelf-dev zlib1g-dev \
              libsqlite3-dev libcmocka-dev pkg-config \
              linux-headers-$(uname -r)
  ```

## Build

```bash
make all          # Build everything (BPF + user-space + CLI)
make bpf          # BPF modules only
make user         # User-space daemons only
make cli          # CLI tools only
make test         # Run all tests
make coverage     # Generate test coverage report
make lint         # Static analysis (cppcheck)
make format       # Auto-format (clang-format)
```

## Install

```bash
sudo make install         # Install to /usr/local
sudo make install PREFIX=/usr  # Install to /usr
sudo make uninstall       # Remove installed files
```

## Configuration

Default config: `/etc/jz/base.yaml`

```bash
jzctl config show         # View current config
jzctl config reload       # Hot-reload config
jzguard add static --ip 10.0.1.50 --mac aa:bb:cc:dd:ee:01
jzguard list
jzlog attack --since 2026-03-01
```

See [design.md](design.md) for full architecture documentation and [DEVELOPMENT.md](DEVELOPMENT.md) for detailed build instructions, API reference, and development guide.

## Current Status

**Overall: ~95% complete** — 24,287 lines of C across 66 source files (plus 33,781 lines vendored).

### What's Done

| Component | Files | Lines | Status |
|---|---|---|---|
| BPF pipeline (8 modules + 3 headers) | 11 | 2,423 | ✅ Complete |
| Common library (8 modules: db, mac_pool, config, config_map, config_history, config_diff, ipc, log) | 16 | 6,889 | ✅ Complete (incl. DB pruning APIs) |
| sniffd (main loop, BPF loader, ringbuf, probe_gen, guard_mgr, REST API) | 11 | 4,665 | ✅ Complete (incl. 31-endpoint HTTPS API) |
| configd (main loop, inotify watcher, reload, BPF map push, remote TLS endpoint) | 3 | 1,313 | ✅ Complete (incl. mTLS HTTPS config push) |
| collectord (main loop, dedup, rate limiter, SQLite batch, JSON export, DB auto-pruning) | 1 | 1,021 | ✅ Complete |
| uploadd (main loop, batch assembly, gzip, native HTTPS via mongoose) | 1 | 1,102 | ✅ Complete (incl. mTLS HTTPS upload) |
| Tests (8 BPF + 7 unit + test_helpers) | 16 | 3,698 | ✅ Complete for implemented modules |
| CLI tools (jzctl, jzguard, jzlog) | 3 | 2,157 | ✅ Complete |
| REST API (31 endpoints, bearer auth, HTTPS/TLS) | 2 | 2,153 | ✅ Complete |
| Systemd services (sniffd, configd, collectord, uploadd) | 4 | 167 | ✅ Complete |
| Vendored: rSwitch headers | 4 | 954 | ✅ |
| Vendored: mongoose (TLS HTTP), cJSON | 4 | 33,781 | ✅ |
| Build system, config, scripts | 3 | ~540 | ✅ |

### What's Remaining

- **Phase 10: Integration & Validation** — End-to-end tests with rSwitch pipeline, performance benchmarks (PPS/latency), final deployment guide.

### Known Issues

All 5 rSwitch integration bugs have been fixed. All daemon core gaps (configd TLS, collectord pruning, uploadd table name bug) resolved. Policy endpoints in the REST API return 501 (needs policy manager module for full implementation).

## Project Structure

```
jz_sniff_rn/
  bpf/              BPF modules (kernel-space)
    include/         Shared BPF headers (jz_common.h, jz_maps.h, jz_events.h)
  src/              User-space daemons
    common/          Shared library (IPC, config, DB, logging)
    sniffd/          Main orchestrator daemon + REST API
    configd/         Configuration manager
    collectord/      Data collector
    uploadd/         Upload agent
  cli/              CLI tools (jzctl, jzguard, jzlog)
  config/           Default YAML config profiles
  systemd/          Systemd service files (sniffd, configd, collectord, uploadd)
  tests/            Unit, BPF, integration, and perf tests
  scripts/          Build and deploy scripts
  include/rswitch/  rSwitch SDK headers (vendored)
  third_party/      Vendored dependencies (mongoose v7.20, cJSON v1.7.18)
```

## License

[MIT](LICENSE)
