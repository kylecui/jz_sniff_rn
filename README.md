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
  sniffd      -- BPF loader, event consumer, probe generator, REST API, device discovery, guard automation
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
make test-perf    # Run BPF performance benchmarks (requires root)
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

One line install from zero (Ubuntu 24.04 LTS, x86_64):
```bash
curl -sL https://github.com/kylecui/jz_sniff_rn/releases/download/v0.9.2/jz-sniff-v0.9.2-linux-x86_64.tar.gz | tar xz -C /tmp && cd /tmp/jz-sniff-v0.9.2-linux-x86_64 && sudo ./install.sh
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

See [design.md](docs/archive/design.md) for full architecture documentation and [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed build instructions, API reference, and development guide.

## Current Status

**Overall: 100% complete** — 28,000+ lines of C across 70+ source files (plus 33,781 lines vendored).

### What's Done

| Component | Files | Lines | Status |
|---|---|---|---|
| BPF pipeline (8 modules + 3 headers) | 11 | 2,423 | ✅ Complete |
| Common library (8 modules: db, mac_pool, config, config_map, config_history, config_diff, ipc, log) | 16 | 6,889 | ✅ Complete (incl. DB pruning APIs) |
| sniffd (main loop, BPF loader, ringbuf, probe_gen, guard_mgr, REST API) | 15+ | 6,500+ | ✅ Complete (incl. 50+-endpoint HTTPS API) |
| configd (main loop, inotify watcher, reload, BPF map push, remote TLS endpoint) | 3 | 1,313 | ✅ Complete (incl. mTLS HTTPS config push) |
| collectord (main loop, dedup, rate limiter, SQLite batch, JSON export, DB auto-pruning) | 3 | 1,200+ | ✅ Complete |
| uploadd (main loop, batch assembly, gzip, native HTTPS via mongoose) | 1 | 1,102 | ✅ Complete (incl. mTLS HTTPS upload) |
| Tests (8 BPF + 7 unit + 15 integration + perf benchmarks) | 17 | 4,600+ | ✅ Complete |
| CLI tools (jzctl, jzguard, jzlog) | 3 | 2,157 | ✅ Complete |
| REST API (50+ endpoints, bearer auth, HTTPS/TLS) | 2+ | 3,000+ | ✅ Complete |
| Frontend (Vue 3 + Vite + Element Plus + vue-i18n) | 20+ | 3,000+ | ✅ Complete (8-page SPA, zh/en i18n) |
| Systemd services (sniffd, configd, collectord, uploadd) | 4 | 167 | ✅ Complete |
| Vendored: rSwitch SDK v2.1.0 headers | 9 | ~1,900 | ✅ |
| Vendored: mongoose (TLS HTTP), cJSON | 4 | 33,781 | ✅ |
| Build system, config, scripts | 3 | ~540 | ✅ |

### What's Remaining

- **v0.9.2 released**. rSwitch SDK v2.1.0 migration, DHCP persistence, frontend i18n fix, bundled rSwitch installer with upstream bug workarounds.

### Known Issues

All 5 rSwitch integration bugs have been fixed. All daemon core gaps resolved. Policy endpoints in the REST API return 501 (needs policy manager module). Serial/inline mode is design-only (not implemented).

## Project Structure

```
jz_sniff_rn/
  bpf/              BPF modules (kernel-space)
    include/         Shared BPF headers (jz_common.h, jz_maps.h, jz_events.h)
  src/              User-space daemons
    common/          Shared library (IPC, config, DB, logging, fingerprint, log_format)
    sniffd/          Main orchestrator daemon + REST API + discovery + guard_auto
    configd/         Configuration manager + staged config
    collectord/      Data collector + syslog export
    uploadd/         Upload agent + MQTT client
  cli/              CLI tools (jzctl, jzguard, jzlog)
  frontend/         Vue 3 management SPA (Element Plus, vue-i18n)
  config/           Default YAML config profiles
  systemd/          Systemd service files (sniffd, configd, collectord, uploadd)
  tests/            Unit, BPF, integration, and perf tests
  scripts/          Build and deploy scripts
  docs/             Documentation
    archive/         Design docs, backlog, planning (historical)
    DEVELOPMENT.md   Build instructions, API reference, dev guide
    OPERATIONS.md    Operations and deployment guide
  include/rswitch/  rSwitch SDK v2.1.0 headers (vendored)
  third_party/      Vendored dependencies (mongoose v7.20, cJSON v1.7.18, Paho MQTT)
```

## License

[MIT](LICENSE)
