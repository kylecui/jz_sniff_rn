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
  guard_classifier (22) -> arp_honeypot (23) / icmp_honeypot (24)
                        -> sniffer_detect (25)
                        -> traffic_weaver (35)
                        -> bg_collector (40)
                        -> threat_detect (50)
                        -> forensics (55)

User-space Daemons:
  sniffd      -- BPF loader, event consumer, probe generator
  configd     -- Config watcher, remote config receiver, map applier
  collectord  -- Event dedup, SQLite persistence, JSON export
  uploadd     -- Batch upload to management platform

CLI Tools:
  jzctl       -- System management
  jzguard     -- Guard table management
  jzlog       -- Log viewer
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

Phases 1-5 are complete (~11,245 lines across 42 files):
- 8 BPF kernel modules (all pipeline stages)
- 6 user-space library modules (db, mac_pool, config, config_map, config_history, config_diff)
- 13 test files (8 BPF + 5 unit)
- Build system, configuration, and infrastructure

Remaining: Phase 6 (bg collection user-space), Phase 7 (daemons), Phase 8 (CLI + REST API + deployment).

## Project Structure

```
jz_sniff_rn/
  bpf/              BPF modules (kernel-space)
    include/         Shared BPF headers (jz_common.h, jz_maps.h, jz_events.h)
  src/              User-space daemons
    common/          Shared library (IPC, config, DB, logging)
    sniffd/          Main orchestrator daemon
    configd/         Configuration manager
    collectord/      Data collector
    uploadd/         Upload agent
  cli/              CLI tools (jzctl, jzguard, jzlog)
  config/           Default YAML config profiles
  tests/            Unit, BPF, integration, and perf tests
  scripts/          Build and deploy scripts
  include/rswitch/  rSwitch SDK headers (vendored)
  third_party/      Vendored dependencies (mongoose, cjson, libyaml)
```

## License

[MIT](LICENSE)
