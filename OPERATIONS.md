# jz_sniff_rn — Operations & Deployment Guide

This guide covers deploying, configuring, and operating `jz_sniff_rn` on a production or test machine running the rSwitch XDP platform.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build from Source](#2-build-from-source)
3. [Install](#3-install)
4. [System User & Directories](#4-system-user--directories)
5. [TLS Certificate Generation](#5-tls-certificate-generation)
6. [Configuration](#6-configuration)
7. [rSwitch Dependency](#7-rswitch-dependency)
8. [Starting Daemons](#8-starting-daemons)
9. [Operational Smoke Test](#9-operational-smoke-test)
10. [CLI Usage](#10-cli-usage)
11. [REST API Usage](#11-rest-api-usage)
12. [Systemd Operation](#12-systemd-operation)
13. [Log Management](#13-log-management)
14. [Troubleshooting](#14-troubleshooting)
15. [Uninstall](#15-uninstall)

---

## 1. Prerequisites

### Hardware / VM

- x86_64 Linux machine (physical or VM)
- At least 2 NICs recommended (one for management SSH, one for XDP attachment)
  - **Single-NIC warning**: If the machine has only one NIC (e.g., `ens33`), DO NOT attach rSwitch XDP to it — this will drop all traffic including SSH. The daemons can still load BPF objects and run in "degraded" mode without XDP attachment.

### Operating System

- Ubuntu 22.04+ or Debian 12+ (kernel 5.8+ with BTF support)
- Verified on Ubuntu 24.04 LTS with kernel 6.8

### Kernel Requirements

```bash
# Verify BTF support (required for CO-RE BPF)
ls /sys/kernel/btf/vmlinux

# Verify BPF filesystem is mounted
mount | grep bpf
# Expected: bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,...)
# If not mounted:
sudo mount -t bpf bpf /sys/fs/bpf
```

### Build Dependencies

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

### rSwitch Platform

rSwitch must be installed for full pipeline operation. See [Section 7](#7-rswitch-dependency) for details. sniffd can run without rSwitch in degraded mode (BPF objects load but are not attached to XDP).

---

## 2. Build from Source

```bash
# Clone the repository (or rsync from dev machine)
cd ~/jz_sniff_rn

# Clean build (IMPORTANT: always clean before rebuilding)
sudo rm -rf build

# Build everything: BPF modules + user-space daemons + CLI tools
make all
```

**Build targets:**

| Target | Description |
|---|---|
| `make all` | Build everything |
| `make bpf` | BPF modules only (kernel-space) |
| `make user` | User-space daemons only |
| `make cli` | CLI tools only |
| `make test` | Run unit + BPF tests |
| `make test-integration` | Pipeline integration tests (requires root, libbpf 1.7) |
| `make clean` | Remove build artifacts |

**Important**: Always run `sudo rm -rf build` before rebuilding after source changes. Stale BPF objects in `build/` can cause subtle runtime failures.

---

## 3. Install

```bash
sudo make install
```

This installs:

| Component | Destination |
|---|---|
| Daemons (`sniffd`, `configd`, `collectord`, `uploadd`) | `/usr/local/sbin/` |
| CLI tools (`jzctl`, `jzguard`, `jzlog`) | `/usr/local/bin/` |
| BPF objects (`*.bpf.o`) | `/etc/jz/bpf/` |
| Configuration (`base.yaml`) | `/etc/jz/` |
| Systemd services | `/etc/systemd/system/` |
| Data directory | `/var/lib/jz/` |
| Runtime directory | `/var/run/jz/` |

Verify installation:

```bash
which sniffd       # /usr/local/sbin/sniffd
which jzctl        # /usr/local/bin/jzctl
ls /etc/jz/bpf/   # Should list 8 .bpf.o files
ls /etc/jz/base.yaml
```

---

## 4. System User & Directories

sniffd drops privileges to `jz:jz` after initialization. Create the system user and required directories:

```bash
# Create system user and group
sudo groupadd --system jz 2>/dev/null || true
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g jz jz 2>/dev/null || true

# Create data directory (SQLite DB, exports)
sudo mkdir -p /var/lib/jz
sudo chown jz:jz /var/lib/jz
sudo chmod 0750 /var/lib/jz

# Create runtime directory (PID files, IPC sockets)
sudo mkdir -p /var/run/jz
sudo chown jz:jz /var/run/jz
sudo chmod 0750 /var/run/jz

# Create BPF pin directory
sudo mkdir -p /sys/fs/bpf/jz
```

Verify:

```bash
id jz              # uid=xxx(jz) gid=xxx(jz) groups=xxx(jz)
ls -la /var/lib/jz # drwxr-x--- jz jz
ls -la /var/run/jz # drwxr-x--- jz jz
```

---

## 5. TLS Certificate Generation

The REST API uses HTTPS with Mongoose's built-in TLS (`MG_TLS_BUILTIN`), which **only supports ECC certificates** (not RSA).

### Generate Self-Signed ECC Certificate

```bash
sudo mkdir -p /etc/jz/tls

# Generate ECC private key (P-256 curve)
sudo openssl ecparam -name prime256v1 -genkey -noout -out /etc/jz/tls/server.key

# Generate self-signed certificate (valid 365 days)
sudo openssl req -new -x509 -key /etc/jz/tls/server.key \
    -out /etc/jz/tls/server.crt -days 365 \
    -subj "/CN=jz-sniff/O=JZZN/C=CN"

# Restrict permissions
sudo chown root:jz /etc/jz/tls/server.key /etc/jz/tls/server.crt
sudo chmod 0640 /etc/jz/tls/server.key
sudo chmod 0644 /etc/jz/tls/server.crt
```

Verify:

```bash
openssl x509 -in /etc/jz/tls/server.crt -text -noout | head -15
# Should show: Public Key Algorithm: id-ecPublicKey
# Should show: ASN1 OID: prime256v1
```

### Disable REST API (alternative)

If you don't need the REST API, pass `--no-api` to sniffd:

```bash
sniffd --no-api --config /etc/jz/base.yaml
```

---

## 6. Configuration

The primary configuration file is `/etc/jz/base.yaml`. Review and customize it:

```bash
sudo vim /etc/jz/base.yaml
```

### Key Settings

```yaml
system:
  device_id: "jz-sniff-001"    # Unique device identifier
  log_level: "info"             # debug, info, warn, error
  data_dir: "/var/lib/jz"
  run_dir: "/var/run/jz"

api:
  enabled: true
  listen: "0.0.0.0:8443"
  tls_cert: "/etc/jz/tls/server.crt"
  tls_key: "/etc/jz/tls/server.key"
  auth_tokens:
    - token: "changeme"         # CHANGE THIS!
      role: "admin"
```

### Generate a Secure API Token

```bash
# Generate random 32-byte hex token
openssl rand -hex 32
# Copy output and replace "changeme" in base.yaml
```

### Module Configuration

All 8 BPF modules are enabled by default. Disable any module by setting `enabled: false`:

```yaml
modules:
  guard_classifier:
    enabled: true       # Must be enabled for ARP/ICMP honeypots
  arp_honeypot:
    enabled: true
    rate_limit_pps: 100
  icmp_honeypot:
    enabled: true
    ttl: 64
  sniffer_detect:
    enabled: true
    probe_interval_sec: 30
  traffic_weaver:
    enabled: true
  bg_collector:
    enabled: true
    sample_rate: 1       # 1 = every packet
  threat_detect:
    enabled: true
  forensics:
    enabled: true
    max_payload_bytes: 256
```

---

## 7. rSwitch Dependency

sniffd integrates with rSwitch's XDP pipeline via shared BPF maps. rSwitch provides:

- The `rs_progs` pinned map at `/sys/fs/bpf/rs_progs` (tail-call dispatch table)
- The `rs_event_bus` ring buffer at `/sys/fs/bpf/rs_event_bus`
- XDP attachment to the network interface

### If rSwitch Is Installed

sniffd will automatically register its BPF programs in `rs_progs` at consecutive slots and reuse the shared maps.

### If rSwitch Is NOT Running

sniffd will:
- Load BPF objects and pin jz-specific maps under `/sys/fs/bpf/jz/`
- Log warnings about missing `rs_progs` and `rs_event_bus`
- Run in degraded mode (no XDP pipeline, no events)
- CLI tools and REST API still work for configuration

### Installing rSwitch (if needed)

```bash
# rSwitch is typically at /opt/rswitch/
# See rSwitch documentation for installation.
# CRITICAL: Do NOT attach XDP to the management/SSH interface!
```

---

## 8. Starting Daemons

### Foreground Mode (recommended for testing)

```bash
# Start sniffd in foreground with verbose logging
sudo sniffd --verbose --config /etc/jz/base.yaml

# Or without REST API (no TLS cert needed)
sudo sniffd --verbose --no-api --config /etc/jz/base.yaml

# Or with custom BPF directory
sudo sniffd --verbose --bpf-dir /etc/jz/bpf --config /etc/jz/base.yaml
```

**sniffd CLI options:**

| Option | Default | Description |
|---|---|---|
| `-c, --config PATH` | `/etc/jz/base.yaml` | Configuration file |
| `-d, --daemon` | (off) | Run as background daemon |
| `-p, --pidfile PATH` | `/var/run/jz/sniffd.pid` | PID file location |
| `-b, --bpf-dir PATH` | `/etc/jz/bpf` | Directory with BPF objects |
| `-v, --verbose` | (off) | Debug-level logging |
| `--api-port PORT` | 8443 | REST API port |
| `--api-cert PATH` | `/etc/jz/tls/server.crt` | TLS certificate |
| `--api-key PATH` | `/etc/jz/tls/server.key` | TLS private key |
| `--api-token TOKEN` | (from config) | Bearer auth token override |
| `--no-api` | (off) | Disable REST API entirely |

### Daemon Startup Sequence

When sniffd starts, it performs these steps in order:

1. Parse CLI arguments and load YAML configuration
2. Install signal handlers (SIGTERM, SIGHUP, SIGUSR1)
3. Optionally daemonize and write PID file
4. Initialize BPF loader → load BPF modules from `/etc/jz/bpf/`
5. Pin maps under `/sys/fs/bpf/jz/` (reuse existing pinned maps if present)

> **Expected behavior:** On a system without rSwitch's shared maps pre-loaded,
> 5 out of 8 modules will load successfully (guard_classifier, arp_honeypot,
> icmp_honeypot, sniffer_detect, traffic_weaver). The remaining 3 modules
> (bg_collector, threat_detect, forensics) may fail due to BPF verifier
> constraints or unresolved extern maps. This is normal degraded operation.
6. Register programs in `rs_progs` (if rSwitch is running)
7. Initialize ring buffer consumer (reads from `rs_event_bus`)
8. Initialize guard table manager (loads static/dynamic guards from config)
9. Discover network interface for ARP probe generator
10. Initialize IPC server (Unix socket at `/var/run/jz/sniffd.sock`)
11. Initialize REST API server on port 8443 (HTTPS)
12. Drop privileges to `jz:jz`
13. Enter main loop

### Starting All Daemons

The full daemon stack (in dependency order):

```bash
# 1. sniffd — Core: BPF loader, events, API
sudo sniffd --verbose --config /etc/jz/base.yaml

# 2. configd — Config watcher (depends on sniffd)
sudo configd --verbose --config /etc/jz/base.yaml

# 3. collectord — Event persistence (depends on sniffd)
sudo collectord --verbose --config /etc/jz/base.yaml

# 4. uploadd — Batch upload (depends on collectord, optional)
sudo uploadd --verbose --config /etc/jz/base.yaml
```

### Stopping Daemons

```bash
# Graceful shutdown via signal
sudo kill $(cat /var/run/jz/sniffd.pid)

# Or kill all jz daemons
sudo pkill -f sniffd
sudo pkill -f configd
sudo pkill -f collectord
sudo pkill -f uploadd
```

---

## 9. Operational Smoke Test

After starting sniffd, verify core functionality:

### 9.1 Verify Process Is Running

```bash
ps aux | grep sniffd
# Should show sniffd process running

ls -la /var/run/jz/sniffd.sock
# Should show the IPC socket
```

### 9.2 Check BPF Maps Are Pinned

```bash
sudo ls -la /sys/fs/bpf/jz/
# jz-specific maps: jz_guard_result_map, jz_arp_rate, jz_icmp_rate, etc.

sudo ls /sys/fs/bpf/jz_*
# Maps with LIBBPF_PIN_BY_NAME pin flat here: jz_static_guards, jz_dynamic_guards, etc.
```

> **Note:** Some maps pin flat under `/sys/fs/bpf/` rather than under `/sys/fs/bpf/jz/`
> due to `LIBBPF_PIN_BY_NAME` behavior in libbpf. This is expected — sniffd's guard
> manager and probe generator will find them at either location.

### 9.3 CLI Health Check

```bash
# Check daemon status via IPC
sudo jzctl status

# List loaded modules
sudo jzctl module list

# List guard entries (should be empty initially)
sudo jzguard list
```

### 9.4 Add a Guard Entry

```bash
# Add a static guard IP (fake MAC is auto-assigned from pool)
sudo jzguard add static --ip 10.0.1.50

# Verify it was added
sudo jzguard list
```

### 9.5 REST API Test (if enabled)

```bash
# Replace TOKEN with the auth token from base.yaml
TOKEN="changeme"

# Health check (no auth required for status endpoint)
curl -sk https://localhost:8443/api/v1/status

# List modules
curl -sk https://localhost:8443/api/v1/modules \
    -H "Authorization: Bearer $TOKEN"

# List guards
curl -sk https://localhost:8443/api/v1/guards \
    -H "Authorization: Bearer $TOKEN"
```

### 9.6 View Logs

```bash
# View recent attack/event logs
sudo jzlog attack --limit 20

# View all log types
sudo jzlog tail

# View sniffer detection logs
sudo jzlog sniffer --limit 20

# View background collection logs
sudo jzlog background --limit 20
```

---

## 10. CLI Usage

### jzctl — System Management

```bash
# Daemon status
sudo jzctl status
sudo jzctl status configd
sudo jzctl status collectord

# Module management
sudo jzctl module list            # List modules and their status
sudo jzctl module enable <name>   # Enable a module
sudo jzctl module disable <name>  # Disable a module

# Configuration
sudo jzctl config show            # Show current config
sudo jzctl config reload          # Hot-reload config (SIGHUP)
sudo jzctl config version         # Show config version

# Collector stats
sudo jzctl stats                  # Show collector statistics
sudo jzctl stats reset            # Reset counters
```

### jzguard — Guard Table Management

```bash
# Add guards
sudo jzguard add static --ip 10.0.1.50                        # Auto MAC
sudo jzguard add static --ip 10.0.1.51 --mac aa:bb:cc:00:00:01  # Explicit MAC
sudo jzguard add static --ip 10.0.1.52 --vlan 100             # VLAN-specific

# List all guard entries
sudo jzguard list

# Delete guard
sudo jzguard del --ip 10.0.1.50

# Whitelist management (exclude from guard checks)
sudo jzguard whitelist add --ip 10.0.1.1 --mac 00:11:22:33:44:55
sudo jzguard whitelist list
sudo jzguard whitelist del --ip 10.0.1.1

# Trigger sniffer detection probe
sudo jzguard probe
```

### jzlog — Log Viewer

```bash
# View by log type
sudo jzlog attack    # Attack / honeypot events
sudo jzlog sniffer   # Sniffer detection results
sudo jzlog background        # Background collector events
sudo jzlog threat    # Threat detection alerts
sudo jzlog audit     # Configuration audit trail

# Options
sudo jzlog attack --limit 50          # Limit number of entries
sudo jzlog attack --since 2026-03-01  # Filter by date
sudo jzlog tail                       # Follow new events (like tail -f)
```

---

## 11. REST API Usage

The REST API runs on HTTPS port 8443 (configurable). All endpoints require Bearer token authentication.

### Authentication

```
Authorization: Bearer <token>
```

The token is configured in `base.yaml` under `api.auth_tokens[].token`.

### Endpoints Overview

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/status` | System status |
| GET | `/api/v1/modules` | List BPF modules |
| POST | `/api/v1/modules/{name}/enable` | Enable module |
| POST | `/api/v1/modules/{name}/disable` | Disable module |
| GET | `/api/v1/guards` | List guard entries |
| POST | `/api/v1/guards` | Add guard entry |
| DELETE | `/api/v1/guards/{ip}` | Delete guard entry |
| GET | `/api/v1/guards/whitelist` | List whitelist |
| POST | `/api/v1/guards/whitelist` | Add whitelist entry |
| DELETE | `/api/v1/guards/whitelist/{ip}` | Delete whitelist entry |
| GET | `/api/v1/config` | Get current config |
| POST | `/api/v1/config/reload` | Reload config |
| GET | `/api/v1/events` | Query events |
| GET | `/api/v1/stats` | Collector stats |

---

## 12. Systemd Operation

For production deployment, use the provided systemd service files.

### Enable and Start

```bash
sudo systemctl daemon-reload

# Start the full stack (sniffd pulls in configd/collectord via dependencies)
sudo systemctl enable sniffd configd collectord
sudo systemctl start sniffd

# configd and collectord start automatically (BindsTo=sniffd.service)

# Optional: enable uploadd if using management platform
sudo systemctl enable uploadd
sudo systemctl start uploadd
```

### Service Dependencies

```
sniffd ← configd (BindsTo, starts/stops with sniffd)
       ← collectord (BindsTo, starts/stops with sniffd)
       ← uploadd (Wants collectord, optional)
```

### Management Commands

```bash
sudo systemctl status sniffd
sudo systemctl restart sniffd     # Restarts configd/collectord too
sudo systemctl stop sniffd        # Stops configd/collectord too
sudo journalctl -u sniffd -f      # Follow logs
sudo journalctl -u sniffd --since "1 hour ago"
```

### Service Hardening

The systemd units include security hardening:
- `ProtectSystem=strict` — Read-only filesystem except whitelisted paths
- `ProtectHome=yes` — No access to /home
- `PrivateTmp=yes` — Private /tmp
- `NoNewPrivileges=yes` — Cannot gain new privileges
- `LimitMEMLOCK=infinity` — Required for BPF map allocation
- `WatchdogSec=60` — sniffd restarts if unresponsive for 60s

---

## 13. Log Management

### Log Destinations

| Mode | Destination |
|---|---|
| Foreground (`sniffd -v`) | stderr |
| Daemon (`sniffd -d`) | syslog / journald |
| Systemd service | journald (via `StandardOutput=journal`) |

### Log Levels

Set in `base.yaml` under `system.log_level`:
- `debug` — All messages (very verbose)
- `info` — Normal operation (default)
- `warn` — Warnings only
- `error` — Errors only

Override at runtime: `sniffd --verbose` forces debug level.

### Database Logs

Event data is stored in SQLite at `/var/lib/jz/jz.db`. The collector auto-prunes old data based on `collector.max_db_size_mb` (default 512MB).

```bash
# Query the database directly
sqlite3 /var/lib/jz/jz.db ".tables"
sqlite3 /var/lib/jz/jz.db "SELECT COUNT(*) FROM events;"
```

---

## 14. Troubleshooting

### sniffd Fails to Start

**"Failed to initialize BPF loader"**
- Ensure BPF objects exist in `/etc/jz/bpf/`: `ls /etc/jz/bpf/*.bpf.o`
- Verify BTF: `ls /sys/kernel/btf/vmlinux`
- Check BPF filesystem: `mount | grep bpf`
- Run with `--verbose` for detailed error messages

**"Failed to load config"**
- Validate YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('/etc/jz/base.yaml'))"`
- Check file permissions: config must be readable by root during startup

**"REST API init failed"**
- Ensure TLS cert/key exist and are ECC (not RSA)
- Verify: `openssl x509 -in /etc/jz/tls/server.crt -text -noout | grep "Public Key Algorithm"`
  - Must show `id-ecPublicKey`, NOT `rsaEncryption`
- Or start with `--no-api` to skip the REST API

**"Ring buffer init failed"**
- This means `/sys/fs/bpf/rs_event_bus` is not pinned (rSwitch not running)
- sniffd continues in degraded mode — this is expected without rSwitch

**"No interface for probe generator"**
- sniffd auto-discovers interfaces: `eth0`, `ens33`, `enp0s3`
- Sniffer detection probes won't work, but everything else runs fine

### Permission Errors

```bash
# Ensure BPF filesystem is writable
sudo mount -o remount,rw /sys/fs/bpf

# Ensure jz user owns required directories
sudo chown -R jz:jz /var/lib/jz /var/run/jz

# sniffd must start as root (drops privileges after init)
sudo sniffd --verbose --config /etc/jz/base.yaml
```

### Stale BPF State

If you see unexpected behavior after a code change or crash:

```bash
# Clean up pinned BPF maps (both namespaced and flat)
sudo rm -rf /sys/fs/bpf/jz
sudo rm -f /sys/fs/bpf/jz_*

# Clean up stale PID/socket files
sudo rm -f /var/run/jz/*.pid /var/run/jz/*.sock

# Restart sniffd (it will re-pin fresh maps)
sudo sniffd --verbose --config /etc/jz/base.yaml
```

### IPC Errors ("Connection refused")

```bash
# Verify socket exists
ls -la /var/run/jz/sniffd.sock

# Verify sniffd is running
ps aux | grep sniffd

# CLI tools need root for socket access
sudo jzctl status
```

### Build Errors

```bash
# Always clean before rebuilding
sudo rm -rf build
make all

# If BPF compilation fails, check clang version
clang --version   # Need clang 14+

# If linking fails, check library packages
dpkg -l | grep -E 'libelf|libsqlite3|libyaml|libcmocka'
```

---

## 15. Uninstall

```bash
# Stop all services
sudo systemctl stop sniffd configd collectord uploadd
sudo systemctl disable sniffd configd collectord uploadd

# Remove installed files
sudo make uninstall

# Clean up runtime state
sudo rm -rf /var/run/jz
sudo rm -rf /sys/fs/bpf/jz

# Optionally remove data and config
sudo rm -rf /var/lib/jz    # WARNING: deletes event database
sudo rm -rf /etc/jz        # WARNING: deletes configuration

# Remove system user
sudo userdel jz
sudo groupdel jz 2>/dev/null
```
