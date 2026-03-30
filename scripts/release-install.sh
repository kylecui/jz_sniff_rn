#!/usr/bin/env bash
# jz_sniff_rn — Release installer (Ubuntu 24.04 LTS)
# Installs pre-built binaries from release tarball + bundled rSwitch platform.
#
# Usage:
#   tar xzf jz-sniff-*.tar.gz && cd jz-sniff-* && sudo ./install.sh
#
# Runtime dependencies (auto-installed):
#   libbpf0/libbpf1, libelf1, zlib1g, libsqlite3-0, libyaml-0-2, openssl
# rSwitch build dependencies (auto-installed by rSwitch installer):
#   build-essential, clang, llvm, libelf-dev, etc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Install paths ─────────────────────────────────────────────
PREFIX="/usr/local"
SBINDIR="$PREFIX/sbin"
BINDIR="$PREFIX/bin"
SYSCONFDIR="/etc/jz"
DATADIR="/var/lib/jz"
RUNDIR="/var/run/jz"
UNITDIR="/etc/systemd/system"
WWWDIR="/usr/share/jz/www"
BPFFS="/sys/fs/bpf"
TLS_DIR="$SYSCONFDIR/tls"

DAEMONS="sniffd configd collectord uploadd"

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
YLW='\033[0;33m'
RST='\033[0m'

info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
ok()    { printf "${GRN}[ OK ]${RST}  %s\n" "$*"; }
warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
die()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; exit 1; }

# ── Usage ─────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Install jz_sniff_rn from pre-built release package.
Requires Ubuntu 24.04 LTS (x86_64).

Options:
  --no-start         Install only, do not start services
  --skip-deps        Skip runtime dependency check
  --skip-rswitch     Skip rSwitch installation (if already installed)
  --uninstall        Stop services and remove installed files
  -h, --help         Show this help

Examples:
  sudo $0                     # Install rSwitch + jz_sniff_rn, start services
  sudo $0 --skip-rswitch      # Skip rSwitch, install jz_sniff_rn only
  sudo $0 --no-start          # Install only
  sudo $0 --uninstall         # Remove everything
EOF
    exit 0
}

NO_START=false
SKIP_DEPS=false
SKIP_RSWITCH=false
UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-start)       NO_START=true; shift ;;
        --skip-deps)      SKIP_DEPS=true; shift ;;
        --skip-rswitch)   SKIP_RSWITCH=true; shift ;;
        --uninstall)      UNINSTALL=true; shift ;;
        -h|--help)        usage ;;
        *)                die "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || die "Must run as root (use sudo)"

# ── Platform check ────────────────────────────────────────────
check_platform() {
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        die "Unsupported architecture: $arch (requires x86_64)"
    fi

    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS — /etc/os-release not found"
    fi

    # shellcheck source=/dev/null
    source /etc/os-release

    if [[ "${ID:-}" != "ubuntu" ]]; then
        die "Unsupported OS: ${ID:-unknown} (requires Ubuntu)"
    fi

    local major_ver="${VERSION_ID%%.*}"
    if [[ "$major_ver" -lt 24 ]]; then
        die "Unsupported Ubuntu version: ${VERSION_ID} (requires 24.04+)"
    fi

    ok "Platform: Ubuntu ${VERSION_ID} ($arch)"
}

# ── Verify release contents ───────────────────────────────────
verify_release() {
    local missing=()
    [[ -d "$SCRIPT_DIR/sbin" ]]    || missing+=("sbin/")
    [[ -d "$SCRIPT_DIR/bpf" ]]     || missing+=("bpf/")
    [[ -d "$SCRIPT_DIR/config" ]]  || missing+=("config/")
    [[ -d "$SCRIPT_DIR/systemd" ]] || missing+=("systemd/")
    [[ -d "$SCRIPT_DIR/www" ]]     || missing+=("www/")

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Incomplete release package — missing: ${missing[*]}"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────
do_uninstall() {
    info "Stopping services..."
    for d in $DAEMONS; do
        systemctl stop "$d" 2>/dev/null || true
        systemctl disable "$d" 2>/dev/null || true
    done
    systemctl daemon-reload

    info "Removing binaries..."
    for d in $DAEMONS; do rm -f "$SBINDIR/$d"; done
    for t in jzctl jzguard jzlog; do rm -f "$BINDIR/$t"; done

    info "Removing BPF modules, systemd units, frontend..."
    rm -rf "$SYSCONFDIR/bpf"
    rm -f "$UNITDIR/sniffd.service" "$UNITDIR/configd.service" \
          "$UNITDIR/collectord.service" "$UNITDIR/uploadd.service"
    rm -rf "$WWWDIR"

    ok "Uninstall complete (config in $SYSCONFDIR and data in $DATADIR preserved)"
    echo "  Note: rSwitch was NOT removed. To remove: sudo /opt/rswitch/scripts/install.sh --uninstall"
    exit 0
}

if $UNINSTALL; then
    do_uninstall
fi

# ── rSwitch installation ─────────────────────────────────────
install_rswitch() {
    if [[ ! -d "$SCRIPT_DIR/rswitch" ]] || [[ ! -f "$SCRIPT_DIR/rswitch/scripts/install.sh" ]]; then
        warn "No bundled rSwitch source found — skipping rSwitch installation"
        warn "Install rSwitch manually: https://github.com/kylecui/rswitch"
        return 0
    fi

    # Check if rSwitch is already installed and functional
    if [[ -f /opt/rswitch/build/rswitch_loader ]]; then
        info "rSwitch already installed at /opt/rswitch/"
        local existing_ver
        existing_ver=$(/opt/rswitch/build/rswitch_loader --version 2>/dev/null || echo "unknown")
        info "  Existing version: $existing_ver"
        info "  Reinstalling from bundled source to ensure compatibility..."
    fi

    info "Installing rSwitch from bundled source..."

    # ── Workaround for rSwitch v2.1.0 build bugs ─────────────
    # Issue #9: .gitmodules uses private SSH URL for libbpf submodule.
    # Issues #10/#11: rs_layers/rs_ctx are defined in rswitch_abi.h, uapi.h,
    #   and inline in .c files — causing redefinition errors. We add a
    #   preprocessor guard around the structs in rswitch_abi.h and set
    #   that guard in uapi.h and the affected .c files.
    local rs_src="$SCRIPT_DIR/rswitch"

    if [[ -f "$rs_src/.gitmodules" ]]; then
        sed -i 's|url = git@github.com:kylecui/libbpf.git|url = https://github.com/libbpf/libbpf.git|' \
            "$rs_src/.gitmodules" 2>/dev/null || true
    fi

    local abi_h="$rs_src/sdk/include/rswitch_abi.h"
    local guard="__RS_CORE_STRUCTS_DEFINED"

    if [[ -f "$abi_h" ]] && ! grep -q "$guard" "$abi_h"; then
        # Helper: wrap struct rs_layers...struct rs_ctx block with #ifndef guard
        patch_struct_guard() {
            local file="$1"
            [[ -f "$file" ]] || return 0
            grep -q '^struct rs_layers {' "$file" || return 0
            grep -q "$guard" "$file" && return 0

            sed -i "/^struct rs_layers {/i\\
#ifndef $guard\\
#define $guard" "$file"

            local ctx_end
            ctx_end=$(awk '/^struct rs_ctx \{/{found=1} found && /^\};/{print NR; exit}' "$file")
            [[ -n "$ctx_end" ]] && sed -i "${ctx_end}a\\
#endif /* $guard */" "$file"
        }

        patch_struct_guard "$abi_h"
        patch_struct_guard "$rs_src/bpf/core/uapi.h"
        patch_struct_guard "$rs_src/sdk/include/uapi.h"

        for src_file in user/ctl/rswitchctl_dev.c user/tools/rs_packet_trace.c; do
            patch_struct_guard "$rs_src/$src_file"
        done

        info "Applied rSwitch build workaround: guarded duplicate struct defs (issues #10, #11)"
    fi
    # ──────────────────────────────────────────────────────────

    # Issue #12: rSwitch loader uses sd_notify() but the installer doesn't
    # pull libsystemd-dev. Install it before the rSwitch build.
    if ! dpkg -s libsystemd-dev >/dev/null 2>&1; then
        info "Installing missing rSwitch build dep: libsystemd-dev (issue #12)"
        apt-get install -y -qq libsystemd-dev 2>&1 | tail -1
    fi

    # The rSwitch installer handles its own dependency installation.
    # RSWITCH_SRC tells it to use the bundled source instead of cloning.
    # RSWITCH_FORCE skips interactive prompts.
    if RSWITCH_SRC="$SCRIPT_DIR/rswitch" RSWITCH_FORCE=1 \
       bash "$SCRIPT_DIR/rswitch/scripts/install.sh"; then
        ok "rSwitch installed"
    else
        die "rSwitch installation failed. Check /var/log/rswitch/install.log"
    fi
}

# ── Runtime dependency check ──────────────────────────────────
check_runtime_deps() {
    info "Checking runtime dependencies..."
    local missing=()

    # Check shared libs needed at runtime
    for lib in libelf libsqlite3 zlib libyaml-0; do
        pkg-config --exists "$lib" 2>/dev/null || missing+=("$lib")
    done

    # Check libbpf (could be libbpf0 or libbpf1)
    if ! pkg-config --exists libbpf 2>/dev/null; then
        if ! ldconfig -p 2>/dev/null | grep -q libbpf; then
            missing+=("libbpf")
        fi
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing runtime libraries: ${missing[*]}"
        info "Installing via apt..."
        apt-get update -qq
        apt-get install -y -qq libbpf1 libelf1t64 zlib1g libsqlite3-0 libyaml-0-2 openssl 2>&1 | tail -1
        ok "Dependencies installed"
    else
        ok "All runtime dependencies present"
    fi
}

# ── Install ───────────────────────────────────────────────────
install_binaries() {
    info "Installing daemons to $SBINDIR..."
    install -d "$SBINDIR"
    for d in $DAEMONS; do
        install -m 0755 "$SCRIPT_DIR/sbin/$d" "$SBINDIR/"
    done

    if [[ -d "$SCRIPT_DIR/bin" ]]; then
        info "Installing CLI tools to $BINDIR..."
        install -d "$BINDIR"
        for t in "$SCRIPT_DIR/bin"/*; do
            install -m 0755 "$t" "$BINDIR/"
        done
    fi
    ok "Binaries installed"
}

install_bpf() {
    info "Installing BPF modules to $SYSCONFDIR/bpf..."
    install -d "$SYSCONFDIR/bpf"
    install -m 0644 "$SCRIPT_DIR"/bpf/*.bpf.o "$SYSCONFDIR/bpf/"
    ok "BPF modules installed"
}

install_config() {
    install -d "$SYSCONFDIR"
    install -d "$SYSCONFDIR/profiles"

    if [[ ! -f "$SYSCONFDIR/base.yaml" ]]; then
        info "Installing default config to $SYSCONFDIR/base.yaml..."
        install -m 0640 "$SCRIPT_DIR/config/base.yaml" "$SYSCONFDIR/"
    else
        info "Preserving existing $SYSCONFDIR/base.yaml"
    fi

    if ls "$SCRIPT_DIR"/config/profiles/*.yaml &>/dev/null; then
        install -m 0640 "$SCRIPT_DIR"/config/profiles/*.yaml "$SYSCONFDIR/profiles/" 2>/dev/null || true
    fi

    # Polkit rule
    if [[ -f "$SCRIPT_DIR/config/50-jz-services.rules" ]]; then
        install -d /etc/polkit-1/rules.d
        install -m 0644 "$SCRIPT_DIR/config/50-jz-services.rules" /etc/polkit-1/rules.d/
    fi

    ok "Config installed"
}

install_systemd() {
    info "Installing systemd units..."
    install -d "$UNITDIR"
    install -m 0644 "$SCRIPT_DIR"/systemd/*.service "$UNITDIR/"
    ok "Systemd units installed"
}

install_frontend() {
    if [[ -d "$SCRIPT_DIR/www" && -f "$SCRIPT_DIR/www/index.html" ]]; then
        info "Installing frontend to $WWWDIR..."
        install -d "$WWWDIR"
        rm -rf "${WWWDIR:?}/"*
        cp -r "$SCRIPT_DIR/www/"* "$WWWDIR/"
        ok "Frontend installed"
    else
        warn "No frontend found in release — skipping"
    fi
}

setup_bpffs() {
    if ! mountpoint -q "$BPFFS" 2>/dev/null; then
        info "Mounting bpffs at $BPFFS..."
        mount -t bpf bpf "$BPFFS" 2>/dev/null || true
    fi

    if ! grep -q "^bpf $BPFFS" /etc/fstab 2>/dev/null; then
        echo "bpf $BPFFS bpf defaults 0 0" >> /etc/fstab
    fi

    install -d -m 0755 "$BPFFS/jz"
    ok "bpffs ready"
}

setup_tls() {
    if [[ -f "$TLS_DIR/server.crt" && -f "$TLS_DIR/server.key" ]]; then
        ok "TLS certificates already exist"
        return 0
    fi

    info "Generating self-signed TLS certificate (ECC P-256, 10yr)..."
    install -d -m 0750 "$TLS_DIR"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TLS_DIR/server.key" \
        -out "$TLS_DIR/server.crt" \
        -days 3650 -nodes \
        -subj "/CN=jz-sniff/O=jz_sniff_rn" \
        2>/dev/null

    chmod 0640 "$TLS_DIR/server.key"
    chmod 0644 "$TLS_DIR/server.crt"
    ok "TLS certificate generated"
}

setup_runtime_dirs() {
    install -d -m 0750 "$DATADIR"
    install -d -m 0750 "$RUNDIR"
    ok "Runtime directories ready"
}

setup_services() {
    systemctl daemon-reload
    for d in $DAEMONS; do
        systemctl enable "$d" 2>/dev/null
    done
    ok "Services enabled"
}

start_services() {
    info "Starting services..."

    # configd first (config manager), then sniffd (main), then the rest
    systemctl restart configd 2>/dev/null || true
    sleep 1
    systemctl restart sniffd
    sleep 2
    for d in collectord uploadd; do
        systemctl restart "$d" 2>/dev/null || true
    done
    sleep 1
    ok "Services started"
}

verify() {
    info "Verifying deployment..."
    local all_ok=true

    for d in $DAEMONS; do
        if systemctl is-active --quiet "$d" 2>/dev/null; then
            ok "  $d: active"
        else
            warn "  $d: not running"
            all_ok=false
        fi
    done

    local health
    health=$(curl -sk --max-time 5 https://localhost:8443/api/v1/health 2>/dev/null) || health=""

    if echo "$health" | grep -q '"status":"ok"'; then
        local version
        version=$(echo "$health" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        ok "  API: healthy (v$version)"
    else
        warn "  API: not responding yet (may need a moment)"
        all_ok=false
    fi

    if [[ -f "$WWWDIR/index.html" ]]; then
        ok "  Frontend: installed"
    else
        warn "  Frontend: not found"
    fi

    echo ""
    if $all_ok; then
        printf "${GRN}=== Installation successful ===${RST}\n"
    else
        printf "${YLW}=== Installation complete with warnings ===${RST}\n"
    fi
    printf "  Web UI:    https://<host>:8443/\n"
    printf "  API:       https://<host>:8443/api/v1/health\n"
    printf "  Logs:      journalctl -u sniffd -f\n"
    printf "  Status:    systemctl status sniffd configd collectord uploadd\n\n"
}

# ── Main ──────────────────────────────────────────────────────

check_platform
verify_release

# Phase 1: rSwitch platform (must be installed before jz_sniff_rn)
if ! $SKIP_RSWITCH; then
    install_rswitch
else
    info "Skipping rSwitch installation (--skip-rswitch)"
    if [[ ! -f /opt/rswitch/build/rswitch_loader ]]; then
        warn "rSwitch not found at /opt/rswitch/ — jz_sniff_rn requires rSwitch to function"
    fi
fi

# Phase 2: jz_sniff_rn
if ! $SKIP_DEPS; then
    check_runtime_deps
fi

install_binaries
install_bpf
install_config
install_systemd
install_frontend

setup_runtime_dirs
setup_bpffs
setup_tls
setup_services

if ! $NO_START; then
    start_services
    verify
else
    ok "Installed but not started (--no-start)"
    printf "  Start: sudo systemctl start configd sniffd collectord uploadd\n"
fi
