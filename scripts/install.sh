#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SYSCONFDIR="/etc/jz"
DATADIR="/var/lib/jz"
RUNDIR="/var/run/jz"
WWWDIR="/usr/share/jz/www"
BPFFS="/sys/fs/bpf"
TLS_DIR="$SYSCONFDIR/tls"

DAEMONS="sniffd configd collectord uploadd"

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
YLW='\033[0;33m'
RST='\033[0m'

info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
ok()    { printf "${GRN}[OK]${RST}    %s\n" "$*"; }
warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
die()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Install jz_sniff_rn to the local system.

Options:
  --skip-build       Skip compilation (use pre-built binaries in build/)
  --skip-frontend    Skip frontend installation
  --skip-deps        Skip dependency check
  --no-start         Install only, do not start services
  --uninstall        Stop services and remove installed files (preserves config/data)
  --purge            Full removal: uninstall + delete config, data, BPF state
  -h, --help         Show this help

Examples:
  sudo $0                     # Full install: build + deploy + start
  sudo $0 --skip-build        # Deploy pre-built binaries + start
  sudo $0 --uninstall         # Remove binaries/services (keep config/data)
  sudo $0 --purge             # Nuke everything for a clean slate
EOF
    exit 0
}

SKIP_BUILD=false
SKIP_FRONTEND=false
SKIP_DEPS=false
NO_START=false
UNINSTALL=false
PURGE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)    SKIP_BUILD=true; shift ;;
        --skip-frontend) SKIP_FRONTEND=true; shift ;;
        --skip-deps)     SKIP_DEPS=true; shift ;;
        --no-start)      NO_START=true; shift ;;
        --uninstall)     UNINSTALL=true; shift ;;
        --purge)         PURGE=true; shift ;;
        -h|--help)       usage ;;
        *)               die "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || die "Must run as root (use sudo)"

do_uninstall() {
    info "Stopping services..."
    for d in $DAEMONS; do
        systemctl stop "$d" 2>/dev/null || true
        systemctl disable "$d" 2>/dev/null || true
    done
    systemctl daemon-reload

    info "Removing installed files..."
    make -C "$PROJECT_DIR" uninstall 2>/dev/null || true
    rm -rf "$WWWDIR"
}

do_purge() {
    do_uninstall

    info "Removing configuration and data..."
    rm -rf "$SYSCONFDIR"
    rm -rf "$DATADIR"
    rm -rf "$RUNDIR"

    info "Detaching XDP from all interfaces..."
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'); do
        ip link set dev "$iface" xdp off 2>/dev/null || true
        ip link set dev "$iface" promisc off 2>/dev/null || true
    done

    info "Cleaning BPF state..."
    rm -rf "$BPFFS/jz"
    rm -f "$BPFFS"/jz_* "$BPFFS/rs_ctx_map" "$BPFFS/rs_progs" \
          "$BPFFS/rs_prog_chain" "$BPFFS/rs_event_bus"
    sed -i '/^bpf \/sys\/fs\/bpf/d' /etc/fstab 2>/dev/null || true

    info "Removing netplan overrides..."
    rm -f /etc/netplan/90-jz-monitors.yaml 2>/dev/null || true
    netplan apply 2>/dev/null || true

    info "Removing polkit rules..."
    rm -f /etc/polkit-1/rules.d/50-jz-services.rules 2>/dev/null || true

    ok "Purge complete — system returned to clean state"
}

if $PURGE; then
    do_purge
    exit 0
fi

if $UNINSTALL; then
    do_uninstall
    ok "Uninstall complete (config in $SYSCONFDIR and data in $DATADIR preserved)"
    echo "  To remove everything: sudo $0 --purge"
    exit 0
fi

check_deps() {
    info "Checking build dependencies..."
    local missing=()

    for cmd in gcc clang llc make pkg-config; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    for lib in libelf libsqlite3 zlib libyaml-0; do
        pkg-config --exists "$lib" 2>/dev/null || missing+=("$lib-dev")
    done

    [[ -d "/usr/include/bpf" ]] || missing+=("libbpf-dev")

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing[*]}"
        info "Installing via apt..."
        apt-get update -qq
        apt-get install -y -qq \
            clang llvm libbpf-dev libelf-dev zlib1g-dev \
            libsqlite3-dev pkg-config build-essential \
            libyaml-dev 2>&1 | tail -1
        ok "Dependencies installed"
    else
        ok "All build dependencies present"
    fi
}

do_build() {
    info "Building project..."
    make -C "$PROJECT_DIR" clean 2>/dev/null || true
    make -C "$PROJECT_DIR" all -j"$(nproc)"
    ok "Build complete"
}

do_install_binaries() {
    info "Installing binaries, BPF modules, config, and systemd services..."
    make -C "$PROJECT_DIR" install
    ok "Binaries installed"
}

do_install_frontend() {
    local dist_dir="$PROJECT_DIR/frontend/dist"

    if [[ -d "$dist_dir" && -f "$dist_dir/index.html" ]]; then
        info "Installing pre-built frontend from $dist_dir..."
    else
        if command -v bun >/dev/null 2>&1; then
            info "Building frontend with bun..."
            (cd "$PROJECT_DIR/frontend" && bun install && bun run build)
        elif [[ -x /snap/bin/bun ]]; then
            info "Building frontend with /snap/bin/bun..."
            (cd "$PROJECT_DIR/frontend" && /snap/bin/bun install && /snap/bin/bun run build)
        else
            warn "No bun found and no pre-built frontend/dist — skipping frontend"
            return 0
        fi
    fi

    install -d "$WWWDIR"
    rm -rf "${WWWDIR:?}/"*
    cp -r "$dist_dir"/* "$WWWDIR/"
    ok "Frontend installed to $WWWDIR"
}

setup_bpffs() {
    if ! mountpoint -q "$BPFFS" 2>/dev/null; then
        info "Mounting bpffs at $BPFFS..."
        mount -t bpf bpf "$BPFFS" 2>/dev/null || true
    fi

    if ! grep -q "^bpf $BPFFS" /etc/fstab 2>/dev/null; then
        info "Adding bpffs to /etc/fstab for persistence..."
        echo "bpf $BPFFS bpf defaults 0 0" >> /etc/fstab
    fi

    install -d -m 0755 "$BPFFS/jz"
    ok "bpffs ready at $BPFFS/jz"
}

setup_tls() {
    if [[ -f "$TLS_DIR/server.crt" && -f "$TLS_DIR/server.key" ]]; then
        ok "TLS certificates already exist at $TLS_DIR"
        return 0
    fi

    info "Generating self-signed TLS certificate..."
    install -d -m 0750 "$TLS_DIR"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TLS_DIR/server.key" \
        -out "$TLS_DIR/server.crt" \
        -days 3650 -nodes \
        -subj "/CN=jz-sniff/O=jz_sniff_rn" \
        2>/dev/null

    chmod 0640 "$TLS_DIR/server.key"
    chmod 0644 "$TLS_DIR/server.crt"
    ok "TLS certificate generated (valid 10 years)"
}

setup_runtime_dirs() {
    install -d -m 0750 "$DATADIR"
    install -d -m 0750 "$RUNDIR"
    install -d -m 0750 "$SYSCONFDIR"
    if id -u jz >/dev/null 2>&1; then
        chown -R jz:jz "$DATADIR"
    fi
    ok "Runtime directories ready"
}

setup_services() {
    info "Reloading systemd and enabling services..."
    systemctl daemon-reload

    for d in $DAEMONS; do
        systemctl enable "$d" 2>/dev/null
    done
    ok "Services enabled (sniffd, configd, collectord, uploadd)"
}

cleanup_stale_bpf_maps() {
    info "Cleaning stale BPF maps..."
    rm -rf "$BPFFS/jz"
    rm -f "$BPFFS"/jz_* "$BPFFS/rs_ctx_map" "$BPFFS/rs_progs" \
          "$BPFFS/rs_prog_chain" "$BPFFS/rs_event_bus"
    mkdir -p "$BPFFS/jz"
    ok "Stale BPF maps cleaned"
}

start_services() {
    info "Starting services..."

    systemctl restart sniffd
    sleep 2

    for d in configd collectord uploadd; do
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
        ok "  API health: ok (v$version)"
    else
        warn "  API health: not responding (may need a moment to initialize)"
        all_ok=false
    fi

    local modules
    modules=$(curl -sk --max-time 5 https://localhost:8443/api/v1/modules 2>/dev/null) || modules=""
    local loaded
    loaded=$(echo "$modules" | grep -o '"loaded":true' | wc -l)

    if [[ "$loaded" -ge 8 ]]; then
        ok "  BPF modules: $loaded/8 loaded"
    elif [[ "$loaded" -gt 0 ]]; then
        warn "  BPF modules: $loaded/8 loaded"
    else
        warn "  BPF modules: could not query"
    fi

    if [[ -f "$WWWDIR/index.html" ]]; then
        ok "  Frontend: installed at $WWWDIR"
    else
        warn "  Frontend: not found at $WWWDIR"
    fi

    if $all_ok; then
        printf "\n${GRN}=== Deployment successful ===${RST}\n"
        printf "  API:       https://localhost:8443/api/v1/health\n"
        printf "  Frontend:  https://localhost:8443/\n"
        printf "  Logs:      journalctl -u sniffd -f\n"
        printf "  Status:    systemctl status sniffd configd collectord uploadd\n\n"
    else
        printf "\n${YLW}=== Deployment complete with warnings ===${RST}\n"
        printf "  Check: systemctl status sniffd configd collectord uploadd\n"
        printf "  Logs:  journalctl -u sniffd --no-pager -n 50\n\n"
    fi
}

if ! $SKIP_DEPS; then
    check_deps
fi

if ! $SKIP_BUILD; then
    do_build
fi

do_install_binaries
setup_runtime_dirs
setup_bpffs
setup_tls

if ! $SKIP_FRONTEND; then
    do_install_frontend
fi

setup_services

if ! $NO_START; then
    cleanup_stale_bpf_maps
    start_services
    verify
else
    ok "Services installed but not started (--no-start)"
    printf "  Start with: sudo systemctl start sniffd configd collectord uploadd\n"
fi
