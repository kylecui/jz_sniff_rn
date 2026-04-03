#!/usr/bin/env bash
set -euo pipefail

JZDIAG_VERSION="1.0.0"

if [ -t 1 ]; then
    RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; YLW='\033[0;33m'; RST='\033[0m'
else
    RED=''; GRN=''; CYN=''; YLW=''; RST=''
fi

QUIET=false
OUTPUT_DIR="/tmp"
API_HOST="localhost"
API_PORT=""
API_TOKEN="changeme"
API_PORT_SET=false
NO_API=false
NO_DB=false

HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname || echo unknown-host)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK_ROOT=""
COLLECT_ROOT=""
TARBALL_PATH=""
SUMMARY_FILE=""

info()  { $QUIET || printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
ok()    { printf "${GRN}[ OK ]${RST}  %s\n" "$*"; }
warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
err()   { printf "${RED}[ERR]${RST}   %s\n" "$*" >&2; }

usage() {
    cat <<EOF
jzdiag v${JZDIAG_VERSION} — jz_sniff_rn diagnostic collection tool

Usage:
  sudo $0 [OPTIONS]

Options:
  --output-dir DIR     Final tarball output directory (default: /tmp)
  --api-host HOST      API host (default: localhost)
  --api-port PORT      API port (default: auto from /etc/jz/base.yaml, fallback 8443)
  --api-token TOKEN    API bearer token (default: changeme)
  --no-api             Skip API section collection
  --no-db              Skip database section collection
  --quiet              Reduce progress output
  -h, --help           Show this help
  -v, --version        Show version

Output:
  /tmp/jzdiag-<hostname>-<date>.tar.gz (or --output-dir)
EOF
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    if [[ -n "${WORK_ROOT:-}" && -d "${WORK_ROOT:-}" ]]; then
        rm -rf "$WORK_ROOT"
    fi
}
trap cleanup EXIT

run_shell_to_file() {
    local outfile="$1"
    local cmd="$2"
    {
        printf '$ %s\n' "$cmd"
        bash -o pipefail -c "$cmd"
    } >"$outfile" 2>&1 || {
        local rc=$?
        printf '\n[COMMAND FAILED rc=%d: %s]\n' "$rc" "$cmd" >>"$outfile"
        return 0
    }
}

append_shell_to_file() {
    local outfile="$1"
    local cmd="$2"
    {
        printf '\n$ %s\n' "$cmd"
        bash -o pipefail -c "$cmd"
    } >>"$outfile" 2>&1 || {
        local rc=$?
        printf '\n[COMMAND FAILED rc=%d: %s]\n' "$rc" "$cmd" >>"$outfile"
        return 0
    }
}

write_text() {
    local outfile="$1"
    shift
    {
        printf '%s\n' "$@"
    } >"$outfile"
}

mask_yaml_secrets() {
    local src="$1"
    local dst="$2"
    if [[ ! -r "$src" ]]; then
        write_text "$dst" "[MISSING] $src is not readable"
        return 0
    fi

    sed -E \
        -e 's/^([[:space:]]*[^#]*([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|api_token)[[:space:]]*:[[:space:]]*).*/\1<redacted>/g' \
        -e 's/((password|passwd|secret|token)=)[^[:space:]]+/\1<redacted>/Ig' \
        "$src" >"$dst" 2>/dev/null || write_text "$dst" "[FAILED] Could not mask $src"
}

detect_api_port_from_config() {
    local cfg="/etc/jz/base.yaml"
    local detected=""
    if [[ -r "$cfg" ]]; then
        detected="$(awk -F: '/^[[:space:]]*api_port[[:space:]]*:/ {gsub(/[^0-9]/, "", $2); if ($2 != "") {print $2; exit}}' "$cfg" 2>/dev/null || true)"
    fi
    if [[ -n "$detected" ]]; then
        API_PORT="$detected"
    else
        API_PORT="8443"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --output-dir)
                [[ $# -ge 2 ]] || { err "--output-dir requires a value"; exit 1; }
                OUTPUT_DIR="$2"; shift 2 ;;
            --api-host)
                [[ $# -ge 2 ]] || { err "--api-host requires a value"; exit 1; }
                API_HOST="$2"; shift 2 ;;
            --api-port)
                [[ $# -ge 2 ]] || { err "--api-port requires a value"; exit 1; }
                API_PORT="$2"; API_PORT_SET=true; shift 2 ;;
            --api-token)
                [[ $# -ge 2 ]] || { err "--api-token requires a value"; exit 1; }
                API_TOKEN="$2"; shift 2 ;;
            --no-api)
                NO_API=true; shift ;;
            --no-db)
                NO_DB=true; shift ;;
            --quiet)
                QUIET=true; shift ;;
            -h|--help)
                usage; exit 0 ;;
            -v|--version)
                printf '%s\n' "$JZDIAG_VERSION"; exit 0 ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

prepare_workspace() {
    WORK_ROOT="$(mktemp -d /tmp/jzdiag-work.XXXXXX)"
    COLLECT_ROOT="$WORK_ROOT/jzdiag-${HOSTNAME_SHORT}-${STAMP}"
    mkdir -p "$COLLECT_ROOT"/{system,services,config,config/profiles,bpf,network,database,api}
    SUMMARY_FILE="$COLLECT_ROOT/diag-summary.txt"

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        warn "Output directory '$OUTPUT_DIR' does not exist, falling back to /tmp"
        OUTPUT_DIR="/tmp"
    fi

    TARBALL_PATH="$OUTPUT_DIR/jzdiag-${HOSTNAME_SHORT}-${STAMP}.tar.gz"
}

map_entry_count() {
    local map_name="$1"
    local map_path="/sys/fs/bpf/jz/${map_name}"
    if ! have_cmd bpftool; then
        printf '%s\n' "-1"
        return 0
    fi
    if [[ ! -e "$map_path" ]]; then
        printf '%s\n' "-1"
        return 0
    fi

    # Use bpftool map show for a reliable entry count regardless of dump format.
    # bpftool show reports "max_entries N" for fixed-size maps; for hash maps the
    # actual used count requires a dump. We count JSON objects ("key") in the dump
    # which works for both old text-format and newer JSON-format bpftool outputs.
    local cnt
    cnt="$(bpftool map dump pinned "$map_path" 2>/dev/null | \
           grep -cE '"key"|^key:' || true)"
    if [[ -z "$cnt" ]]; then
        printf '%s\n' "-1"
    else
        printf '%s\n' "$cnt"
    fi
}

dump_map_with_limit() {
    local map_name="$1"
    local outfile="$2"
    local max_entries="${3:-500}"
    local count_only_if_gt="${4:-0}"
    local map_path="/sys/fs/bpf/jz/${map_name}"
    local tmpfile="$WORK_ROOT/.map-${map_name}.tmp"

    if ! have_cmd bpftool; then
        write_text "$outfile" "bpftool not available"
        return 0
    fi

    if [[ ! -e "$map_path" ]]; then
        write_text "$outfile" "Pinned map not found: $map_path"
        return 0
    fi

    if bpftool map dump pinned "$map_path" >"$tmpfile" 2>&1; then
        # Count entries: support both old "key: XX XX" text format and new JSON format.
        local entries
        entries="$(grep -cE '"key"|^key:' "$tmpfile" 2>/dev/null || true)"
        entries="${entries:-0}"
        {
            printf 'map: %s\n' "$map_name"
            printf 'path: %s\n' "$map_path"
            printf 'entry_count: %s\n\n' "$entries"

            if [[ "$count_only_if_gt" -gt 0 && "$entries" -gt "$count_only_if_gt" ]]; then
                printf '[INFO] Entry count > %s, showing count only.\n' "$count_only_if_gt"
            else
                # Emit up to max_entries entries from the dump.
                # Works for both JSON (array of objects) and legacy text output.
                if [[ "$entries" -le "$max_entries" ]]; then
                    cat "$tmpfile"
                else
                    # JSON output: each entry is a {...} block; extract first max_entries.
                    # Legacy text: each entry starts with "key:"; print until we hit the limit.
                    awk -v max="$max_entries" '
                        BEGIN {k=0; in_json=0}
                        # JSON: count "{" at start of top-level object lines
                        /^[[:space:]]*\{/ && k == 0 { in_json=1 }
                        in_json && /^[[:space:]]*\{/ { k++ }
                        # Legacy text: key: lines mark new entries
                        !in_json && /^key:/ { k++ }
                        { if (k <= max) print }
                        END {
                            if (k > max)
                                printf "\n[TRUNCATED] showing first %d of %d entries.\n", max, k
                        }
                    ' "$tmpfile"
                fi
            fi
        } >"$outfile"
    else
        cp "$tmpfile" "$outfile" 2>/dev/null || write_text "$outfile" "[FAILED] Unable to dump map $map_name"
        printf '\n[COMMAND FAILED: bpftool map dump pinned %s]\n' "$map_path" >>"$outfile"
    fi

    rm -f "$tmpfile"
}

collect_system() {
    info "Collecting system information..."
    run_shell_to_file "$COLLECT_ROOT/system/uname.txt" "uname -a"
    run_shell_to_file "$COLLECT_ROOT/system/os-release.txt" "cat /etc/os-release"
    run_shell_to_file "$COLLECT_ROOT/system/date.txt" "date -u; timedatectl 2>/dev/null || true"
    run_shell_to_file "$COLLECT_ROOT/system/uptime.txt" "uptime"
    run_shell_to_file "$COLLECT_ROOT/system/dmesg-bpf.txt" "dmesg 2>/dev/null | grep -iE 'bpf|xdp|jz_|sniffd|configd' | tail -n 200"

    local kcfg="/boot/config-$(uname -r)"
    if [[ -r "$kcfg" ]]; then
        run_shell_to_file "$COLLECT_ROOT/system/kernel-config-bpf.txt" \
            "grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|BPF_JIT_DEFAULT_ON|BPF_EVENTS|BPF_STREAM_PARSER|XDP_SOCKETS|DEBUG_INFO_BTF|DEBUG_INFO_DWARF4|IKHEADERS)=' '$kcfg'"
    else
        write_text "$COLLECT_ROOT/system/kernel-config-bpf.txt" "[MISSING] $kcfg not found/readable"
    fi

    run_shell_to_file "$COLLECT_ROOT/system/sysctl-bpf.txt" "sysctl -a 2>/dev/null | grep -E 'net.core|bpf|xdp'"
}

collect_services() {
    info "Collecting service status and journals..."
    run_shell_to_file "$COLLECT_ROOT/services/status-all.txt" "systemctl status sniffd configd collectord uploadd"
    run_shell_to_file "$COLLECT_ROOT/services/journal-sniffd.txt" "journalctl -u sniffd --no-pager -n 500"
    run_shell_to_file "$COLLECT_ROOT/services/journal-configd.txt" "journalctl -u configd --no-pager -n 500"
    run_shell_to_file "$COLLECT_ROOT/services/journal-collectord.txt" "journalctl -u collectord --no-pager -n 500"
    run_shell_to_file "$COLLECT_ROOT/services/journal-uploadd.txt" "journalctl -u uploadd --no-pager -n 200"
    run_shell_to_file "$COLLECT_ROOT/services/journal-rswitch.txt" "journalctl -u rswitch --no-pager -n 200"

    local svc_out="$COLLECT_ROOT/services/service-files.txt"
    : >"$svc_out"
    if ls /etc/systemd/system/*.service >/dev/null 2>&1; then
        for svc in /etc/systemd/system/*.service; do
            local bn
            bn="$(basename "$svc")"
            if [[ "$bn" =~ sniffd|configd|collectord|uploadd ]]; then
                {
                    printf '===== %s =====\n' "$svc"
                    cat "$svc"
                    printf '\n'
                } >>"$svc_out" 2>/dev/null || printf '[FAILED] %s\n' "$svc" >>"$svc_out"
            fi
        done
    else
        write_text "$svc_out" "No matching service files in /etc/systemd/system"
    fi
}

collect_config() {
    info "Collecting configuration..."
    mask_yaml_secrets "/etc/jz/base.yaml" "$COLLECT_ROOT/config/base.yaml"

    if ls /etc/jz/profiles/*.yaml >/dev/null 2>&1; then
        for p in /etc/jz/profiles/*.yaml; do
            cp "$p" "$COLLECT_ROOT/config/profiles/" 2>/dev/null || true
        done
    else
        write_text "$COLLECT_ROOT/config/profiles/README.txt" "No profile YAML files found"
    fi

    write_text "$COLLECT_ROOT/config/notes.txt" "TLS private keys intentionally NOT collected (e.g. /etc/jz/tls/*.key)."
}

collect_bpf() {
    info "Collecting BPF information..."
    run_shell_to_file "$COLLECT_ROOT/bpf/maps-ls.txt" "ls -la /sys/fs/bpf/jz/"

    if have_cmd bpftool; then
        write_text "$COLLECT_ROOT/bpf/bpftool-available.txt" "bpftool: available"
        run_shell_to_file "$COLLECT_ROOT/bpf/progs-ls.txt" "bpftool prog list 2>/dev/null"

        if ls /sys/fs/bpf/jz/* >/dev/null 2>&1; then
            for mp in /sys/fs/bpf/jz/*; do
                local name
                name="$(basename "$mp")"
                dump_map_with_limit "$name" "$COLLECT_ROOT/bpf/map-${name}.txt" 500 0
            done
        else
            write_text "$COLLECT_ROOT/bpf/map-README.txt" "No pinned maps found under /sys/fs/bpf/jz/"
        fi

        dump_map_with_limit "jz_fake_mac_pool" "$COLLECT_ROOT/bpf/jz_fake_mac_pool.txt" 500 0
        dump_map_with_limit "jz_bg_filter" "$COLLECT_ROOT/bpf/jz_bg_filter.txt" 500 0
        dump_map_with_limit "jz_dynamic_guards" "$COLLECT_ROOT/bpf/jz_dynamic_guards.txt" 500 200
        dump_map_with_limit "jz_static_guards" "$COLLECT_ROOT/bpf/jz_static_guards.txt" 500 0
        dump_map_with_limit "jz_dhcp_exception" "$COLLECT_ROOT/bpf/jz_dhcp_exception.txt" 500 0
    else
        write_text "$COLLECT_ROOT/bpf/bpftool-available.txt" "bpftool: NOT available"
        write_text "$COLLECT_ROOT/bpf/progs-ls.txt" "bpftool unavailable; skipping program list"
        write_text "$COLLECT_ROOT/bpf/jz_fake_mac_pool.txt" "bpftool unavailable"
        write_text "$COLLECT_ROOT/bpf/jz_bg_filter.txt" "bpftool unavailable"
        write_text "$COLLECT_ROOT/bpf/jz_dynamic_guards.txt" "bpftool unavailable"
        write_text "$COLLECT_ROOT/bpf/jz_static_guards.txt" "bpftool unavailable"
        write_text "$COLLECT_ROOT/bpf/jz_dhcp_exception.txt" "bpftool unavailable"
    fi
}

collect_interfaces_for_tc() {
    local cfg="/etc/jz/base.yaml"
    local out_file="$1"

    : >"$out_file"

    if [[ -r "$cfg" ]]; then
        awk '
            BEGIN{in_if=0; depth=0}
            /^[[:space:]]*interfaces[[:space:]]*:/ {in_if=1; next}
            in_if && /^[^[:space:]-]/ {in_if=0}
            # Only process top-level list items (leading "- "), skip nested items
            in_if && /^[[:space:]]*-[[:space:]]/ {
                # Count leading spaces to detect nesting level
                match($0, /^[[:space:]]*/)
                cur_indent = RLENGTH
                if (depth == 0) depth = cur_indent
                if (cur_indent > depth) next  # skip nested list items (vlans etc.)
                gsub(/^[[:space:]]*-[[:space:]]*/, "", $0)
                gsub(/[[:space:]]+#.*$/, "", $0)
                # Handle "name: ens33" format
                if ($0 ~ /^name[[:space:]]*:/) {
                    sub(/^name[[:space:]]*:[[:space:]]*/, "", $0)
                    gsub(/[[:space:]]*$/, "", $0)
                }
                # Skip inline objects like { id: 10, ... }
                if ($0 ~ /^\{/) next
                if ($0 != "") print $0
            }
        ' "$cfg" | sort -u >"$out_file" 2>/dev/null || true
    fi

    if [[ ! -s "$out_file" ]]; then
        ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '!/lo/ {print $1}' | sort -u >"$out_file" 2>/dev/null || true
    fi
}

collect_network() {
    info "Collecting network state..."
    run_shell_to_file "$COLLECT_ROOT/network/interfaces.txt" "ip addr show"
    run_shell_to_file "$COLLECT_ROOT/network/routes.txt" "ip route show"
    run_shell_to_file "$COLLECT_ROOT/network/xdp-links.txt" "ip link show | grep -A2 -E 'xdp|prog'"

    local if_list="$WORK_ROOT/interfaces-for-tc.txt"
    collect_interfaces_for_tc "$if_list"

    local tc_out="$COLLECT_ROOT/network/tc-filters.txt"
    : >"$tc_out"
    if [[ -s "$if_list" ]]; then
        while IFS= read -r ifn; do
            [[ -n "$ifn" ]] || continue
            {
                printf '===== tc filter show dev %s ingress =====\n' "$ifn"
                tc filter show dev "$ifn" ingress 2>/dev/null || printf '[no tc ingress filters or command failed]\n'
                printf '\n'
            } >>"$tc_out"
        done <"$if_list"
    else
        write_text "$tc_out" "No interfaces available for tc filter collection"
    fi

    if have_cmd arp; then
        run_shell_to_file "$COLLECT_ROOT/network/arp-table.txt" "arp -n"
    else
        run_shell_to_file "$COLLECT_ROOT/network/arp-table.txt" "ip neigh show"
    fi
}

collect_database() {
    info "Collecting database data..."
    local db_file="/var/lib/jz/jz.db"
    local db_stats="$COLLECT_ROOT/database/db-stats.txt"

    if $NO_DB; then
        write_text "$db_stats" "Database section skipped by --no-db"
        return 0
    fi

    if ! have_cmd sqlite3; then
        write_text "$db_stats" "sqlite3 unavailable; skipping database collection"
        return 0
    fi

    if [[ ! -r "$db_file" ]]; then
        write_text "$db_stats" "Database not found/readable: $db_file"
        return 0
    fi

    {
        printf 'db_file: %s\n' "$db_file"
        printf 'generated_at_utc: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'table_row_counts:\n'
    } >"$db_stats"

    local tables_file="$WORK_ROOT/db-tables.txt"
    sqlite3 "$db_file" "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" >"$tables_file" 2>/dev/null || true

    if [[ -s "$tables_file" ]]; then
        while IFS= read -r t; do
            [[ -n "$t" ]] || continue
            local cnt
            cnt="$(sqlite3 "$db_file" "SELECT COUNT(*) FROM \"$t\";" 2>/dev/null || echo ERR)"
            printf '  - %s: %s\n' "$t" "$cnt" >>"$db_stats"
        done <"$tables_file"
    else
        printf '  [none]\n' >>"$db_stats"
    fi

    run_shell_to_file "$COLLECT_ROOT/database/recent-attacks.txt" "sqlite3 '$db_file' 'SELECT * FROM attack_log ORDER BY rowid DESC LIMIT 20;'"
    run_shell_to_file "$COLLECT_ROOT/database/recent-bg.txt" "sqlite3 '$db_file' 'SELECT * FROM bg_capture ORDER BY rowid DESC LIMIT 20;'"
    run_shell_to_file "$COLLECT_ROOT/database/recent-sniffer.txt" "sqlite3 '$db_file' 'SELECT * FROM sniffer_log ORDER BY rowid DESC LIMIT 20;'"
    run_shell_to_file "$COLLECT_ROOT/database/recent-audit.txt" "sqlite3 '$db_file' 'SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 20;'"
    run_shell_to_file "$COLLECT_ROOT/database/system-state.txt" "sqlite3 '$db_file' 'SELECT * FROM system_state;'"
}

collect_api() {
    info "Collecting API responses..."
    local api_dir="$COLLECT_ROOT/api"
    local api_base="https://${API_HOST}:${API_PORT}"

    if $NO_API; then
        write_text "$api_dir/api-skipped.txt" "API collection skipped by --no-api"
        return 0
    fi

    if ! have_cmd curl; then
        write_text "$api_dir/api-skipped.txt" "curl unavailable; skipping API collection"
        return 0
    fi

    if ! systemctl is-active --quiet sniffd 2>/dev/null; then
        write_text "$api_dir/api-skipped.txt" "sniffd is not active; API collection skipped"
        return 0
    fi

    run_shell_to_file "$api_dir/api-health.txt" "curl -sk --connect-timeout 3 --max-time 10 '${api_base}/api/v1/health'"
    run_shell_to_file "$api_dir/api-status.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/status'"
    run_shell_to_file "$api_dir/api-guards.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/guards'"
    run_shell_to_file "$api_dir/api-guards-dynamic.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/guards/dynamic'"
    run_shell_to_file "$api_dir/api-guards-auto-config.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/guards/auto/config'"
    run_shell_to_file "$api_dir/api-discovery-devices.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/discovery/devices'"
    run_shell_to_file "$api_dir/api-dhcp-exceptions.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/dhcp_exceptions'"
    run_shell_to_file "$api_dir/api-modules.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/modules'"
    run_shell_to_file "$api_dir/api-stats-guards.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/stats/guards'"
    run_shell_to_file "$api_dir/api-stats-background.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/stats/background'"
    run_shell_to_file "$api_dir/api-system-daemons.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/system/daemons'"
    run_shell_to_file "$api_dir/api-system-interfaces.txt" "curl -sk --connect-timeout 3 --max-time 10 -H 'Authorization: Bearer ${API_TOKEN}' '${api_base}/api/v1/system/interfaces'"
}

service_active() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        printf 'PASS'
    else
        printf 'FAIL'
    fi
}

build_summary() {
    info "Building diagnostic summary..."

    local sniffd_stat configd_stat collectord_stat
    sniffd_stat="$(service_active sniffd)"
    configd_stat="$(service_active configd)"
    collectord_stat="$(service_active collectord)"

    local bpftool_note="PASS"
    if ! have_cmd bpftool; then
        bpftool_note="WARN"
    fi

    local fake_cnt bg_cnt dyn_cnt
    fake_cnt="$(map_entry_count jz_fake_mac_pool)"
    bg_cnt="$(map_entry_count jz_bg_filter)"
    dyn_cnt="$(map_entry_count jz_dynamic_guards)"

    local fake_stat="UNKNOWN" bg_stat="UNKNOWN" dyn_stat="UNKNOWN"
    [[ "$fake_cnt" =~ ^[0-9]+$ ]] && { [[ "$fake_cnt" -gt 0 ]] && fake_stat="PASS" || fake_stat="FAIL"; }
    [[ "$bg_cnt" =~ ^[0-9]+$ ]] && { [[ "$bg_cnt" -gt 0 ]] && bg_stat="PASS" || bg_stat="FAIL"; }
    [[ "$dyn_cnt" =~ ^[0-9]+$ ]] && { [[ "$dyn_cnt" -gt 0 ]] && dyn_stat="PASS" || dyn_stat="FAIL"; }

    local cfg_stat="FAIL"
    [[ -r /etc/jz/base.yaml ]] && cfg_stat="PASS"

    local db_stat="FAIL"
    [[ -e /var/lib/jz/jz.db ]] && db_stat="PASS"

    local api_health_stat="SKIP"
    if $NO_API; then
        api_health_stat="SKIP"
    elif have_cmd curl && systemctl is-active --quiet sniffd 2>/dev/null; then
        if curl -sk --connect-timeout 3 --max-time 8 "https://${API_HOST}:${API_PORT}/api/v1/health" >/dev/null 2>&1; then
            api_health_stat="PASS"
        else
            api_health_stat="FAIL"
        fi
    else
        api_health_stat="SKIP"
    fi

    local rswitch_stat="FAIL"
    if systemctl is-active --quiet rswitch 2>/dev/null || pgrep -x rswitch >/dev/null 2>&1; then
        rswitch_stat="PASS"
    fi

    local xdp_stat="FAIL"
    if ip link show 2>/dev/null | grep -Eiq 'xdpgeneric|xdpdrv|xdpoffload|prog/xdp'; then
        xdp_stat="PASS"
    fi

    local btf_stat="FAIL"
    [[ -e /sys/kernel/btf/vmlinux ]] && btf_stat="PASS"

    {
        printf 'jzdiag summary (read this first)\n'
        printf 'version: %s\n' "$JZDIAG_VERSION"
        printf 'host: %s\n' "$HOSTNAME_SHORT"
        printf 'generated_utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'api_target: https://%s:%s\n' "$API_HOST" "$API_PORT"
        printf '\n'
        printf '%-36s %-8s %s\n' 'CHECK' 'STATUS' 'DETAILS'
        printf '%-36s %-8s %s\n' '------------------------------------' '--------' '-------------------------------'
        printf '%-36s %-8s %s\n' 'service sniffd active' "$sniffd_stat" 'systemctl is-active sniffd'
        printf '%-36s %-8s %s\n' 'service configd active' "$configd_stat" 'systemctl is-active configd'
        printf '%-36s %-8s %s\n' 'service collectord active' "$collectord_stat" 'systemctl is-active collectord'
        printf '%-36s %-8s %s\n' 'bpftool installed' "$bpftool_note" 'required for map dumps'
        printf '%-36s %-8s %s\n' 'map jz_fake_mac_pool non-empty' "$fake_stat" "entries=${fake_cnt}"
        printf '%-36s %-8s %s\n' 'map jz_bg_filter non-empty' "$bg_stat" "entries=${bg_cnt}"
        printf '%-36s %-8s %s\n' 'map jz_dynamic_guards non-empty' "$dyn_stat" "entries=${dyn_cnt}"
        printf '%-36s %-8s %s\n' 'config /etc/jz/base.yaml readable' "$cfg_stat" '/etc/jz/base.yaml'
        printf '%-36s %-8s %s\n' 'database file exists' "$db_stat" '/var/lib/jz/jz.db'
        printf '%-36s %-8s %s\n' 'api /api/v1/health responds' "$api_health_stat" "https://${API_HOST}:${API_PORT}/api/v1/health"
        printf '%-36s %-8s %s\n' 'rswitch service/process running' "$rswitch_stat" 'systemctl or pgrep'
        printf '%-36s %-8s %s\n' 'xdp program attachment seen' "$xdp_stat" 'ip link show'
        printf '%-36s %-8s %s\n' 'kernel btf vmlinux available' "$btf_stat" '/sys/kernel/btf/vmlinux'
        printf '\n'
        printf 'Troubleshooting hints:\n'
        printf '  - fake_mac_pool empty => configd may not have pushed maps.\n'
        printf '  - bg_filter empty => discovery pipeline may not be seeing DHCP/ARP.\n'
        printf '  - dynamic_guards empty with discovered devices => auto-guard config/ratio issue.\n'
        printf '  - guards/auto/config enabled=false => dynamic guard deployment disabled.\n'
    } >"$SUMMARY_FILE"
}

create_tarball() {
    info "Creating diagnostic archive..."
    tar -C "$WORK_ROOT" -czf "$TARBALL_PATH" "$(basename "$COLLECT_ROOT")" || {
        err "Failed to create tarball: $TARBALL_PATH"
        exit 1
    }
}

main() {
    parse_args "$@"

    if ! $API_PORT_SET; then
        detect_api_port_from_config
    fi

    if [[ "${API_PORT}" =~ [^0-9] ]] || [[ -z "$API_PORT" ]]; then
        warn "Invalid API port '$API_PORT', using 8443"
        API_PORT="8443"
    fi

    if [[ $(id -u) -ne 0 ]]; then
        warn "Not running as root. Some diagnostics may be incomplete."
    fi

    prepare_workspace

    collect_system
    collect_services
    collect_config
    collect_bpf
    collect_network
    collect_database
    collect_api
    build_summary
    create_tarball

    ok "Diagnostics saved to: $TARBALL_PATH"
}

main "$@"
