#!/usr/bin/env bash
#
# gen_vmlinux.sh – CO-RE vmlinux.h generation
#
# Generates vmlinux.h from kernel BTF data using bpftool.
# This header is required for CO-RE (Compile-Once, Run-Everywhere) BPF modules
# to access kernel data structures without explicit field offsets.
#
# Usage:
#   gen_vmlinux.sh [OUTPUT_PATH]
#   gen_vmlinux.sh --help
#   gen_vmlinux.sh --force [OUTPUT_PATH]
#
# Environment:
#   - Requires: bpftool (from linux-tools package)
#   - Kernel: 5.8+ with BTF support (/sys/kernel/btf/vmlinux must exist)
#
# Exit codes:
#   0 — Success (generated or skipped with current file)
#   1 — Error (missing bpftool, no BTF support, or generation failed)
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────

# Derive project root from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPDIR="$(dirname "$SCRIPT_DIR")"

# Default output path
DEFAULT_OUTPUT="${TOPDIR}/vmlinux.h"

# BTF kernel interface
KERNEL_BTF="/sys/kernel/btf/vmlinux"

# ── Functions ──────────────────────────────────────────────────────

usage() {
    cat << 'EOF'
gen_vmlinux.sh – Generate vmlinux.h from kernel BTF

USAGE:
  gen_vmlinux.sh [OPTIONS] [OUTPUT_PATH]

OPTIONS:
  -h, --help      Show this help message
  --force         Force regeneration (skip timestamp check)

ARGUMENTS:
  OUTPUT_PATH     Output file path (default: $TOPDIR/vmlinux.h)

EXAMPLES:
  # Generate to default location
  gen_vmlinux.sh

  # Generate to custom location
  gen_vmlinux.sh /tmp/vmlinux.h

  # Force regeneration
  gen_vmlinux.sh --force

ENVIRONMENT:
  Requires bpftool from linux-tools package:
    sudo apt install linux-tools-generic

  Requires kernel 5.8+ with BTF support (Ubuntu 22.04+)
EOF
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

info() {
    echo "INFO: $*" >&2
}

check_bpftool() {
    if ! command -v bpftool &> /dev/null; then
        error "bpftool not found. Install it with: sudo apt install linux-tools-generic"
    fi
}

check_kernel_btf() {
    if [[ ! -f "$KERNEL_BTF" ]]; then
        error "Kernel BTF not available at $KERNEL_BTF. Requires kernel 5.8+ (Ubuntu 22.04+)"
    fi
}

# ── Main ───────────────────────────────────────────────────────────

main() {
    local force=0
    local output="$DEFAULT_OUTPUT"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --force)
                force=1
                shift
                ;;
            *)
                # Treat as output path
                output="$1"
                shift
                ;;
        esac
    done

    # Validate prerequisites
    check_bpftool
    check_kernel_btf

    # Create output directory if needed
    local output_dir
    output_dir="$(dirname "$output")"
    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir"
        info "Created output directory: $output_dir"
    fi

    # Check if regeneration is needed (idempotency with timestamp check)
    if [[ -f "$output" ]] && [[ $force -eq 0 ]]; then
        # File exists; check if it's newer than kernel BTF
        if [[ "$output" -nt "$KERNEL_BTF" ]]; then
            local size
            size=$(stat -f%z "$output" 2>/dev/null || stat -c%s "$output" 2>/dev/null)
            info "vmlinux.h is up-to-date ($(stat -f%z "$output" 2>/dev/null || stat -c%s "$output" 2>/dev/null) bytes) — skipping"
            return 0
        fi
    fi

    # Generate vmlinux.h
    info "Generating vmlinux.h from $KERNEL_BTF..."
    if bpftool btf dump file "$KERNEL_BTF" format c > "$output"; then
        local size
        size=$(stat -f%z "$output" 2>/dev/null || stat -c%s "$output" 2>/dev/null)
        info "✓ Generated: $output ($size bytes)"
        return 0
    else
        error "Failed to generate vmlinux.h from $KERNEL_BTF"
    fi
}

main "$@"
