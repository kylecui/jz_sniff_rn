# jz_sniff_rn — Top-level Makefile
# Build system for BPF modules (kernel-space) and user-space daemons
# Target: Ubuntu 22.04+ with kernel 5.8+
#
# Usage:
#   make all       — Build everything
#   make bpf       — Build BPF modules only
#   make user      — Build user-space programs only
#   make test      — Run all tests
#   make clean     — Remove build artifacts
#   make install   — Install to system paths

.PHONY: all bpf user cli test clean install \
        test-unit test-bpf test-integration test-perf \
        coverage lint format help

# ── Toolchain ──────────────────────────────────────────────────
CLANG      ?= clang
LLC        ?= llc
CC         ?= gcc
BPFTOOL    ?= bpftool
INSTALL    ?= install
PKG_CONFIG ?= pkg-config

# ── Directories ────────────────────────────────────────────────
TOPDIR     := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BPF_DIR    := $(TOPDIR)/bpf
SRC_DIR    := $(TOPDIR)/src
CLI_DIR    := $(TOPDIR)/cli
TEST_DIR   := $(TOPDIR)/tests
BUILD_DIR  := $(TOPDIR)/build
INCLUDE_DIR:= $(TOPDIR)/include
SCRIPTS_DIR:= $(TOPDIR)/scripts
CONFIG_DIR := $(TOPDIR)/config
SYSTEMD_DIR:= $(TOPDIR)/systemd

# Install paths
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc/jz
DATADIR    ?= /var/lib/jz
RUNDIR     ?= /var/run/jz
UNITDIR    ?= /etc/systemd/system

# ── BPF Build Flags ───────────────────────────────────────────
# Kernel headers (auto-detect or override with KERNEL_HEADERS=)
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)
VMLINUX_H     ?= $(TOPDIR)/vmlinux.h

BPF_CFLAGS := -g -O2 \
              -target bpf \
              -D__TARGET_ARCH_x86 \
              -Wall -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -I$(BPF_DIR)/include \
              -I$(INCLUDE_DIR) \
              -I$(INCLUDE_DIR)/rswitch \
              -I$(TOPDIR) \
              -idirafter /usr/include/x86_64-linux-gnu

# ── User-space Build Flags ────────────────────────────────────
USER_CFLAGS  := -g -O2 -Wall -Wextra -Werror \
                -std=c11 -D_GNU_SOURCE \
                -I$(SRC_DIR)/common \
                -I$(BPF_DIR)/include \
                -I$(INCLUDE_DIR) \
                -I$(INCLUDE_DIR)/rswitch \
                -I$(TOPDIR)/third_party/mongoose \
                -I$(TOPDIR)/third_party/cjson \
                -I$(TOPDIR)/third_party/libyaml/include

USER_LDFLAGS := -lbpf -lelf -lz -lpthread -lsqlite3 -lm -lyaml

# Test flags (cmocka)
TEST_CFLAGS  := $(USER_CFLAGS) -I$(TEST_DIR) \
                --coverage -fprofile-arcs -ftest-coverage
TEST_LDFLAGS := $(USER_LDFLAGS) -lcmocka --coverage

# ── Source Files ──────────────────────────────────────────────

# BPF modules
BPF_SRCS := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(BPF_DIR)/%.bpf.c,$(BUILD_DIR)/bpf/%.bpf.o,$(BPF_SRCS))

# Common library
COMMON_SRCS := $(wildcard $(SRC_DIR)/common/*.c)
COMMON_OBJS := $(patsubst $(SRC_DIR)/common/%.c,$(BUILD_DIR)/common/%.o,$(COMMON_SRCS))

# Vendored third-party sources (compiled as common objects)
VENDOR_SRCS := $(TOPDIR)/third_party/cjson/cJSON.c \
               $(TOPDIR)/third_party/mongoose/mongoose.c
VENDOR_OBJS := $(BUILD_DIR)/vendor/cJSON.o \
               $(BUILD_DIR)/vendor/mongoose.o
COMMON_OBJS += $(VENDOR_OBJS)

# Daemons
DAEMONS := sniffd configd collectord uploadd
DAEMON_BINS := $(foreach d,$(DAEMONS),$(BUILD_DIR)/$(d)/$(d))

# CLI tools
CLI_TOOLS := jzctl jzguard jzlog
CLI_BINS  := $(foreach t,$(CLI_TOOLS),$(BUILD_DIR)/cli/$(t))

# ── Targets ───────────────────────────────────────────────────

all: bpf user cli
	@echo "=== Build complete ==="

# ── BPF Modules ───────────────────────────────────────────────

bpf: $(BPF_OBJS)
	@echo "=== BPF modules built ==="

$(BUILD_DIR)/bpf/%.bpf.o: $(BPF_DIR)/%.bpf.c $(wildcard $(BPF_DIR)/include/*.h) | $(BUILD_DIR)/bpf
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── User-space Daemons ────────────────────────────────────────

user: $(COMMON_OBJS) $(DAEMON_BINS)
	@echo "=== User-space daemons built ==="

# Common library objects
$(BUILD_DIR)/common/%.o: $(SRC_DIR)/common/%.c | $(BUILD_DIR)/common
	$(CC) $(USER_CFLAGS) -c $< -o $@

# Vendored third-party objects (no -Werror to tolerate upstream warnings)
$(BUILD_DIR)/vendor/cJSON.o: $(TOPDIR)/third_party/cjson/cJSON.c | $(BUILD_DIR)/vendor
	$(CC) $(USER_CFLAGS) -Wno-error -c $< -o $@

$(BUILD_DIR)/vendor/mongoose.o: $(TOPDIR)/third_party/mongoose/mongoose.c | $(BUILD_DIR)/vendor
	$(CC) $(USER_CFLAGS) -Wno-error -DMG_TLS=MG_TLS_BUILTIN -DMG_ENABLE_LINES=1 -c $< -o $@

# Daemon build rules (each daemon links common + its own sources)
define DAEMON_RULES
$(BUILD_DIR)/$(1)/$(1): $(wildcard $(SRC_DIR)/$(1)/*.c) $(COMMON_OBJS) | $(BUILD_DIR)/$(1)
	$(CC) $(USER_CFLAGS) -o $$@ $$(filter %.c,$$^) $(COMMON_OBJS) $(USER_LDFLAGS)
endef

$(foreach d,$(DAEMONS),$(eval $(call DAEMON_RULES,$(d))))

# ── CLI Tools ─────────────────────────────────────────────────

cli: $(CLI_BINS)
	@echo "=== CLI tools built ==="

$(BUILD_DIR)/cli/%: $(CLI_DIR)/%.c $(COMMON_OBJS) | $(BUILD_DIR)/cli
	$(CC) $(USER_CFLAGS) -o $@ $< $(COMMON_OBJS) $(USER_LDFLAGS)

# ── Build directories ─────────────────────────────────────────

$(BUILD_DIR)/bpf $(BUILD_DIR)/common $(BUILD_DIR)/cli $(BUILD_DIR)/vendor:
	mkdir -p $@

$(BUILD_DIR)/sniffd $(BUILD_DIR)/configd $(BUILD_DIR)/collectord $(BUILD_DIR)/uploadd:
	mkdir -p $@

# ── Tests ─────────────────────────────────────────────────────

test: test-unit test-bpf
	@echo "=== All tests passed ==="

test-unit: $(COMMON_OBJS) | $(BUILD_DIR)/tests/unit
	@echo "--- Running unit tests ---"
	@for src in $(wildcard $(TEST_DIR)/unit/test_*.c); do \
		name=$$(basename $$src .c); \
		$(CC) $(TEST_CFLAGS) -o $(BUILD_DIR)/tests/unit/$$name \
			$$src $(COMMON_OBJS) $(TEST_LDFLAGS); \
		$(BUILD_DIR)/tests/unit/$$name || exit 1; \
	done

test-bpf: bpf | $(BUILD_DIR)/tests/bpf
	@echo "--- Running BPF tests ---"
	@for src in $(wildcard $(TEST_DIR)/bpf/test_*.c); do \
		name=$$(basename $$src .c); \
		$(CC) $(TEST_CFLAGS) -o $(BUILD_DIR)/tests/bpf/$$name \
			$$src $(TEST_LDFLAGS); \
		$(BUILD_DIR)/tests/bpf/$$name || exit 1; \
	done

LIBBPF17_INC := /usr/local/bpf/include
LIBBPF17_LIB := /usr/local/bpf/lib64/libbpf.a

test-integration: bpf | $(BUILD_DIR)/tests/integration
	@echo "--- Running integration tests (requires root, libbpf 1.7) ---"
	@for src in $(wildcard $(TEST_DIR)/integration/test_*.c); do \
		name=$$(basename $$src .c); \
		$(CC) $(USER_CFLAGS) -I$(LIBBPF17_INC) \
			-o $(BUILD_DIR)/tests/integration/$$name \
			$$src $(LIBBPF17_LIB) -lelf -lz -lcmocka; \
		$(BUILD_DIR)/tests/integration/$$name || exit 1; \
	done

test-perf: bpf | $(BUILD_DIR)/tests/perf
	@echo "--- Running performance benchmarks (requires root, libbpf 1.7) ---"
	@for src in $(wildcard $(TEST_DIR)/perf/test_*.c); do \
		name=$$(basename $$src .c); \
		$(CC) $(USER_CFLAGS) -I$(LIBBPF17_INC) \
			-o $(BUILD_DIR)/tests/perf/$$name \
			$$src $(LIBBPF17_LIB) -lelf -lz; \
		$(BUILD_DIR)/tests/perf/$$name || exit 1; \
	done

$(BUILD_DIR)/tests/unit $(BUILD_DIR)/tests/bpf $(BUILD_DIR)/tests/integration $(BUILD_DIR)/tests/perf:
	mkdir -p $@

# ── Coverage ──────────────────────────────────────────────────

coverage: test
	lcov --capture --directory $(BUILD_DIR) --output-file $(BUILD_DIR)/lcov.info
	genhtml $(BUILD_DIR)/lcov.info --output-directory $(BUILD_DIR)/coverage
	@echo "Coverage report: $(BUILD_DIR)/coverage/index.html"

# ── Lint & Format ─────────────────────────────────────────────

lint:
	@echo "--- Static analysis ---"
	cppcheck --enable=all --suppress=missingIncludeSystem \
		$(SRC_DIR) $(CLI_DIR) $(BPF_DIR)

format:
	find $(SRC_DIR) $(CLI_DIR) $(BPF_DIR) -name '*.c' -o -name '*.h' | \
		xargs clang-format -i --style=file

# ── Install ───────────────────────────────────────────────────

install: all
	# Daemons
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(foreach d,$(DAEMONS),$(INSTALL) -m 0755 $(BUILD_DIR)/$(d)/$(d) $(DESTDIR)$(SBINDIR)/;)
	# CLI tools
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(foreach t,$(CLI_TOOLS),$(INSTALL) -m 0755 $(BUILD_DIR)/cli/$(t) $(DESTDIR)$(BINDIR)/;)
	# BPF modules
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/bpf
	$(INSTALL) -m 0644 $(BUILD_DIR)/bpf/*.bpf.o $(DESTDIR)$(SYSCONFDIR)/bpf/
	# Config files
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/profiles
	$(INSTALL) -m 0640 $(CONFIG_DIR)/base.yaml $(DESTDIR)$(SYSCONFDIR)/
	-$(INSTALL) -m 0640 $(CONFIG_DIR)/profiles/*.yaml $(DESTDIR)$(SYSCONFDIR)/profiles/ 2>/dev/null || true
	# Systemd services
	$(INSTALL) -d $(DESTDIR)$(UNITDIR)
	$(INSTALL) -m 0644 $(SYSTEMD_DIR)/*.service $(DESTDIR)$(UNITDIR)/
	# Runtime directories
	$(INSTALL) -d -m 0750 $(DESTDIR)$(DATADIR)
	$(INSTALL) -d -m 0750 $(DESTDIR)$(RUNDIR)

uninstall:
	$(foreach d,$(DAEMONS),rm -f $(DESTDIR)$(SBINDIR)/$(d);)
	$(foreach t,$(CLI_TOOLS),rm -f $(DESTDIR)$(BINDIR)/$(t);)
	rm -rf $(DESTDIR)$(SYSCONFDIR)/bpf
	rm -f $(DESTDIR)$(UNITDIR)/sniffd.service \
	      $(DESTDIR)$(UNITDIR)/configd.service \
	      $(DESTDIR)$(UNITDIR)/collectord.service \
	      $(DESTDIR)$(UNITDIR)/uploadd.service

# ── Clean ─────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD_DIR)

# ── Help ──────────────────────────────────────────────────────

help:
	@echo "jz_sniff_rn Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build everything (BPF + user-space + CLI)"
	@echo "  bpf              Build BPF modules only"
	@echo "  user             Build user-space daemons"
	@echo "  cli              Build CLI tools"
	@echo "  test             Run all tests (unit + BPF)"
	@echo "  test-unit        Run C unit tests (cmocka)"
	@echo "  test-bpf         Run BPF tests (prog_test_run)"
	@echo "  test-integration Run BPF pipeline integration tests (requires root)"
	@echo "  test-perf        Run BPF performance benchmarks (requires root)"
	@echo "  coverage         Generate test coverage report"
	@echo "  lint             Run static analysis (cppcheck)"
	@echo "  format           Auto-format source code (clang-format)"
	@echo "  install          Install to system paths"
	@echo "  uninstall        Remove installed files"
	@echo "  clean            Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  CC=gcc           C compiler for user-space"
	@echo "  CLANG=clang      Clang for BPF compilation"
	@echo "  PREFIX=/usr/local Install prefix"
	@echo "  DESTDIR=         Staging directory for packaging"
