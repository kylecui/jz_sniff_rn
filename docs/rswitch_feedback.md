# rSwitch Platform — Comprehensive Feedback Report

**Project**: https://github.com/kylecui/rswitch
**Report Date**: 2026-03-24
**Context**: This report is based on hands-on experience building a full-stack product (`jz_sniff_rn`) on top of rSwitch, covering 8 BPF modules, 4 user-space daemons, CLI tools, REST API, and a Vue 3 frontend — approximately 25,000+ lines of C and TypeScript.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Platform Architecture & Design](#2-platform-architecture--design)
3. [SDK & Module Development Experience](#3-sdk--module-development-experience)
4. [Documentation Quality](#4-documentation-quality)
5. [Build System & Developer Experience](#5-build-system--developer-experience)
6. [Code Quality & Organization](#6-code-quality--organization)
7. [Testing & CI/CD](#7-testing--cicd)
8. [Versioning, Releases & Legal](#8-versioning-releases--legal)
9. [Community & Governance](#9-community--governance)
10. [Ecosystem Comparison](#10-ecosystem-comparison)
11. [Hands-On Integration Pain Points](#11-hands-on-integration-pain-points)
12. [Recommendations (Prioritized)](#12-recommendations-prioritized)

---

## 1. Executive Summary

rSwitch is an ambitious XDP/eBPF reconfigurable switch platform that offers a genuinely novel approach to programmable networking: a modular, tail-call-chained BPF pipeline with hot-swappable modules, per-CPU context passing, and declarative YAML profiles. The core architectural ideas are sound and, in some respects, ahead of established alternatives like Cilium or Katran.

However, the project suffers from a significant gap between **vision and execution**. The architecture docs describe a production-grade platform; the actual repo delivers something closer to a well-structured prototype. Critical gaps — no LICENSE file, a broken build dependency (SSH-only libbpf submodule), zero CI, misleading documentation of unimplemented features, and no standalone SDK — undermine trust and adoptability.

For our team, building `jz_sniff_rn` on rSwitch was simultaneously **architecturally rewarding** (the pipeline model is elegant, the module ABI is clean) and **practically painful** (integration friction at every turn, no stability contract, undocumented gotchas). This report details both sides.

### Overall Assessment

| Dimension | Score | Summary |
|---|---|---|
| Architecture & Design | **A−** | Excellent modular pipeline; some design gaps in rs_ctx size and stage allocation |
| SDK & Module Dev | **D+** | Backlog admits "no standalone SDK"; module dev requires full source tree |
| Documentation | **B−** | Comprehensive but cluttered; documents features that don't exist yet |
| Build & DX | **C** | Works for the author; broken for everyone else (SSH submodule) |
| Code Quality | **B** | Clean module code; hygiene issues (backup files, duplicate scripts) |
| Testing & CI | **F** | No CI pipeline. Tests require root + real hardware. Tests were broken on kernel 6.8 |
| Versioning & Legal | **F** | No LICENSE file (legally "all rights reserved"). Inconsistent tags. No releases |
| Community | **D** | Solo developer, zero external engagement, self-merged PRs titled "Dev" |
| Ecosystem Position | **B** | Unique niche (modular XDP switch); weaker than alternatives in maturity |

---

## 2. Platform Architecture & Design

### 2.1 What rSwitch Gets Right

**The tail-call pipeline model is elegant.** rSwitch chains BPF programs via `bpf_tail_call()` through the `rs_progs` program array, with each module occupying a consecutive slot. The `RS_TAIL_CALL_NEXT()` macro increments `next_prog_id` and tail-calls to the next slot. This gives:

- Zero-copy pipeline — no userspace context switches between stages
- Hot-swappable modules — update a single `rs_progs` entry to replace a module
- Ordering via stage numbers — modules declare a stage for sorting, but actual slots are assigned consecutively by the loader

This is cleaner than Cilium's approach (monolithic BPF programs with internal dispatch) and more modular than Katran (single-purpose XDP programs). The closest comparison is Polycube's service chaining, but rSwitch achieves it with lower overhead (pure tail calls vs. bpf_redirect).

**The per-CPU context (`rs_ctx`) is well-designed.** A single per-CPU array entry serves as the pipeline context, carrying parsed headers (`rs_layers`), VLAN info, QoS markings, forwarding decisions, and error codes. Modules read/write `rs_ctx` without any locking or copy overhead. The struct layout is carefully aligned for cache performance:

```c
struct rs_ctx {
    __u32 ifindex;
    __u32 timestamp;
    __u8  parsed; __u8 modified; __u8 pad[2];
    struct rs_layers layers;  // parsed L2/L3/L4
    __u16 ingress_vlan; __u16 egress_vlan;
    __u8 prio; __u8 dscp; __u8 ecn; __u8 traffic_class;
    __u32 egress_ifindex;
    __u8 action; __u8 mirror; __u16 mirror_port;
    __u32 error; __u32 drop_reason;
    __u32 next_prog_id; __u32 call_depth;
    __u32 reserved[4];  // 16 bytes for user modules
};
```

**The module declaration macro (`RS_DECLARE_MODULE`) is clean.** Embedding metadata in `.rodata.mod` ELF sections for auto-discovery is a proper plugin pattern. The ABI version check, hook point selection, capability flags, and dependency declaration system show thoughtful design:

```c
RS_DECLARE_MODULE("jz_guard_classifier",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_GUARD_CLASSIFIER,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "Guard IP classifier for honeypot deception");
```

**The shared map system works.** Pinned maps under `/sys/fs/bpf/` allow modules to share state (MAC table, stats, event bus) without coupling. The `rs_event_bus` ringbuf provides a clean event channel from BPF to userspace.

### 2.2 Design Concerns

**`rs_ctx.reserved[4]` is only 16 bytes — far too small for serious user modules.** Our project needed to pass guard classification results, weaver actions, threat levels, and sampling flags between pipeline stages. We defined 8 bytes of custom state at `rs_ctx` offsets 192-255 (per design.md). But `reserved[4]` is only 16 bytes (4 × `__u32`). This forces user modules to rely on per-CPU maps for inter-stage communication, adding map lookups to the hot path.

**Recommendation**: Expand `rs_ctx` reserved area to at least 64 bytes, or provide a dedicated per-CPU "user context" map that's separate from `rs_ctx`.

**Stage number allocation has no user-reserved range.** The stage convention (module_abi.h lines 147-176) carves the ingress pipeline into semantic ranges:

```
10-19: Pre-processing
20-29: VLAN processing
30-39: Access control and security
40-49: Routing
50-69: QoS
70-79: Mirroring
80-89: Learning/observability
90-99: Final decision (lastcall)
```

Every range is claimed by rSwitch core modules. There is **no designated user module range**. We had to squeeze 8 modules into the 21-28 gap between VLAN(20) and ACL(30). This works until someone enables both rSwitch's source_guard(18)/dhcp_snoop(19) and our modules — then stage ordering collisions become unpredictable.

**Recommendation**: Reserve an explicit range (e.g., 100-149 ingress, 200-249 egress) for user/third-party modules. Document this in module_abi.h with the same clarity as the core ranges.

**The egress pipeline uses a different dispatch mechanism (`rs_prog_chain`) than ingress.** Ingress uses simple `next_prog_id++` (consecutive slots), while egress uses a linked-list map lookup via `rs_prog_chain`. This asymmetry is undocumented in the API reference and confusing for module developers who need egress modules.

**No graceful degradation contract.** When rSwitch is not running, our `bpf_loader.c` tries to open `/sys/fs/bpf/rs_progs` and fails. We had to build an entire "degraded mode" ourselves. The platform should define a standard behavior for partial-stack deployments.

---

## 3. SDK & Module Development Experience

### 3.1 The Current State

The `sdk/` directory exists with headers, templates, and a `Makefile.module`. This creates the **impression** of a usable SDK. It is not.

The project's own backlog (`docs/backlog/api-backlog.md`) states:
> "Standalone Module SDK — 🔴 Critical — Module development requires the full rswitch source tree. No standalone SDK exists."

This is the single most impactful gap for downstream developers. Our experience confirms it:

1. **We vendored 4 headers** (`module_abi.h`, `uapi.h`, `rswitch_bpf.h`, `map_defs.h`) into our project. These headers have internal cross-references (`#include "map_defs.h"` from within `rswitch_bpf.h`) that assume a flat directory layout, which differs from the actual rSwitch repo structure (`bpf/core/` vs `bpf/include/`). We had to add a NOTE in our vendored copy:
   ```c
   /* NOTE: Path adjusted for flat include/rswitch/ layout.
    * Original rSwitch repo uses "../core/map_defs.h" from bpf/include/. */
   ```

2. **Map definitions are embedded in headers, not separated.** `map_defs.h` and `uapi.h` both define BPF maps inline (e.g., `rs_ctx_map`, `rs_progs`, `rs_port_config_map`). When a user module includes these headers, it inherits ALL shared maps — even ones it doesn't use. This bloats the BPF object and can cause map creation failures if the kernel limits are tight.

3. **No `make install-sdk` that actually works.** The Makefile target copies headers within the repo tree. It doesn't install to `/usr/local/include/rswitch/` or create a pkg-config file. There is no `rswitch.pc` for downstream build systems to discover.

4. **No ABI stability contract.** `RS_ABI_VERSION` is 1.0, but the backlog admits there is "no formal compatibility policy, no deprecation mechanism." If rSwitch changes `struct rs_ctx` layout, all downstream modules silently break. The `RS_API_STABLE` / `RS_API_EXPERIMENTAL` annotations exist but are not enforced by anything.

### 3.2 What a Real SDK Should Look Like

Compare to libxdp (from the xdp-project):
- **Installable package**: `apt install libxdp-dev` gives you headers + pkg-config
- **Stable API**: versioned symbols, deprecation warnings, semantic versioning
- **Minimal include**: one header, no map definitions leaking
- **CI-tested**: every commit tests the SDK against multiple kernel versions

rSwitch's SDK should aim for:
```
/usr/local/include/rswitch/
    rswitch_module.h     ← single entry point header
    rswitch_abi.h        ← stable ABI definitions only
    rswitch_helpers.h    ← packet parsing, stats, config lookup helpers
/usr/local/lib/pkgconfig/
    rswitch.pc           ← pkg-config for build integration
/usr/local/share/rswitch/
    templates/           ← module scaffolds
    Makefile.module      ← standalone module build recipe
```

### 3.3 Positive Notes

Despite the SDK gaps, some aspects of module development are genuinely pleasant:

- **`RS_DECLARE_MODULE()` is friction-free.** One macro gives you a complete module declaration with zero boilerplate.
- **`RS_GET_CTX()`, `RS_TAIL_CALL_NEXT()`, `RS_EMIT_EVENT()`** — the three core helper macros are intuitive and cover 90% of what a module needs.
- **The capability flags system** (`RS_FLAG_NEED_L2L3_PARSE`, `RS_FLAG_MAY_DROP`, etc.) is a good idea for dependency resolution — once the loader actually enforces them.
- **The API stability tier annotations** (`RS_API_STABLE`, `RS_API_EXPERIMENTAL`, `RS_API_INTERNAL`) show the right thinking, even if they're not yet backed by policy.
- **The `RS_DEPENDS_ON()` macro** for module dependencies is a nice touch — our `jz_traffic_weaver` declares `RS_DEPENDS_ON("jz_guard_classifier")` cleanly.

---

## 4. Documentation Quality

### 4.1 Structure

The `docs/` tree is large and organized:
```
docs/
├── usage/          ← user-facing guides
├── deployment/     ← deployment/install guides
├── development/    ← Module Developer Guide, API Reference, Contributing
├── concepts/       ← XDP pipeline, CO-RE, BPF map explanations
├── backlog/        ← platform + API backlogs (publicly visible)
├── troubleshooting/← troubleshooting guides
├── marketplace/    ← module marketplace concept (stub)
├── zh-CN/          ← Chinese translations (Quick Start, Config, README)
└── archive/        ← 50+ superseded/internal documents (!!)
```

### 4.2 Strengths

- **Module Developer Guide** (587 lines) is the strongest document — clear structure, real code examples, explains the full module lifecycle.
- **API Reference** (580 lines) covers BPF helpers, map definitions, and context structures reasonably well.
- **Concept docs** explain XDP pipeline, CO-RE portability, and BPF maps at the right level for someone new to eBPF.
- **Chinese translations** exist — a positive signal for the target market.

### 4.3 Problems

**`docs/archive/` is a public embarrassment.** 50+ files including:
- `.bak` files (`README.md.bak`, `PHASE1_SUMMARY.md.bak`)
- Internal AI development artifacts (working notes from Sisyphus AI agent sessions)
- Superseded changelogs and design documents

This is not "archive" — it's undeleted working debris. A new developer landing here cannot tell what's current vs. historical. This should be `.gitignore`d or moved to a private repo.

**The README documents features that don't exist.** Specifically:
- `modules: config:` fields in YAML profiles — marked as 🟡 High priority in the backlog, **not implemented**
- `optional_modules:` YAML syntax — **not implemented**
- Profile references to `vlan-isolation.yaml` and `l3-qos-voqd-test.yaml` — these files only exist in `docs/archive/`, not in `etc/profiles/`

This creates false expectations. A new developer following the README will hit dead ends.

**The backlog docs are left public.** `docs/backlog/platform-backlog.md` and `api-backlog.md` openly list critical missing features (no CI, no SDK, no ABI contract, no benchmarks). While transparency is admirable, these docs directly contradict the "production-ready" impression the README and main docs create. At minimum, the README should acknowledge these gaps prominently.

**No versioned documentation.** All docs assume latest. If someone pins to `v0.9`, there's no way to know what was true at that version.

---

## 5. Build System & Developer Experience

### 5.1 Makefile

The Makefile is 658 lines and covers BPF compilation, user-space builds, test targets, install, SDK, and vmlinux generation. The structure is logical.

### 5.2 The SSH Submodule Problem (Showstopper)

`.gitmodules` specifies:
```
[submodule "external/libbpf"]
    url = git@github.com:kylecui/libbpf.git
```

This is a **private SSH URL** pointing to the author's fork of libbpf. Consequences:
- `git clone --recursive` fails for any external developer without SSH access to `kylecui/libbpf`
- Any CI system fails to initialize the submodule
- The `external/libbpf` directory is empty in any clone

**This single issue makes the project unbuildable by anyone other than the author.**

Fix: Change to `https://github.com/libbpf/libbpf` (the canonical upstream).

### 5.3 Other Build Issues

- **Silent bpftool dependency.** `make vmlinux` fails cryptically if `bpftool` is not installed. The README doesn't list it as a prerequisite.
- **No pkg-config integration.** Downstream projects (like ours) must hardcode include paths.
- **No `make install` to standard paths.** The install target exists but installs modules to a non-standard `/usr/local/lib/rswitch/modules/` path that nothing else knows about.
- **Vendored mongoose has no version noted.** The bundled `mongoose.c` in `user/mgmt/` has no version comment, making it impossible to check for CVEs.

---

## 6. Code Quality & Organization

### 6.1 Strengths

- **Module isolation is clean.** Each BPF module is a self-contained `.bpf.c` file with clear concerns.
- **The core dispatcher** (`bpf/core/dispatcher.bpf.c`) and `module_abi.h` establish a clear plugin contract.
- **25 BPF modules** cover a wide feature set: VLAN, ACL, routing, QoS, mirroring, L2 learning, STP, LLDP, LACP, conntrack, sFlow, source guard, etc.
- **Helper functions** in `rswitch_bpf.h` (`get_ethhdr()`, `get_iphdr()`, `rs_get_port_config()`, etc.) are well-written with proper bounds checks.

### 6.2 Hygiene Issues

- **`user/voqd/voqd_dataplane.h.backup`** — a backup file committed to the repo. No place for this in a public codebase.
- **Duplicate test scripts at root**: `test-software-queues.sh` AND `test_software_queues.sh` — two naming conventions, presumably the same test.
- **No `.clang-format` or style enforcement.** Code style is consistent within modules but varies across user-space components.
- **Some AI-authored commits** (`Co-authored-by: Sisyphus`) were merged without apparent human review, though the code quality in these commits is generally acceptable.

### 6.3 Language Breakdown

```
C:       82.7%
Shell:    6.7%
C++:      4.1% (likely mongoose or testing)
HTML:     3.0% (web portal)
Python:   1.9% (testing/scripting)
Makefile: 0.9%
```

This is a healthy distribution for a systems networking project.

---

## 7. Testing & CI/CD

### 7.1 CI/CD: Non-Existent

**Grade: F**

The only GitHub Actions workflow is the auto-added "Copilot Code Review" bot. There is:
- No build automation on push
- No BPF verifier check
- No unit test runner
- No integration test runner
- No cross-kernel compatibility matrix
- No artifact build (no `.deb`, no container image)
- No static analysis (`clang-tidy`, `sparse`)

The platform backlog acknowledges this:
> "CI Pipeline — 🟡 High priority — No automated build or test pipeline exists."

**Consequence**: Recent commits (2026-03-20) show tests being fixed for kernel 6.8 compatibility — meaning tests were **broken** and no CI caught it. There is no confidence gate between `dev` and `main`.

### 7.2 Test Suite

The test suite itself is actually reasonable in coverage:
- `test/unit/` — 13 test files covering dispatcher, ACL, VLAN, STP, rate limiter, source guard, conntrack, etc.
- `test/integration/` — shell-script integration tests (loader, pipeline, profiles, hot-reload)
- `test/benchmark/` — throughput and latency measurement scripts
- `test/fuzz/` — fuzz harness for BPF modules

**But all tests require root and real hardware.** There is no mocking, no BPF emulation, no containerized test environment. This makes the tests:
- Impossible to run in standard CI (GitHub Actions runners don't have BPF_PROG_RUN capability)
- Impossible for a new contributor to run without a dedicated test machine
- Effectively untested — if no one runs them, they rot (as the kernel 6.8 breakage demonstrated)

**Recommendation**: Adopt `BPF_PROG_TEST_RUN` with pre-built test packets for unit tests (runnable in unprivileged containers). Use QEMU+virtme for integration tests in CI.

---

## 8. Versioning, Releases & Legal

### 8.1 Versioning

**Tags**: `v1.0.0`, `v0.9`, `legacy-backup-20251112`, `0.5`, `0.4`, `0.3`

Problems:
- **Inconsistent tag prefixing.** Early tags (`0.3`, `0.4`, `0.5`) lack the `v` prefix. This breaks standard semver tooling.
- **No GitHub Releases.** Tags are lightweight git objects with no release notes, no binary artifacts, no changelog.
- **`v1.0.0` carries no stability promise.** The backlog admits there's no ABI compatibility policy. `v1.0.0` by convention signals API stability — here it means nothing.
- **`RS_ABI_VERSION` = 1 in `module_abi.h`**, but with no enforcement mechanism. Modules compiled against ABI v1 will silently break if `rs_ctx` changes.

### 8.2 License: Legal Emergency

**The README claims**: LGPL-2.1 OR BSD-2-Clause for the project, GPL-2.0 for BPF/user-space, CC-BY-4.0 for docs.

**Reality**: **There is no LICENSE file in the repository.** GitHub's API returns `"license": null`.

Without a LICENSE file:
- The project is technically **All Rights Reserved** under default copyright law
- The claimed multi-license scheme is legally unenforceable
- Any downstream project (including `jz_sniff_rn`) has **no legal clarity** on usage rights
- The complex multi-license structure (LGPL + GPL + CC-BY) is unnecessarily complicated for a project this size

**This must be fixed immediately.** A single `LICENSE` file with the appropriate SPDX identifier is a 5-minute task with enormous legal implications.

---

## 9. Community & Governance

### 9.1 Current State

| Metric | Value |
|---|---|
| Stars | 0 |
| Forks | 0 |
| Watchers | 0 |
| Open Issues | 0 |
| Contributors | 1 primary + 1 AI agent |
| PRs | 4 (all self-merged, 3 titled "Dev") |
| Discussions | Disabled |
| Wiki | Disabled |
| `.github/` templates | None |

This is effectively a **private project hosted publicly**. There is zero external engagement.

### 9.2 PR Discipline

All 4 PRs were opened and merged by the same person (`dev` → `main`):
- PR #1: Title "Dev", body: "most designed features and modules have been implemented. few hasn't been tested yet."
- PR #2: Title "Dev"
- PR #3: "refactor: Revamp README.md" (the only properly titled PR)
- PR #4: Title "Dev"

This is not code review — it's using PRs as a sync mechanism. There's no accountability gate between branches.

### 9.3 What Would Attract Contributors

1. A LICENSE file (current state is a legal minefield for anyone who tries to contribute)
2. Issue templates and "good first issue" labels
3. A CONTRIBUTING.md with clear guidelines
4. A working CI that validates PRs
5. Proper PR descriptions and review process
6. Community channels (Discussions enabled, or a Discord/Matrix)

---

## 10. Ecosystem Comparison

### How rSwitch Compares to Alternatives

| Dimension | rSwitch | Cilium | Katran | libxdp (xdp-tools) | Polycube |
|---|---|---|---|---|---|
| **Architecture** | Modular tail-call pipeline | Monolithic BPF with internal dispatch | Single-purpose XDP LB | Multi-prog chaining via freplace | Service chain via bpf_redirect |
| **Module System** | `.rodata.mod` auto-discovery + stage ordering | N/A (not modular) | N/A | libxdp multi-prog | Service cubes |
| **Hot Swap** | Yes (replace rs_progs entry) | No (reload entire program) | No | Yes (via freplace) | Yes (via namespaces) |
| **SDK** | Exists in theory; requires full source tree | N/A | N/A | `apt install libxdp-dev` | Go API |
| **CI** | None | Extensive (GitHub Actions, Jenkins) | GitHub Actions | GitHub Actions | GitHub Actions |
| **License** | Claims LGPL; no LICENSE file | Apache-2.0 | GPL-2.0 | LGPL-2.1/BSD-2-Clause | Apache-2.0 |
| **Stars** | 0 | 20,000+ | 4,500+ | 500+ | 600+ |
| **Maturity** | Prototype/alpha | Production (Meta, Google) | Production (Meta) | Production (Red Hat) | Research/archived |

### Where rSwitch Excels

1. **Most modular XDP pipeline.** No other project offers the same level of module isolation with auto-discovery and stage-ordered chaining. Cilium's BPF is a monolith; Katran is single-purpose; libxdp uses freplace (which has limitations).

2. **Per-CPU context passing.** The `rs_ctx` pattern is elegant and avoids the overhead of per-packet metadata maps that other solutions use.

3. **Dual pipeline (ingress + egress).** Most XDP projects focus on ingress only. rSwitch's egress pipeline via devmap is forward-thinking.

4. **Feature breadth.** 25 BPF modules covering L2-L4 networking is comprehensive. Few open-source projects attempt a full switch feature set in XDP.

### Where rSwitch Falls Behind

1. **Maturity.** Every alternative listed above has CI, releases, and at least some community. rSwitch has none.

2. **SDK/Integration.** libxdp is installable via package manager with pkg-config. rSwitch requires vendoring headers from a repo you can't even clone (SSH submodule).

3. **Documentation honesty.** Cilium and libxdp clearly distinguish experimental from stable APIs. rSwitch documents unimplemented features as current.

4. **Performance validation.** Katran publishes benchmark numbers. Cilium has extensive performance regression testing. rSwitch's backlog admits: "Performance claims are based on XDP inherent speed, not measured rSwitch throughput."

---

## 11. Hands-On Integration Pain Points

These are specific issues we encountered while building `jz_sniff_rn` on rSwitch:

### 11.1 RS_FLAG_MAY_REDIRECT Was Missing

When we wrote `jz_traffic_weaver.bpf.c`, we needed `RS_FLAG_MAY_REDIRECT` in the module capability flags. It wasn't defined in the vendored `module_abi.h`. We had to add it ourselves (bit 6). This means either:
- The vendored headers were from an older version (no way to tell — no ABI versioning enforcement)
- The flag was never added to the upstream repo

**Root cause**: No SDK versioning, no way to know if your headers are current.

### 11.2 bpf_loader Slot Registration Confusion

The `module_abi.h` comments clearly state:
> "Actual slot assignment in rs_progs array is done automatically by the loader: Ingress modules: slots 0, 1, 2, ... (ascending from 0)"

But there is no public documentation on **how** the rSwitch loader does this. Our `bpf_loader.c` initially used stage numbers as map keys (writing to `rs_progs[22]`, `rs_progs[23]`, etc.). This is wrong — stages are for ordering only. We had to reverse-engineer the correct behavior (consecutive slots starting from 0) from the `RS_TAIL_CALL_NEXT()` macro implementation.

**Root cause**: The loader behavior is implicit in a macro, not documented anywhere.

### 11.3 Stage Number Collision Risk

We placed our 8 modules at stages 21-28 (between VLAN=20 and ACL=30). This works only because:
- We run in a controlled environment where we know which rSwitch core modules are enabled
- We don't use rSwitch's `source_guard` (stage 18) or `dhcp_snoop` (stage 19) which would crowd the same range

In a general deployment, there is no way to know which stage numbers are safe for user modules without reading every core module's source code.

### 11.4 rs_ctx Reserved Space Too Small

`rs_ctx.reserved[4]` provides only 16 bytes for user module state. We needed:
- Guard result (1 byte)
- Guard protocol (1 byte)
- Guard flags (2 bytes)
- Weaver action (1 byte)
- Weaver port (1 byte)
- Threat level (1 byte)
- Sample flag (1 byte)

That's 8 bytes — we fit, but barely. Any more complex module chain would overflow and need per-CPU maps. The design.md claims "offset 192-255" (64 bytes), but the actual `rs_ctx` struct only has `reserved[4]` (16 bytes). This discrepancy is confusing.

### 11.5 No Graceful Degradation Protocol

When deploying to a machine without rSwitch installed:
- `bpf_obj_get("/sys/fs/bpf/rs_progs")` returns `-ENOENT`
- `bpf_obj_get("/sys/fs/bpf/rs_event_bus")` returns `-ENOENT`
- Our BPF modules can load (libbpf creates fresh maps) but aren't registered in any pipeline

We built an entire "degraded mode" in sniffd to handle this — BPF objects load, maps populate, but XDP is not attached and ringbuf polling uses our own maps instead of the shared `rs_event_bus`.

**There should be a documented degradation protocol**: what happens when rSwitch maps don't exist, what subset of functionality is expected, how modules should detect and adapt.

### 11.6 Map Reuse Dance

Loading user modules after rSwitch is already running requires carefully reusing its pinned maps. Our `bpf_loader.c` lines 200-223 implement a map reuse dance:

```c
bpf_object__for_each_map(map, obj) {
    // Try jz pin path first
    snprintf(pin, sizeof(pin), "%s/%s", loader->pin_path, map_name);
    existing_fd = bpf_obj_get(pin);
    if (existing_fd < 0) {
        // Fallback to flat /sys/fs/bpf/ for rSwitch shared maps
        snprintf(pin, sizeof(pin), "/sys/fs/bpf/%s", map_name);
        existing_fd = bpf_obj_get(pin);
    }
    if (existing_fd >= 0)
        bpf_map__reuse_fd(map, existing_fd);
}
```

This works, but it's fragile. The pin path convention (`/sys/fs/bpf/` vs `/sys/fs/bpf/rswitch/`) is undocumented. Our design.md says shared maps are at `/sys/fs/bpf/rswitch/` but the actual headers use `LIBBPF_PIN_BY_NAME` which pins to `/sys/fs/bpf/` flat.

**Root cause**: Undocumented map pinning convention.

### 11.7 Event Type Namespace Collision

`rs_event_bus` is a shared ringbuf. rSwitch core events use `RS_EVENT_*` types (0x0000-0xFFFF). We defined `JZ_EVENT_*` types (1-8, simple integers). There is no documented namespace allocation for user module event types. If two independent module sets both use type ID 1, their events are indistinguishable on the shared bus.

**Recommendation**: Reserve an event type range for user modules (e.g., 0x1000-0x7FFF) and document the allocation process.

---

## 12. Recommendations (Prioritized)

### 🔴 Critical (Must Fix — Blocking Adoption)

| # | Issue | Fix | Effort |
|---|---|---|---|
| 1 | **No LICENSE file** | Create `LICENSE` with LGPL-2.1-or-later. One file, 5 minutes. | 5 min |
| 2 | **SSH submodule breaks all external builds** | Change `.gitmodules` URL from `git@github.com:kylecui/libbpf.git` to `https://github.com/libbpf/libbpf` | 5 min |
| 3 | **No CI pipeline** | Add minimal GitHub Actions: `make` on push to `dev`/`main`, kernel 6.6+6.8 matrix via QEMU/virtme | 1 day |
| 4 | **No GitHub Releases** | Create a proper v1.0.0 Release with changelog, known limitations, kernel requirements | 1 hour |
| 5 | **README documents unimplemented features** | Audit README against backlog; mark planned features with 🚧 or remove them | 2 hours |

### 🟡 High Priority (Significant Quality Improvement)

| # | Issue | Fix | Effort |
|---|---|---|---|
| 6 | **No standalone SDK** | Create installable SDK: headers + pkg-config + Makefile.module that works without the full source tree | 1 week |
| 7 | **No user module stage range** | Reserve stages 100-149 (ingress user) and 200-249 (egress user) in module_abi.h | 1 hour |
| 8 | **rs_ctx reserved area too small** | Expand `reserved[4]` to `reserved[16]` (64 bytes) — matches the documented "offset 192-255" | 1 hour |
| 9 | **docs/archive/ publicly visible** | Move to a private repo or add to `.gitignore`. Purge `.bak` files from git history | 2 hours |
| 10 | **No ABI stability contract** | Publish an ABI policy: "rs_ctx layout is stable in ABI v1.x. Struct size changes require ABI v2" | 1 day |

### 🟢 Nice to Have (Polish & Community)

| # | Issue | Fix | Effort |
|---|---|---|---|
| 11 | **Map pin path undocumented** | Document: "Core maps pin to /sys/fs/bpf/{name}. User maps should pin to /sys/fs/bpf/{namespace}/" | 1 hour |
| 12 | **Event type namespace collision** | Reserve 0x1000-0x7FFF for user events. Document allocation | 1 hour |
| 13 | **No "hello world" tutorial** | Write "Build your first module" walkthrough: count packets, load, verify, unload | 1 day |
| 14 | **GitHub repo metadata empty** | Add description, topics (xdp, ebpf, networking, switch), enable Discussions | 15 min |
| 15 | **No CHANGELOG.md** | Create root-level CHANGELOG.md following Keep a Changelog format | 2 hours |
| 16 | **Add `.clang-format`** | Enforce consistent code style across all C source | 1 hour |
| 17 | **Vendored mongoose has no version** | Add version comment to mongoose.c header, check for known CVEs | 30 min |
| 18 | **Degradation protocol** | Document what happens when rSwitch maps don't exist; define standard fallback behavior | 1 day |

---

## Appendix A: Files Referenced

| File | Role | Notes |
|---|---|---|
| `include/rswitch/module_abi.h` | Module ABI definition | 195 lines, well-structured |
| `include/rswitch/uapi.h` | Shared data structures | 201 lines, rs_ctx + maps + helper macros |
| `include/rswitch/rswitch_bpf.h` | BPF common header | 285 lines, CO-RE helpers + packet parsers |
| `include/rswitch/map_defs.h` | Shared map definitions | 275 lines, port config + MAC table + VLAN + stats |
| `bpf/jz_guard_classifier.bpf.c` | Our first pipeline module | 236 lines, demonstrates full SDK usage |
| `bpf/jz_traffic_weaver.bpf.c` | Our redirect/mirror module | 295 lines, hit RS_FLAG_MAY_REDIRECT issue |
| `bpf/include/jz_common.h` | Our shared definitions | 83 lines, stage numbers + rs_ctx offsets + event types |
| `src/sniffd/bpf_loader.c` | Our module loader | 465 lines, map reuse dance + slot registration |

## Appendix B: Positive Takeaways

Despite the critical gaps, building on rSwitch was architecturally rewarding:

1. **The pipeline model scales.** We loaded 8 modules with zero visible performance degradation. Tail calls are essentially free.
2. **Module isolation is real.** Our modules never had to touch rSwitch core code. The constraint held.
3. **Per-CPU context works.** Zero-lock packet state passing between stages is elegant and fast.
4. **The BPF helper macros are well-designed.** `RS_GET_CTX()`, `RS_TAIL_CALL_NEXT()`, `RS_EMIT_EVENT()` covered 95% of our needs.
5. **Hot-reload potential is genuine.** We can replace a single `rs_progs` entry to swap a module at runtime — no pipeline restart needed.
6. **The event bus abstraction is clean.** One ringbuf for all events, type-tagged, user-space subscription — this is the right pattern.

rSwitch has the bones of something excellent. The architecture deserves a mature implementation around it.
