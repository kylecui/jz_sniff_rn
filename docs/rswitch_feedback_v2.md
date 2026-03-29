# rSwitch 平台 — 第二轮综合反馈报告

**项目**: https://github.com/kylecui/rswitch
**报告日期**: 2026-03-29
**反馈轮次**: 第二轮（第一轮: 2026-03-24）
**背景**: 本报告基于在 rSwitch 平台上构建完整生产级产品 `jz_sniff_rn`（28,000+ 行 C 代码，8 个 BPF 模块，4 个用户态守护进程，Vue 3 前端）的实际开发经验。自第一轮反馈以来，rSwitch 已发布多个版本更新，本报告评估改进效果并提出剩余建议。

---

## 目录

1. [总体评价与评分对比](#1-总体评价与评分对比)
2. [第一轮反馈采纳情况](#2-第一轮反馈采纳情况)
3. [SDK 与二次开发便利性](#3-sdk-与二次开发便利性)
4. [ABI 稳定性与版本兼容性](#4-abi-稳定性与版本兼容性)
5. [文档齐全性与准确性](#5-文档齐全性与准确性)
6. [构建系统与工具链](#6-构建系统与工具链)
7. [运行时架构与服务管理](#7-运行时架构与服务管理)
8. [Map 共享与命名空间](#8-map-共享与命名空间)
9. [测试框架与 CI](#9-测试框架与-ci)
10. [社区治理与发布管理](#10-社区治理与发布管理)
11. [仍存在的问题与建议](#11-仍存在的问题与建议)
12. [总结](#12-总结)

---

## 1. 总体评价与评分对比

rSwitch 在第一轮反馈后进行了**大规模的改进**，从一个"架构优秀但执行不成熟的原型"演变为一个**具备真正 SDK、正式 ABI 合约、CI 流水线和完善文档体系的开源平台**。改进的幅度和速度令人印象深刻。

### 评分对比

| 维度 | 第一轮评分 | 第二轮评分 | 变化 | 主要改进 |
|------|-----------|-----------|------|---------|
| 架构与设计 | **A−** | **A** | ↑ | rs_ctx 扩展为 64 字节 reserved、用户阶段范围明确划分 |
| SDK 与模块开发 | **D+** | **A−** | ↑↑↑ | 独立 SDK 包、pkg-config、Makefile.module、三套模板、820 行教程 |
| 文档质量 | **B−** | **A−** | ↑↑ | Documentation_Index、概念文档（双语）、SDK 快速入门、API 参考（自动生成） |
| 构建与 DX | **C** | **B+** | ↑↑ | HTTPS submodule、一键安装器、SDK 安装目标 |
| 代码质量 | **B** | **B+** | ↑ | SPDX 头、clang-format、头文件层次清晰 |
| 测试与 CI | **F** | **B−** | ↑↑↑↑ | CI 流水线、test_harness.h、mock_maps.h、BPF_PROG_TEST_RUN |
| 版本与法律 | **F** | **B+** | ↑↑↑↑ | LICENSE 文件、ABI v2.0 正式策略、语义化标签 (v2.0.0, v2.0.1) |
| 社区与治理 | **D** | **C+** | ↑ | CONTRIBUTING.md、PR 工作流文档、issue 模板 |

**总体评级**: 从 **C+** 提升到 **B+/A−**。这是一次质的飞跃。

---

## 2. 第一轮反馈采纳情况

### 🔴 Critical 级别建议 — 采纳率: 5/5 (100%)

| # | 第一轮建议 | 状态 | 实现质量 |
|---|-----------|------|---------|
| 1 | **无 LICENSE 文件** | ✅ 已修复 | LGPL-2.1-or-later，SPDX 头全覆盖 |
| 2 | **SSH submodule 阻断构建** | ✅ 已修复 | 改为 HTTPS URL |
| 3 | **无 CI 流水线** | ✅ 已实现 | GitHub Actions，含 BPF 测试、clang-format 检查 |
| 4 | **无 GitHub Releases** | ✅ 已实现 | v2.0.0、v2.0.1 正式发布 |
| 5 | **README 描述未实现功能** | ✅ 已修复 | Known Limitations 表格明确标注"Planned"功能 |

### 🟡 High Priority 建议 — 采纳率: 5/5 (100%)

| # | 第一轮建议 | 状态 | 实现质量 |
|---|-----------|------|---------|
| 6 | **无独立 SDK** | ✅ 已实现 | `sdk/` 目录、`make install-sdk`、pkg-config、Makefile.module、三套模板 |
| 7 | **无用户模块阶段范围** | ✅ 已实现 | 用户 ingress 200-299、用户 egress 400-499，module_abi.h 明确文档化 |
| 8 | **rs_ctx reserved 区域过小** | ✅ 已实现 | `reserved[16]`（64 字节），ABI v2.0 |
| 9 | **docs/archive/ 公开可见** | ✅ 已处理 | archive/ 保留但标注为历史文档 |
| 10 | **无 ABI 稳定性合约** | ✅ 已实现 | ABI_POLICY.md (203 行)，三级稳定性标注，loader 强制版本校验 |

### 🟢 Nice to Have 建议 — 采纳率: 6/8 (75%)

| # | 第一轮建议 | 状态 | 备注 |
|---|-----------|------|------|
| 11 | Map pin 路径文档 | ✅ 已实现 | MAP_PINNING.md |
| 12 | Event type 命名空间 | ✅ 已实现 | 用户事件范围 0x1000-0x7FFF |
| 13 | "Hello world" 教程 | ✅ 已实现 | SDK_Quick_Start.md (820 行！) |
| 14 | GitHub 仓库元数据 | 部分 | 仍可改善 |
| 15 | CHANGELOG.md | ❌ 未实现 | 版本历史仅在 ABI_POLICY.md 中提及 |
| 16 | `.clang-format` | ✅ 已实现 | CI 中包含 clang-format 检查 |
| 17 | Vendored mongoose 版本标注 | 未确认 | — |
| 18 | 降级协议文档 | ✅ 已实现 | DEGRADATION.md + RS_IS_PIPELINE_ACTIVE() 宏 |

**总计: 16/18 建议已采纳 (89%)**。这是非常高的响应率，表明项目维护者高度重视下游开发者的反馈。

---

## 3. SDK 与二次开发便利性

### 3.1 SDK 架构 — 质的飞跃

第一轮评分 **D+** → 第二轮评分 **A−**

这是改进最显著的领域。SDK 从"名义上存在、实际不可用"变为一个**结构完整、可独立安装、有教程有模板**的正式开发工具包。

**SDK 目录结构:**
```
sdk/
├── include/
│   ├── rswitch_module.h    ← 统一入口头文件 (新增!)
│   ├── rswitch_abi.h       ← ABI v2.0 定义 (311 行)
│   ├── rswitch_helpers.h   ← BPF 辅助函数和宏 (339 行)
│   ├── rswitch_maps.h      ← 可选: 共享 map 定义 (419 行)
│   ├── rswitch_common.h    ← 向后兼容: 全量导入
│   ├── module_abi.h        ← 模块 ABI 定义 (202 行)
│   ├── rswitch_bpf.h       ← 遗留兼容
│   ├── uapi.h              ← 遗留兼容
│   └── map_defs.h          ← 遗留兼容
├── templates/
│   ├── simple_module.bpf.c
│   ├── stateful_module.bpf.c
│   └── egress_module.bpf.c
├── test/
│   ├── test_harness.h
│   └── mock_maps.h
├── docs/
│   ├── SDK_Quick_Start.md      ← 820 行!
│   ├── Module_Development_Spec.md
│   └── zh-CN/SDK_Quick_Start.md
├── Makefile.module         ← 独立模块构建系统
└── rswitch.pc.in           ← pkg-config 模板
```

**关键改进点:**

1. **统一入口头文件 `rswitch_module.h`** — 一个 `#include <rswitch_module.h>` 即可获得所有必要定义。第一轮反馈中我们建议的方案被完整实现。

2. **Map 定义解耦** — `rswitch_helpers.h` 使用 `extern` 前向声明 pipeline map（`rs_ctx_map`、`rs_progs`、`rs_prog_chain`、`rs_event_bus`），不实例化任何 map。只有显式 `#include <rswitch_maps.h>` 才会引入完整 map 定义。这解决了第一轮反馈中提到的"所有 map 泄漏到用户模块"问题。

3. **`Makefile.module` 支持 pkg-config 发现** — 外部模块可以通过标准 `pkg-config --cflags rswitch` 获取头文件路径，无需硬编码。

4. **三套模板** — `simple_module.bpf.c`（极简 ingress）、`stateful_module.bpf.c`（有状态模块）、`egress_module.bpf.c`（egress 管道）。模板代码质量高，注释清晰，包含降级处理（`RS_IS_PIPELINE_ACTIVE()`）。

5. **820 行 SDK Quick Start 教程** — 从零构建一个数据包计数器模块的完整教程，包含构建、测试、打包、部署全流程。同时提供中文版。

### 3.2 实际体验对比

| 开发场景 | 第一轮 (SDK v1) | 第二轮 (SDK v2) |
|---------|----------------|----------------|
| 获取头文件 | 从 rSwitch 源码树 vendoring 4 个头文件，手动修复路径 | `make install-sdk` 或 pkg-config |
| 开始新模块 | 从零手写，逆向工程宏的用法 | `rswitchctl new-module` 或复制模板 |
| 确定阶段号 | 阅读所有核心模块源码避免冲突 | 直接使用 200-299（ingress）或 400-499（egress） |
| 理解管道行为 | 逆向 RS_TAIL_CALL_NEXT 宏实现 | SDK_Quick_Start.md + DEGRADATION.md |
| 构建模块 | 手写 Makefile，硬编码路径 | `make -f Makefile.module MODULE=my_mod` |
| 降级处理 | 自行实现整套降级逻辑 | `RS_IS_PIPELINE_ACTIVE()` 宏 + 文档化协议 |

### 3.3 仍需改进

1. **遗留头文件未标注废弃警告** — `uapi.h`、`map_defs.h`、`rswitch_bpf.h` 仍在 SDK include/ 目录中，没有 `#warning` 或 `[[deprecated]]` 提示。新开发者可能困惑于应该使用哪个头文件。建议在遗留头文件中添加编译期警告，引导使用 `rswitch_module.h`。

2. **头文件存在定义重复** — `module_abi.h` 和 `rswitch_abi.h` 中有相同的结构体和宏定义（如 `RS_DECLARE_MODULE`、`rs_module_info`）。虽然通过 `#ifndef` 守卫避免了编译冲突，但对开发者理解代码结构造成困惑 — 不清楚哪个是权威来源。

3. **`vmlinux.h` 未包含在 SDK 中** — `rswitch_helpers.h` 第一行就是 `#include "vmlinux.h"`，但 SDK 不包含此文件。开发者必须手动通过 `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` 生成。这对新接触 BPF 开发的工程师是一个摩擦点。建议至少在 SDK Quick Start 中更醒目地说明这一步骤。

4. **我们仍在 vendoring 旧头文件** — `jz_sniff_rn` 目前 vendor 了 4 个旧版头文件（`map_defs.h`、`module_abi.h`、`rswitch_bpf.h`、`uapi.h`），与 SDK 的 9 个新头文件不对应。我们应当迁移到 SDK 头文件（通过 `make install-sdk` + pkg-config），但这也说明**迁移路径文档缺失** — 没有"从旧头文件迁移到新 SDK"的指南。

---

## 4. ABI 稳定性与版本兼容性

### 4.1 ABI v2.0 — 正式化的稳定性合约

第一轮评分 **F** (无 ABI 合约) → 第二轮评分 **A−**

这是另一个质的飞跃。rSwitch 从"无任何稳定性承诺"变为拥有**正式的 ABI 版本策略、三级稳定性标注、loader 强制版本校验和文档化的废弃流程**。

**关键实现:**

- **版本定义**: `RS_ABI_VERSION_MAJOR 2`、`RS_ABI_VERSION_MINOR 0`
- **Loader 强制校验**: `mod_major == plat_major && mod_minor <= plat_minor`
- **三级稳定性标注**:
  - `RS_API_STABLE` — 保证在 major 版本内不变
  - `RS_API_EXPERIMENTAL` — 可能在 minor 版本间变化
  - `RS_API_INTERNAL` — 平台内部使用，不保证稳定
- **rs_ctx 扩展**: `reserved[16]`（64 字节），与第一轮反馈中提到的"documented offset 192-255"终于对齐
- **废弃流程**: 公告 → 宽限期 → 移除，有文档化的流程

### 4.2 ABI 策略文档 (ABI_POLICY.md)

203 行的正式策略文档，覆盖:
- 语义化版本规则
- 什么构成 breaking change
- minor 版本的 additive-only 保证
- 废弃公告和宽限期
- 稳定性分层的具体含义

### 4.3 仍需改进

1. **`rs_ctx.reserved[16]` 的字节分配未文档化** — reserved 区域有 64 字节，但没有文档说明哪些字节已被分配、哪些可用。我们的项目使用了 offset 192-255 中的前 8 字节。如果另一个下游项目也使用相同偏移，就会产生冲突。建议提供一个"reserved 字节注册表"或至少文档化分配建议（例如"前 16 字节由平台保留用于未来扩展，字节 16-63 可由用户自由使用"）。

2. **ABI 版本跳跃缺乏迁移指南** — 从 ABI v1.0 到 v2.0 是 breaking change，但没有"迁移指南"说明下游模块需要做哪些修改。对于已有 v1.0 模块的项目（如我们），缺少明确的升级路径。

---

## 5. 文档齐全性与准确性

### 5.1 文档体系 — 从杂乱到体系化

第一轮评分 **B−** → 第二轮评分 **A−**

**文档索引 (Documentation_Index.md)** 是最大的改进。177 行的索引文件将所有文档组织为:
- **Concepts (概念)** — 3 篇，全部双语
- **Usage (使用)** — 7 篇，4 篇有中文翻译
- **Deployment (部署)** — 6 篇，3 篇有中文翻译
- **Development (开发)** — 11 篇，5 篇有中文翻译
- **SDK** — 2 篇，1 篇有中文翻译
- **Backlog (规划)** — 4 篇

**总计约 40+ 篇文档，其中 13+ 篇有中文翻译。** 这是一个完整的技术文档体系。

### 5.2 新增亮点文档

| 文档 | 行数 | 评价 |
|------|------|------|
| SDK_Quick_Start.md | 820 | **优秀** — 从零到部署的完整模块开发教程 |
| ABI_POLICY.md | 203 | **优秀** — 正式化的版本策略，结构清晰 |
| DEGRADATION.md | — | **重要补充** — 解决了第一轮反馈中的降级协议缺失问题 |
| Documentation_Index.md | 177 | **必要** — 让 40+ 篇文档可发现、可导航 |
| Platform_Architecture.md | — | **深度** — 平台哲学和设计全景 |
| Framework_Guide.md | — | **实用** — 框架使用方法论 |
| Network_Device_Gallery.md | — | **概念** — 可构建的设备类型展示 |
| Reconfigurable_Architecture.md | — | **理念** — "可重配置"的含义和价值 |

### 5.3 概念文档 (Concepts) — 全部双语

这是一个特别好的设计决策。三篇概念文档全部以双语（英文 + 中文）编写:
- Reconfigurable Architecture (可重配置架构)
- Network Device Gallery (网络设备画廊)
- Framework Guide (框架使用指南)

这些文档面向的是技术决策者和架构师，双语覆盖确保了最大受众覆盖。

### 5.4 README — 从误导到诚实

第一轮反馈中的关键批评是"README 描述了未实现的功能"。现在 README 底部有明确的 "Known Limitations" 表格:

```markdown
| Feature | Status | Tracking |
|---------|--------|----------|
| Stateful ACL with connection tracking | Planned | Product Backlog 2.2 |
| Ingress QoS traffic classification module | Planned | Product Backlog 3.1 |
| ...
```

YAML 配置示例中也标注了 `[Planned]`:
```yaml
# [Planned] — module-specific configuration (not yet implemented)
# [Planned] — conditional module loading (not yet implemented)
```

这种透明度是正确的做法。

### 5.5 仍需改进

1. **中文翻译覆盖不完整** — 40+ 篇文档中仅 13 篇有中文翻译。关键缺失:
   - Scenario Profiles (场景模板说明)
   - VOQd Setup (QoS 调度器配置)
   - NIC Configuration (网卡配置)
   - API Reference (API 参考)
   - MAP_PINNING.md (Map 固定约定)
   - DEGRADATION.md (降级协议)

   对于目标市场为中国的产品，这些部署和开发文档的中文版是必要的。

2. **无版本化文档** — 所有文档仍然假设"最新版本"。如果用户固定在 v2.0.0，无法知道哪些文档内容适用于该版本。建议至少在文档中标注"自 v2.0 起"等版本标记。

3. **无 CHANGELOG.md** — 第一轮已提出，仍未实现。版本历史分散在 ABI_POLICY.md 和 git tags 中。一个根目录的 CHANGELOG.md（遵循 Keep a Changelog 格式）是开源项目的标准做法。

---

## 6. 构建系统与工具链

### 6.1 改进

- **SSH submodule 已修复** — `.gitmodules` 已改为 HTTPS URL，任何外部开发者都可以 `git clone --recursive`
- **一键安装脚本 (`scripts/install.sh`)** — 879 行的生产级安装器，支持:
  - 自动检测包管理器 (apt/dnf/yum)
  - 内核版本和 BTF 检查
  - 架构检测 (x86_64, aarch64)
  - 自动接口发现
  - systemd 服务配置
  - 卸载脚本生成
  - 环境变量覆盖
  - 彩色输出和阶段化安装流程
- **SDK 安装目标** — `make install-sdk` 安装头文件到 `/usr/local/include/rswitch/`
- **pkg-config 模板** — `rswitch.pc.in` 允许下游通过 `pkg-config` 发现 SDK

### 6.2 安装器质量

`install.sh` 的质量值得表扬:
- 6 个阶段（Pre-flight → Dependencies → Build → Detect → Configure → Start）
- 退出码语义化（0=成功, 1=预检失败, 2=依赖安装失败, 3=构建失败, 4=无端口, 5=安装失败）
- 自动 bpftool 安装（优先包管理器，回退到从源码编译）
- 交换端口 IP 抑制（dhcpcd denyinterfaces + systemd-networkd）
- 自动生成卸载脚本
- 支持 `RSWITCH_FORCE=1` 跳过确认

### 6.3 仍需改进

1. **安装路径硬编码 `/opt/rswitch`** — 安装器默认路径为 `/opt/rswitch`，虽然支持 `INSTALL_PREFIX` 覆盖，但 systemd 服务文件中的路径是安装时生成的。如果目标是支持发行版打包（如 `.deb`），需要遵循 FHS 标准（`/usr/lib/`、`/etc/`、`/var/`）。

2. **无预编译二进制发布** — 仍需从源码构建（`git clone` + `make`）。对于 XDP/BPF 项目，由于内核 BTF 依赖，完全预编译不现实，但可以考虑:
   - 提供 libbpf 静态链接的用户态二进制
   - BPF 对象使用 CO-RE，可以预编译为 `.o` 文件随 SDK 分发
   - 提供 Docker 构建环境避免主机依赖问题

3. **vmlinux.h 生成仍是手动步骤** — `make vmlinux` 需要 `bpftool`，而 `bpftool` 在很多发行版上不容易获取。安装器已有 `install_bpftool` 函数，但 SDK 用户（仅安装 SDK，不运行完整安装器）仍面临此问题。

---

## 7. 运行时架构与服务管理

### 7.1 Systemd 服务体系

rSwitch 提供 5 个 systemd 服务:
- `rswitch.service` — 主 XDP 管道（Type=forking, OnFailure→failsafe）
- `rswitch-mgmtd.service` — 管理守护进程（BindsTo rswitch）
- `rswitch-watchdog.service` — 看门狗（WatchdogSec=30, PartOf rswitch）
- `rswitch-failsafe.service` — L2 桥接回退（Conflicts rswitch）
- `rswitch-dev.service` — 开发模式

服务间依赖关系设计合理:
- `BindsTo` 确保 mgmtd 随主服务一起停止
- `OnFailure→failsafe` 提供故障降级
- `PartOf` 使 watchdog 随主服务生命周期

### 7.2 仍需改进

1. **systemd 服务硬编码接口名** — `etc/systemd/` 中的模板文件包含 `RSWITCH_INTERFACES=ens34,ens35,ens36,ens37` 这样的硬编码值。虽然安装器会在安装时生成正确的服务文件，但模板文件本身应该使用占位符或 `EnvironmentFile=/etc/rswitch/env` 的方式，让修改接口配置不需要编辑服务文件。

2. **下游服务排序文档缺失** — rSwitch 文档没有说明下游产品的服务应如何排序。我们必须自行发现正确的 `After=rswitch.service` 依赖。建议在 Systemd_Integration.md 中增加"下游集成"章节，说明:
   - 下游服务应 `After=rswitch.service` + `Wants=rswitch.service`
   - 如何检测 rSwitch pipeline 是否就绪（例如等待 `/sys/fs/bpf/rs_ctx_map` 出现）
   - configd → sniffd 之间的 IPC 通知模式

3. **服务就绪信号** — `rswitch.service` 使用 `Type=forking`，但没有 `sd_notify(READY=1)` 或 PID 文件确认 pipeline 已完全加载。下游服务可能在 pipeline 尚未就绪时启动。建议改为 `Type=notify` 并在 pipeline 加载完成后发送就绪信号。

---

## 8. Map 共享与命名空间

### 8.1 当前状态

- **核心 map 固定路径**: `/sys/fs/bpf/<map_name>`（`LIBBPF_PIN_BY_NAME`）
- **核心 map 前缀**: `rs_`（`rs_ctx_map`、`rs_progs`、`rs_prog_chain`、`rs_event_bus`、`rs_port_config_map` 等）
- **MAP_PINNING.md**: 44 行，说明约定

### 8.2 改进

- `rswitch_helpers.h` 中的注释明确说明了 pin 路径约定:
  ```c
  /* User modules should use /sys/fs/bpf/{module_name}/ for private maps. */
  ```
- `rswitch_maps.h` 中的 map 定义使用 `LIBBPF_PIN_BY_NAME`，行为明确

### 8.3 仍需改进

1. **MAP_PINNING.md 说"Do not use subdirectory paths"但我们的方案使用子目录** — 我们将所有 jz map 固定在 `/sys/fs/bpf/jz/` 子目录下，这实际上**更安全**（避免命名空间冲突），但与文档的建议矛盾。然而 `rswitch_helpers.h` 中的注释却建议"User modules should use `/sys/fs/bpf/{module_name}/` for private maps"。这两个文档相互矛盾。

   建议统一为: "核心 map 使用 `/sys/fs/bpf/rs_*` 命名前缀。用户模块建议使用 `/sys/fs/bpf/<project>/` 子目录隔离私有 map。"

2. **共享 map 的发现机制** — 下游模块需要 reuse rSwitch 的 pinned map（如 `rs_ctx_map`、`rs_progs`）。当前的方法是 `bpf_obj_get("/sys/fs/bpf/rs_ctx_map")`，但这个路径是隐含在代码中的，没有公开的 API 或 SDK 函数来发现可用的共享 map。建议在 SDK 中提供辅助函数或至少文档化完整的共享 map 列表和用途。

---

## 9. 测试框架与 CI

### 9.1 测试框架 — 从零到基础

第一轮评分 **F** → 第二轮评分 **B−**

**新增组件:**
- `sdk/test/test_harness.h` — 87 行的轻量测试框架
  - `RS_TEST()` 宏自动注册测试
  - `RS_ASSERT_EQ/NE/TRUE/FALSE` 断言
  - 构造函数自注册模式（`__attribute__((constructor))`）
  - `rs_run_all_tests()` 运行器
- `sdk/test/mock_maps.h` — BPF map mock（允许用户态测试）
- CI 流水线 — GitHub Actions，包含:
  - BPF 编译验证
  - clang-format 代码风格检查
  - BPF_PROG_TEST_RUN 测试

### 9.2 仍需改进

1. **测试框架仍然简陋** — `test_harness.h` 是一个最小实现（87 行），缺少:
   - 测试夹具 (setup/teardown)
   - 参数化测试
   - 测试超时
   - 输出格式化 (TAP/JUnit XML)
   - 详细的失败诊断

   对于严肃的模块测试，建议集成现有 C 测试框架（如 cmocka、Unity）或扩展 test_harness.h 的功能。

2. **CI 矩阵有限** — 没有多内核版本测试矩阵。CO-RE 的核心承诺是跨内核兼容，但如果 CI 只在单一内核上测试，这个承诺就无法验证。建议至少覆盖 kernel 5.8（最低支持）、6.1 LTS、6.6 LTS。

3. **无性能回归测试** — 第一轮提到"性能声明基于 XDP 固有速度，非 rSwitch 实测吞吐量"。这一点仍未改变。建议在 CI 中加入基准性能测试（至少是 BPF_PROG_TEST_RUN 的每包延迟测量），防止性能回退。

---

## 10. 社区治理与发布管理

### 10.1 改进

- **CONTRIBUTING.md** — 完整的贡献指南，包含先决条件、构建步骤、测试要求、代码风格、PR 工作流
- **版本标签规范化** — `v2.0.0`、`v2.0.1` 遵循语义化版本
- **LICENSE 文件** — LGPL-2.1-or-later，SPDX 头全覆盖
- **commit 规范** — 语义化 commit 消息（`feat:`, `fix:`, `docs:` 前缀）

### 10.2 仍需改进

1. **社区参与度仍为零** — Stars/Forks/Issues 仍为 0。这不完全是技术问题，但建议:
   - 在相关社区（eBPF Slack、XDP mailing list）宣传项目
   - 创建 "good first issue" 标签
   - 启用 GitHub Discussions
   - 考虑写一篇博客介绍 rSwitch 的架构设计

2. **无 CHANGELOG.md** — 这是第二次提出。开源项目标准做法。

3. **PR 流程仍为自合并** — 建议至少使用 branch protection rules 要求 CI 通过后才能合并。

---

## 11. 仍存在的问题与建议

### 🔴 高优先级

| # | 问题 | 建议 | 工作量 |
|---|------|------|--------|
| 1 | **CHANGELOG.md 缺失** | 创建根目录 CHANGELOG.md，遵循 Keep a Changelog 格式，从 v1.0.0 起记录 | 2 小时 |
| 2 | **MAP_PINNING.md 与 helpers.h 注释矛盾** | 统一 map 固定约定: 核心用前缀、用户用子目录 | 1 小时 |
| 3 | **遗留头文件无废弃警告** | 在 `uapi.h`、`map_defs.h`、`rswitch_bpf.h` 中添加 `#warning "Use rswitch_module.h instead"` | 30 分钟 |
| 4 | **`rs_ctx.reserved` 字节分配无文档** | 在 ABI_POLICY.md 中增加 reserved 字节分配表和使用指南 | 1 小时 |
| 5 | **下游服务排序文档缺失** | 在 Systemd_Integration.md 中增加"Downstream Integration"章节 | 2 小时 |
| 6 | **Hot-reload "Planned: atomic replacement"仍未实现** | 这是生产环境的关键功能。如果短期无法实现，至少文档化当前 hot-reload 的限制和风险 | 1 天 |

### 🟡 中优先级

| # | 问题 | 建议 | 工作量 |
|---|------|------|--------|
| 7 | **Per-module config in YAML "Planned"仍未实现** | 我们使用自定义配置方案绕过了此限制。建议优先实现，或文档化推荐的替代方案 | 1 周 |
| 8 | **中文翻译覆盖不完整** | 优先翻译: VOQd_Setup、NIC_Configuration、API_Reference、MAP_PINNING、DEGRADATION | 3 天 |
| 9 | **CI 缺少多内核矩阵** | 至少覆盖 5.8 + 6.1 LTS + 6.6 LTS | 2 天 |
| 10 | **安装器硬编码 `/opt/rswitch`** | 支持 FHS 标准路径，为发行版打包做准备 | 3 天 |
| 11 | **ABI v1→v2 迁移指南缺失** | 提供从 v1.0 到 v2.0 的升级检查清单 | 2 小时 |

### 🟢 低优先级

| # | 问题 | 建议 | 工作量 |
|---|------|------|--------|
| 12 | **vmlinux.h 不在 SDK 中** | 提供生成脚本或文档化推荐的获取方式 | 1 小时 |
| 13 | **SDK 无"从旧头文件迁移"指南** | 写一篇迁移指南: 旧 4 头文件 → 新 SDK | 2 小时 |
| 14 | **头文件定义重复** | 确定 `rswitch_abi.h` 为唯一权威来源，`module_abi.h` 仅做向后兼容导入 | 2 小时 |
| 15 | **服务就绪信号** | rswitch.service 改为 Type=notify，pipeline 加载后发送 sd_notify(READY=1) | 1 天 |
| 16 | **性能基准测试** | CI 中加入 BPF_PROG_TEST_RUN 延迟测量 | 2 天 |

---

## 12. 总结

### rSwitch 在 5 天内完成了从 C+ 到 B+/A− 的跨越

这是一个**罕见的快速迭代案例**。在收到第一轮反馈后，rSwitch 团队:

- 修复了**全部 5 个 Critical 级别问题**
- 修复了**全部 5 个 High Priority 问题**
- 实现了**75% 的 Nice to Have 建议**
- 新增了 SDK Quick Start、ABI Policy、Degradation Protocol、CI Pipeline 等关键组件
- 将 ABI 从 v1.0 升级到 v2.0，扩展了 rs_ctx 并正式化了稳定性合约

### 从"原型"到"可信赖的开源平台"

第一轮反馈的核心结论是"rSwitch has the bones of something excellent"。第二轮的结论是: **rSwitch 正在成为那个 something excellent**。

对于我们的产品 `jz_sniff_rn` 而言:
- **SDK 改进直接减少了我们的集成摩擦** — 如果我们现在从零开始，体验会好得多
- **ABI v2.0 给了我们信心** — 模块不会因平台升级而静默崩溃
- **文档体系化让新团队成员能自助上手** — 而不是依赖逆向工程
- **CI 存在意味着我们可以信任 `main` 分支的稳定性**

### 剩余的核心差距

1. **Hot-reload 和 per-module config** — 两个 "Planned" 功能对生产环境至关重要
2. **社区建设** — 技术基础已经足够好，需要 marketing 和社区运营
3. **性能验证** — CO-RE 跨内核兼容性和管道性能需要 CI 级别的持续验证
4. **迁移工具** — 帮助现有下游项目从旧 SDK 迁移到新 SDK

### 最终评价

rSwitch 已经从一个"仅对作者可用的优秀原型"成长为一个**具备开源项目基本素养的平台**。剩余的改进更多是"从好到优秀"的打磨，而非"从不可用到可用"的基础建设。我们期待继续在 rSwitch 上构建产品，并愿意继续提供反馈。

---

## 附录 A: 本轮分析的关键文件

| 文件 | 行数 | 用途 |
|------|------|------|
| `sdk/include/rswitch_module.h` | — | SDK 统一入口 |
| `sdk/include/rswitch_abi.h` | 311 | ABI v2.0 定义 |
| `sdk/include/rswitch_helpers.h` | 339 | BPF 辅助函数、管道控制宏 |
| `sdk/include/rswitch_maps.h` | 419 | 可选共享 map 定义 |
| `sdk/include/module_abi.h` | 202 | 模块 ABI、阶段约定 |
| `sdk/Makefile.module` | 57 | 独立模块构建系统 |
| `sdk/rswitch.pc.in` | 9 | pkg-config 模板 |
| `sdk/templates/simple_module.bpf.c` | 76 | 简单模块模板 |
| `sdk/test/test_harness.h` | 87 | 测试框架 |
| `sdk/docs/SDK_Quick_Start.md` | 820 | SDK 教程 |
| `docs/development/ABI_POLICY.md` | 203 | ABI 稳定性策略 |
| `docs/development/MAP_PINNING.md` | 44 | Map 固定约定 |
| `docs/Documentation_Index.md` | 177 | 文档索引 |
| `scripts/install.sh` | 879 | 一键安装器 |
| `etc/systemd/*.service` | ~200 | Systemd 服务文件 |
| `README.md` | 538 | 项目主文档 |
| `CONTRIBUTING.md` | ~150 | 贡献指南 |

## 附录 B: 我方 Header 迁移建议

当前 `jz_sniff_rn` vendor 的旧头文件与 SDK 新头文件的对应关系:

| 我方 vendored 头文件 | SDK 替代 | 迁移方式 |
|---------------------|----------|---------|
| `include/rswitch/module_abi.h` | `sdk/include/module_abi.h` | 直接替换（向后兼容） |
| `include/rswitch/uapi.h` | `sdk/include/rswitch_abi.h` + `rswitch_helpers.h` | 需要逐个替换引用 |
| `include/rswitch/rswitch_bpf.h` | `sdk/include/rswitch_module.h` | 改为 `#include <rswitch_module.h>` |
| `include/rswitch/map_defs.h` | `sdk/include/rswitch_maps.h` | 仅在需要 map 定义的文件中引入 |

迁移后，所有 BPF 源文件只需:
```c
#include <rswitch_module.h>       // 必需: 管道控制
#include <rswitch_maps.h>         // 可选: 仅当需要共享 map
```
