# 设备发现功能故障根因分析

**日期**: 2026-03-24
**背景**: 在 VMware Workstation 虚拟机实验环境（10.174.254.136）部署后，配置监控网段 10.174.1.0/24（后改为 10.174.254.0/24），发现零设备在线。经排查共发现 3 个 bug，修复后设备发现功能恢复正常（数秒内发现 3 台设备）。

---

## 一、三个 Bug 概览

| # | Bug 摘要 | 影响范围 | 根因归属 |
|---|---------|---------|---------|
| 1 | 缺失 blacklist.txt 导致全部 BPF map 推送失败 | **致命** — 所有 BPF map 数据为空 | ✅ 我方疏忽 |
| 2 | configd 与 sniffd 的 BPF map pin 路径不一致 | **致命** — configd 无法写入配置到 BPF map | ⚠️ 双方都有责任（我方实现缺陷 + rSwitch 文档不足） |
| 3 | 单播 ARP 应答未被 Discovery 模块接收 | **致命** — 主动扫描有发无收 | ⚠️ 双方都有责任（我方架构疏忽 + rSwitch 事件模型文档不足） |

---

## 二、Bug 1：缺失 blacklist.txt 导致全部 BPF map 推送失败

### 2.1 现象

configd 日志显示 `Failed to translate config to BPF maps`，所有 BPF map（包括 `jz_bg_filter`、`jz_static_guards`、`jz_dynamic_guards` 等）均为空。设备发现功能所依赖的 `jz_bg_filter` map 未被写入任何过滤规则，导致 bg_collector BPF 模块对所有流量一律放行或一律丢弃（取决于默认值），实际效果是无事件产生。

### 2.2 根因

`config_map.c` 中的 `jz_config_load_blacklist()` 函数在 `/etc/jz/blacklist.txt` 文件不存在时返回 `-1`（错误）。而 `jz_config_to_maps()` 的实现逻辑是：**任何一个子函数返回错误即中止全部 map 推送**。

```c
// 修复前
int jz_config_load_blacklist(jz_config_map_batch_t *batch) {
    FILE *f = fopen("/etc/jz/blacklist.txt", "r");
    if (!f) return -1;  // ← 文件不存在 = 致命错误
    ...
}

int jz_config_to_maps(const jz_config_t *cfg, ...) {
    if (jz_config_load_blacklist(batch) < 0) return -1;  // ← 中止全部
    if (jz_config_translate_guards(cfg, batch) < 0) return -1;
    if (jz_config_translate_bg_filter(cfg, batch) < 0) return -1;
    // ... 后续全部被跳过
}
```

blacklist.txt 是一个**可选配置文件**——黑名单为空是完全合法的初始状态。将"文件不存在"视为致命错误是明显的逻辑缺陷。

### 2.3 修复

```c
// 修复后
int jz_config_load_blacklist(jz_config_map_batch_t *batch) {
    FILE *f = fopen("/etc/jz/blacklist.txt", "r");
    if (!f) {
        if (errno == ENOENT) {
            LOG_INFO("blacklist.txt not found, using empty blacklist");
            return 0;  // ← 缺失 = 空黑名单，不是错误
        }
        return -1;  // 其他 IO 错误仍然是真正的错误
    }
    ...
}
```

同时在 VM 上创建了空文件 `touch /etc/jz/blacklist.txt` 作为即时缓解。

### 2.4 归属判定：✅ 完全是我方疏忽

**理由**：
- 这是纯粹的防御性编程缺失。可选配置文件不存在时应该回退到默认值，这是基本的软件工程常识。
- rSwitch 与此无关——blacklist.txt 是我们自己定义的配置文件，不涉及任何外部 SDK。
- `jz_config_to_maps()` 的"一个失败全部中止"策略本身也值得商榷。更健壮的做法是：记录错误、跳过失败的子系统、继续推送其余 map。但在首次部署这种关键场景下，全量中止的策略让问题更加隐蔽。

**教训**：
- 所有配置文件加载函数都应区分"文件不存在"（合法的初始状态）和"IO 错误"（真正的故障）。
- 部署前应有集成测试覆盖"全新安装"场景（无任何自定义配置文件）。

---

## 三、Bug 2：configd 与 sniffd 的 BPF map pin 路径不一致

### 3.1 现象

即使 Bug 1 修复后，configd 仍然无法更新 BPF map。configd 日志显示 `bpf_obj_get failed for jz_bg_filter`（ENOENT）。但 `bpftool map list` 显示 map 确实存在，且已被 sniffd 加载。

### 3.2 根因

**sniffd 的 `bpf_loader.c`** 实现了两级查找逻辑：

```c
// bpf_loader.c line 27
#define JZ_BPF_PIN_PATH "/sys/fs/bpf/jz"

// 加载时：先尝试 /sys/fs/bpf/jz/<name>，再回退到 /sys/fs/bpf/<name>
snprintf(pin, sizeof(pin), "%s/%s", loader->pin_path, map_name);  // /sys/fs/bpf/jz/xxx
existing_fd = bpf_obj_get(pin);
if (existing_fd < 0) {
    snprintf(pin, sizeof(pin), "/sys/fs/bpf/%s", map_name);       // /sys/fs/bpf/xxx
    existing_fd = bpf_obj_get(pin);
}
```

这个回退逻辑的存在是因为：rSwitch 核心 map（如 `rs_progs`、`rs_event_bus`）由 rSwitch 自身的 loader pin 在 `/sys/fs/bpf/<name>`（平铺路径）。而我们自己的 map 应该 pin 在 `/sys/fs/bpf/jz/<name>`（命名空间隔离）。

**但 pin 新 map 时**，如果 `/sys/fs/bpf/jz/` 目录创建失败或 pin 操作失败，`bpf_loader.c` 只是打印 warning 并继续（不中止）。这意味着某些 map 实际上可能 pin 在了 `/sys/fs/bpf/<name>` 而不是 `/sys/fs/bpf/jz/<name>`。

**configd 的 `main.c`**（修复前）只查找一个路径：

```c
// configd/main.c（修复前）
snprintf(path, sizeof(path), "/sys/fs/bpf/jz/%s", map_name);
fd = bpf_obj_get(path);
// 没有回退逻辑 → 如果 map 在 /sys/fs/bpf/<name>，直接 ENOENT
```

### 3.3 修复

为 configd 添加了与 sniffd 相同的两级查找 helper：

```c
// configd/main.c（修复后）
static int open_pinned_map(const char *name) {
    char path[256];
    int fd;
    // 先尝试 jz 命名空间
    snprintf(path, sizeof(path), "/sys/fs/bpf/jz/%s", name);
    fd = bpf_obj_get(path);
    if (fd >= 0) return fd;
    // 回退到平铺路径
    snprintf(path, sizeof(path), "/sys/fs/bpf/%s", name);
    fd = bpf_obj_get(path);
    return fd;
}
```

### 3.4 归属判定：⚠️ 双方都有责任

#### 我方责任（主要）

- **configd 的实现不完整**。sniffd 已经实现了两级查找，configd 理应采用相同的逻辑。这是跨进程一致性问题——两个进程访问同一组 BPF map，pin 路径查找逻辑必须对齐。
- **没有抽取公共的 map 查找函数**。`open_pinned_map()` 逻辑应该在 `src/common/` 中作为公共函数提供给所有 daemon 使用，而不是在 sniffd 和 configd 中各自实现。

#### rSwitch 文档责任（次要但重要）

- **`LIBBPF_PIN_BY_NAME` 的 pin 路径行为未被文档化**。rSwitch 的 `map_defs.h` 中所有共享 map 都使用 `__uint(pinning, LIBBPF_PIN_BY_NAME);`。`rswitch_bpf.h` 定义 `BPF_PIN_PATH "/sys/fs/bpf"`。但**没有任何文档说明**：
  - rSwitch 核心 map 最终 pin 在哪个确切路径？
  - 用户模块的 map 应该 pin 在哪里？
  - 当用户模块引用 rSwitch 共享 map 时，应该去哪个路径找？

- 我们的 `design.md`（line 168）写道：

  > jz modules reference rSwitch shared maps (...) via pinned BPF maps at `/sys/fs/bpf/rswitch/`

  但实际上 rSwitch 的 map pin 在 `/sys/fs/bpf/<name>`（平铺），不是 `/sys/fs/bpf/rswitch/<name>`。这个误解的根源是 rSwitch 未明确文档化其 pin 路径约定。

- **我们已在 `docs/rswitch_feedback.md` 的建议 #11 中向 rSwitch 提出了此问题**：

  > **Map pin path undocumented** — Document: "Core maps pin to /sys/fs/bpf/{name}. User maps should pin to /sys/fs/bpf/{namespace}/"

**教训**：
- 跨进程共享 BPF map 时，pin 路径查找逻辑必须抽取为公共函数，所有 daemon 统一使用。
- 即使上游文档不完善，也应在首次集成时通过实验验证 pin 路径，并将结论记录在我们自己的文档中（OPERATIONS.md §9.2 后来补充了这一点，但为时已晚）。

---

## 四、Bug 3：单播 ARP 应答未被 Discovery 模块接收

### 4.1 现象

Bug 1 和 Bug 2 修复后，`jz_bg_filter` map 正确写入，bg_collector BPF 模块开始产生事件。但设备发现模块仍然只能看到广播流量（如 ARP 请求），看不到任何单播 ARP 应答。

`discovery.c` 中的主动扫描逻辑（`jz_discovery_tick()`）每 300 秒发送 ARP 请求探测子网内的 IP，但从未收到任何回复——即使 `tcpdump` 可以看到对端确实回复了单播 ARP 应答。

### 4.2 根因

**数据流分析**：

```
我方发出 ARP 请求 (广播) → 对端回复 ARP 应答 (单播)
                                    ↓
                         XDP pipeline (内核)
                                    ↓
                         bg_collector.bpf.c line 255:
                         if (!jz_is_broadcast_or_multicast(eth->h_dest))
                             return XDP_PASS;  // ← 单播直接放行，不产生事件
                                    ↓
                         rs_event_bus 上无任何事件
                                    ↓
                         sniffd ringbuf consumer 收不到任何东西
                                    ↓
                         discovery 模块永远看不到 ARP 应答
```

**核心问题**：`bg_collector` 的设计目标是收集**背景广播流量**（ARP、DHCP、mDNS、LLDP 等协议的广播/多播帧），用于被动设备发现和网络基线建模。它**有意过滤掉单播流量**——这是正确的设计决策，因为单播流量量级远大于广播，如果全部上报会淹没事件总线。

但我们的主动扫描模块（`probe_gen.c`）发出的 ARP 请求会收到**单播** ARP 应答。这些应答不经过 bg_collector 的事件路径，也不经过任何其他 BPF 模块的事件路径。整个 BPF pipeline 中**没有任何模块会为通用单播流量产生事件**。

### 4.3 修复

在 `discovery.c` 中添加 `jz_discovery_recv_arp()` 函数，直接从 `probe_gen.c` 已有的 AF_PACKET raw socket（绑定了 ETH_P_ARP）非阻塞读取 ARP 帧：

```c
void jz_discovery_recv_arp(jz_discovery_t *disc, int arp_sock) {
    uint8_t buf[128];
    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);
    
    for (int i = 0; i < 64; i++) {  // 每次最多处理 64 帧
        ssize_t n = recvfrom(arp_sock, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&sll, &sll_len);
        if (n <= 0) break;
        
        // 解析 ARP 帧，提取 sender IP/MAC
        struct ethhdr *eth = (struct ethhdr *)buf;
        if (ntohs(eth->h_proto) != ETH_P_ARP) continue;
        
        struct arphdr *arp = (struct arphdr *)(buf + sizeof(struct ethhdr));
        if (ntohs(arp->ar_op) != ARPOP_REPLY) continue;
        
        // 提取 sender IP 和 MAC，feed 到 discovery
        uint8_t *sender_mac = (uint8_t *)(arp + 1);
        uint32_t sender_ip;
        memcpy(&sender_ip, sender_mac + 6, 4);
        
        jz_discovery_feed_event(disc, sender_ip, sender_mac, JZ_EVENT_BG_CAPTURE);
    }
}
```

在 sniffd 主循环中调用此函数，与 ringbuf polling 并行执行。

### 4.4 归属判定：⚠️ 双方都有责任

#### 我方责任（主要）

- **架构设计时未考虑主动扫描的回程路径**。我们设计了主动 ARP 扫描（probe_gen）但没有设计对应的应答接收路径。这是一个明显的架构遗漏——"有发无收"。
- **过度依赖 BPF 事件总线**。我们假设所有有用的网络事件都会通过 `rs_event_bus` ringbuf 上报到用户态，但实际上 `bg_collector` 的过滤逻辑排除了单播流量。我们应该在设计阶段就识别到这个 gap。
- **probe_gen.c 已经绑定了 AF_PACKET raw socket 并且可以接收 ARP 帧**（用于发送探测包时创建的 socket）。我们手上已经有了解决方案的所有组件，只是没有把它们连接起来。

#### rSwitch 事件模型文档责任（次要）

- **rSwitch 的事件总线 (`rs_event_bus`) 的覆盖范围未被明确文档化**。rSwitch 的文档和头文件中：
  - `uapi.h` 定义了事件类型范围：`RS_EVENT_L2_*`、`RS_EVENT_ACL_*`、`RS_EVENT_ROUTE_*` 等——全部是安全/网络事件，不是通用流量可见性
  - `module_abi.h` 的 `RS_FLAG_CREATES_EVENTS` flag 表示模块会产生事件，但没有说明事件覆盖的流量范围
  - 没有文档明确说明：**事件总线不是通用的流量镜像机制，它只上报特定安全事件**

  如果 rSwitch 文档明确说明：

  > "rs_event_bus 是安全事件通道，不保证覆盖所有流量类型。如果用户模块需要处理事件总线未覆盖的流量（如单播 ARP），应在用户态使用 AF_PACKET 或其他机制补充。"

  我们可能在设计阶段就会意识到需要为主动扫描的回程设计独立的接收路径。

- **我们已在 `docs/rswitch_feedback.md` §11.7 中提出了事件类型命名空间问题，但未涉及事件覆盖范围的文档化**。这是一个新的反馈点。

**教训**：
- 设计主动探测功能时，必须同时设计回程接收路径。"有发无收"是架构级缺陷。
- 不要假设平台的事件机制覆盖所有流量。应在集成初期通过实验验证事件总线的实际覆盖范围。
- XDP pipeline 天然偏向入口方向的广播/多播流量处理。对于单播流量的用户态消费，AF_PACKET raw socket 是正确的补充手段。

---

## 五、对 rSwitch 的补充反馈建议

以下建议是对 `docs/rswitch_feedback.md` 已有反馈的补充，专门针对本次发现的 2 个与 rSwitch 相关的问题。

### 5.1 建议：文档化 BPF map pin 路径约定

**问题**：rSwitch 的 `rswitch_bpf.h` 定义了 `BPF_PIN_PATH "/sys/fs/bpf"`，所有共享 map 使用 `LIBBPF_PIN_BY_NAME`。但没有文档说明：
1. rSwitch 核心 map 最终 pin 在 `/sys/fs/bpf/<name>`（平铺路径）
2. 用户模块如果想要命名空间隔离，应该使用 `/sys/fs/bpf/<namespace>/<name>`
3. 用户模块访问 rSwitch 核心 map 时需要查找 `/sys/fs/bpf/<name>` 而非 `/sys/fs/bpf/rswitch/<name>`

**建议的文档补充**（适合放在 Module Developer Guide 或 API Reference 中）：

```markdown
### Map Pinning Convention

rSwitch core maps are pinned at `/sys/fs/bpf/<map_name>` (flat layout).
Examples:
- `/sys/fs/bpf/rs_progs`
- `/sys/fs/bpf/rs_ctx_map`
- `/sys/fs/bpf/rs_event_bus`

User modules SHOULD pin their own maps under a namespace directory
to avoid name collisions: `/sys/fs/bpf/<project_name>/<map_name>`.
Example: `/sys/fs/bpf/jz/jz_static_guards`

When referencing rSwitch shared maps from user-space, use
`bpf_obj_get("/sys/fs/bpf/<map_name>")`.
```

**优先级**：🟡 高——这直接影响所有基于 rSwitch 开发的下游项目。
**工作量**：约 1 小时。

### 5.2 建议：文档化事件总线 (`rs_event_bus`) 的覆盖范围与限制

**问题**：`rs_event_bus` ringbuf 是一个高效的内核→用户态事件通道，但其文档未说明：
1. 事件总线的设计定位——安全事件通道 vs. 通用流量可见性
2. 哪些流量类型会产生事件，哪些不会
3. 用户模块如果需要处理事件总线未覆盖的流量，应该使用什么补充机制

**当前状态**：
- rSwitch 核心模块的事件类型全部是安全/网络事件（L2、ACL、ROUTE、MIRROR、QOS、ERROR）
- 没有"通用流量捕获"类型的事件
- `RS_EMIT_EVENT()` 宏本身不做过滤——过滤逻辑在各模块内部
- 一个下游开发者看到 `rs_event_bus` 可能会误以为它类似 `tcpdump` 那样提供全量流量可见性

**建议的文档补充**：

```markdown
### Event Bus Scope

`rs_event_bus` is a **security and network event channel**, not a
general-purpose traffic mirror. Events are emitted by individual BPF
modules when specific conditions are met (e.g., ACL match, route
decision, error condition).

The event bus does NOT guarantee visibility into:
- All unicast traffic
- Packets that pass through the pipeline without triggering any module

If your user-space application needs to process traffic types not
covered by the event bus (e.g., unicast ARP replies for active
scanning), consider supplementary mechanisms:
- AF_PACKET raw sockets bound to specific EtherTypes
- Dedicated BPF ring buffers in your own modules
- TC (traffic control) hooks for egress visibility
```

**优先级**：🟢 中等——影响有用户态流量处理需求的下游项目。
**工作量**：约 1 小时。

---

## 六、总结

| Bug | 根因 | 归属 | 可预防性 |
|-----|------|------|---------|
| #1 blacklist.txt 缺失 | 可选文件缺失被视为致命错误 | **100% 我方疏忽** | 集成测试覆盖"全新安装"场景即可发现 |
| #2 pin 路径不一致 | configd 缺少回退查找逻辑 | **~70% 我方 / ~30% rSwitch 文档** | 公共 helper 函数 + rSwitch 文档化 pin 约定 |
| #3 单播 ARP 未接收 | 主动扫描无回程路径 | **~75% 我方 / ~25% rSwitch 文档** | 架构评审时追踪数据流闭环 + rSwitch 文档化事件覆盖范围 |

**核心反思**：三个 bug 中，我方的架构和实现缺陷是主要原因。rSwitch 的文档不足是次要因素——它增加了集成的认知负担，但如果我们在设计阶段做了更充分的验证和测试，这些问题都是可以避免的。

**对 rSwitch 的建议已整合到 `docs/rswitch_feedback.md` 的建议列表中**（#11 map pin path、新增事件覆盖范围文档化建议）。这些建议的目标不是推卸责任，而是帮助 rSwitch 降低下游开发者的集成摩擦。
