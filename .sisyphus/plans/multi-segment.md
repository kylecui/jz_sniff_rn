# Multi-Segment Support Plan

## Problem
The codebase assumes a single monitor interface with a single subnet. With multiple monitor NICs and/or multiple VLANs per NIC, these subsystems break:
- Discovery: `find_monitor_interface()` returns FIRST monitor only; ARP/DHCP sockets bind to single interface; device hash is MAC-only
- Guard Auto: `parse_monitor_subnet()` takes FIRST monitor only; single `deploy_cursor`; deploys with `vlan_id=0`
- Guard Maps (BPF): key is `__u32` (IP only) — can't distinguish same IP on different interfaces
- Guard Maps (userspace): all `bpf_map_*_elem` calls use `&ip` as key

## Design Decisions (User-Confirmed)
- BPF guard map key: `(IP, ifindex)` — guard_entry.vlan_id handles VLAN filtering within interface
- DHCP exception: Keep MAC-only (trusted everywhere)
- Device discovery: Per-segment `(MAC, ifindex)` — different entries per interface

## Key Fact
- `jz_event_hdr.ifindex` already exists at offset 16 in all ring buffer events
- `event_callback` in main.c reads vlan_id (offset 20) but NEVER reads ifindex (offset 16)
- `ctx->ifindex = xdp_ctx->ingress_ifindex` is set in jz_parse_packet (line 257)
- XDP programs already attach to ALL non-manage interfaces via `discover_business_ifaces`

## Changes Required

### Layer 1: BPF — Guard Map Key Change
**Files**: `bpf/include/jz_maps.h`, `bpf/jz_guard_classifier.bpf.c`

1. **jz_maps.h**: Add new struct for composite guard key:
```c
struct jz_guard_key {
    __u32 ip_addr;
    __u32 ifindex;   /* 0 = match all interfaces (backward compat) */
};
```

2. **jz_guard_classifier.bpf.c**: Change map key types:
```c
// jz_static_guards: __type(key, __u32) → __type(key, struct jz_guard_key)
// jz_dynamic_guards: __type(key, __u32) → __type(key, struct jz_guard_key)
```

3. **jz_guard_classifier.bpf.c**: Update `jz_lookup_guard()`:
- Build `struct jz_guard_key` from `dst_ip` + `ctx->ifindex`
- First try exact match (ip + ifindex)
- Then try wildcard match (ip + ifindex=0) for backward compat with static guards configured without interface
- Same for both static and dynamic maps

4. **jz_guard_result**: Add `ifindex` field so downstream modules know which interface:
```c
struct jz_guard_result {
    // ... existing fields ...
    __u32 ifindex;        /* interface where guard was matched */
};
```

### Layer 2: Userspace — Guard Manager Key Change
**Files**: `src/sniffd/guard_mgr.h`, `src/sniffd/guard_mgr.c`

1. **guard_mgr.h**: Add ifindex to `jz_guard_entry_user_t`:
```c
typedef struct jz_guard_entry_user {
    uint32_t ip;
    uint32_t ifindex;     /* NEW: 0 = all interfaces */
    // ... rest unchanged
} jz_guard_entry_user_t;
```

2. **guard_mgr.c**: Add composite key struct mirror:
```c
struct bpf_guard_key {
    uint32_t ip_addr;
    uint32_t ifindex;
};
```

3. **guard_mgr.c**: Update ALL bpf_map_*_elem calls:
- `push_static_guard()`: key = {ip, 0} (static guards default to all interfaces, or from config if specified)
- `jz_guard_mgr_add()`: key = {ip, ifindex} (new parameter)
- `jz_guard_mgr_remove()`: key = {ip, ifindex} (new parameter)
- `jz_guard_mgr_tick()` (TTL expiry): key = {entry->ip, entry->ifindex}
- `jz_guard_mgr_list()`: iterate with composite key

4. **guard_mgr.h**: Update function signatures:
```c
int jz_guard_mgr_add(jz_guard_mgr_t *gm, uint32_t ip, uint32_t ifindex, ...);
int jz_guard_mgr_remove(jz_guard_mgr_t *gm, uint32_t ip, uint32_t ifindex, ...);
```

### Layer 3: Guard Auto — Multi-Subnet
**Files**: `src/sniffd/guard_auto.h`, `src/sniffd/guard_auto.c`

1. **guard_auto.h**: Replace scalar subnet with per-interface array:
```c
#define JZ_GUARD_AUTO_MAX_SEGMENTS  JZ_CONFIG_MAX_INTERFACES

typedef struct jz_guard_auto_segment {
    uint32_t ifindex;
    uint32_t subnet_addr;
    uint32_t subnet_mask;
    int      subnet_total;
    uint32_t deploy_cursor;
    uint32_t host_ip;       /* our IP on this interface */
    int      current_dynamic;
} jz_guard_auto_segment_t;

typedef struct jz_guard_auto {
    jz_guard_mgr_t    *guard_mgr;
    const jz_config_t *config;
    const jz_discovery_t *discovery;
    int                max_ratio;

    jz_guard_auto_segment_t segments[JZ_GUARD_AUTO_MAX_SEGMENTS];
    int                segment_count;

    uint64_t           last_eval_ns;
    bool               initialized;
} jz_guard_auto_t;
```

2. **guard_auto.c**: `parse_monitor_subnet()` → `parse_monitor_subnets()`:
- Loop over ALL monitor interfaces, fill segments[] array
- Resolve ifindex for each interface name via `if_nametoindex()`

3. **guard_auto.c**: `jz_guard_auto_tick()`:
- Loop over all segments, deploy guards per-segment
- Each segment has its own deploy_cursor and current_dynamic count
- Call `jz_guard_mgr_add(gm, ip, seg->ifindex, ...)` with correct ifindex

4. **guard_auto.c**: `jz_guard_auto_deploy()`:
- Accept segment index or ifindex parameter
- Pass ifindex through to guard_mgr_add

### Layer 4: Discovery — Per-Segment Devices
**Files**: `src/sniffd/discovery.h`, `src/sniffd/discovery.c`

1. **discovery.h**: Add ifindex to feed_event:
```c
int jz_discovery_feed_event(jz_discovery_t *disc, uint8_t proto,
                            const uint8_t *payload, uint32_t payload_len,
                            uint16_t vlan_id, uint32_t ifindex);
```

2. **discovery.h**: Add ifindex to device profile linkage:
```c
typedef struct jz_discovery_device {
    device_profile_t   profile;
    uint32_t           ifindex;    /* NEW: which interface this device was seen on */
    struct jz_discovery_device *next;
} jz_discovery_device_t;
```

3. **discovery.c**: Update `mac_hash()` to include ifindex:
```c
static uint32_t mac_ifindex_hash(const uint8_t mac[6], uint32_t ifindex)
```

4. **discovery.c**: Update `jz_discovery_lookup()`:
```c
jz_discovery_device_t *jz_discovery_lookup(jz_discovery_t *disc,
                                            const uint8_t mac[6],
                                            uint32_t ifindex);
```

5. **discovery.c**: Multi-interface ARP/DHCP sockets:
- Replace single `arp_sock`/`arp_ifindex` with per-interface array:
```c
typedef struct jz_discovery_iface {
    int      arp_sock;
    int      dhcp_sock;
    int      ifindex;
    uint32_t src_ip;
    uint8_t  src_mac[6];
    uint32_t scan_subnet;
    uint32_t scan_mask;
    uint32_t scan_next_ip;
} jz_discovery_iface_t;
```
- `jz_discovery_init()`: loop all monitor interfaces, open sockets per-interface
- `jz_discovery_tick()`: tick each interface's ARP scan
- `jz_discovery_recv_arp()`: poll all ARP sockets (or use epoll)

6. **discovery.c**: Update `jz_discovery_list_json()` to include ifindex in output

7. **discovery.c**: Update `jz_discovery_find_dhcp_servers()` to include ifindex

### Layer 5: Event Callback — Extract ifindex
**File**: `src/sniffd/main.c`

1. **event_callback()**: Extract ifindex from event header (offset 16):
```c
uint32_t ifindex;
memcpy(&ifindex, ev + 16, 4);
jz_discovery_feed_event(&g_ctx.discovery, bg_proto, ev + 56, plen, vlan_id, ifindex);
```

### Layer 6: API — Add ifindex to Guard Endpoints
**File**: `src/sniffd/api.c`

1. **handle_guards_static_add()**: Accept optional `ifindex` in JSON body (default 0)
2. **handle_guards_dynamic_list()**: Include ifindex in response
3. **handle_guards_static_list()**: Include ifindex in response
4. **api_add_static_guards_to_array()**: Read composite key, include ifindex
5. **api_add_dynamic_guards_to_array()**: Read composite key, include ifindex
6. **handle_guards_static_del()**: Accept ifindex parameter (default 0)
7. **handle_guards_dynamic_del()**: Accept ifindex parameter (default 0)
8. **handle_dhcp_alerts()**: Include ifindex in response (from discovery)
9. **handle_discovery_list()**: Include ifindex in response (from discovery)

### Layer 7: Config — Static Guard ifindex
**File**: `src/common/config.h`, `src/common/config.c`

1. Add optional `interface` field to static guard config:
```yaml
guards:
  static:
    - ip: 10.0.1.50
      mac: aa:bb:cc:dd:ee:01
      interface: ens33    # NEW: optional, resolved to ifindex at load time
```

2. **config.h**: Add interface field to `jz_config_guard_static_t`
3. **config.c**: Parse interface field from YAML

### Layer 8: Frontend — Show ifindex in Guards/Discovery
**Files**: `frontend/src/views/Guards.vue`, `frontend/src/views/Discovery.vue`

1. Guards table: Add "Interface" column (resolve ifindex to name via API)
2. Discovery table: Add "Interface" column
3. Guard add form: Optional interface selector
4. DHCP alerts: Show which interface detected the server

### Layer 9: config_map.c — Composite Key Serialization
**File**: `src/common/config_map.c`, `src/common/config_map.h`

1. Update guard map serialization to use composite key struct

## Implementation Order (Bottom-Up)

Phase A — BPF + Shared Headers (must be first, everything depends on map key):
1. jz_maps.h: Add jz_guard_key struct
2. jz_guard_classifier.bpf.c: Update map definitions and lookup
3. Build BPF, verify compilation

Phase B — Guard Manager (adapts to new key):
4. guard_mgr.h: Add ifindex to entry, update signatures
5. guard_mgr.c: All bpf_map calls use composite key
6. Build userspace, verify compilation

Phase C — Guard Auto (multi-subnet):
7. guard_auto.h: Replace scalars with segments array
8. guard_auto.c: Multi-subnet parsing and deployment
9. Build, verify

Phase D — Discovery (multi-interface, per-segment devices):
10. discovery.h: Add ifindex to feed_event, lookup, device struct
11. discovery.c: Multi-interface sockets, per-segment hash
12. main.c: Extract ifindex in event_callback
13. Build, verify

Phase E — API (expose ifindex):
14. api.c: Update guard and discovery endpoints
15. config.h/c: Optional interface field for static guards
16. config_map.c: Composite key serialization
17. Build, verify

Phase F — Frontend:
18. Guards.vue: Interface column + selector
19. Discovery.vue: Interface column
20. Dashboard.vue: DHCP alert interface info

Phase G — Integration Test:
21. Deploy to test env with 2 NICs
22. Verify guard creation on each interface
23. Verify discovery sees devices per-interface
24. Verify DHCP alerts show interface info

## Risk Assessment
- **BPF map key change is breaking** — old pinned maps must be deleted on upgrade (`rm -f /sys/fs/bpf/jz/jz_static_guards /sys/fs/bpf/jz/jz_dynamic_guards`)
- **API backward compat**: ifindex=0 means "all interfaces" — existing API calls without ifindex still work
- **Config backward compat**: interface field is optional — existing configs work
- **LRU_HASH with composite key**: Need to verify BPF verifier accepts struct key for LRU maps (it should, but must test)
