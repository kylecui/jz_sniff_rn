// SPDX-License-Identifier: GPL-2.0
/* jz_guard_classifier.bpf.c — Guard IP classifier for honeypot deception
 *
 * Stage 21 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * Classifies incoming packets against guard tables (static guards,
 * dynamic guards, whitelists). Sets guard result in per-CPU map
 * for downstream honeypot modules.
 *
 * Pipeline flow:
 *   guard_classifier(21) -> arp_honeypot(22) / icmp_honeypot(23)
 *                        -> sniffer_detect(24)
 *                        -> traffic_weaver(25)
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* ── Module Declaration ── */

RS_DECLARE_MODULE("jz_guard_classifier",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_GUARD_CLASSIFIER,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "Guard IP classifier for honeypot deception");

/* ── BPF Maps (module-specific instances) ── */

/* Static guard entries — manually configured honeypot IPs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                    /* IP address */
    __type(value, struct jz_guard_entry);
    __uint(max_entries, JZ_MAX_STATIC_GUARDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_static_guards SEC(".maps");

/* Dynamic guard entries — auto-discovered IPs (LRU for auto-eviction) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct jz_guard_entry);
    __uint(max_entries, JZ_MAX_DYNAMIC_GUARDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_dynamic_guards SEC(".maps");

/* Whitelist — trusted devices exempt from guard checks */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                      /* IP address */
    __type(value, struct jz_whitelist_entry);
    __uint(max_entries, JZ_MAX_WHITELIST);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_whitelist SEC(".maps");

/* Guard classification result — per-CPU scratch for passing to next stage */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_guard_result);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_guard_result_map SEC(".maps");

/* ── Helper: Check if source is whitelisted ── */

static __always_inline bool
jz_check_whitelist(struct rs_ctx *ctx, __u32 src_ip, const __u8 *src_mac)
{
    struct jz_whitelist_entry *wl;

    wl = bpf_map_lookup_elem(&jz_whitelist, &src_ip);
    if (!wl || !wl->enabled)
        return false;

    /* IP-only match */
    if (!wl->match_mac)
        return true;

    /* IP+MAC match — compare 6 bytes */
    if (__builtin_memcmp(src_mac, wl->mac, 6) == 0)
        return true;

    return false;
}

/* ── Helper: Lookup guard entry (static first, then dynamic) ── */

static __always_inline struct jz_guard_entry *
jz_lookup_guard(__u32 dst_ip, __u8 *out_guard_type)
{
    struct jz_guard_entry *entry;

    /* Check static guards first */
    entry = bpf_map_lookup_elem(&jz_static_guards, &dst_ip);
    if (entry && entry->enabled) {
        *out_guard_type = JZ_GUARD_STATIC;
        return entry;
    }

    /* Check dynamic guards */
    entry = bpf_map_lookup_elem(&jz_dynamic_guards, &dst_ip);
    if (entry && entry->enabled) {
        *out_guard_type = JZ_GUARD_DYNAMIC;
        return entry;
    }

    return NULL;
}

/* ── Helper: Determine protocol from parsed layers ── */

static __always_inline __u8
jz_classify_proto(struct rs_ctx *ctx)
{
    __u16 eth_proto = ctx->layers.eth_proto;

    if (eth_proto == bpf_htons(0x0806))  /* ETH_P_ARP */
        return 1;  /* ARP */

    if (eth_proto == bpf_htons(0x0800)) {  /* ETH_P_IP */
        if (ctx->layers.ip_proto == 1)     /* IPPROTO_ICMP */
            return 2;  /* ICMP */
        if (ctx->layers.ip_proto == 6)     /* IPPROTO_TCP */
            return 3;  /* TCP */
        if (ctx->layers.ip_proto == 17)    /* IPPROTO_UDP */
            return 4;  /* UDP */
    }

    return 0;  /* unknown */
}

/* ── Helper: Store guard result in per-CPU map ── */

static __always_inline void
jz_store_result(__u8 guard_type, __u8 proto, __u16 flags,
                __u32 guarded_ip, const __u8 *fake_mac)
{
    __u32 key = 0;
    struct jz_guard_result *result;

    result = bpf_map_lookup_elem(&jz_guard_result_map, &key);
    if (!result)
        return;

    result->guard_type = guard_type;
    result->proto = proto;
    result->flags = flags;
    result->guarded_ip = guarded_ip;

    if (fake_mac)
        __builtin_memcpy(result->fake_mac, fake_mac, 6);
    else
        __builtin_memset(result->fake_mac, 0, 6);
}

/* ── Main XDP Program ── */

SEC("xdp")
int jz_guard_classifier_prog(struct xdp_md *xdp_ctx)
{
    /* Get per-CPU rSwitch context */
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    /* Access packet data */
    void *data     = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    /* Bounds check: ensure at least Ethernet header is present */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Extract source MAC and IPs from parsed context */
    __u8 *src_mac = eth->h_source;
    __u32 src_ip = ctx->layers.saddr;
    __u32 dst_ip = ctx->layers.daddr;

    /* Step 1: Check whitelist — if whitelisted, skip guard classification */
    if (jz_check_whitelist(ctx, src_ip, src_mac)) {
        /* Store whitelist bypass result */
        jz_store_result(JZ_GUARD_NONE, 0, JZ_FLAG_WHITELIST_BYPASS, 0, NULL);

        /* Tail-call to next stage in pipeline */
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    /* Step 2: Lookup guard tables */
    __u8 guard_type = JZ_GUARD_NONE;
    struct jz_guard_entry *entry = jz_lookup_guard(dst_ip, &guard_type);

    if (!entry) {
        /* No guard match — continue pipeline */
        jz_store_result(JZ_GUARD_NONE, 0, 0, 0, NULL);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    /* Step 3: Guard matched — classify protocol */
    __u8 proto = jz_classify_proto(ctx);
    __u16 flags = 0;

    if (proto == 1)  /* ARP */
        flags |= JZ_FLAG_ARP_REQUEST;
    else if (proto == 2)  /* ICMP */
        flags |= JZ_FLAG_ICMP_REQUEST;

    /* Step 4: Store guard result for downstream modules */
    const __u8 *fake_mac = NULL;
    /* Check if entry has a specific fake MAC (non-zero) */
    if (entry->fake_mac[0] || entry->fake_mac[1] || entry->fake_mac[2])
        fake_mac = entry->fake_mac;

    jz_store_result(guard_type, proto, flags, dst_ip, fake_mac);

    /* Step 5: Update guard entry stats (best-effort) */
    __sync_fetch_and_add(&entry->hit_count, 1);
    entry->last_hit = bpf_ktime_get_ns();

    /* Step 6: Tail-call to next stage
     * RS_TAIL_CALL_NEXT handles sequential pipeline chaining.
     * The rSwitch loader assigns modules to sequential slots.
     * ARP/ICMP honeypot modules (stages 23/24) will read
     * the guard_result from the per-CPU map.
     */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    /* Fallthrough: if tail call fails, pass packet */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
