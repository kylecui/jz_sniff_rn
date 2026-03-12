// SPDX-License-Identifier: GPL-2.0
/* jz_threat_detect.bpf.c -- Fast-path threat pattern matching engine
 *
 * Stage 50 in the rSwitch ingress pipeline.
 *
 * Performs quick source-IP blacklist checks and bounded threat pattern
 * matching. Emits threat events, updates per-CPU counters, and stores a
 * small per-packet threat result for the downstream forensics stage.
 *
 * Pipeline flow:
 *   guard_classifier(22) -> arp_honeypot(23) / icmp_honeypot(24)
 *                        -> sniffer_detect(25)
 *                        -> traffic_weaver(35)
 *                        -> bg_collector(40)
 *                        -> threat_detect(50)
 *                        -> forensics(55)
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* -- Module Declaration -- */

RS_DECLARE_MODULE("jz_threat_detect",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_THREAT_DETECT,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_MAY_REDIRECT | RS_FLAG_CREATES_EVENTS,
                  "Fast-path threat pattern matching");

RS_DEPENDS_ON("jz_bg_collector");

/* -- Local scratch result for downstream forensics stage -- */

struct jz_threat_result {
    __u8  threat_level;    /* 0=none, 1=low, 2=med, 3=high, 4=critical */
    __u8  sample_flag;     /* 1=sample this packet */
    __u16 _pad;
};

/* -- BPF Maps -- */

/* Threat patterns keyed by pattern_id. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct jz_threat_pattern);
    __uint(max_entries, JZ_MAX_THREAT_PATTERNS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_patterns SEC(".maps");

/* Fast blacklist of source IPv4 addresses. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);            /* first_seen timestamp */
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_blacklist SEC(".maps");

/* Per-CPU threat counters (single key). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_stats SEC(".maps");

/* Threat detect output consumed by next stage via extern map reference. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_result);
    __uint(max_entries, 1);
} jz_threat_result_map SEC(".maps");

/* Shared redirect config map owned by jz_traffic_weaver. */
extern struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_redirect_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_redirect_config SEC(".maps");

/* -- Helpers -- */

static const char jz_blacklist_desc[32] = "blacklist_src_ip";

static __always_inline int
jz_tail_pass(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline bool
jz_check_blacklist(__u32 src_ip)
{
    __u64 *first_seen;

    first_seen = bpf_map_lookup_elem(&jz_threat_blacklist, &src_ip);
    return first_seen != NULL;
}

static __always_inline bool
jz_match_pattern(const struct jz_threat_pattern *pattern,
                 __u32 src_ip,
                 __u32 dst_ip,
                 __u16 dst_port,
                 __u8 proto)
{
    if (pattern->src_ip != 0 && pattern->src_ip != src_ip)
        return false;

    if (pattern->dst_ip != 0 && pattern->dst_ip != dst_ip)
        return false;

    if (pattern->dst_port != 0 && pattern->dst_port != dst_port)
        return false;

    if (pattern->proto != 0 && pattern->proto != proto)
        return false;

    return true;
}

static __always_inline void
jz_update_threat_stats(__u8 threat_level)
{
    __u32 key = 0;
    struct jz_threat_stats *stats;

    stats = bpf_map_lookup_elem(&jz_threat_stats, &key);
    if (!stats)
        return;

    switch (threat_level) {
    case 1:
        stats->threats_low += 1;
        break;
    case 2:
        stats->threats_medium += 1;
        break;
    case 3:
        stats->threats_high += 1;
        break;
    case 4:
        stats->threats_critical += 1;
        break;
    default:
        break;
    }
}

static __always_inline void
jz_store_threat_result(__u8 threat_level, __u8 sample_flag)
{
    __u32 key = 0;
    struct jz_threat_result *result;

    result = bpf_map_lookup_elem(&jz_threat_result_map, &key);
    if (!result)
        return;

    result->threat_level = threat_level;
    result->sample_flag = sample_flag;
}

static __always_inline void
jz_emit_threat_event(struct rs_ctx *ctx,
                     const struct ethhdr *eth,
                     __u32 src_ip,
                     __u32 dst_ip,
                     __u32 pattern_id,
                     __u8 threat_level,
                     __u8 action_taken,
                     const char *description)
{
    struct jz_event_threat evt;

    __builtin_memset(&evt, 0, sizeof(evt));

    evt.hdr.type = JZ_EVENT_THREAT_DETECTED;
    evt.hdr.len = sizeof(evt);
    evt.hdr.timestamp_ns = bpf_ktime_get_ns();
    evt.hdr.ifindex = ctx->ifindex;
    __builtin_memcpy(evt.hdr.src_mac, eth->h_source, 6);
    __builtin_memcpy(evt.hdr.dst_mac, eth->h_dest, 6);
    evt.hdr.src_ip = src_ip;
    evt.hdr.dst_ip = dst_ip;

    evt.pattern_id = pattern_id;
    evt.threat_level = threat_level;
    evt.action_taken = action_taken;
    if (description)
        __builtin_memcpy(evt.description, description, sizeof(evt.description));

    RS_EMIT_EVENT(&evt, sizeof(evt));
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_threat_detect_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 proto;
    __u32 key = 0;
    struct jz_threat_stats *stats;
    struct jz_threat_pattern *matched_pattern = NULL;
    __u8 threat_level;
    __u8 action;
    __u8 sample_flag;

    /* 1) Load rs_ctx and do minimum packet bounds check. */
    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return jz_tail_pass(xdp_ctx, ctx);

    /* 2) Extract tuple fields from parsed context. */
    src_ip = (__u32)ctx->layers.saddr;
    dst_ip = (__u32)ctx->layers.daddr;
    dst_port = bpf_ntohs(ctx->layers.dport);
    proto = ctx->layers.ip_proto;

    /* Initialize downstream scratch to avoid stale per-CPU values. */
    jz_store_threat_result(0, 0);

    /* 3) Increment total_checked. */
    stats = bpf_map_lookup_elem(&jz_threat_stats, &key);
    if (stats)
        stats->total_checked += 1;

    /* 4) O(1) source blacklist check. */
    if (jz_check_blacklist(src_ip)) {
        threat_level = 3;                /* HIGH */
        action = 1;                      /* log + drop */
        sample_flag = 1;                 /* medium+ => sample */

        jz_update_threat_stats(threat_level);
        jz_store_threat_result(threat_level, sample_flag);
        jz_emit_threat_event(ctx,
                             eth,
                             src_ip,
                             dst_ip,
                             0,
                             threat_level,
                             action,
                             jz_blacklist_desc);

        if (stats)
            stats->dropped += 1;

        return XDP_DROP;
    }

    /* 5) Pattern matching loop: bounded 0..31, first match wins. */
#pragma unroll
    for (int i = 0; i < 32; i++) {
        struct jz_threat_pattern *pattern;
        __u32 pattern_id = i;

        pattern = bpf_map_lookup_elem(&jz_threat_patterns, &pattern_id);
        if (!pattern)
            break;      /* sparse array semantics: stop at first gap */

        if (!jz_match_pattern(pattern, src_ip, dst_ip, dst_port, proto))
            continue;

        matched_pattern = pattern;
        break;
    }

    /* 6) Threat found: stats, event, action, and forensics flag. */
    if (matched_pattern) {
        __u32 redirect_ifindex = 0;

        threat_level = matched_pattern->threat_level;
        action = matched_pattern->action;
        sample_flag = (threat_level >= 2) ? 1 : 0;

        jz_update_threat_stats(threat_level);
        jz_store_threat_result(threat_level, sample_flag);
        jz_emit_threat_event(ctx,
                             eth,
                             src_ip,
                             dst_ip,
                             matched_pattern->pattern_id,
                             threat_level,
                             action,
                             matched_pattern->description);

        switch (action) {
        case 0: /* log only */
            return jz_tail_pass(xdp_ctx, ctx);

        case 1: /* log + drop */
            if (stats)
                stats->dropped += 1;
            return XDP_DROP;

        case 2: /* log + redirect */
        {
            struct jz_redirect_config *cfg;

            cfg = bpf_map_lookup_elem(&jz_redirect_config, &key);
            if (cfg && cfg->enabled)
                redirect_ifindex = cfg->honeypot_ifindex;

            if (redirect_ifindex != 0) {
                if (stats)
                    stats->redirected += 1;
                return bpf_redirect(redirect_ifindex, 0);
            }

            return jz_tail_pass(xdp_ctx, ctx);
        }

        default:
            return jz_tail_pass(xdp_ctx, ctx);
        }
    }

    /* 7) No threat detected -> continue pipeline to forensics (stage 55). */
    return jz_tail_pass(xdp_ctx, ctx);
}

char LICENSE[] SEC("license") = "GPL";
