// SPDX-License-Identifier: GPL-2.0
/* jz_traffic_weaver.bpf.c -- Per-flow traffic steering engine
 *
 * Stage 35 in the rSwitch ingress pipeline.
 *
 * Performs exact 5-tuple policy lookup and executes one of:
 *   PASS, DROP, REDIRECT, MIRROR, REDIRECT_MIRROR
 *
 * Pipeline flow:
 *   guard_classifier(22) -> arp_honeypot(23) / icmp_honeypot(24)
 *                        -> sniffer_detect(25)
 *                        -> traffic_weaver(35)
 *                        -> bg_collector(40)
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* -- Module Declaration -- */

RS_DECLARE_MODULE("jz_traffic_weaver",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_TRAFFIC_WEAVER,   // = 35
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_MAY_REDIRECT | RS_FLAG_CREATES_EVENTS,
                  "Per-flow traffic steering and mirroring");

RS_DEPENDS_ON("jz_guard_classifier");   // needs parsed context

/* -- BPF Maps (module-specific instances) -- */

/* Flow steering policy table (exact 5-tuple match) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct jz_flow_key);
    __type(value, struct jz_flow_policy);
    __uint(max_entries, JZ_MAX_FLOW_POLICIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_flow_policy SEC(".maps");

/* Global redirect/mirror runtime configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_redirect_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_redirect_config SEC(".maps");

/* Per-flow per-CPU traffic counters (ephemeral) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct jz_flow_key);
    __type(value, struct jz_flow_stats);
    __uint(max_entries, JZ_MAX_FLOW_POLICIES);
} jz_flow_stats SEC(".maps");

/* -- Helpers -- */

/*
 * Helper contract:
 * - build flow key directly from parsed rs_ctx layers
 * - keep stack objects zero-initialized for verifier safety
 * - perform map lookup null-checks before dereference
 * - use best-effort event emission (no data-plane failure on event pressure)
 * - continue pipeline on tail-call failure with XDP_PASS fallback
 */

static __always_inline int
jz_tail_pass(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline void
jz_build_flow_key(struct rs_ctx *ctx, struct jz_flow_key *flow)
{
    __builtin_memset(flow, 0, sizeof(*flow));

    /* Keep IPs as raw bytes from parsed context (__be32). */
    flow->src_ip = (__u32)ctx->layers.saddr;
    flow->dst_ip = (__u32)ctx->layers.daddr;

    /* Ports are stored in host-order for policy table matching. */
    flow->src_port = bpf_ntohs(ctx->layers.sport);
    flow->dst_port = bpf_ntohs(ctx->layers.dport);
    flow->proto = ctx->layers.ip_proto;
}

static __always_inline void
jz_update_flow_stats(const struct jz_flow_key *flow, __u64 pkt_bytes, __u64 now_ns)
{
    struct jz_flow_stats *stats;

    stats = bpf_map_lookup_elem(&jz_flow_stats, flow);
    if (!stats) {
        struct jz_flow_stats init_stats;

        __builtin_memset(&init_stats, 0, sizeof(init_stats));
        bpf_map_update_elem(&jz_flow_stats, flow, &init_stats, BPF_NOEXIST);

        stats = bpf_map_lookup_elem(&jz_flow_stats, flow);
        if (!stats)
            return;
    }

    /* Per-CPU map value update is lockless on the local CPU. */
    stats->packets += 1;
    stats->bytes += pkt_bytes;
    stats->last_seen_ns = now_ns;
}

static __always_inline __u32
jz_get_redirect_ifindex(const struct jz_flow_policy *policy)
{
    __u32 key = 0;
    struct jz_redirect_config *cfg;

    if (policy->redirect_port != 0)
        return (__u32)policy->redirect_port;

    cfg = bpf_map_lookup_elem(&jz_redirect_config, &key);
    if (!cfg || !cfg->enabled)
        return 0;

    return cfg->honeypot_ifindex;
}

static __always_inline __u32
jz_get_mirror_ifindex(const struct jz_flow_policy *policy)
{
    __u32 key = 0;
    struct jz_redirect_config *cfg;

    if (policy->mirror_port != 0)
        return (__u32)policy->mirror_port;

    cfg = bpf_map_lookup_elem(&jz_redirect_config, &key);
    if (!cfg || !cfg->enabled)
        return 0;

    return cfg->mirror_ifindex;
}

static __always_inline void
jz_emit_policy_event(struct rs_ctx *ctx,
                     const struct ethhdr *eth,
                     const struct jz_flow_key *flow,
                     __u8 action,
                     __u64 now_ns)
{
    struct jz_event_policy evt;

    __builtin_memset(&evt, 0, sizeof(evt));

    /* Header fields are shared across all jz events. */
    evt.hdr.type = JZ_EVENT_POLICY_MATCH;
    evt.hdr.len = sizeof(evt);
    evt.hdr.timestamp_ns = now_ns;
    evt.hdr.ifindex = ctx->ifindex;
    __builtin_memcpy(evt.hdr.src_mac, eth->h_source, 6);
    __builtin_memcpy(evt.hdr.dst_mac, eth->h_dest, 6);
    evt.hdr.src_ip = flow->src_ip;
    evt.hdr.dst_ip = flow->dst_ip;

    evt.action = action;
    /* policy_id is not encoded in jz_flow_policy map value currently. */
    evt.policy_id = 0;
    __builtin_memcpy(&evt.flow, flow, sizeof(*flow));

    RS_EMIT_EVENT(&evt, sizeof(evt));
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_traffic_weaver_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct jz_flow_key flow;
    struct jz_flow_policy *policy;
    __u64 now_ns;
    __u64 pkt_bytes;
    __u32 ifindex;

    /* 1) Load per-CPU context from rs_ctx_map */
    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    /* 2) Bounds check: packet must have ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    pkt_bytes = (__u64)((__u8 *)data_end - (__u8 *)data);

    /* 3+4) Build normalized 5-tuple flow key */
    jz_build_flow_key(ctx, &flow);

    /* 5) Policy lookup */
    policy = bpf_map_lookup_elem(&jz_flow_policy, &flow);

    /* 6) No policy match -> continue pipeline */
    if (!policy)
        return jz_tail_pass(xdp_ctx, ctx);

    now_ns = bpf_ktime_get_ns();

    /* 7a) Per-flow stats (per-CPU hash) */
    jz_update_flow_stats(&flow, pkt_bytes, now_ns);

    /* 7b) Policy aggregate counters (global hash value) */
    __sync_fetch_and_add(&policy->hit_count, 1);
    __sync_fetch_and_add(&policy->byte_count, pkt_bytes);

    /*
     * 7c) Execute action
     *
     * PASS:              continue pipeline
     * DROP:              drop immediately
     * REDIRECT:          send original packet to target ifindex
     * MIRROR:            clone packet to mirror ifindex, keep original in pipeline
     * REDIRECT_MIRROR:   clone to mirror and redirect original to target
     */
    switch (policy->action) {
    case JZ_ACTION_PASS:
        return jz_tail_pass(xdp_ctx, ctx);

    case JZ_ACTION_DROP:
        jz_emit_policy_event(ctx, eth, &flow, JZ_ACTION_DROP, now_ns);
        return XDP_DROP;

    case JZ_ACTION_REDIRECT:
        ifindex = jz_get_redirect_ifindex(policy);
        if (ifindex == 0)
            return jz_tail_pass(xdp_ctx, ctx);

        jz_emit_policy_event(ctx, eth, &flow, JZ_ACTION_REDIRECT, now_ns);
        return bpf_redirect(ifindex, 0);

    case JZ_ACTION_MIRROR:
        ifindex = jz_get_mirror_ifindex(policy);

        jz_emit_policy_event(ctx, eth, &flow, JZ_ACTION_MIRROR, now_ns);

        if (ifindex != 0)
            (void)bpf_clone_redirect(xdp_ctx, ifindex, 0);

        return jz_tail_pass(xdp_ctx, ctx);

    case JZ_ACTION_REDIRECT_MIRROR:
    {
        __u32 mirror_ifindex = jz_get_mirror_ifindex(policy);
        __u32 redirect_ifindex = jz_get_redirect_ifindex(policy);

        jz_emit_policy_event(ctx, eth, &flow, JZ_ACTION_REDIRECT_MIRROR, now_ns);

        if (mirror_ifindex != 0)
            (void)bpf_clone_redirect(xdp_ctx, mirror_ifindex, 0);

        if (redirect_ifindex == 0)
            return XDP_DROP;

        return bpf_redirect(redirect_ifindex, 0);
    }

    default:
        /* Unknown action -> fail-safe pass to keep pipeline alive. */
        return jz_tail_pass(xdp_ctx, ctx);
    }
}

char LICENSE[] SEC("license") = "GPL";
