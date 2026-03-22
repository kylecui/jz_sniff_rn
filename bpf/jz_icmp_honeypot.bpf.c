// SPDX-License-Identifier: GPL-2.0
/* jz_icmp_honeypot.bpf.c - ICMP echo reply honeypot
 *
 * Stage 23 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * Reads guard classification result from stage 21 and, for guarded
 * ICMP echo requests, crafts an in-place echo reply with configurable
 * TTL spoofing to emulate a target host fingerprint.
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* -- Module Declaration -- */

RS_DECLARE_MODULE("jz_icmp_honeypot",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_ICMP_HONEYPOT,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_MODIFIES_PACKET | RS_FLAG_CREATES_EVENTS,
                  "ICMP honeypot echo reply generator");

RS_DEPENDS_ON("jz_guard_classifier");

/* -- BPF Maps (module-specific instances) -- */

/* ICMP honeypot configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_icmp_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_icmp_config SEC(".maps");

/* Per-CPU token bucket for ICMP reply rate limiting */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_rate_state);
    __uint(max_entries, 1);
} jz_icmp_rate SEC(".maps");

/* Guard classifier output (shared with jz_guard_classifier via pinning) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_guard_result);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_guard_result_map SEC(".maps");

/* -- Local Protocol Header -- */

struct icmphdr_echo {
    __u8  type;       /* 8=echo request, 0=echo reply */
    __u8  code;       /* 0 */
    __sum16 checksum;
    __be16 id;
    __be16 sequence;
} __attribute__((packed));

/* -- Helpers -- */

static __always_inline __sum16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__sum16)~csum;
}

static __always_inline void update_ip_checksum(struct iphdr *iph)
{
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)iph;
    iph->check = 0;

#pragma unroll
    for (int i = 0; i < 10; i++)  /* iphdr is 20 bytes = 10 u16 words */
        csum += ptr[i];

    iph->check = csum_fold(csum);
}

static __always_inline int jz_tail_next(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline bool jz_mac_is_zero(const __u8 *mac)
{
    return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

static __always_inline bool jz_rate_allow(__u16 rate_limit_pps)
{
    __u32 key = 0;
    struct jz_rate_state *state;
    __u64 now_ns;

    if (rate_limit_pps == 0)
        return true;

    state = bpf_map_lookup_elem(&jz_icmp_rate, &key);
    if (!state)
        return true;

    now_ns = bpf_ktime_get_ns();

    if (state->last_refill_ns == 0) {
        state->last_refill_ns = now_ns;
        state->tokens = rate_limit_pps;
    }

    {
        __u64 elapsed_ns = now_ns - state->last_refill_ns;
        __u64 add = (elapsed_ns * rate_limit_pps) / 1000000000ULL;

        if (add > 0) {
            __u64 new_tokens = (__u64)state->tokens + add;

            if (new_tokens > rate_limit_pps)
                new_tokens = rate_limit_pps;

            state->tokens = (__u32)new_tokens;
            state->last_refill_ns = now_ns;
        }
    }

    if (state->tokens == 0)
        return false;

    state->tokens--;
    return true;
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_icmp_honeypot_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    __u32 key = 0;
    struct jz_guard_result *result;
    struct jz_icmp_config *config;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr_echo *icmp;
    __u8 orig_src_mac[6];
    __u8 orig_dst_mac[6];
    __u32 orig_src_ip;
    __u32 orig_dst_ip;
    __u8 reply_src_mac[6];
    __u32 old_check;

    if (!ctx)
        return XDP_PASS;

    result = bpf_map_lookup_elem(&jz_guard_result_map, &key);
    if (!result)
        return jz_tail_next(xdp_ctx, ctx);

    if (result->guard_type == JZ_GUARD_NONE)
        return jz_tail_next(xdp_ctx, ctx);

    if (!(result->flags & JZ_FLAG_ICMP_REQUEST))
        return jz_tail_next(xdp_ctx, ctx);

    config = bpf_map_lookup_elem(&jz_icmp_config, &key);
    if (!config || !config->enabled)
        return jz_tail_next(xdp_ctx, ctx);

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return jz_tail_next(xdp_ctx, ctx);

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return jz_tail_next(xdp_ctx, ctx);

    if (iph->ihl != 5)
        return jz_tail_next(xdp_ctx, ctx);

    icmp = (void *)iph + sizeof(*iph);
    if ((void *)(icmp + 1) > data_end)
        return jz_tail_next(xdp_ctx, ctx);

    if (ctx->layers.eth_proto != bpf_htons(ETH_P_IP) || eth->h_proto != bpf_htons(ETH_P_IP))
        return jz_tail_next(xdp_ctx, ctx);

    if (ctx->layers.ip_proto != IPPROTO_ICMP || iph->protocol != IPPROTO_ICMP)
        return jz_tail_next(xdp_ctx, ctx);

    if (icmp->type != 8 || icmp->code != 0)
        return jz_tail_next(xdp_ctx, ctx);

    if (!jz_rate_allow(config->rate_limit_pps))
        return jz_tail_next(xdp_ctx, ctx);

    __builtin_memcpy(orig_src_mac, eth->h_source, 6);
    __builtin_memcpy(orig_dst_mac, eth->h_dest, 6);
    orig_src_ip = iph->saddr;
    orig_dst_ip = iph->daddr;

    if (!jz_mac_is_zero(result->fake_mac))
        __builtin_memcpy(reply_src_mac, result->fake_mac, 6);
    else
        __builtin_memcpy(reply_src_mac, orig_dst_mac, 6);

    /* Ethernet reply direction */
    __builtin_memcpy(eth->h_dest, orig_src_mac, 6);
    __builtin_memcpy(eth->h_source, reply_src_mac, 6);

    /* IP reply direction + TTL spoofing */
    iph->saddr = orig_dst_ip;
    iph->daddr = orig_src_ip;
    iph->ttl = config->ttl;

    /* ICMP echo request (8) -> echo reply (0): checksum delta is +0x0800 */
    old_check = (__u32)bpf_ntohs(icmp->checksum);
    old_check += 0x0800;
    old_check = (old_check & 0xffff) + (old_check >> 16);
    icmp->type = 0;
    icmp->checksum = bpf_htons((__u16)old_check);

    update_ip_checksum(iph);

    {
        struct jz_event_attack evt = {};

        evt.hdr.type = JZ_EVENT_ATTACK_ICMP;
        evt.hdr.len = sizeof(evt);
        evt.hdr.timestamp_ns = bpf_ktime_get_ns();
        evt.hdr.ifindex = ctx->ifindex;
        __builtin_memcpy(evt.hdr.src_mac, orig_src_mac, 6);
        __builtin_memcpy(evt.hdr.dst_mac, orig_dst_mac, 6);
        evt.hdr.src_ip = orig_src_ip;
        evt.hdr.dst_ip = orig_dst_ip;

        evt.guard_type = result->guard_type;
        evt.protocol = 2;  /* ICMP */
        __builtin_memcpy(evt.fake_mac, result->fake_mac, 6);
        evt.guarded_ip = result->guarded_ip;

        RS_EMIT_EVENT(&evt, sizeof(evt));
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
