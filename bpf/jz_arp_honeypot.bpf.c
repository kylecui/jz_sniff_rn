// SPDX-License-Identifier: GPL-2.0
/* jz_arp_honeypot.bpf.c — ARP honeypot response generator
 *
 * Stage 22 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * Reads guard classification result from stage 21 and, for guarded ARP
 * requests, crafts a fake ARP reply in-place and transmits it with XDP_TX.
 */

#define  __RSWITCH_MAPS_H      /* non-extern pipeline maps defined in jz_maps.h */
#include "rswitch_module.h"    /* rSwitch SDK v2.1.0: ABI types, CO-RE helpers, pipeline macros */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* ── Module Declaration ── */

RS_DECLARE_MODULE("jz_arp_honeypot",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_ARP_HONEYPOT,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_MODIFIES_PACKET | RS_FLAG_CREATES_EVENTS,
                  "ARP honeypot response generator");

RS_DEPENDS_ON("jz_guard_classifier");

/* ── BPF Maps (module-specific instances) ── */

/* ARP honeypot runtime config */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_arp_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_arp_config SEC(".maps");

/* Shared fake MAC pool */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_fake_mac);
    __uint(max_entries, JZ_MAX_FAKE_MACS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_fake_mac_pool SEC(".maps");

/* Per-CPU ARP rate limiter state (ephemeral) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_rate_state);
    __uint(max_entries, 1);
} jz_arp_rate SEC(".maps");

/* Guard classification result (shared with jz_guard_classifier via pinning) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_guard_result);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_guard_result_map SEC(".maps");

/* ── Local ARP Header (Ethernet + IPv4) ── */

struct arphdr_eth_ip {
    __be16 ar_hrd;    /* format of hardware address (1=Ethernet) */
    __be16 ar_pro;    /* format of protocol address (0x0800=IPv4) */
    __u8   ar_hln;    /* length of hardware address (6) */
    __u8   ar_pln;    /* length of protocol address (4) */
    __be16 ar_op;     /* ARP opcode (1=request, 2=reply) */
    __u8   ar_sha[6]; /* sender hardware address */
    __be32 ar_sip;    /* sender IP address */
    __u8   ar_tha[6]; /* target hardware address */
    __be32 ar_tip;    /* target IP address */
} __attribute__((packed));

/* ── Helpers ── */

static __always_inline __be32 arp_read_ip(const __be32 *p)
{
    __be32 val;

    __builtin_memcpy(&val, p, sizeof(val));
    return val;
}

static __always_inline void arp_write_ip(__be32 *p, __be32 val)
{
    __builtin_memcpy(p, &val, sizeof(val));
}

static __always_inline int
jz_tail_pass(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline bool
jz_arp_rate_check(__u16 limit_pps)
{
    __u32 key = 0;
    struct jz_rate_state *rate = bpf_map_lookup_elem(&jz_arp_rate, &key);
    if (!rate)
        return false;

    __u64 now = bpf_ktime_get_ns();

    if (rate->last_refill_ns == 0) {
        rate->last_refill_ns = now;
        rate->tokens = limit_pps;
    }

    __u64 elapsed = now - rate->last_refill_ns;

    /* Refill tokens: 1 token per (1e9 / limit_pps) ns */
    if (elapsed > 0 && limit_pps > 0) {
        __u32 new_tokens = (elapsed * limit_pps) / 1000000000ULL;
        if (new_tokens > 0) {
            rate->tokens += new_tokens;
            if (rate->tokens > limit_pps)
                rate->tokens = limit_pps;
            rate->last_refill_ns = now;
        }
    }

    if (rate->tokens > 0) {
        rate->tokens--;
        return true;
    }

    return false;
}

static __always_inline bool
jz_get_fake_mac(const struct jz_guard_result *result, __u8 *out_mac)
{
    if (result->fake_mac[0] || result->fake_mac[1] || result->fake_mac[2] ||
        result->fake_mac[3] || result->fake_mac[4] || result->fake_mac[5]) {
        __builtin_memcpy(out_mac, result->fake_mac, 6);
        return true;
    }

    __u32 base = (__u32)bpf_ktime_get_ns();

    for (int i = 0; i < JZ_MAX_FAKE_MACS; i++) {
        __u32 idx = (base + i) % JZ_MAX_FAKE_MACS;
        struct jz_fake_mac *entry = bpf_map_lookup_elem(&jz_fake_mac_pool, &idx);

        if (!entry || !entry->in_use)
            continue;

        __builtin_memcpy(out_mac, entry->mac, 6);
        return true;
    }

    return false;
}

/* ── Main XDP Program ── */

SEC("xdp")
int jz_arp_honeypot_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    __u32 key = 0;

    struct jz_guard_result *result = bpf_map_lookup_elem(&jz_guard_result_map, &key);
    if (!result)
        return jz_tail_pass(xdp_ctx, ctx);

    if (result->guard_type == JZ_GUARD_NONE)
        return jz_tail_pass(xdp_ctx, ctx);

    if (!(result->flags & JZ_FLAG_ARP_REQUEST))
        return jz_tail_pass(xdp_ctx, ctx);

    struct jz_arp_config *cfg = bpf_map_lookup_elem(&jz_arp_config, &key);
    if (!cfg || !cfg->enabled)
        return jz_tail_pass(xdp_ctx, ctx);

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return jz_tail_pass(xdp_ctx, ctx);

    if (ctx->layers.eth_proto != bpf_htons(ETH_P_ARP))
        return jz_tail_pass(xdp_ctx, ctx);

    /* Mask l3_offset for BPF verifier packet range proof */
    __u16 l3_off = ctx->layers.l3_offset & RS_L3_OFFSET_MASK;
    struct arphdr_eth_ip *arp = (void *)data + l3_off;
    if ((void *)(arp + 1) > data_end)
        return jz_tail_pass(xdp_ctx, ctx);

    if (arp->ar_hrd != bpf_htons(1) ||
        arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hln != 6 ||
        arp->ar_pln != 4)
        return jz_tail_pass(xdp_ctx, ctx);

    if (arp->ar_op != bpf_htons(1))
        return jz_tail_pass(xdp_ctx, ctx);

    if (cfg->rate_limit_pps > 0 && !jz_arp_rate_check(cfg->rate_limit_pps))
        return jz_tail_pass(xdp_ctx, ctx);

    __u8 fake_mac[6];
    if (!jz_get_fake_mac(result, fake_mac))
        return jz_tail_pass(xdp_ctx, ctx);

    __u8 orig_eth_src[6];
    __u8 orig_eth_dst[6];
    __u8 orig_arp_sha[6];
    __be32 orig_arp_sip = arp_read_ip(&arp->ar_sip);
    __be32 orig_arp_tip = arp_read_ip(&arp->ar_tip);

    __builtin_memcpy(orig_eth_src, eth->h_source, 6);
    __builtin_memcpy(orig_eth_dst, eth->h_dest, 6);
    __builtin_memcpy(orig_arp_sha, arp->ar_sha, 6);

    /* Craft ARP reply in-place */
    __builtin_memcpy(eth->h_dest, orig_eth_src, 6);
    __builtin_memcpy(eth->h_source, fake_mac, 6);

    arp->ar_op = bpf_htons(2);
    __builtin_memcpy(arp->ar_tha, orig_arp_sha, 6);
    arp_write_ip(&arp->ar_tip, orig_arp_sip);
    __builtin_memcpy(arp->ar_sha, fake_mac, 6);
    arp_write_ip(&arp->ar_sip, (__be32)result->guarded_ip);

    struct jz_event_attack evt = {};
    evt.hdr.type = JZ_EVENT_ATTACK_ARP;
    evt.hdr.len = sizeof(evt);
    evt.hdr.timestamp_ns = bpf_ktime_get_ns();
    evt.hdr.ifindex = ctx->ifindex;
    evt.hdr.vlan_id = ctx->ingress_vlan;
    __builtin_memcpy(evt.hdr.src_mac, orig_eth_src, 6);
    __builtin_memcpy(evt.hdr.dst_mac, orig_eth_dst, 6);
    evt.hdr.src_ip = (__u32)orig_arp_sip;
    evt.hdr.dst_ip = (__u32)orig_arp_tip;
    evt.guard_type = result->guard_type;
    evt.protocol = 1;  /* ARP */
    __builtin_memcpy(evt.fake_mac, fake_mac, 6);
    evt.guarded_ip = result->guarded_ip;
    RS_EMIT_EVENT(&evt, sizeof(evt));

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
