// SPDX-License-Identifier: GPL-2.0
/* jz_bg_collector.bpf.c -- Background broadcast/multicast collector
 *
 * Stage 26 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * Detects common background L2/L3 broadcast/multicast protocols,
 * updates per-CPU baseline stats, and emits sampled capture events.
 *
 * Pipeline flow:
 *   guard_classifier(21) -> arp_honeypot(22) / icmp_honeypot(23)
 *                        -> sniffer_detect(24)
 *                        -> traffic_weaver(25)
 *                        -> bg_collector(26)
 *                        -> threat_detect(27)
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88cc
#endif

#ifndef ETH_P_CDP
#define ETH_P_CDP 0x2000
#endif

#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

#define JZ_BG_PROTO_ARP     1
#define JZ_BG_PROTO_DHCP    2
#define JZ_BG_PROTO_MDNS    3
#define JZ_BG_PROTO_SSDP    4
#define JZ_BG_PROTO_LLDP    5
#define JZ_BG_PROTO_CDP     6
#define JZ_BG_PROTO_STP     7
#define JZ_BG_PROTO_IGMP    8
#define JZ_BG_PROTO_OTHER   9

/* -- Module Declaration -- */

RS_DECLARE_MODULE("jz_bg_collector",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_BG_COLLECTOR,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
                  "Background broadcast/multicast traffic collector");

RS_DEPENDS_ON("jz_traffic_weaver");

/* -- BPF Maps (module-specific instances) -- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                              /* filter_id */
    __type(value, struct jz_bg_filter_entry);
    __uint(max_entries, JZ_MAX_BG_FILTERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_bg_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_bg_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_bg_stats SEC(".maps");

/* -- Helpers -- */

static __always_inline int
jz_tail_pass(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline bool
jz_is_broadcast_or_multicast(const __u8 *dst_mac)
{
    bool is_broadcast;

    is_broadcast = (dst_mac[0] == 0xff && dst_mac[1] == 0xff &&
                    dst_mac[2] == 0xff && dst_mac[3] == 0xff &&
                    dst_mac[4] == 0xff && dst_mac[5] == 0xff);

    if (is_broadcast)
        return true;

    return (dst_mac[0] & 0x01) != 0;
}

static __always_inline __u8
jz_classify_bg_proto(const struct ethhdr *eth,
                     struct rs_ctx *ctx,
                     __u16 *out_ethertype,
                     __u16 *out_udp_dport)
{
    __u16 ethertype = bpf_ntohs(ctx->layers.eth_proto);
    __u8 ip_proto = ctx->layers.ip_proto;

    *out_ethertype = ethertype;
    *out_udp_dport = 0;

    /* STP destination MAC: 01:80:c2:00:00:00 */
    if (eth->h_dest[0] == 0x01 && eth->h_dest[1] == 0x80 &&
        eth->h_dest[2] == 0xc2 && eth->h_dest[3] == 0x00 &&
        eth->h_dest[4] == 0x00 && eth->h_dest[5] == 0x00)
        return JZ_BG_PROTO_STP;

    /* CDP destination MAC: 01:00:0c:cc:cc:cc */
    if (eth->h_dest[0] == 0x01 && eth->h_dest[1] == 0x00 &&
        eth->h_dest[2] == 0x0c && eth->h_dest[3] == 0xcc &&
        eth->h_dest[4] == 0xcc && eth->h_dest[5] == 0xcc)
        return JZ_BG_PROTO_CDP;

    if (ethertype == ETH_P_ARP)
        return JZ_BG_PROTO_ARP;

    if (ethertype == ETH_P_LLDP)
        return JZ_BG_PROTO_LLDP;

    if (ethertype == ETH_P_CDP)
        return JZ_BG_PROTO_CDP;

    if (ethertype == ETH_P_IP) {
        if (ip_proto == IPPROTO_IGMP)
            return JZ_BG_PROTO_IGMP;

        if (ip_proto == IPPROTO_UDP) {
            __u16 dport = bpf_ntohs(ctx->layers.dport);

            *out_udp_dport = dport;

            if (dport == 67 || dport == 68)
                return JZ_BG_PROTO_DHCP;
            if (dport == 5353)
                return JZ_BG_PROTO_MDNS;
            if (dport == 1900)
                return JZ_BG_PROTO_SSDP;
        }
    }

    return JZ_BG_PROTO_OTHER;
}

static __always_inline void
jz_update_bg_stats(__u8 bg_proto, __u64 pkt_bytes)
{
    __u32 key = 0;
    struct jz_bg_stats *stats;

    stats = bpf_map_lookup_elem(&jz_bg_stats, &key);
    if (!stats)
        return;

    switch (bg_proto) {
    case JZ_BG_PROTO_ARP:
        stats->arp_count += 1;
        break;
    case JZ_BG_PROTO_DHCP:
        stats->dhcp_count += 1;
        break;
    case JZ_BG_PROTO_MDNS:
        stats->mdns_count += 1;
        break;
    case JZ_BG_PROTO_SSDP:
        stats->ssdp_count += 1;
        break;
    case JZ_BG_PROTO_LLDP:
        stats->lldp_count += 1;
        break;
    case JZ_BG_PROTO_CDP:
        stats->cdp_count += 1;
        break;
    case JZ_BG_PROTO_STP:
        stats->stp_count += 1;
        break;
    case JZ_BG_PROTO_IGMP:
        stats->igmp_count += 1;
        break;
    default:
        stats->other_count += 1;
        break;
    }

    stats->total_bytes += pkt_bytes;
}

static __always_inline bool
jz_bg_should_capture(__u16 ethertype,
                     __u16 udp_dport,
                     __u8 *out_include_payload)
{
    __u32 filter_id;

    *out_include_payload = 0;

#pragma unroll
    for (filter_id = 0; filter_id < 8; filter_id++) {
        struct jz_bg_filter_entry *entry;
        bool matched = false;
        __u8 sample_rate;

        entry = bpf_map_lookup_elem(&jz_bg_filter, &filter_id);
        if (!entry)
            continue;

        if (!entry->capture)
            continue;

        if (entry->ethertype != 0 && entry->ethertype == ethertype)
            matched = true;

        if (entry->udp_port != 0 && entry->udp_port == udp_dport)
            matched = true;

        if (!matched)
            continue;

        sample_rate = entry->sample_rate;
        if (sample_rate == 0)
            sample_rate = 1;

        if (sample_rate > 1 && ((__u32)bpf_ktime_get_ns() % sample_rate) != 0)
            return false;

        *out_include_payload = entry->include_payload ? 1 : 0;
        return true;
    }

    return false;
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_bg_collector_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u64 pkt_bytes;
    __u16 ethertype;
    __u16 udp_dport;
    __u8 bg_proto;
    __u8 include_payload;

    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (!jz_is_broadcast_or_multicast(eth->h_dest))
        return jz_tail_pass(xdp_ctx, ctx);

    pkt_bytes = (__u64)((__u8 *)data_end - (__u8 *)data);

    bg_proto = jz_classify_bg_proto(eth, ctx, &ethertype, &udp_dport);
    jz_update_bg_stats(bg_proto, pkt_bytes);

    if (jz_bg_should_capture(ethertype, udp_dport, &include_payload)) {
        struct jz_event_bg evt;
        __u32 payload_len = 0;

        __builtin_memset(&evt, 0, sizeof(evt));

        evt.hdr.type = JZ_EVENT_BG_CAPTURE;
        evt.hdr.len = sizeof(evt);
        evt.hdr.timestamp_ns = bpf_ktime_get_ns();
        evt.hdr.ifindex = ctx->ifindex;
        __builtin_memcpy(evt.hdr.src_mac, eth->h_source, 6);
        __builtin_memcpy(evt.hdr.dst_mac, eth->h_dest, 6);
        evt.hdr.src_ip = (__u32)ctx->layers.saddr;
        evt.hdr.dst_ip = (__u32)ctx->layers.daddr;
        evt.bg_proto = bg_proto;

        if (include_payload) {
            payload_len = (__u32)((__u8 *)data_end - (__u8 *)data);
            if (payload_len > sizeof(evt.payload))
                payload_len = sizeof(evt.payload);

            /* BPF verifier requires constant-size memcpy.
             * Use bpf_probe_read_kernel with mask to bound
             * the variable length for the verifier.
             */
            if (payload_len > 0 &&
                (__u8 *)data + payload_len <= (__u8 *)data_end)
                bpf_probe_read_kernel(evt.payload,
                                      payload_len & 0x7F,
                                      data);

            evt.payload_len = payload_len;
        }

        RS_EMIT_EVENT(&evt, sizeof(evt));
    }

    return jz_tail_pass(xdp_ctx, ctx);
}

char LICENSE[] SEC("license") = "GPL";
