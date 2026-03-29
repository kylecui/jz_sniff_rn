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

#define  __RSWITCH_MAPS_H      /* non-extern pipeline maps defined in jz_maps.h */
#include "rswitch_module.h"    /* rSwitch SDK v2.1.0: ABI types, CO-RE helpers, pipeline macros */
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
    __type(key, struct jz_guard_key);
    __type(value, struct jz_guard_entry);
    __uint(max_entries, JZ_MAX_STATIC_GUARDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_static_guards SEC(".maps");

/* Dynamic guard entries — auto-discovered IPs (LRU for auto-eviction) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct jz_guard_key);
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

/* DHCP exception — DHCP servers exempt from guard ARP Probe responses only */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct jz_dhcp_exception_key);
    __type(value, struct jz_whitelist_entry);
    __uint(max_entries, JZ_MAX_DHCP_EXCEPTION);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_dhcp_exception SEC(".maps");

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
        goto check_dhcp;

    /* IP-only match */
    if (!wl->match_mac)
        return true;

    /* IP+MAC match — compare 6 bytes */
    if (__builtin_memcmp(src_mac, wl->mac, 6) == 0)
        return true;

check_dhcp:
    /* ARP Probe: src_ip == 0 — check DHCP exception by MAC */
    if (src_ip == 0) {
        struct jz_dhcp_exception_key dk = {};
        __builtin_memcpy(dk.mac, src_mac, 6);
        if (bpf_map_lookup_elem(&jz_dhcp_exception, &dk))
            return true;
    }

    return false;
}

/* ── Helper: Lookup guard entry (static first, then dynamic) ── */

static __always_inline struct jz_guard_entry *
jz_lookup_guard(__u32 dst_ip, __u16 ingress_vlan, __u32 ifindex,
                __u8 *out_guard_type)
{
    struct jz_guard_entry *entry;
    struct jz_guard_key key;

    /* Try exact match (ip + ifindex) on static guards */
    key.ip_addr = dst_ip;
    key.ifindex = ifindex;
    entry = bpf_map_lookup_elem(&jz_static_guards, &key);
    if (entry && entry->enabled &&
        (entry->vlan_id == 0 || entry->vlan_id == ingress_vlan)) {
        *out_guard_type = JZ_GUARD_STATIC;
        return entry;
    }

    /* Wildcard fallback (ip + ifindex=0) on static guards */
    key.ifindex = 0;
    entry = bpf_map_lookup_elem(&jz_static_guards, &key);
    if (entry && entry->enabled &&
        (entry->vlan_id == 0 || entry->vlan_id == ingress_vlan)) {
        *out_guard_type = JZ_GUARD_STATIC;
        return entry;
    }

    /* Try exact match on dynamic guards */
    key.ifindex = ifindex;
    entry = bpf_map_lookup_elem(&jz_dynamic_guards, &key);
    if (entry && entry->enabled &&
        (entry->vlan_id == 0 || entry->vlan_id == ingress_vlan)) {
        *out_guard_type = JZ_GUARD_DYNAMIC;
        return entry;
    }

    /* Wildcard fallback on dynamic guards */
    key.ifindex = 0;
    entry = bpf_map_lookup_elem(&jz_dynamic_guards, &key);
    if (entry && entry->enabled &&
        (entry->vlan_id == 0 || entry->vlan_id == ingress_vlan)) {
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

    if (eth_proto == bpf_htons(ETH_P_ARP))
        return 1;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        if (ctx->layers.ip_proto == IPPROTO_ICMP)
            return 2;
        if (ctx->layers.ip_proto == IPPROTO_TCP)
            return 3;
        if (ctx->layers.ip_proto == IPPROTO_UDP)
            return 4;
    }

    return 0;
}

/* ── Helper: Store guard result in per-CPU map ── */

static __always_inline void
jz_store_result(__u8 guard_type, __u8 proto, __u16 flags,
                __u32 guarded_ip, const __u8 *fake_mac, __u16 vlan_id,
                __u32 ifindex)
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
    result->vlan_id = vlan_id;
    result->ifindex = ifindex;

    if (fake_mac)
        __builtin_memcpy(result->fake_mac, fake_mac, 6);
    else
        __builtin_memset(result->fake_mac, 0, 6);
}

/* ── ARP Header (for extracting target IP) ── */

struct arphdr_ipv4 {
    __be16 ar_hrd;    /* hardware type (1=Ethernet) */
    __be16 ar_pro;    /* protocol type (0x0800=IPv4) */
    __u8   ar_hln;    /* hardware address length (6) */
    __u8   ar_pln;    /* protocol address length (4) */
    __be16 ar_op;     /* opcode (1=request, 2=reply) */
    __u8   ar_sha[6]; /* sender hardware address */
    __be32 ar_sip;    /* sender IP address */
    __u8   ar_tha[6]; /* target hardware address */
    __be32 ar_tip;    /* target IP address */
} __attribute__((packed));

static __always_inline __be32 arp_read_be32(const void *p)
{
    __be32 val;
    __builtin_memcpy(&val, p, sizeof(val));
    return val;
}

/* ── Inline L2/L3 Parser ──
 *
 * When running without rSwitch core (ctx->parsed == 0), the per-CPU
 * rs_ctx_map is zero-initialized and no upstream program populates
 * the packet metadata.  This inline parser fills ctx->layers so the
 * entire downstream pipeline (guard_classifier logic, arp_honeypot,
 * icmp_honeypot, bg_collector, threat_detect, forensics) can work.
 *
 * The parser is a no-op when rSwitch core IS present (ctx->parsed != 0),
 * satisfying the constraint "jz modules must not alter rs_ctx fields
 * used by rSwitch core modules".
 */
static __always_inline void
jz_parse_packet(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    void *data     = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return;

    __u16 eth_proto = eth->h_proto;
    __u16 offset = sizeof(struct ethhdr);  /* 14 bytes */

    /* VLAN: peel up to RS_VLAN_MAX_DEPTH (2) tags — 802.1Q / 802.1AD */
    __u8  vlan_depth = 0;

#pragma unroll
    for (int i = 0; i < RS_VLAN_MAX_DEPTH; i++) {
        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;

        /* Bounds check for 4-byte VLAN TCI + next ethertype */
        if (data + offset + 4 > data_end)
            return;

        /* TCI is at data+offset: 16-bit (3-bit PCP, 1-bit DEI, 12-bit VID) */
        __u16 tci;
        __builtin_memcpy(&tci, data + offset, 2);
        ctx->layers.vlan_ids[i] = bpf_ntohs(tci) & 0x0FFF;
        vlan_depth++;

        /* Next ethertype sits at offset+2 */
        __builtin_memcpy(&eth_proto, data + offset + 2, 2);
        offset += 4;
    }

    ctx->layers.vlan_depth = vlan_depth;
    ctx->layers.eth_proto  = eth_proto;
    ctx->layers.l2_offset  = 0;
    ctx->layers.l3_offset  = offset;
    ctx->ifindex           = xdp_ctx->ingress_ifindex;

    /* Set ingress VLAN from outermost tag (0 if untagged) */
    ctx->ingress_vlan = (vlan_depth > 0) ? ctx->layers.vlan_ids[0] : 0;

    /* L3: Parse IPv4 header for saddr/daddr/ip_proto */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        if (data + offset + sizeof(struct iphdr) > data_end)
            return;

        struct iphdr *iph = data + offset;
        if ((void *)(iph + 1) > data_end)
            return;

        ctx->layers.saddr    = iph->saddr;
        ctx->layers.daddr    = iph->daddr;
        ctx->layers.ip_proto = iph->protocol;

        __u16 ihl = (__u16)(iph->ihl) * 4;
        if (ihl < 20)
            ihl = 20;
        ctx->layers.l4_offset = offset + ihl;

        /* L4: Parse TCP/UDP ports so downstream modules (bg_collector,
         * traffic_weaver, threat_detect) can classify by port. */
        __u16 l4_off = offset + ihl;
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *uh = data + l4_off;
            if ((void *)(uh + 1) <= data_end) {
                ctx->layers.sport = uh->source;
                ctx->layers.dport = uh->dest;
                ctx->layers.payload_offset = l4_off + sizeof(*uh);
                ctx->layers.payload_len = bpf_ntohs(uh->len) > sizeof(*uh)
                    ? bpf_ntohs(uh->len) - sizeof(*uh) : 0;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = data + l4_off;
            if ((void *)(th + 1) <= data_end) {
                ctx->layers.sport = th->source;
                ctx->layers.dport = th->dest;
                __u16 tcp_hlen = (__u16)(th->doff) * 4;
                if (tcp_hlen < 20) tcp_hlen = 20;
                ctx->layers.payload_offset = l4_off + tcp_hlen;
            }
        }
    }

    ctx->parsed = 1;
}

/* ── Main XDP Program ── */

SEC("xdp")
int jz_guard_classifier_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    /* As the first module in the pipeline, reset per-CPU context for
     * each new packet.  In standalone mode (no rSwitch core upstream),
     * the per-CPU rs_ctx_map retains stale data from the previous
     * invocation — including parsed=1 — which would cause us to skip
     * the inline parser and use stale L2/L3 metadata.
     *
     * When rSwitch core IS present, it resets ctx before us, so this
     * is a harmless no-op (core will re-parse after us anyway via its
     * own pipeline stage).
     */
    ctx->parsed = 0;
    ctx->call_depth = 0;
    ctx->next_prog_id = 0;

    jz_parse_packet(xdp_ctx, ctx);

    /* Access packet data */
    void *data     = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    /* Bounds check: ensure at least Ethernet header is present */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Extract source MAC */
    __u8 *src_mac = eth->h_source;

    /* Determine src/dst IPs depending on protocol.
     * For IP packets (ICMP, TCP, UDP), the parser (rSwitch core or
     * our inline parser above) populates ctx->layers.saddr/daddr
     * from the IP header.
     * For ARP packets, these fields are ZERO because there is no
     * IP header — we must extract from the ARP payload directly.
     */
    __u32 src_ip;
    __u32 dst_ip;

    if (ctx->layers.eth_proto == bpf_htons(ETH_P_ARP)) {
        /* ARP: extract IPs from ARP payload (use l3_offset for VLAN support)
         * Mask offset with RS_L3_OFFSET_MASK so the BPF verifier can
         * prove the range after the subsequent bounds check.
         */
        __u16 l3_off = ctx->layers.l3_offset & RS_L3_OFFSET_MASK;
        struct arphdr_ipv4 *arp = (void *)data + l3_off;
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        /* Only handle Ethernet/IPv4 ARP */
        if (arp->ar_hrd != bpf_htons(1) ||
            arp->ar_pro != bpf_htons(0x0800) ||
            arp->ar_hln != 6 || arp->ar_pln != 4)
            return XDP_PASS;

        src_ip = arp_read_be32(&arp->ar_sip);
        dst_ip = arp_read_be32(&arp->ar_tip);
    } else {
        /* IP and everything else: use parsed context */
        src_ip = ctx->layers.saddr;
        dst_ip = ctx->layers.daddr;
    }

    /* Step 1: Check whitelist — if whitelisted, skip guard classification */
    if (jz_check_whitelist(ctx, src_ip, src_mac)) {
        /* Store whitelist bypass result */
        jz_store_result(JZ_GUARD_NONE, 0, JZ_FLAG_WHITELIST_BYPASS, 0, NULL,
                        ctx->ingress_vlan, ctx->ifindex);

        /* Tail-call to next stage in pipeline */
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    /* Step 2: Lookup guard tables */
    __u8 guard_type = JZ_GUARD_NONE;
    struct jz_guard_entry *entry = jz_lookup_guard(dst_ip, ctx->ingress_vlan,
                                                    ctx->ifindex, &guard_type);

    if (!entry) {
        /* No guard match — continue pipeline */
        jz_store_result(JZ_GUARD_NONE, 0, 0, 0, NULL, ctx->ingress_vlan,
                        ctx->ifindex);
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

    jz_store_result(guard_type, proto, flags, dst_ip, fake_mac,
                    ctx->ingress_vlan, ctx->ifindex);

    /* Step 5: Update guard entry stats (best-effort) */
    __sync_fetch_and_add(&entry->hit_count, 1);
    entry->last_hit = bpf_ktime_get_ns();

    /* Step 6: Tail-call to next stage
     * RS_TAIL_CALL_NEXT handles sequential pipeline chaining.
     * The rSwitch loader assigns modules to sequential slots.
     * ARP honeypot (stage 22) / ICMP honeypot (stage 23) will
     * read the guard_result from the per-CPU map.
     */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    /* Fallthrough: if tail call fails, pass packet */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
