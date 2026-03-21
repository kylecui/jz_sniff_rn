// SPDX-License-Identifier: GPL-2.0
/* jz_forensics.bpf.c -- Forensic packet sampling module
 *
 * Stage 28 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * Reads threat sampling hints from upstream threat detection and captures
 * packet bytes into a dedicated forensic ring buffer.
 */

#include "rswitch_bpf.h"       /* vmlinux.h, CO-RE helpers, map_defs.h, uapi.h */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* Local event type reserved for forensic samples. */
#define JZ_EVENT_FORENSIC_SAMPLE 9
#define JZ_FORENSIC_PAYLOAD_MAX  512

/* -- Module Declaration -- */

RS_DECLARE_MODULE("jz_forensics",
                  RS_HOOK_XDP_INGRESS,
                  JZ_STAGE_FORENSICS,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
                  "Packet sampling for forensic analysis");

RS_DEPENDS_ON("jz_threat_detect");

/* -- BPF Maps -- */

/* Runtime sampling configuration (single global entry). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_sample_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_sample_config SEC(".maps");

/* Dedicated forensic ring buffer (separate from rs_event_bus). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_sample_ringbuf SEC(".maps");

/* Threat result written by jz_threat_detect. */
struct jz_threat_result {
    __u8  threat_level;
    __u8  sample_flag;
    __u16 _pad;
};

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_result);
    __uint(max_entries, 1);
} jz_threat_result_map SEC(".maps");

/* Fixed-size forensic sample record for verifier-friendly ringbuf writes. */
struct jz_sample_entry {
    struct jz_event_hdr hdr;
    __u8  threat_level;
    __u8  _pad[3];
    __u32 payload_len;
    __u8  payload[JZ_FORENSIC_PAYLOAD_MAX];
};

/* -- Helpers -- */

static __always_inline int
jz_tail_pass(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

static __always_inline bool
jz_should_sample(const struct jz_threat_result *threat,
                 const struct jz_sample_config *cfg)
{
    if (threat && threat->sample_flag)
        return true;

    if (cfg->sample_rate == 0)
        return false;

    return (bpf_get_prng_u32() % cfg->sample_rate) == 0;
}

static __always_inline void
jz_copy_sample(struct rs_ctx *ctx,
               void *data,
               void *data_end,
               const struct ethhdr *eth,
               __u8 threat_level,
               __u16 max_payload_bytes)
{
    struct jz_sample_entry *entry;
    __u32 pkt_len;
    __u32 copy_len;

    pkt_len = (__u32)((__u8 *)data_end - (__u8 *)data);
    copy_len = pkt_len;

    if (copy_len > max_payload_bytes)
        copy_len = max_payload_bytes;
    if (copy_len > JZ_FORENSIC_PAYLOAD_MAX)
        copy_len = JZ_FORENSIC_PAYLOAD_MAX;

    entry = bpf_ringbuf_reserve(&jz_sample_ringbuf, sizeof(*entry), 0);
    if (!entry)
        return;

    __builtin_memset(entry, 0, sizeof(*entry));

    entry->hdr.type = JZ_EVENT_FORENSIC_SAMPLE;
    entry->hdr.len = sizeof(*entry);
    entry->hdr.timestamp_ns = bpf_ktime_get_ns();
    entry->hdr.ifindex = ctx->ifindex;
    __builtin_memcpy(entry->hdr.src_mac, eth->h_source, 6);
    __builtin_memcpy(entry->hdr.dst_mac, eth->h_dest, 6);
    entry->hdr.src_ip = (__u32)ctx->layers.saddr;
    entry->hdr.dst_ip = (__u32)ctx->layers.daddr;

    entry->threat_level = threat_level;
    entry->payload_len = copy_len;

    /* BPF verifier requires bounded variable length.
     * Mask to 0x1FF (max 511) satisfies the verifier
     * while allowing up to JZ_FORENSIC_PAYLOAD_MAX bytes.
     */
    if (copy_len > 0 &&
        ((__u8 *)data + copy_len) <= (__u8 *)data_end) {
        long ret = bpf_probe_read_kernel(entry->payload,
                                         copy_len & 0x1FF,
                                         data);
        if (ret < 0)
            entry->payload_len = 0;
    }

    bpf_ringbuf_submit(entry, 0);
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_forensics_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx;
    struct jz_sample_config *cfg;
    struct jz_threat_result *threat;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u32 key = 0;
    __u8 threat_level = 0;

    /* 1) Load per-CPU context from rs_ctx_map. */
    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    /* 2) Bounds check: packet must have Ethernet header. */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return jz_tail_pass(xdp_ctx, ctx);

    /* 3) Load sampling config and exit fast when disabled. */
    cfg = bpf_map_lookup_elem(&jz_sample_config, &key);
    if (!cfg || !cfg->enabled)
        return jz_tail_pass(xdp_ctx, ctx);

    /* 4) Read threat result produced by jz_threat_detect. */
    threat = bpf_map_lookup_elem(&jz_threat_result_map, &key);
    if (threat)
        threat_level = threat->threat_level;

    /* 5) Triggered sampling first, then optional 1-in-N random sampling. */
    if (!jz_should_sample(threat, cfg))
        return jz_tail_pass(xdp_ctx, ctx);

    /* 6) Best-effort forensic capture to dedicated ringbuf. */
    jz_copy_sample(ctx, data, data_end, eth, threat_level, cfg->max_payload_bytes);

    /* 7) Non-intrusive module: always continue pipeline/pass. */
    return jz_tail_pass(xdp_ctx, ctx);
}

char LICENSE[] SEC("license") = "GPL";
