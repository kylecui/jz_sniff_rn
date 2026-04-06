// SPDX-License-Identifier: GPL-2.0
/* jz_threat_detect.bpf.c -- Fast-path threat pattern matching engine (v2)
 *
 * Stage 27 in the jz_sniff_rn ingress pipeline (rSwitch user module).
 *
 * v2 changes from v1:
 *   - ARRAY map with priority ordering (was HASH, first-match)
 *   - rule_count singleton map bounds iteration
 *   - continue_matching flag for multi-rule chains
 *   - capture_packet flag with ring buffer output
 *   - true mirror (non-terminal, via ctx->mirror)
 *   - src_mac matching
 *   - attacker session map for stealth redirect convergence
 *
 * Implementation note:
 *   The rule matching loop uses bpf_loop() (kernel 5.17+) instead of an
 *   open-coded for-loop.  This avoids the BPF verifier instruction limit
 *   (1 M insns) because the verifier only needs to verify the callback
 *   body once, regardless of loop count.  Terminal XDP actions (DROP,
 *   REDIRECT) are deferred to the main function via the loop context
 *   because bpf_redirect() writes per-CPU state that must be returned
 *   from the XDP program entry point.
 *
 * Pipeline flow:
 *   guard_classifier(21) -> arp_honeypot(22) / icmp_honeypot(23)
 *                        -> sniffer_detect(24)
 *                        -> traffic_weaver(25)
 *                        -> bg_collector(26)
 *                        -> threat_detect(27)
 *                        -> forensics(28)
 */

#define  __RSWITCH_MAPS_H      /* non-extern pipeline maps defined in jz_maps.h */
#include "rswitch_module.h"    /* rSwitch SDK v2.1.0: ABI types, CO-RE helpers, pipeline macros */
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

#define JZ_THREAT_FLAG_CONTINUE   0x01
#define JZ_THREAT_FLAG_CAPTURE    0x02
#define JZ_THREAT_MAX_EVENTS      8
#define JZ_CAPTURE_RB_SIZE        (4 * 1024 * 1024)  /* 4 MB */
#define JZ_ATTACKER_SESSION_MAX   1024
#define JZ_CAPTURE_SNAP_LEN       1500               /* max captured bytes per packet */
#define JZ_CAPTURE_BUF_SIZE       (sizeof(struct jz_capture_meta) + JZ_CAPTURE_SNAP_LEN)

/* Terminal action codes communicated from callback to main function.
 * These are NOT XDP return codes — just internal signals. */
#define JZ_ACT_PASS       0
#define JZ_ACT_DROP       1
#define JZ_ACT_REDIRECT   2

/* -- BPF Maps -- */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_pattern);
    __uint(max_entries, JZ_MAX_THREAT_PATTERNS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_patterns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_rule_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, JZ_CAPTURE_RB_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_capture_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct jz_attacker_session);
    __uint(max_entries, JZ_ATTACKER_SESSION_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_attacker_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_threat_result);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_threat_result_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_redirect_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_redirect_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jz_redirect_target);
    __uint(max_entries, JZ_MAX_REDIRECT_TARGETS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} jz_redirect_targets SEC(".maps");

/* ================================================================
 * bpf_loop callback context
 *
 * Carries per-packet state into the callback and accumulates the
 * matching result back to the main function.  Packet capture is
 * deferred to the main function (needs xdp_md for direct access);
 * the callback only records the first capture-eligible rule's
 * metadata.
 * ================================================================ */

struct jz_loop_ctx {
    /* ── Packet identity (immutable across iterations) ── */
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
    __u8  src_mac[6];
    __u8  _pad0;

    /* ── XDP / pipeline context ── */
    __u16 ifindex;
    __u16 ingress_vlan;

    /* ── Accumulated result (written by callback) ── */
    __u8  highest_threat;
    __u8  final_sample;
    __u8  terminal_action; /* JZ_ACT_PASS / DROP / REDIRECT */
    __u8  events_emitted;
    __u32 redirect_ifindex;

    /* ── Deferred capture request (filled by callback, executed by main) ── */
    __u8  want_capture;
    __u8  capture_threat_level;
    __u8  capture_action;
    __u8  _pad1;
    __u32 capture_pattern_id;
};

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
    return bpf_map_lookup_elem(&jz_threat_blacklist, &src_ip) != NULL;
}

static __always_inline bool
jz_match_pattern_v2(const struct jz_threat_pattern *p,
                    __u32 src_ip,
                    __u32 dst_ip,
                    __u16 dst_port,
                    __u8 proto,
                    const __u8 *pkt_src_mac)
{
    if (p->src_ip != 0 && p->src_ip != src_ip)
        return false;

    if (p->dst_ip != 0 && p->dst_ip != dst_ip)
        return false;

    if (p->dst_port != 0 && p->dst_port != dst_port)
        return false;

    if (p->proto != 0 && p->proto != proto)
        return false;

    /* src_mac: all-zeros = wildcard */
    if ((p->src_mac[0] | p->src_mac[1] | p->src_mac[2] |
         p->src_mac[3] | p->src_mac[4] | p->src_mac[5]) != 0) {
        if (__builtin_memcmp(p->src_mac, pkt_src_mac, 6) != 0)
            return false;
    }

    return true;
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

/* ================================================================
 * bpf_loop callback — per-rule matching and action dispatch
 *
 * Called once per priority slot.  Returns 0 to continue to the next
 * rule, 1 to stop iteration (terminal action or end of chain).
 *
 * Terminal actions (drop, redirect) are NOT executed here; they are
 * signalled via lctx->terminal_action so the main function can call
 * bpf_redirect() / return XDP_DROP from the proper XDP entry point.
 * ================================================================ */

static long __noinline
jz_rule_match_cb(__u32 idx, struct jz_loop_ctx *lctx)
{
    struct jz_threat_pattern *p;
    struct jz_threat_stats *stats;
    struct rs_ctx *rs;
    __u32 key = 0;

    /* Lookup the rule at this priority slot */
    p = bpf_map_lookup_elem(&jz_threat_patterns, &idx);
    if (!p)
        return 0;  /* empty slot, continue */

    /* Pattern matching */
    if (!jz_match_pattern_v2(p, lctx->src_ip, lctx->dst_ip,
                             lctx->dst_port, lctx->proto,
                             lctx->src_mac))
        return 0;  /* no match, continue */

    /* ── Matched ── */

    /* Re-lookup stats (per-CPU, cheap) */
    stats = bpf_map_lookup_elem(&jz_threat_stats, &key);

    /* Capture if flagged — defer actual capture to main function */
    if ((p->flags & JZ_THREAT_FLAG_CAPTURE) && !lctx->want_capture) {
        lctx->want_capture = 1;
        lctx->capture_pattern_id = p->pattern_id;
        lctx->capture_threat_level = p->threat_level;
        lctx->capture_action = p->action;

        if (stats)
            stats->captured += 1;
    }

    /* Emit threat event */
    if (lctx->events_emitted < JZ_THREAT_MAX_EVENTS) {
        /* Re-lookup rs_ctx for event metadata */
        rs = bpf_map_lookup_elem(&rs_ctx_map, &key);
        if (rs) {
            struct jz_event_threat evt;

            __builtin_memset(&evt, 0, sizeof(evt));
            evt.hdr.type = JZ_EVENT_THREAT_DETECTED;
            evt.hdr.len = sizeof(evt);
            evt.hdr.timestamp_ns = bpf_ktime_get_ns();
            evt.hdr.ifindex = lctx->ifindex;
            evt.hdr.vlan_id = lctx->ingress_vlan;
            /* Use src_mac from loop ctx (original packet MAC) */
            __builtin_memcpy(evt.hdr.src_mac, lctx->src_mac, 6);
            evt.hdr.src_ip = lctx->src_ip;
            evt.hdr.dst_ip = lctx->dst_ip;

            evt.pattern_id = p->pattern_id;
            evt.threat_level = p->threat_level;
            evt.action_taken = p->action;
            __builtin_memcpy(evt.description, p->description,
                             sizeof(evt.description));

            RS_EMIT_EVENT(&evt, sizeof(evt));
        }
        lctx->events_emitted += 1;
    }

    /* Track highest threat level */
    if (p->threat_level > lctx->highest_threat) {
        lctx->highest_threat = p->threat_level;
        lctx->final_sample = (p->threat_level >= 2) ? 1 : 0;
    }

    /* Per-threat-level stats */
    if (stats) {
        switch (p->threat_level) {
        case 1: stats->threats_low += 1;      break;
        case 2: stats->threats_medium += 1;    break;
        case 3: stats->threats_high += 1;      break;
        case 4: stats->threats_critical += 1;  break;
        default: break;
        }
    }

    /* ── Action dispatch ── */

    switch (p->action) {

    case 1: /* drop (terminal) */
        if (stats)
            stats->dropped += 1;
        lctx->terminal_action = JZ_ACT_DROP;
        return 1;  /* stop iteration */

    case 2: /* redirect (terminal) — stealth redirect with session map */
    {
        struct jz_attacker_session *session;

        session = bpf_map_lookup_elem(&jz_attacker_sessions, &lctx->src_ip);
        if (session) {
            /* Subsequent sentinel hit: do NOT redirect.
             * Just update counters for stealth convergence. */
            if (session->hit_count < 255)
                session->hit_count += 1;
            session->last_seen = (__u32)(bpf_ktime_get_ns() / 1000000000ULL);

            if (p->flags & JZ_THREAT_FLAG_CONTINUE)
                return 0;  /* continue matching */
            return 1;  /* stop (non-terminal pass-through) */
        }

        /* First sentinel hit: resolve target and signal redirect */
        {
            __u32 target_id = (__u32)p->redirect_target;
            struct jz_redirect_target *tgt;
            __u32 rkey = 0;
            __u32 redirect_ifindex = 0;

            tgt = bpf_map_lookup_elem(&jz_redirect_targets, &target_id);
            if (tgt && tgt->active && tgt->ifindex != 0) {
                redirect_ifindex = tgt->ifindex;
            } else {
                struct jz_redirect_config *cfg;
                cfg = bpf_map_lookup_elem(&jz_redirect_config, &rkey);
                if (cfg && cfg->enabled)
                    redirect_ifindex = cfg->honeypot_ifindex;
            }

            if (redirect_ifindex != 0) {
                /* Install attacker session */
                struct jz_attacker_session new_session = {};
                __u32 now_sec = (__u32)(bpf_ktime_get_ns() / 1000000000ULL);

                new_session.src_ip = lctx->src_ip;
                new_session.first_sentinel_ip = lctx->dst_ip;
                new_session.first_dst_port = lctx->dst_port;
                new_session.redirect_target = p->redirect_target;
                new_session.hit_count = 1;
                new_session.first_seen = now_sec;
                new_session.last_seen = now_sec;

                bpf_map_update_elem(&jz_attacker_sessions, &lctx->src_ip,
                                    &new_session, BPF_ANY);

                if (stats)
                    stats->redirected += 1;

                lctx->terminal_action = JZ_ACT_REDIRECT;
                lctx->redirect_ifindex = redirect_ifindex;
                return 1;  /* stop iteration */
            }
        }

        /* No target configured: fall through */
        if (p->flags & JZ_THREAT_FLAG_CONTINUE)
            return 0;
        return 1;
    }

    case 3: /* mirror (NON-TERMINAL) */
    {
        __u32 target_id = (__u32)p->redirect_target;
        struct jz_redirect_target *tgt;
        __u32 rkey = 0;
        __u32 mirror_ifindex = 0;

        tgt = bpf_map_lookup_elem(&jz_redirect_targets, &target_id);
        if (tgt && tgt->active && tgt->ifindex != 0) {
            mirror_ifindex = tgt->ifindex;
        } else {
            struct jz_redirect_config *cfg;
            cfg = bpf_map_lookup_elem(&jz_redirect_config, &rkey);
            if (cfg && cfg->enabled && cfg->mirror_ifindex != 0)
                mirror_ifindex = cfg->mirror_ifindex;
        }

        if (mirror_ifindex != 0) {
            /* Set mirror in rs_ctx — re-lookup from map */
            rs = bpf_map_lookup_elem(&rs_ctx_map, &key);
            if (rs) {
                rs->mirror = 1;
                rs->mirror_port = (__u16)mirror_ifindex;
            }
            if (stats)
                stats->mirrored += 1;
        }

        if (p->flags & JZ_THREAT_FLAG_CONTINUE)
            return 0;
        return 1;
    }

    case 0: /* log (non-terminal) */
    default:
        if (p->flags & JZ_THREAT_FLAG_CONTINUE)
            return 0;
        return 1;
    }
}

/* -- Main XDP Program -- */

SEC("xdp")
int jz_threat_detect_prog(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u32 key = 0;
    struct jz_threat_stats *stats;

    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return jz_tail_pass(xdp_ctx, ctx);

    /* Initialize result for downstream forensics stage */
    jz_store_threat_result(0, 0);

    stats = bpf_map_lookup_elem(&jz_threat_stats, &key);
    if (stats)
        stats->total_checked += 1;

    __u32 src_ip = (__u32)ctx->layers.saddr;
    __u32 dst_ip = (__u32)ctx->layers.daddr;
    __u16 dst_port = bpf_ntohs(ctx->layers.dport);
    __u8  proto = ctx->layers.ip_proto;

    /* O(1) source blacklist check */
    if (jz_check_blacklist(src_ip)) {
        struct jz_event_threat evt;

        __builtin_memset(&evt, 0, sizeof(evt));
        evt.hdr.type = JZ_EVENT_THREAT_DETECTED;
        evt.hdr.len = sizeof(evt);
        evt.hdr.timestamp_ns = bpf_ktime_get_ns();
        evt.hdr.ifindex = ctx->ifindex;
        evt.hdr.vlan_id = ctx->ingress_vlan;
        __builtin_memcpy(evt.hdr.src_mac, eth->h_source, 6);
        __builtin_memcpy(evt.hdr.dst_mac, eth->h_dest, 6);
        evt.hdr.src_ip = src_ip;
        evt.hdr.dst_ip = dst_ip;
        evt.pattern_id = 0;
        evt.threat_level = 3;
        evt.action_taken = 1;
        __builtin_memcpy(evt.description, jz_blacklist_desc,
                         sizeof(jz_blacklist_desc));

        RS_EMIT_EVENT(&evt, sizeof(evt));

        if (stats) {
            stats->threats_high += 1;
            stats->dropped += 1;
        }
        jz_store_threat_result(3, 1);
        return XDP_DROP;
    }

    /* Rule count from singleton map */
    __u32 *rule_count_ptr = bpf_map_lookup_elem(&jz_threat_rule_count, &key);
    __u32 rule_count = rule_count_ptr ? *rule_count_ptr : 0;

    if (rule_count == 0)
        return jz_tail_pass(xdp_ctx, ctx);

    /* Cap to map size for the verifier */
    if (rule_count > JZ_MAX_THREAT_PATTERNS)
        rule_count = JZ_MAX_THREAT_PATTERNS;

    /* Populate loop context with per-packet immutable state */
    struct jz_loop_ctx lctx = {};
    lctx.src_ip = src_ip;
    lctx.dst_ip = dst_ip;
    lctx.dst_port = dst_port;
    lctx.proto = proto;
    __builtin_memcpy(lctx.src_mac, eth->h_source, 6);
    lctx.ifindex = (__u16)ctx->ifindex;
    lctx.ingress_vlan = ctx->ingress_vlan;

    /* Priority-ordered pattern matching with continue-matching chains.
     * bpf_loop verifies the callback body once — O(1) verifier cost. */
    bpf_loop(rule_count, jz_rule_match_cb, &lctx, 0);

    /* Execute deferred packet capture (needs xdp_ctx for direct access) */
    if (lctx.want_capture) {
        __u32 pkt_len = (__u32)((void *)(long)xdp_ctx->data_end -
                                (void *)(long)xdp_ctx->data);

        if (pkt_len > 0 && pkt_len <= 9000) {
            __u32 cap_len = pkt_len;
            if (cap_len > JZ_CAPTURE_SNAP_LEN)
                cap_len = JZ_CAPTURE_SNAP_LEN;

            __u8 *buf = bpf_ringbuf_reserve(&jz_threat_capture_rb,
                                            JZ_CAPTURE_BUF_SIZE, 0);
            if (buf) {
                struct jz_capture_meta *meta = (struct jz_capture_meta *)buf;
                meta->timestamp_ns = bpf_ktime_get_ns();
                meta->wire_len = pkt_len;
                meta->cap_len = cap_len;
                meta->pattern_id = lctx.capture_pattern_id;
                meta->ifindex = lctx.ifindex;
                meta->action = lctx.capture_action;
                meta->threat_level = lctx.capture_threat_level;

                /* Clamp cap_len to [1, JZ_CAPTURE_SNAP_LEN] for verifier.
                 * pkt_len > 0 above guarantees cap_len >= 1, but the verifier
                 * loses that bound through the min() pattern. */
                if (cap_len < 1)
                    cap_len = 1;
                bpf_xdp_load_bytes(xdp_ctx, 0,
                                   buf + sizeof(struct jz_capture_meta),
                                   cap_len);

                bpf_ringbuf_submit(buf, 0);
            }
        }
    }

    /* Store accumulated threat result for downstream forensics */
    jz_store_threat_result(lctx.highest_threat, lctx.final_sample);

    /* Dispatch terminal action set by callback */
    switch (lctx.terminal_action) {

    case JZ_ACT_DROP:
        return XDP_DROP;

    case JZ_ACT_REDIRECT:
        if (lctx.redirect_ifindex != 0)
            return bpf_redirect(lctx.redirect_ifindex, 0);
        /* Fallback: redirect target gone between callback and here */
        break;
    }

    return jz_tail_pass(xdp_ctx, ctx);
}

char LICENSE[] SEC("license") = "GPL";
