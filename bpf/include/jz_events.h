/* jz_events.h — Event structures for jz_sniff_rn BPF modules */

#ifndef __JZ_EVENTS_H
#define __JZ_EVENTS_H

#include "jz_common.h"
#include "jz_maps.h"    /* for struct jz_flow_key */

/* ── Event structures emitted to rs_event_bus ring buffer ── */

/* Attack event (ARP/ICMP honeypot triggered) */
struct jz_event_attack {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_ATTACK_ARP or _ICMP */
    __u8  guard_type;           /* static or dynamic */
    __u8  protocol;             /* ARP=1, ICMP=2 */
    __u8  fake_mac[6];          /* MAC used in honeypot response */
    __u32 guarded_ip;           /* the guard IP that was triggered */
};

/* Sniffer detected event */
struct jz_event_sniffer {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_SNIFFER_DETECTED */
    __u8  suspect_mac[6];
    __u16 _pad;
    __u32 suspect_ip;
    __u32 probe_ip;             /* the non-existent IP that was probed */
    __u32 response_count;
};

/* Policy match event */
struct jz_event_policy {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_POLICY_MATCH */
    __u8  action;               /* JZ_ACTION_* */
    __u8  _pad[3];
    __u32 policy_id;
    struct jz_flow_key flow;
};

/* Threat detected event */
struct jz_event_threat {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_THREAT_DETECTED */
    __u32 pattern_id;
    __u8  threat_level;
    __u8  action_taken;         /* log-only, drop, redirect */
    __u16 _pad;
    char  description[32];
};

/* Background capture event */
struct jz_event_bg {
    struct jz_event_hdr hdr;    /* type = JZ_EVENT_BG_CAPTURE */
    __u8  bg_proto;             /* internal protocol classification */
    __u8  _pad[3];
    __u32 payload_len;          /* actual payload captured */
    __u8  payload[128];         /* first 128 bytes of packet */
};

/* Forensic sample event (emitted to jz_sample_ringbuf, not rs_event_bus) */
struct jz_event_sample {
    struct jz_event_hdr hdr;
    __u8  threat_level;
    __u8  _pad[3];
    __u32 payload_len;
    __u8  payload[];            /* variable-length payload (up to 512B) */
};

#endif /* __JZ_EVENTS_H */
