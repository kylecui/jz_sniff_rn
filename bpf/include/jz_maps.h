/* jz_maps.h — BPF map struct definitions for all jz_sniff_rn modules */

#ifndef __JZ_MAPS_H
#define __JZ_MAPS_H

#include "jz_common.h"

/*
 * rSwitch pipeline maps — non-extern definitions for standalone loading.
 *
 * rswitch_helpers.h declares these as extern (guarded by __RSWITCH_MAPS_H).
 * Our BPF files pre-define __RSWITCH_MAPS_H to suppress those externs and
 * instead pick up these concrete instances, because bpf_loader.c uses plain
 * bpf_object__open() which cannot resolve extern map references.
 */
#ifdef __bpf__
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");
#endif /* __bpf__ */

/* ═══════════════════════════════════════════════
 * Section 3.2: Guard Classifier Maps
 * ═══════════════════════════════════════════════ */

/* Guard map composite key — scoped by (IP, interface) */
struct jz_guard_key {
    __u32 ip_addr;        /* guarded IP address (network order) */
    __u32 ifindex;        /* ingress interface index (0 = all interfaces) */
};

/* Static guard entries — manually configured honeypot IPs */
struct jz_guard_entry {
    __u32 ip_addr;        /* guarded IP address */
    __u8  fake_mac[6];    /* associated fake MAC (or 0 for pool) */
    __u8  guard_type;     /* JZ_GUARD_STATIC or JZ_GUARD_DYNAMIC */
    __u8  enabled;        /* 0=disabled, 1=enabled */
    __u16 vlan_id;        /* VLAN scope (0=all VLANs) */
    __u16 flags;          /* reserved */
    __u64 created_at;     /* timestamp */
    __u64 last_hit;       /* last time this guard was triggered */
    __u64 hit_count;      /* total hits */
};

/* Whitelist — trusted devices exempt from guard checks */
struct jz_whitelist_entry {
    __u32 ip_addr;
    __u8  mac[6];
    __u8  match_mac;      /* 1=must match both IP+MAC, 0=IP only */
    __u8  enabled;
    __u64 created_at;
};

/* DHCP exception key — MAC address with padding for alignment */
struct jz_dhcp_exception_key {
    __u8  mac[6];
    __u8  _pad[2];
};

/* Guard classification result — per-CPU scratch for passing to next stage */
struct jz_guard_result {
    __u8  guard_type;     /* JZ_GUARD_NONE / STATIC / DYNAMIC */
    __u8  proto;          /* detected protocol needing response */
    __u16 flags;          /* JZ_FLAG_* */
    __u32 guarded_ip;     /* the IP that was matched */
    __u8  fake_mac[6];    /* MAC to use for response (from entry or pool) */
    __u16 vlan_id;        /* ingress VLAN (0=untagged) */
    __u32 ifindex;        /* ingress interface index */
};

/* ═══════════════════════════════════════════════
 * Section 3.3: ARP Honeypot Maps
 * ═══════════════════════════════════════════════ */

/* ARP honeypot configuration */
struct jz_arp_config {
    __u8  enabled;           /* global enable/disable */
    __u8  log_all;           /* log every ARP response (vs. first-only) */
    __u16 rate_limit_pps;    /* max responses per second (0=unlimited) */
    __u32 _pad;
};

/* Fake MAC address pool — rotating pool of synthetic MACs */
struct jz_fake_mac {
    __u8  mac[6];
    __u8  in_use;
    __u8  _pad;
    __u32 assigned_ip;      /* which guard IP this is assigned to */
};

/* Rate limiter — per-CPU token bucket */
struct jz_rate_state {
    __u64 last_refill_ns;
    __u32 tokens;
    __u32 _pad;
};

/* ═══════════════════════════════════════════════
 * Section 3.4: ICMP Honeypot Maps
 * ═══════════════════════════════════════════════ */

/* ICMP honeypot configuration */
struct jz_icmp_config {
    __u8  enabled;
    __u8  ttl;              /* TTL value in fake reply (e.g., 64 for Linux, 128 for Windows) */
    __u16 rate_limit_pps;
    __u32 _pad;
};

/* ═══════════════════════════════════════════════
 * Section 3.5: Sniffer Detect Maps
 * ═══════════════════════════════════════════════ */

/* Probe targets — IPs we've sent ARP probes to (non-existent IPs) */
struct jz_probe_target {
    __u32 probe_ip;         /* non-existent IP we probed */
    __u64 probe_sent_ns;    /* when the probe was sent */
    __u32 probe_ifindex;    /* interface the probe was sent on */
    __u8  status;           /* 0=pending, 1=response_received, 2=expired */
    __u8  _pad[3];
};

/* Sniffer suspects — devices that responded to probes */
struct jz_sniffer_suspect {
    __u8  mac[6];
    __u16 _pad;
    __u32 ip_addr;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 response_count;
    __u32 ifindex;
};

/* ═══════════════════════════════════════════════
 * Section 3.6: Traffic Weaver Maps
 * ═══════════════════════════════════════════════ */

/* Flow policy key — 5-tuple match */
struct jz_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;         /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    __u8  _pad[3];
};

/* Flow policy value — action to take */
struct jz_flow_policy {
    __u8  action;         /* JZ_ACTION_* */
    __u8  redirect_port;  /* ifindex for redirect target */
    __u8  mirror_port;    /* ifindex for mirror target */
    __u8  priority;       /* higher = checked first */
    __u32 flags;          /* reserved */
    __u64 created_at;
    __u64 hit_count;
    __u64 byte_count;
};

/* Redirect port configuration */
struct jz_redirect_config {
    __u32 honeypot_ifindex;    /* default honeypot VM interface */
    __u32 mirror_ifindex;      /* default mirror analyzer interface */
    __u8  enabled;
    __u8  _pad[3];
};

/* Per-flow statistics */
struct jz_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

/* ═══════════════════════════════════════════════
 * Section 3.7: Background Collector Maps
 * ═══════════════════════════════════════════════ */

/* Background capture filter — which protocols to capture */
struct jz_bg_filter_entry {
    __u16 ethertype;        /* ETH_P_ARP, ETH_P_LLDP, etc. (0=match by port) */
    __u16 udp_port;         /* UDP dest port (67=DHCP, 5353=mDNS, 1900=SSDP) */
    __u8  capture;          /* 1=capture, 0=ignore */
    __u8  sample_rate;      /* 1=every packet, N=1-in-N sampling */
    __u8  include_payload;  /* 1=include first 128B of payload */
    __u8  _pad;
};

/* Background capture statistics */
struct jz_bg_stats {
    __u64 arp_count;
    __u64 dhcp_count;
    __u64 mdns_count;
    __u64 ssdp_count;
    __u64 lldp_count;
    __u64 cdp_count;
    __u64 stp_count;
    __u64 igmp_count;
    __u64 other_count;
    __u64 total_bytes;
};

/* ═══════════════════════════════════════════════
 * Section 3.8: Threat Detect Maps
 * ═══════════════════════════════════════════════ */

/* Threat pattern — header-based matching */
struct jz_threat_pattern {
    __u32 src_ip;           /* 0 = wildcard */
    __u32 dst_ip;           /* 0 = wildcard */
    __u16 dst_port;         /* 0 = wildcard */
    __u8  proto;            /* 0 = wildcard */
    __u8  threat_level;     /* 1=low, 2=medium, 3=high, 4=critical */
    __u32 pattern_id;       /* unique ID for this pattern */
    __u8  action;           /* 0=log-only, 1=log+drop, 2=log+redirect */
    __u8  _pad[3];
    char  description[32];  /* human-readable description */
};

/* Threat detection statistics */
struct jz_threat_stats {
    __u64 total_checked;
    __u64 threats_low;
    __u64 threats_medium;
    __u64 threats_high;
    __u64 threats_critical;
    __u64 dropped;
    __u64 redirected;
};

/* ═══════════════════════════════════════════════
 * Section 3.9: Forensics Maps
 * ═══════════════════════════════════════════════ */

/* Forensic sample configuration */
struct jz_sample_config {
    __u8  enabled;
    __u8  _pad;
    __u16 max_payload_bytes;  /* how many bytes of payload to capture (128/256/512) */
    __u32 sample_rate;        /* 1-in-N sampling for non-flagged packets (0=only flagged) */
};

#endif /* __JZ_MAPS_H */
