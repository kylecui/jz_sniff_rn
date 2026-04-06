/* jz_common.h — Shared definitions for all jz_sniff_rn BPF modules */

#ifndef __JZ_COMMON_H
#define __JZ_COMMON_H

/* Kernel types and BPF helpers come from rswitch_module.h (vmlinux.h + libbpf).
 * Do NOT add <linux/bpf.h> — it redefines vmlinux.h symbols. */

/* ── Stage Numbers ──
 * All jz modules run in the 21-28 range (after VLAN at 20, before ACL at 30).
 * This avoids collision with rSwitch core modules (vlan=20, acl=30, route=50,
 * mirror=70, l2learn=80, lastcall=90).
 */
#define JZ_STAGE_GUARD_CLASSIFIER   21
#define JZ_STAGE_ARP_HONEYPOT       22
#define JZ_STAGE_ICMP_HONEYPOT      23
#define JZ_STAGE_SNIFFER_DETECT     24
#define JZ_STAGE_TRAFFIC_WEAVER     25
#define JZ_STAGE_BG_COLLECTOR       26
#define JZ_STAGE_THREAT_DETECT      27
#define JZ_STAGE_FORENSICS          28

/* ── rs_ctx Offsets (jz reserved: 192-255) ── */
#define JZ_CTX_OFFSET               192
#define JZ_CTX_GUARD_RESULT         192  /* __u8: 0=no-match, 1=static, 2=dynamic */
#define JZ_CTX_GUARD_PROTO          193  /* __u8: matched protocol (ARP/ICMP/TCP/UDP) */
#define JZ_CTX_GUARD_FLAGS          194  /* __u16: flags (whitelist_bypass, probe, etc.) */
#define JZ_CTX_WEAVER_ACTION        196  /* __u8: PASS/DROP/REDIRECT/MIRROR */
#define JZ_CTX_WEAVER_PORT          197  /* __u8: redirect target port */
#define JZ_CTX_THREAT_LEVEL         198  /* __u8: 0=none, 1=low, 2=med, 3=high, 4=crit */
#define JZ_CTX_SAMPLE_FLAG          199  /* __u8: 1=sample this packet */
#define JZ_CTX_VLAN_ID              200  /* __u16: ingress VLAN ID (0=untagged) */

/* ── Guard Types ── */
#define JZ_GUARD_NONE               0
#define JZ_GUARD_STATIC             1
#define JZ_GUARD_DYNAMIC            2

/* ── Guard Flags ── */
#define JZ_FLAG_WHITELIST_BYPASS    (1 << 0)
#define JZ_FLAG_IS_PROBE_RESPONSE  (1 << 1)
#define JZ_FLAG_ARP_REQUEST        (1 << 2)
#define JZ_FLAG_ICMP_REQUEST       (1 << 3)
#define JZ_FLAG_TCP_SYN            (1 << 4)
#define JZ_FLAG_UDP                (1 << 5)

/* ── Weaver Actions ── */
#define JZ_ACTION_PASS              0
#define JZ_ACTION_DROP              1
#define JZ_ACTION_REDIRECT          2
#define JZ_ACTION_MIRROR            3
#define JZ_ACTION_REDIRECT_MIRROR   4  /* both redirect + mirror */

/* ── Event Types ── */
#define JZ_EVENT_ATTACK_ARP         1
#define JZ_EVENT_ATTACK_ICMP        2
#define JZ_EVENT_SNIFFER_DETECTED   3
#define JZ_EVENT_POLICY_MATCH       4
#define JZ_EVENT_THREAT_DETECTED    5
#define JZ_EVENT_BG_CAPTURE         6
#define JZ_EVENT_CONFIG_CHANGE      7
#define JZ_EVENT_SYSTEM_STATUS      8
#define JZ_EVENT_DHCP_UNPROTECTED   9
#define JZ_EVENT_ATTACK_TCP        10
#define JZ_EVENT_ATTACK_UDP        11

/* ── Event Header (common to all events) ── */
struct jz_event_hdr {
    __u32 type;           /* JZ_EVENT_* */
    __u32 len;            /* total event length */
    __u64 timestamp_ns;   /* bpf_ktime_get_ns() */
    __u32 ifindex;        /* ingress interface */
    __u16 vlan_id;        /* ingress VLAN (0=untagged) */
    __u8  _pad_hdr[2];
    __u8  src_mac[6];     /* source MAC */
    __u8  dst_mac[6];     /* destination MAC */
    __u32 src_ip;         /* source IP (0 if not applicable) */
    __u32 dst_ip;         /* destination IP (0 if not applicable) */
};

/* ── Map Size Limits ── */
#define JZ_MAX_STATIC_GUARDS       4096
#define JZ_MAX_DYNAMIC_GUARDS      16384
#define JZ_MAX_WHITELIST           4096
#define JZ_MAX_FAKE_MACS           256
#define JZ_MAX_FLOW_POLICIES       8192
#define JZ_MAX_PROBE_TARGETS       1024
#define JZ_MAX_THREAT_PATTERNS     128
#define JZ_MAX_BG_FILTERS          64
#define JZ_MAX_DHCP_EXCEPTION      256

#endif /* __JZ_COMMON_H */
