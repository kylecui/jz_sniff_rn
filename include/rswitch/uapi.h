// SPDX-License-Identifier: GPL-2.0
/* rSwitch Unified API
 * 
 * Shared data structures and map definitions for kernel/user communication.
 * This header is included by both BPF programs and user-space code.
 */

#ifndef __RSWITCH_UAPI_H
#define __RSWITCH_UAPI_H

/* BPF programs use vmlinux.h (CO-RE), user-space uses kernel headers */
#ifdef __BPF__
    /* BPF side: types already defined in vmlinux.h (included via rswitch_bpf.h) */
    #include <bpf/bpf_helpers.h>
#else
    /* User-space side: use kernel UAPI headers */
    #include <linux/types.h>
    #include <linux/bpf.h>
#endif

/* Constants */
#define RS_ONLYKEY          0       /* Single-entry per-CPU map key */
#define RS_MAX_PROGS        256     /* Maximum tail-call programs */
#define RS_MAX_INTERFACES   64      /* Maximum network interfaces */
#define RS_MAX_VLANS        4096    /* Maximum VLAN IDs */
#define RS_MAX_ALLOWED_VLANS 128    /* Maximum allowed VLANs per port (trunk/hybrid) */
#define RS_VLAN_MAX_DEPTH   2       /* Q-in-Q support (802.1ad) */
#define RS_DEFAULT_VLAN     1       /* IEEE 802.1Q default VLAN */

/* Verifier-friendly offset masks for packet access */
#define RS_L2_OFFSET_MASK  0x00
#define RS_L3_OFFSET_MASK  0x3F
#define RS_L4_OFFSET_MASK  0x7F
#define RS_PAYLOAD_MASK    0xFF

/* Parsed packet layer offsets and metadata */
struct rs_layers {
    __u16 eth_proto;
    __u16 vlan_ids[RS_VLAN_MAX_DEPTH];
    
    __u8  vlan_depth;
    __u8  ip_proto;
    __u8  pad[2];
    
    __be32 saddr;
    __be32 daddr;
    
    __be16 sport;
    __be16 dport;
    
    __u16 l2_offset;
    __u16 l3_offset;
    __u16 l4_offset;
    __u16 payload_offset;
    __u32 payload_len;
};

/* Per-packet processing context */
struct rs_ctx {
    __u32 ifindex;
    __u32 timestamp;
    
    __u8  parsed;
    __u8  modified;
    __u8  pad[2];
    struct rs_layers layers;
    
    __u16 ingress_vlan;
    __u16 egress_vlan;
    
    __u8  prio;
    __u8  dscp;
    __u8  ecn;
    __u8  traffic_class;
    
    __u32 egress_ifindex;
    __u8  action;
    __u8  mirror;
    __u16 mirror_port;
    
    __u32 error;
    __u32 drop_reason;
    
    __u32 next_prog_id;
    __u32 call_depth;
    
    __u32 reserved[4];
};

/* Error codes */
#define RS_ERROR_NONE           0
#define RS_ERROR_PARSE_FAILED   1
#define RS_ERROR_INVALID_VLAN   2
#define RS_ERROR_ACL_DENY       3
#define RS_ERROR_NO_ROUTE       4
#define RS_ERROR_QUEUE_FULL     5
#define RS_ERROR_INTERNAL       99

/* Drop reasons */
#define RS_DROP_NONE            0
#define RS_DROP_PARSE_ERROR     1
#define RS_DROP_VLAN_FILTER     2
#define RS_DROP_ACL_BLOCK       3
#define RS_DROP_NO_FWD_ENTRY    4
#define RS_DROP_TTL_EXCEEDED    5
#define RS_DROP_RATE_LIMIT      6
#define RS_DROP_CONGESTION      7

/* Per-CPU context map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

/* Tail-call program array */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

/* Program chain configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

/* Unified Event Bus */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");

/* Event Type Enumeration */
#define RS_EVENT_RESERVED       0x0000
#define RS_EVENT_PKT_TRACE      0x0001
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_ROUTE_BASE     0x0300
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_QOS_BASE       0x0500
#define RS_EVENT_ERROR_BASE     0xFF00

#define RS_EVENT_MAC_LEARNED    (RS_EVENT_L2_BASE + 1)
#define RS_EVENT_MAC_MOVED      (RS_EVENT_L2_BASE + 2)
#define RS_EVENT_MAC_AGED       (RS_EVENT_L2_BASE + 3)

#define RS_EVENT_ACL_HIT        (RS_EVENT_ACL_BASE + 1)
#define RS_EVENT_ACL_DENY       (RS_EVENT_ACL_BASE + 2)

#define RS_EVENT_PARSE_ERROR    (RS_EVENT_ERROR_BASE + 1)
#define RS_EVENT_MAP_FULL       (RS_EVENT_ERROR_BASE + 2)

/* Helper macros for module development */

#define RS_GET_CTX() ({ \
    __u32 __key = RS_ONLYKEY; \
    bpf_map_lookup_elem(&rs_ctx_map, &__key); \
})

#define RS_TAIL_CALL_NEXT(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        (rs_ctx_ptr)->next_prog_id++; \
        bpf_tail_call((xdp_ctx_ptr), &rs_progs, (rs_ctx_ptr)->next_prog_id); \
    } \
})

#define RS_TAIL_CALL_EGRESS(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        __u32 __current_slot = (rs_ctx_ptr)->next_prog_id; \
        __u32 *__next_slot = bpf_map_lookup_elem(&rs_prog_chain, &__current_slot); \
        if (__next_slot && *__next_slot != 0) { \
            (rs_ctx_ptr)->next_prog_id = *__next_slot; \
            bpf_tail_call((xdp_ctx_ptr), &rs_progs, *__next_slot); \
        } \
    } \
})

#define RS_EMIT_EVENT(event_ptr, event_size) ({ \
    void *__evt = bpf_ringbuf_reserve(&rs_event_bus, (event_size), 0); \
    int __ret = -1; \
    if (__evt) { \
        __builtin_memcpy(__evt, (event_ptr), (event_size)); \
        bpf_ringbuf_submit(__evt, 0); \
        __ret = 0; \
    } \
    __ret; \
})

#endif /* __RSWITCH_UAPI_H */
