/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __RSWITCH_BPF_H
#define __RSWITCH_BPF_H

/*
 * rSwitch BPF Common Header with CO-RE Support
 * 
 * This header provides unified kernel type definitions using vmlinux.h
 * for Compile Once - Run Everywhere (CO-RE) compatibility.
 */

/* Core kernel types from vmlinux.h (CO-RE) */
#include "vmlinux.h"

/* libbpf helpers and macros */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

/* rSwitch shared map definitions
 * NOTE: Path adjusted for flat include/rswitch/ layout.
 * Original rSwitch repo uses "../core/map_defs.h" from bpf/include/.
 */
#include "map_defs.h"
#include "module_abi.h"

#ifndef RS_API_STABLE
#define RS_API_STABLE
#endif

#ifndef RS_API_EXPERIMENTAL
#define RS_API_EXPERIMENTAL
#endif

#ifndef RS_API_INTERNAL
#define RS_API_INTERNAL
#endif

#ifndef RS_DEPRECATED
#define RS_DEPRECATED(msg) __attribute__((deprecated(msg)))
#endif

/* Common network protocol constants not in vmlinux.h */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP   0x0806
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* XDP action return codes */
#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

/* Common BPF map flags */
#ifndef BPF_ANY
#define BPF_ANY     0
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

#ifndef BPF_EXIST
#define BPF_EXIST   2
#endif

/* CO-RE Helper Macros */
#define READ_KERN(dst, src) bpf_core_read(&(dst), sizeof(dst), &(src))
#define FIELD_EXISTS(type, field) bpf_core_field_exists(((type *)0)->field)
#define FIELD_SIZE(type, field) bpf_core_field_size(((type *)0)->field)

/* Bounds check for packet data access */
#define CHECK_BOUNDS(ctx, ptr, size) \
    ((void *)(ptr) + (size) <= (void *)(long)(ctx)->data_end)

/* Safe packet header access */
#define GET_HEADER(ctx, ptr, type) \
    ({ \
        type *_h = (type *)(ptr); \
        if (!CHECK_BOUNDS(ctx, _h, sizeof(type))) \
            _h = NULL; \
        _h; \
    })

/* Debug Macros */
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
    bpf_printk("[rSwitch] " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) do { } while (0)
#endif

/* Compiler Hints for BPF Verifier */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

/* BPF Map Pin Path */
#define BPF_PIN_PATH "/sys/fs/bpf"

/* Common Network Structure Helpers */

static __always_inline struct ethhdr *
get_ethhdr(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return NULL;
    
    return eth;
}

static __always_inline struct iphdr *
get_iphdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = l3_offset;
    
    if ((void *)(iph + 1) > data_end)
        return NULL;
    
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return NULL;
    
    return iph;
}

static __always_inline struct ipv6hdr *
get_ipv6hdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = l3_offset;
    
    if ((void *)(ip6h + 1) > data_end)
        return NULL;
    
    return ip6h;
}

static __always_inline struct tcphdr *
get_tcphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcph = l4_offset;
    
    if ((void *)(tcph + 1) > data_end)
        return NULL;
    
    if ((void *)tcph + (tcph->doff * 4) > data_end)
        return NULL;
    
    return tcph;
}

static __always_inline struct udphdr *
get_udphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct udphdr *udph = l4_offset;
    
    if ((void *)(udph + 1) > data_end)
        return NULL;
    
    return udph;
}

/* Module config helper */
static __always_inline struct rs_module_config_value *
rs_get_module_config(const char *module_name, const char *param_name)
{
    struct rs_module_config_key key = {};

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = module_name[i];
        key.module_name[i] = c;
        if (c == '\0')
            break;
    }

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = param_name[i];
        key.param_name[i] = c;
        if (c == '\0')
            break;
    }

    return bpf_map_lookup_elem(&rs_module_config_map, &key);
}

/* Module stats helpers */
RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_update(__u32 module_idx, __u64 bytes, int forwarded)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_processed, 1);
    __sync_fetch_and_add(&stats->bytes_processed, bytes);
    if (forwarded)
        __sync_fetch_and_add(&stats->packets_forwarded, 1);
    else
        __sync_fetch_and_add(&stats->packets_dropped, 1);
    stats->last_seen_ns = bpf_ktime_get_ns();
}

RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_error(__u32 module_idx)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_error, 1);
}

#endif /* __RSWITCH_BPF_H */
