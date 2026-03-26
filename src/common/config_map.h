/* SPDX-License-Identifier: MIT */
/*
 * config_map.h - Translate parsed config into BPF map entry payloads.
 *
 * NOTE: jz_config_map_batch_t is intentionally large (~800KB+) because it
 * contains fixed-size arrays for all map entries, including threat blacklist
 * buffers. Allocate jz_config_map_batch_t on the heap (malloc/calloc), not
 * on the stack.
 */

#ifndef JZ_CONFIG_MAP_H
#define JZ_CONFIG_MAP_H

#include <stdint.h>

/* Mirror of jz_common.h constants for user-space translation code. */
#define JZ_GUARD_STATIC           1
#define JZ_GUARD_DYNAMIC          2

#define JZ_ACTION_PASS            0
#define JZ_ACTION_DROP            1
#define JZ_ACTION_REDIRECT        2
#define JZ_ACTION_MIRROR          3
#define JZ_ACTION_REDIRECT_MIRROR 4

#define JZ_BG_PROTO_ARP           1
#define JZ_BG_PROTO_DHCP          2
#define JZ_BG_PROTO_MDNS          3
#define JZ_BG_PROTO_SSDP          4
#define JZ_BG_PROTO_LLDP          5
#define JZ_BG_PROTO_CDP           6
#define JZ_BG_PROTO_STP           7
#define JZ_BG_PROTO_IGMP          8

/*
 * These structs mirror bpf/include/jz_maps.h using standard C integer types.
 * They are kept in user-space to avoid pulling kernel/BPF headers into
 * config translation modules.
 */
struct jz_guard_map_key {
    uint32_t ip_addr;
    uint32_t ifindex;
};

struct jz_guard_entry {
    uint32_t ip_addr;
    uint8_t  fake_mac[6];
    uint8_t  guard_type;
    uint8_t  enabled;
    uint16_t vlan_id;
    uint16_t flags;
    uint64_t created_at;
    uint64_t last_hit;
    uint64_t hit_count;
};

struct jz_whitelist_entry {
    uint32_t ip_addr;
    uint8_t  mac[6];
    uint8_t  match_mac;
    uint8_t  enabled;
    uint64_t created_at;
};

struct jz_arp_config {
    uint8_t  enabled;
    uint8_t  log_all;
    uint16_t rate_limit_pps;
    uint32_t _pad;
};

struct jz_fake_mac {
    uint8_t  mac[6];
    uint8_t  in_use;
    uint8_t  _pad;
    uint32_t assigned_ip;
};

struct jz_icmp_config {
    uint8_t  enabled;
    uint8_t  ttl;
    uint16_t rate_limit_pps;
    uint32_t _pad;
};

struct jz_flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  _pad[3];
};

struct jz_flow_policy {
    uint8_t  action;
    uint8_t  redirect_port;
    uint8_t  mirror_port;
    uint8_t  priority;
    uint32_t flags;
    uint64_t created_at;
    uint64_t hit_count;
    uint64_t byte_count;
};

struct jz_bg_filter_entry {
    uint16_t ethertype;
    uint16_t udp_port;
    uint8_t  capture;
    uint8_t  sample_rate;
    uint8_t  include_payload;
    uint8_t  _pad;
};

struct jz_threat_pattern {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  threat_level;
    uint32_t pattern_id;
    uint8_t  action;
    uint8_t  _pad[3];
    char     description[32];
};

struct jz_sample_config {
    uint8_t  enabled;
    uint8_t  _pad;
    uint16_t max_payload_bytes;
    uint32_t sample_rate;
};

/* Forward declaration (actual definition in config.h). */
typedef struct jz_config jz_config_t;

typedef struct jz_config_map_batch {
    struct {
        struct jz_guard_map_key keys[4096];
        struct jz_guard_entry values[4096];
        int count;
    } static_guards;

    struct {
        uint32_t keys[4096];
        struct jz_whitelist_entry values[4096];
        int count;
    } whitelist;

    struct {
        struct jz_flow_key keys[512];
        struct jz_flow_policy values[512];
        int count;
    } policies;

    struct {
        uint32_t keys[512];
        struct jz_threat_pattern values[512];
        int count;
    } threat_patterns;

    struct {
        uint32_t keys[65536];
        uint64_t values[65536];
        int count;
    } threat_blacklist;

    struct {
        struct jz_fake_mac entries[256];
        int count;
    } fake_macs;

    struct jz_arp_config arp_config;
    struct jz_icmp_config icmp_config;
    struct jz_sample_config sample_config;

    struct {
        uint32_t keys[64];
        struct jz_bg_filter_entry values[64];
        int count;
    } bg_filters;
} jz_config_map_batch_t;

/* Translate config to BPF map entries; returns 0 on success, -1 on error. */
int jz_config_to_maps(const jz_config_t *cfg, jz_config_map_batch_t *batch);

/* Load threat blacklist from file (one IPv4 per line), appending to batch. */
int jz_config_load_blacklist(const char *path, jz_config_map_batch_t *batch);

/* Generate fake MAC pool entries from prefix AA:BB:CC and desired count. */
int jz_config_generate_macs(const char *prefix, int count, jz_config_map_batch_t *batch);

#endif /* JZ_CONFIG_MAP_H */
