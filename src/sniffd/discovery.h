/* SPDX-License-Identifier: MIT */

#ifndef JZ_DISCOVERY_H
#define JZ_DISCOVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "fingerprint.h"

typedef struct jz_guard_auto jz_guard_auto_t;

#define JZ_DISCOVERY_MAX_DEVICES    4096
#define JZ_DISCOVERY_ARP_INTERVAL   300   /* 300 seconds = 5 minutes */
#define JZ_DISCOVERY_HASH_BUCKETS   256
#define JZ_DISCOVERY_MAX_IFACES     JZ_CONFIG_MAX_INTERFACES

typedef struct jz_discovery_device {
    device_profile_t   profile;
    uint32_t           ifindex;
    struct jz_discovery_device *next;   /* hash chain */
} jz_discovery_device_t;

typedef struct jz_discovery_iface {
    int                    arp_sock;
    int                    dhcp_sock;
    int                    ifindex;
    uint32_t               src_ip;
    uint8_t                src_mac[6];
    uint32_t               scan_subnet;
    uint32_t               scan_mask;
    uint32_t               scan_next_ip;
} jz_discovery_iface_t;

typedef struct jz_discovery {
    jz_discovery_device_t *buckets[JZ_DISCOVERY_HASH_BUCKETS];
    int                    device_count;
    int                    max_devices;

    jz_discovery_iface_t   ifaces[JZ_DISCOVERY_MAX_IFACES];
    int                    iface_count;

    uint64_t               last_arp_scan_ns;
    int                    arp_interval_sec;
    jz_guard_auto_t       *guard_auto;

    /* Active DHCP probing */
    bool                   aggressive_mode;
    uint64_t               last_dhcp_probe_ns;
    int                    dhcp_probe_interval_sec;

    bool                   initialized;
} jz_discovery_t;

int  jz_discovery_init(jz_discovery_t *disc, const jz_config_t *cfg);
void jz_discovery_destroy(jz_discovery_t *disc);
int  jz_discovery_tick(jz_discovery_t *disc);
int  jz_discovery_recv_arp(jz_discovery_t *disc);
int  jz_discovery_feed_event(jz_discovery_t *disc, uint8_t proto,
                             const uint8_t *payload, uint32_t payload_len,
                             uint16_t vlan_id, uint32_t ifindex);
jz_discovery_device_t *jz_discovery_lookup(jz_discovery_t *disc,
                                            const uint8_t mac[6],
                                            uint32_t ifindex);
jz_discovery_device_t *jz_discovery_lookup_by_ip(jz_discovery_t *disc,
                                                  uint32_t ip,
                                                  uint32_t ifindex);
int  jz_discovery_find_dhcp_servers(const jz_discovery_t *disc,
                                    jz_discovery_device_t **out, int max_out);
int  jz_discovery_list_json(const jz_discovery_t *disc, char *buf, size_t buf_size);
int  jz_discovery_list_vlans(const jz_discovery_t *disc, char *buf, size_t buf_size);
void jz_discovery_update_config(jz_discovery_t *disc, const jz_config_t *cfg);

#endif /* JZ_DISCOVERY_H */
