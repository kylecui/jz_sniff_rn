/* SPDX-License-Identifier: MIT */

#ifndef JZ_DISCOVERY_H
#define JZ_DISCOVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "fingerprint.h"

#define JZ_DISCOVERY_MAX_DEVICES    4096
#define JZ_DISCOVERY_ARP_INTERVAL   300   /* 300 seconds = 5 minutes */
#define JZ_DISCOVERY_HASH_BUCKETS   256

typedef struct jz_discovery_device {
    device_profile_t   profile;
    struct jz_discovery_device *next;   /* hash chain */
} jz_discovery_device_t;

typedef struct jz_discovery {
    jz_discovery_device_t *buckets[JZ_DISCOVERY_HASH_BUCKETS];
    int                    device_count;
    int                    max_devices;

    /* Active ARP scanning */
    int                    arp_sock;           /* raw socket for ARP */
    int                    arp_ifindex;        /* interface index */
    uint32_t               arp_src_ip;         /* our IP for ARP source */
    uint8_t                arp_src_mac[6];     /* our MAC for ARP source */
    uint32_t               scan_subnet;        /* network address */
    uint32_t               scan_mask;          /* subnet mask */
    uint32_t               scan_next_ip;       /* next IP to probe */
    uint64_t               last_arp_scan_ns;   /* monotonic timestamp */
    int                    arp_interval_sec;

    bool                   initialized;
} jz_discovery_t;

int  jz_discovery_init(jz_discovery_t *disc, const jz_config_t *cfg);
void jz_discovery_destroy(jz_discovery_t *disc);
int  jz_discovery_tick(jz_discovery_t *disc);
int  jz_discovery_feed_event(jz_discovery_t *disc, uint8_t proto,
                             const uint8_t *payload, uint32_t payload_len);
jz_discovery_device_t *jz_discovery_lookup(jz_discovery_t *disc, const uint8_t mac[6]);
int  jz_discovery_list_json(const jz_discovery_t *disc, char *buf, size_t buf_size);
void jz_discovery_update_config(jz_discovery_t *disc, const jz_config_t *cfg);

#endif /* JZ_DISCOVERY_H */
