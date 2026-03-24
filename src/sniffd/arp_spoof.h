/* SPDX-License-Identifier: MIT */
#ifndef JZ_ARP_SPOOF_H
#define JZ_ARP_SPOOF_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define JZ_ARP_SPOOF_MAX_TARGETS  JZ_CONFIG_MAX_ARP_SPOOF_TARGETS

typedef struct jz_arp_spoof_target {
    uint32_t target_ip;
    uint32_t gateway_ip;
    uint8_t  target_mac[6];
    uint8_t  gateway_mac[6];
    bool     resolved;
} jz_arp_spoof_target_t;

typedef struct jz_arp_spoof {
    int              timerfd;
    int              raw_sock;
    int              ifindex;
    uint32_t         local_ip;
    uint8_t          local_mac[6];
    int              interval_sec;
    bool             enabled;
    bool             initialized;

    jz_arp_spoof_target_t targets[JZ_ARP_SPOOF_MAX_TARGETS];
    int              target_count;
} jz_arp_spoof_t;

int  jz_arp_spoof_init(jz_arp_spoof_t *as, const jz_config_t *cfg, int ifindex);
void jz_arp_spoof_destroy(jz_arp_spoof_t *as);
int  jz_arp_spoof_tick(jz_arp_spoof_t *as);
void jz_arp_spoof_update_config(jz_arp_spoof_t *as, const jz_config_t *cfg);
int  jz_arp_spoof_start(jz_arp_spoof_t *as);
int  jz_arp_spoof_stop(jz_arp_spoof_t *as);

#endif /* JZ_ARP_SPOOF_H */
