/* SPDX-License-Identifier: MIT */
/*
 * probe_gen.h - ARP probe generator for sniffd.
 *
 * Periodically sends ARP probes to non-existent IPs on the local subnet.
 * Probe targets are tracked in user space and mirrored to jz_probe_targets
 * BPF map so sniffer_detect can flag promiscuous-mode responders.
 */

#ifndef JZ_PROBE_GEN_H
#define JZ_PROBE_GEN_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define JZ_PROBE_MAX_TARGETS              64
#define JZ_PROBE_DEFAULT_INTERVAL_SEC     30
#define JZ_PROBE_DEFAULT_COUNT            4
#define JZ_PROBE_EXPIRY_SEC               120

typedef struct jz_probe_gen {
    int              timerfd;          /* timerfd for periodic probing */
    int              raw_sock;         /* AF_PACKET raw socket for sending ARP */
    int              bpf_map_fd;       /* fd for jz_probe_targets pinned map */
    int              ifindex;          /* interface to send probes on */
    uint32_t         local_ip;         /* our IP on the interface */
    uint32_t         netmask;          /* subnet mask */
    uint8_t          local_mac[6];     /* our MAC address */

    struct {
        uint32_t     ip;               /* non-existent IP we probed */
        uint64_t     sent_ns;          /* monotonic timestamp when sent */
        bool         active;           /* is this slot in use */
    } targets[JZ_PROBE_MAX_TARGETS];
    int              target_count;

    int              interval_sec;     /* probe interval from config */
    int              probe_count;      /* how many probes per cycle */
    bool             initialized;
} jz_probe_gen_t;

int  jz_probe_gen_init(jz_probe_gen_t *pg, const jz_config_t *cfg, int ifindex);
void jz_probe_gen_destroy(jz_probe_gen_t *pg);
int  jz_probe_gen_tick(jz_probe_gen_t *pg);  /* called from main loop when timerfd fires */
void jz_probe_gen_update_config(jz_probe_gen_t *pg, const jz_config_t *cfg);

#endif /* JZ_PROBE_GEN_H */
