/* SPDX-License-Identifier: MIT */
/* heartbeat.h — Periodic heartbeat data assembly for sniffd. */

#ifndef JZ_HEARTBEAT_H
#define JZ_HEARTBEAT_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "bpf_loader.h"
#include "guard_mgr.h"
#include "discovery.h"

/* Heartbeat context — references to sniffd subsystems. */
typedef struct jz_heartbeat {
    const jz_config_t      *config;
    const jz_bpf_loader_t  *loader;
    const jz_guard_mgr_t   *guard_mgr;
    const jz_discovery_t   *discovery;

    int      interval_sec;         /* from config: log.heartbeat_interval_sec */
    uint64_t last_tick_sec;        /* last heartbeat epoch (CLOCK_REALTIME) */
    uint64_t daemon_start_epoch;   /* epoch when daemon started */

    bool     initialized;
} jz_heartbeat_t;

/* Initialize heartbeat module. Returns 0 on success. */
int jz_heartbeat_init(jz_heartbeat_t *hb, const jz_config_t *cfg,
                      const jz_bpf_loader_t *loader,
                      const jz_guard_mgr_t *guard_mgr,
                      const jz_discovery_t *discovery);

/* Periodic tick — returns a malloc'd JSON string if heartbeat is due,
 * or NULL if not yet time. Caller must free() the returned string.
 * The returned string is the V2 "data" object (not the full envelope). */
char *jz_heartbeat_tick(jz_heartbeat_t *hb);

/* Update config on reload. */
void jz_heartbeat_update_config(jz_heartbeat_t *hb, const jz_config_t *cfg);

/* Destroy heartbeat module. */
void jz_heartbeat_destroy(jz_heartbeat_t *hb);

#endif /* JZ_HEARTBEAT_H */
