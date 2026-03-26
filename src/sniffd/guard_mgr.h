/* SPDX-License-Identifier: MIT */
/*
 * guard_mgr.h - Guard table manager for sniffd.
 *
 * Manages static/dynamic guard entries and whitelist synchronization
 * between user-space configuration/IPC commands and pinned BPF maps.
 */

#ifndef JZ_GUARD_MGR_H
#define JZ_GUARD_MGR_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define JZ_GUARD_STATIC                 1
#define JZ_GUARD_DYNAMIC                2

#define JZ_GUARD_MGR_MAX_DYNAMIC        256
#define JZ_GUARD_MGR_EXPIRY_CHECK_SEC   60

typedef struct jz_guard_entry_user {
    uint32_t ip;
    uint32_t ifindex;         /* 0 = all interfaces */
    uint8_t  mac[6];
    uint8_t  guard_type;      /* JZ_GUARD_STATIC=1, JZ_GUARD_DYNAMIC=2 */
    uint8_t  enabled;
    uint16_t vlan_id;
    uint64_t created_at;      /* monotonic ns */
    uint32_t ttl_sec;         /* 0 = no expiry (static) */
} jz_guard_entry_user_t;

typedef struct jz_guard_mgr {
    int              static_map_fd;    /* fd for jz_static_guards */
    int              dynamic_map_fd;   /* fd for jz_dynamic_guards */
    int              whitelist_map_fd; /* fd for jz_whitelist */
    int              dhcp_exception_map_fd; /* fd for jz_dhcp_exception */

    jz_guard_entry_user_t dynamic_entries[JZ_GUARD_MGR_MAX_DYNAMIC];
    int              dynamic_count;

    uint32_t         default_ttl_sec;  /* from config: dynamic.ttl_hours * 3600 */
    bool             auto_discover;    /* from config */
    int              max_dynamic;      /* from config */

    uint64_t         last_expiry_check_ns;
    bool             initialized;
} jz_guard_mgr_t;

int  jz_guard_mgr_init(jz_guard_mgr_t *gm, const jz_config_t *cfg);
void jz_guard_mgr_destroy(jz_guard_mgr_t *gm);

/* Push all static guards + whitelist from config to BPF maps. Called on init and reload. */
int  jz_guard_mgr_load_config(jz_guard_mgr_t *gm, const jz_config_t *cfg);

/* Periodic tick — check dynamic guard TTL expiry. Call every N seconds from main loop. */
int  jz_guard_mgr_tick(jz_guard_mgr_t *gm);

/* IPC command handlers — return reply string length, or -1 on error */
int  jz_guard_mgr_add(jz_guard_mgr_t *gm, uint32_t ip, uint32_t ifindex,
                      const uint8_t *mac, uint8_t guard_type, uint16_t vlan_id,
                      char *reply, size_t reply_size);
int  jz_guard_mgr_remove(jz_guard_mgr_t *gm, uint32_t ip, uint32_t ifindex,
                         char *reply, size_t reply_size);
int  jz_guard_mgr_list(const jz_guard_mgr_t *gm,
                       char *reply, size_t reply_size);

void jz_guard_mgr_update_config(jz_guard_mgr_t *gm, const jz_config_t *cfg);

#endif /* JZ_GUARD_MGR_H */
