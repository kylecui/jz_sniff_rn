/* SPDX-License-Identifier: MIT */

#ifndef JZ_GUARD_AUTO_H
#define JZ_GUARD_AUTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"

typedef struct jz_guard_mgr jz_guard_mgr_t;
typedef struct jz_discovery jz_discovery_t;

#define JZ_GUARD_AUTO_EVAL_INTERVAL  60
#define JZ_GUARD_AUTO_MAX_SEGMENTS  JZ_CONFIG_MAX_INTERFACES

typedef struct jz_guard_auto_segment {
    uint32_t           ifindex;
    uint32_t           subnet_addr;
    uint32_t           subnet_mask;
    int                subnet_total;
    uint32_t           deploy_cursor;
    uint32_t           host_ip;
    int                current_dynamic;

    bool               auto_discover;
    int                max_ratio;
    int                max_entries;
    int                ttl_hours;

    bool               warmup_ready;
    bool               warmup_logged;
    uint64_t           created_ns;
    int                warmup_mode;
} jz_guard_auto_segment_t;

typedef struct jz_guard_auto {
    jz_guard_mgr_t    *guard_mgr;
    const jz_config_t *config;
    const jz_discovery_t *discovery;

    jz_guard_auto_segment_t segments[JZ_GUARD_AUTO_MAX_SEGMENTS];
    int                segment_count;

    uint64_t           last_eval_ns;
    bool               initialized;
} jz_guard_auto_t;

int  jz_guard_auto_init(jz_guard_auto_t *ga, jz_guard_mgr_t *gm, const jz_config_t *cfg);
void jz_guard_auto_destroy(jz_guard_auto_t *ga);
int  jz_guard_auto_tick(jz_guard_auto_t *ga);
bool jz_guard_auto_is_frozen(const jz_guard_auto_t *ga, uint32_t ip);
int  jz_guard_auto_deploy(jz_guard_auto_t *ga, uint32_t ip);
int  jz_guard_auto_check_conflict(jz_guard_auto_t *ga, uint32_t ip, const uint8_t mac[6]);
int  jz_guard_auto_evict_ip(jz_guard_auto_t *ga, uint32_t ip, uint32_t ifindex);
int  jz_guard_auto_list_json(const jz_guard_auto_t *ga, char *buf, size_t buf_size);
void jz_guard_auto_update_config(jz_guard_auto_t *ga, const jz_config_t *cfg);
void jz_guard_auto_set_discovery(jz_guard_auto_t *ga, const jz_discovery_t *disc);

#endif
