/* SPDX-License-Identifier: MIT */

#ifndef JZ_POLICY_AUTO_H
#define JZ_POLICY_AUTO_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

typedef struct jz_policy_mgr jz_policy_mgr_t;

#define JZ_POLICY_AUTO_MAX_TRACKERS 1024
#define JZ_POLICY_AUTO_EVAL_INTERVAL_SEC 10

typedef struct jz_attack_tracker {
    uint32_t src_ip;
    uint32_t hit_count;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    bool policy_created;
    uint32_t policy_id;
    uint8_t current_action;
} jz_attack_tracker_t;

typedef struct jz_policy_auto {
    jz_attack_tracker_t trackers[JZ_POLICY_AUTO_MAX_TRACKERS];
    int tracker_count;
    jz_policy_mgr_t *policy_mgr;

    bool enabled;
    int threshold;
    int window_sec;
    int ttl_sec;
    int max_auto_policies;
    uint8_t default_action;
    bool escalation;

    int auto_policy_count;
    uint64_t last_eval_ns;
    bool initialized;
} jz_policy_auto_t;

int jz_policy_auto_init(jz_policy_auto_t *pa, jz_policy_mgr_t *pm, const jz_config_t *cfg);
void jz_policy_auto_destroy(jz_policy_auto_t *pa);
int jz_policy_auto_tick(jz_policy_auto_t *pa);
void jz_policy_auto_feed_attack(jz_policy_auto_t *pa, uint32_t src_ip, uint32_t guarded_ip, uint8_t protocol);
void jz_policy_auto_update_config(jz_policy_auto_t *pa, const jz_config_t *cfg);

#endif
