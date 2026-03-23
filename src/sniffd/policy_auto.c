/* SPDX-License-Identifier: MIT */

#include "policy_auto.h"
#include "policy_mgr.h"
#include "log.h"
#include "config_map.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>

static uint64_t get_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static bool ip_to_text(uint32_t ip_be, char *buf, size_t buf_len)
{
    struct in_addr addr;

    if (!buf || buf_len == 0)
        return false;

    addr.s_addr = ip_be;
    return inet_ntop(AF_INET, &addr, buf, (socklen_t)buf_len) != NULL;
}

static jz_attack_tracker_t *find_tracker(jz_policy_auto_t *pa, uint32_t src_ip)
{
    int i;

    if (!pa)
        return NULL;

    for (i = 0; i < JZ_POLICY_AUTO_MAX_TRACKERS; i++) {
        if (pa->trackers[i].first_seen_ns == 0)
            continue;
        if (pa->trackers[i].src_ip == src_ip)
            return &pa->trackers[i];
    }

    return NULL;
}

static jz_attack_tracker_t *add_tracker(jz_policy_auto_t *pa, uint32_t src_ip, uint64_t now_ns)
{
    int i;
    int empty_idx = -1;
    int oldest_idx = -1;
    uint64_t oldest_ns = UINT64_MAX;

    if (!pa)
        return NULL;

    for (i = 0; i < JZ_POLICY_AUTO_MAX_TRACKERS; i++) {
        if (pa->trackers[i].first_seen_ns == 0) {
            empty_idx = i;
            break;
        }
        if (pa->trackers[i].first_seen_ns < oldest_ns) {
            oldest_ns = pa->trackers[i].first_seen_ns;
            oldest_idx = i;
        }
    }

    if (empty_idx >= 0) {
        jz_attack_tracker_t *tracker = &pa->trackers[empty_idx];

        memset(tracker, 0, sizeof(*tracker));
        tracker->src_ip = src_ip;
        tracker->first_seen_ns = now_ns;
        tracker->last_seen_ns = now_ns;
        pa->tracker_count++;
        return tracker;
    }

    if (oldest_idx >= 0) {
        jz_attack_tracker_t *tracker = &pa->trackers[oldest_idx];

        memset(tracker, 0, sizeof(*tracker));
        tracker->src_ip = src_ip;
        tracker->first_seen_ns = now_ns;
        tracker->last_seen_ns = now_ns;
        return tracker;
    }

    return NULL;
}

static void expire_trackers(jz_policy_auto_t *pa, uint64_t now_ns)
{
    int i;
    uint64_t window_ns;

    if (!pa || pa->window_sec <= 0)
        return;

    window_ns = (uint64_t)pa->window_sec * 1000000000ULL;

    for (i = 0; i < JZ_POLICY_AUTO_MAX_TRACKERS; i++) {
        jz_attack_tracker_t *tracker = &pa->trackers[i];

        if (tracker->first_seen_ns == 0)
            continue;
        if (tracker->policy_created)
            continue;
        if ((now_ns - tracker->first_seen_ns) <= window_ns)
            continue;
        if (tracker->hit_count >= (uint32_t)pa->threshold)
            continue;

        memset(tracker, 0, sizeof(*tracker));
        if (pa->tracker_count > 0)
            pa->tracker_count--;
    }
}

static int escalate_tracker_policy(jz_policy_auto_t *pa, jz_attack_tracker_t *tracker)
{
    jz_policy_entry_user_t update_entry;
    char ip_text[INET_ADDRSTRLEN];
    int rc;

    if (!pa || !tracker)
        return -1;

    if (tracker->current_action != JZ_ACTION_REDIRECT)
        return 0;

    memset(&update_entry, 0, sizeof(update_entry));
    update_entry.action = JZ_ACTION_REDIRECT_MIRROR;
    update_entry.ttl_sec = (uint32_t)pa->ttl_sec;
    update_entry.is_auto = true;

    rc = jz_policy_mgr_update(pa->policy_mgr, tracker->policy_id, &update_entry);
    if (rc != 0) {
        if (!ip_to_text(tracker->src_ip, ip_text, sizeof(ip_text)))
            (void)snprintf(ip_text, sizeof(ip_text), "?");
        jz_log_warn("policy_auto: escalation failed for attacker %s (policy_id=%u)",
                    ip_text, tracker->policy_id);
        return -1;
    }

    tracker->current_action = JZ_ACTION_REDIRECT_MIRROR;
    if (!ip_to_text(tracker->src_ip, ip_text, sizeof(ip_text)))
        (void)snprintf(ip_text, sizeof(ip_text), "?");
    jz_log_info("policy_auto: escalated policy for attacker %s to redirect+mirror", ip_text);
    return 1;
}

int jz_policy_auto_init(jz_policy_auto_t *pa, jz_policy_mgr_t *pm, const jz_config_t *cfg)
{
    if (!pa || !pm)
        return -1;

    memset(pa, 0, sizeof(*pa));
    pa->policy_mgr = pm;
    jz_policy_auto_update_config(pa, cfg);
    pa->last_eval_ns = get_monotonic_ns();
    pa->initialized = true;
    return 0;
}

void jz_policy_auto_destroy(jz_policy_auto_t *pa)
{
    if (!pa)
        return;

    memset(pa, 0, sizeof(*pa));
}

void jz_policy_auto_feed_attack(jz_policy_auto_t *pa, uint32_t src_ip,
                                uint32_t guarded_ip, uint8_t protocol)
{
    uint64_t now_ns;
    jz_attack_tracker_t *tracker;
    jz_policy_entry_user_t entry;
    char ip_text[INET_ADDRSTRLEN];
    int policy_id;

    (void)guarded_ip;
    (void)protocol;

    if (!pa || !pa->initialized || !pa->enabled)
        return;

    now_ns = get_monotonic_ns();
    tracker = find_tracker(pa, src_ip);
    if (!tracker) {
        tracker = add_tracker(pa, src_ip, now_ns);
        if (!tracker)
            return;
    }

    tracker->hit_count++;
    tracker->last_seen_ns = now_ns;

    if (tracker->policy_created)
        return;
    if (tracker->hit_count != (uint32_t)pa->threshold)
        return;
    if (pa->auto_policy_count >= pa->max_auto_policies) {
        jz_log_warn("policy_auto: auto policy cap reached (%d)", pa->max_auto_policies);
        return;
    }

    memset(&entry, 0, sizeof(entry));
    if (!ip_to_text(src_ip, ip_text, sizeof(ip_text)))
        (void)snprintf(ip_text, sizeof(ip_text), "?");
    (void)snprintf(entry.name, sizeof(entry.name), "auto:%s", ip_text);

    entry.src_ip = src_ip;
    entry.action = pa->default_action;
    entry.is_auto = true;
    entry.ttl_sec = (uint32_t)pa->ttl_sec;

    policy_id = jz_policy_mgr_add(pa->policy_mgr, &entry);
    if (policy_id < 0) {
        jz_log_warn("policy_auto: failed to create policy for attacker %s", ip_text);
        return;
    }

    tracker->policy_created = true;
    tracker->policy_id = (uint32_t)policy_id;
    tracker->current_action = entry.action;
    pa->auto_policy_count++;

    jz_log_info("policy_auto: created %s policy for attacker %s (hits=%u)",
                (entry.action == JZ_ACTION_REDIRECT_MIRROR) ? "redirect+mirror" : "redirect",
                ip_text, tracker->hit_count);
}

int jz_policy_auto_tick(jz_policy_auto_t *pa)
{
    uint64_t now_ns;
    uint64_t eval_interval_ns;
    int i;
    int actions_taken = 0;

    if (!pa || !pa->initialized)
        return -1;

    now_ns = get_monotonic_ns();
    eval_interval_ns = (uint64_t)JZ_POLICY_AUTO_EVAL_INTERVAL_SEC * 1000000000ULL;

    if (pa->last_eval_ns != 0 && (now_ns - pa->last_eval_ns) < eval_interval_ns)
        return 0;

    pa->last_eval_ns = now_ns;
    expire_trackers(pa, now_ns);

    if (!pa->escalation)
        return 0;

    for (i = 0; i < JZ_POLICY_AUTO_MAX_TRACKERS; i++) {
        jz_attack_tracker_t *tracker = &pa->trackers[i];
        int rc;

        if (!tracker->policy_created)
            continue;
        if (tracker->current_action != JZ_ACTION_REDIRECT)
            continue;
        if (tracker->hit_count < (uint32_t)(pa->threshold * 2))
            continue;

        rc = escalate_tracker_policy(pa, tracker);
        if (rc > 0)
            actions_taken += rc;
    }

    return actions_taken;
}

void jz_policy_auto_update_config(jz_policy_auto_t *pa, const jz_config_t *cfg)
{
    if (!pa)
        return;

    if (cfg) {
        pa->enabled = cfg->policy_auto.enabled;
        pa->threshold = cfg->policy_auto.threshold;
        pa->window_sec = cfg->policy_auto.window_sec;
        pa->ttl_sec = cfg->policy_auto.ttl_sec;
        pa->max_auto_policies = cfg->policy_auto.max_auto_policies;
        pa->escalation = cfg->policy_auto.escalation;

        if (strcasecmp(cfg->policy_auto.default_action, "drop") == 0)
            pa->default_action = JZ_ACTION_DROP;
        else if (strcasecmp(cfg->policy_auto.default_action, "redirect_mirror") == 0 ||
                 strcasecmp(cfg->policy_auto.default_action, "redirect-mirror") == 0)
            pa->default_action = JZ_ACTION_REDIRECT_MIRROR;
        else if (strcasecmp(cfg->policy_auto.default_action, "mirror") == 0)
            pa->default_action = JZ_ACTION_MIRROR;
        else
            pa->default_action = JZ_ACTION_REDIRECT;
    } else {
        pa->enabled = true;
        pa->threshold = 5;
        pa->window_sec = 300;
        pa->ttl_sec = 3600;
        pa->max_auto_policies = 256;
        pa->default_action = JZ_ACTION_REDIRECT;
        pa->escalation = true;
    }

    if (pa->threshold <= 0)
        pa->threshold = 5;
    if (pa->window_sec <= 0)
        pa->window_sec = 300;
    if (pa->ttl_sec <= 0)
        pa->ttl_sec = 3600;
    if (pa->max_auto_policies <= 0)
        pa->max_auto_policies = 256;
}
