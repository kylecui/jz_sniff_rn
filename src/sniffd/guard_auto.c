/* SPDX-License-Identifier: MIT */

#include "guard_auto.h"
#include "guard_mgr.h"
#include "discovery.h"

#if __has_include("log.h")
#include "log.h"
#elif __has_include("../common/log.h")
#include "../common/log.h"
#endif

#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef JZ_GUARD_DYNAMIC
#define JZ_GUARD_DYNAMIC 2
#endif

#define JZ_GUARD_AUTO_DEPLOY_BATCH  32

static uint64_t get_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static int clamp_ratio(int ratio)
{
    if (ratio < 0)
        return 0;
    if (ratio > 100)
        return 100;
    return ratio;
}

static int free_ips(const jz_guard_auto_t *ga)
{
    int online;
    int stat;
    int frozen;
    int avail;

    if (!ga || ga->subnet_total <= 0)
        return 0;

    online = (ga->discovery) ? ga->discovery->device_count : 0;
    stat   = (ga->config) ? ga->config->guards.static_count : 0;
    frozen = (ga->config) ? ga->config->guards.frozen_ip_count : 0;

    avail = ga->subnet_total - online - stat - frozen;
    return (avail > 0) ? avail : 0;
}

static int max_allowed_dynamic(const jz_guard_auto_t *ga)
{
    int64_t by_ratio;
    int available;

    if (!ga || ga->subnet_total <= 0 || ga->max_ratio <= 0)
        return 0;

    available = free_ips(ga);
    by_ratio  = ((int64_t)ga->subnet_total * (int64_t)ga->max_ratio) / 100;

    if (by_ratio <= 0)
        return 0;
    if (by_ratio > (int64_t)available)
        by_ratio = (int64_t)available;
    if (by_ratio > INT_MAX)
        return INT_MAX;
    return (int)by_ratio;
}

static void mac_to_text(const uint8_t mac[6], char *buf, size_t buf_size)
{
    if (!mac || !buf || buf_size == 0)
        return;

    (void)snprintf(buf, buf_size,
                   "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void generate_fake_mac(const jz_guard_auto_t *ga, uint32_t ip, uint8_t mac[6])
{
    uint32_t h;
    uint8_t oui[3] = { 0xaa, 0xbb, 0xcc };

    if (ga && ga->config && ga->config->fake_mac_pool.prefix[0]) {
        unsigned int a, b, c;

        if (sscanf(ga->config->fake_mac_pool.prefix, "%x:%x:%x", &a, &b, &c) == 3) {
            oui[0] = (uint8_t)a;
            oui[1] = (uint8_t)b;
            oui[2] = (uint8_t)c;
        }
    }

    h = ntohl(ip) * 2654435761U;
    mac[0] = oui[0];
    mac[1] = oui[1];
    mac[2] = oui[2];
    mac[3] = (uint8_t)(h >> 16);
    mac[4] = (uint8_t)(h >> 8);
    mac[5] = (uint8_t)(h);
    mac[0] &= 0xFE;
    mac[0] |= 0x02;
}

static bool is_ip_online(const jz_guard_auto_t *ga, uint32_t ip)
{
    int i;

    if (!ga || !ga->discovery)
        return false;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        const jz_discovery_device_t *node = ga->discovery->buckets[i];

        while (node) {
            if (node->profile.ip == ip)
                return true;
            node = node->next;
        }
    }
    return false;
}

static bool is_ip_existing_dynamic(const jz_guard_auto_t *ga, uint32_t ip)
{
    int i;

    if (!ga || !ga->guard_mgr)
        return false;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        if (ga->guard_mgr->dynamic_entries[i].enabled &&
            ga->guard_mgr->dynamic_entries[i].ip == ip)
            return true;
    }
    return false;
}

static uint32_t subnet_first_host(const jz_guard_auto_t *ga)
{
    uint32_t net_h = ntohl(ga->subnet_addr);

    return htonl(net_h + 1);
}

static uint32_t subnet_last_host(const jz_guard_auto_t *ga)
{
    uint32_t net_h = ntohl(ga->subnet_addr);
    uint32_t mask_h = ntohl(ga->subnet_mask);
    uint32_t bcast_h = net_h | ~mask_h;

    return htonl(bcast_h - 1);
}

static uint32_t next_host_ip(const jz_guard_auto_t *ga, uint32_t ip)
{
    uint32_t ip_h = ntohl(ip);
    uint32_t last_h = ntohl(subnet_last_host(ga));
    uint32_t first_h = ntohl(subnet_first_host(ga));

    ip_h++;
    if (ip_h > last_h)
        ip_h = first_h;
    return htonl(ip_h);
}

static int parse_monitor_subnet(jz_guard_auto_t *ga, const jz_config_t *cfg)
{
    int i;

    if (!ga || !cfg)
        return -1;

    ga->subnet_addr = 0;
    ga->subnet_mask = 0;
    ga->subnet_total = 0;

    for (i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface;
        char subnet[sizeof(iface->subnet)];
        char *slash;
        struct in_addr addr;
        char *endptr;
        long prefix_long;
        int prefix_len;
        int host_bits;
        uint32_t mask;
        uint64_t total_hosts;

        iface = &cfg->system.interfaces[i];
        if (strcmp(iface->role, "monitor") != 0)
            continue;

        memcpy(subnet, iface->subnet, sizeof(subnet));
        subnet[sizeof(subnet) - 1] = '\0';
        slash = strchr(subnet, '/');
        if (!slash)
            return -1;
        *slash = '\0';

        if (inet_pton(AF_INET, subnet, &addr) != 1)
            return -1;

        prefix_long = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0' || prefix_long < 0 || prefix_long > 32)
            return -1;
        prefix_len = (int)prefix_long;

        if (prefix_len == 0) {
            mask = 0;
        } else {
            mask = htonl(~((1u << (32 - prefix_len)) - 1u));
        }

        ga->subnet_mask = mask;
        ga->subnet_addr = addr.s_addr & ga->subnet_mask;

        host_bits = 32 - prefix_len;
        if (host_bits <= 1) {
            ga->subnet_total = 0;
        } else {
            total_hosts = (1ULL << host_bits) - 2ULL;
            if (total_hosts > (uint64_t)INT_MAX)
                ga->subnet_total = INT_MAX;
            else
                ga->subnet_total = (int)total_hosts;
        }

        return 0;
    }

    return -1;
}

int jz_guard_auto_init(jz_guard_auto_t *ga, jz_guard_mgr_t *gm, const jz_config_t *cfg)
{
    if (!ga || !gm || !cfg)
        return -1;

    memset(ga, 0, sizeof(*ga));
    ga->guard_mgr = gm;
    ga->config = cfg;
    ga->max_ratio = clamp_ratio(cfg->guards.max_ratio);
    ga->current_dynamic = 0;

    if (parse_monitor_subnet(ga, cfg) < 0) {
        jz_log_error("guard_auto init failed: monitor subnet parse error");
        return -1;
    }

    ga->deploy_cursor = subnet_first_host(ga);
    ga->initialized = true;
    return 0;
}

void jz_guard_auto_destroy(jz_guard_auto_t *ga)
{
    if (!ga)
        return;

    memset(ga, 0, sizeof(*ga));
}

int jz_guard_auto_tick(jz_guard_auto_t *ga)
{
    uint64_t now_ns;
    uint64_t interval_ns;
    int max_allowed;
    int deployed;
    int scanned;

    if (!ga || !ga->initialized)
        return -1;

    if (!ga->config || !ga->config->guards.dynamic.auto_discover)
        return 0;

    now_ns = get_monotonic_ns();
    interval_ns = (uint64_t)JZ_GUARD_AUTO_EVAL_INTERVAL * 1000000000ULL;
    if (ga->last_eval_ns != 0 && (now_ns - ga->last_eval_ns) < interval_ns)
        return 0;

    ga->last_eval_ns = now_ns;

    if (ga->discovery && ga->discovery->arp_src_ip != 0)
        ga->host_ip = ga->discovery->arp_src_ip;

    max_allowed = max_allowed_dynamic(ga);
    if (ga->current_dynamic >= max_allowed) {
        jz_log_debug("guard_auto ratio limit hit: current=%d allowed=%d",
                     ga->current_dynamic, max_allowed);
        return 0;
    }

    if (ga->deploy_cursor == 0)
        ga->deploy_cursor = subnet_first_host(ga);

    deployed = 0;
    scanned = 0;

    while (deployed < JZ_GUARD_AUTO_DEPLOY_BATCH &&
           ga->current_dynamic < max_allowed &&
           scanned < ga->subnet_total) {

        uint32_t ip = ga->deploy_cursor;

        ga->deploy_cursor = next_host_ip(ga, ip);
        scanned++;

        if (ip == ga->host_ip)
            continue;
        if (jz_guard_auto_is_frozen(ga, ip))
            continue;
        if (is_ip_online(ga, ip))
            continue;
        if (is_ip_existing_dynamic(ga, ip))
            continue;

        if (jz_guard_auto_deploy(ga, ip) == 0)
            deployed++;
    }

    if (deployed > 0)
        jz_log_info("guard_auto: deployed %d dynamic guards (total=%d, max=%d)",
                    deployed, ga->current_dynamic, max_allowed);

    return deployed;
}

bool jz_guard_auto_is_frozen(const jz_guard_auto_t *ga, uint32_t ip)
{
    int i;
    uint32_t gateway;

    if (!ga || !ga->config)
        return false;

    gateway = ga->subnet_addr | htonl(1u);
    if (ip == gateway)
        return true;

    for (i = 0; i < ga->config->guards.frozen_ip_count && i < JZ_CONFIG_MAX_FROZEN_IPS; i++) {
        struct in_addr addr;

        if (inet_pton(AF_INET, ga->config->guards.frozen_ips[i].ip, &addr) != 1)
            continue;
        if (addr.s_addr == ip)
            return true;
    }

    return false;
}

int jz_guard_auto_deploy(jz_guard_auto_t *ga, uint32_t ip)
{
    int max_allowed;
    int ret;
    char reply[256];
    uint8_t fake_mac[6];

    if (!ga || !ga->initialized || !ga->guard_mgr)
        return -1;

    if (jz_guard_auto_is_frozen(ga, ip))
        return -1;

    max_allowed = max_allowed_dynamic(ga);
    if (ga->current_dynamic >= max_allowed) {
        jz_log_warn("guard_auto deploy blocked by ratio: current=%d allowed=%d",
                     ga->current_dynamic, max_allowed);
        return -1;
    }

    generate_fake_mac(ga, ip, fake_mac);

    ret = jz_guard_mgr_add(ga->guard_mgr, ip, fake_mac, JZ_GUARD_DYNAMIC, 0,
                           reply, sizeof(reply));
    if (ret < 0)
        return -1;
    if (strncmp(reply, "guard_add:ok", strlen("guard_add:ok")) != 0)
        return -1;

    ga->current_dynamic++;
    return 0;
}

int jz_guard_auto_check_conflict(jz_guard_auto_t *ga, uint32_t ip, const uint8_t mac[6])
{
    int i;
    char reply[256];

    if (!ga || !ga->initialized || !ga->guard_mgr || !mac)
        return -1;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *entry;

        entry = &ga->guard_mgr->dynamic_entries[i];
        if (!entry->enabled)
            continue;
        if (entry->guard_type != JZ_GUARD_DYNAMIC)
            continue;
        if (entry->ip != ip)
            continue;

        if (memcmp(entry->mac, mac, 6) == 0)
            return 0;

        if (jz_guard_mgr_remove(ga->guard_mgr, ip, reply, sizeof(reply)) < 0)
            return -1;
        if (strncmp(reply, "guard_remove:ok", strlen("guard_remove:ok")) != 0)
            return -1;

        if (ga->current_dynamic > 0)
            ga->current_dynamic--;

        {
            struct in_addr addr;
            char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";
            char real_mac[18] = "00:00:00:00:00:00";

            addr.s_addr = ip;
            if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                snprintf(ipbuf, sizeof(ipbuf), "0.0.0.0");
            mac_to_text(mac, real_mac, sizeof(real_mac));
            jz_log_info("guard_auto: conflict detected ip=%s real_mac=%s — removing dynamic guard",
                        ipbuf, real_mac);
        }

        return 1;
    }

    return 0;
}

int jz_guard_auto_list_json(const jz_guard_auto_t *ga, char *buf, size_t buf_size)
{
    int n;
    int max_allowed;
    int frozen_count;
    int online_devices;
    int static_count;
    int free;

    if (!ga || !buf || buf_size == 0)
        return -1;

    max_allowed    = max_allowed_dynamic(ga);
    frozen_count   = ga->config ? ga->config->guards.frozen_ip_count : 0;
    static_count   = ga->config ? ga->config->guards.static_count : 0;
    online_devices = ga->discovery ? ga->discovery->device_count : 0;
    free           = free_ips(ga);

    n = snprintf(buf, buf_size,
                 "{\"max_ratio\":%d,\"subnet_total\":%d,\"max_allowed\":%d,"
                 "\"current_dynamic\":%d,\"frozen_count\":%d,"
                 "\"static_count\":%d,\"online_devices\":%d,\"free_ips\":%d,"
                 "\"enabled\":%s,\"scan_interval\":%d}",
                 ga->max_ratio, ga->subnet_total, max_allowed,
                 ga->current_dynamic, frozen_count,
                 static_count, online_devices, free,
                 (ga->config && ga->config->guards.dynamic.auto_discover) ? "true" : "false",
                 ga->config ? ga->config->guards.dynamic.ttl_hours : 24);
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size)
        return (int)(buf_size - 1);
    return n;
}

void jz_guard_auto_update_config(jz_guard_auto_t *ga, const jz_config_t *cfg)
{
    if (!ga || !cfg)
        return;

    ga->config = cfg;
    ga->max_ratio = clamp_ratio(cfg->guards.max_ratio);
    if (parse_monitor_subnet(ga, cfg) < 0)
        jz_log_warn("guard_auto config update: monitor subnet parse error");

}

void jz_guard_auto_set_discovery(jz_guard_auto_t *ga, const jz_discovery_t *disc)
{
    if (!ga)
        return;
    ga->discovery = disc;
    if (disc && disc->arp_src_ip != 0)
        ga->host_ip = disc->arp_src_ip;
}
