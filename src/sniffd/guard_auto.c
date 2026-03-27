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
#include <net/if.h>
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

static int total_subnet_hosts(const jz_guard_auto_t *ga)
{
    int total;
    int i;

    if (!ga)
        return 0;

    total = 0;
    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        if (ga->segments[i].subnet_total <= 0)
            continue;
        if (total > INT_MAX - ga->segments[i].subnet_total)
            return INT_MAX;
        total += ga->segments[i].subnet_total;
    }

    return total;
}

static int total_current_dynamic(const jz_guard_auto_t *ga)
{
    int total;
    int i;

    if (!ga)
        return 0;

    total = 0;
    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        if (ga->segments[i].current_dynamic <= 0)
            continue;
        if (total > INT_MAX - ga->segments[i].current_dynamic)
            return INT_MAX;
        total += ga->segments[i].current_dynamic;
    }

    return total;
}

static int free_ips(const jz_guard_auto_t *ga)
{
    int total_hosts;
    int online;
    int stat;
    int frozen;
    int avail;

    if (!ga)
        return 0;

    total_hosts = total_subnet_hosts(ga);
    if (total_hosts <= 0)
        return 0;

    online = (ga->discovery) ? ga->discovery->device_count : 0;
    stat   = (ga->config) ? ga->config->guards.static_count : 0;
    frozen = (ga->config) ? ga->config->guards.frozen_ip_count : 0;

    avail = total_hosts - online - stat - frozen;
    return (avail > 0) ? avail : 0;
}

static int max_allowed_dynamic_segment(const jz_guard_auto_segment_t *seg)
{
    int64_t by_ratio;

    if (!seg || seg->max_ratio <= 0 || seg->subnet_total <= 0)
        return 0;

    by_ratio = ((int64_t)seg->subnet_total * (int64_t)seg->max_ratio) / 100;

    if (by_ratio <= 0)
        return 0;
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
        unsigned int a;
        unsigned int b;
        unsigned int c;

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

static bool ip_in_segment(const jz_guard_auto_segment_t *seg, uint32_t ip)
{
    if (!seg)
        return false;
    return (ip & seg->subnet_mask) == seg->subnet_addr;
}

static jz_guard_auto_segment_t *find_segment_for_ip(jz_guard_auto_t *ga,
                                                     uint32_t ip,
                                                     uint32_t ifindex)
{
    int i;

    if (!ga)
        return NULL;

    if (ifindex != 0) {
        for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
            if (ga->segments[i].ifindex == ifindex && ip_in_segment(&ga->segments[i], ip))
                return &ga->segments[i];
        }
    }

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        if (ip_in_segment(&ga->segments[i], ip))
            return &ga->segments[i];
    }

    return NULL;
}

static bool is_ip_online(const jz_guard_auto_t *ga,
                         const jz_guard_auto_segment_t *seg,
                         uint32_t ip)
{
    if (!ga || !ga->discovery || !seg)
        return false;

    return jz_discovery_lookup_by_ip((jz_discovery_t *)ga->discovery, ip, seg->ifindex) != NULL;
}

static bool is_ip_existing_dynamic(const jz_guard_auto_t *ga,
                                   const jz_guard_auto_segment_t *seg,
                                   uint32_t ip)
{
    int i;

    if (!ga || !ga->guard_mgr || !seg)
        return false;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        if (ga->guard_mgr->dynamic_entries[i].enabled &&
            ga->guard_mgr->dynamic_entries[i].ifindex == seg->ifindex &&
            ga->guard_mgr->dynamic_entries[i].ip == ip)
            return true;
    }

    return false;
}

static uint32_t subnet_first_host(const jz_guard_auto_segment_t *seg)
{
    uint32_t net_h = ntohl(seg->subnet_addr);

    return htonl(net_h + 1);
}

static uint32_t subnet_last_host(const jz_guard_auto_segment_t *seg)
{
    uint32_t net_h = ntohl(seg->subnet_addr);
    uint32_t mask_h = ntohl(seg->subnet_mask);
    uint32_t bcast_h = net_h | ~mask_h;

    return htonl(bcast_h - 1);
}

static uint32_t next_host_ip(const jz_guard_auto_segment_t *seg, uint32_t ip)
{
    uint32_t ip_h = ntohl(ip);
    uint32_t last_h = ntohl(subnet_last_host(seg));
    uint32_t first_h = ntohl(subnet_first_host(seg));

    ip_h++;
    if (ip_h > last_h)
        ip_h = first_h;
    return htonl(ip_h);
}

static void refresh_segment_host_ips(jz_guard_auto_t *ga)
{
    int i;

    if (!ga)
        return;

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++)
        ga->segments[i].host_ip = 0;

    if (!ga->discovery)
        return;

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        int j;

        for (j = 0; j < ga->discovery->iface_count && j < JZ_DISCOVERY_MAX_IFACES; j++) {
            if ((uint32_t)ga->discovery->ifaces[j].ifindex == ga->segments[i].ifindex) {
                ga->segments[i].host_ip = ga->discovery->ifaces[j].src_ip;
                break;
            }
        }
    }
}

static int parse_monitor_subnets(jz_guard_auto_t *ga, const jz_config_t *cfg)
{
    int i;
    int seg_count;

    if (!ga || !cfg)
        return -1;

    memset(ga->segments, 0, sizeof(ga->segments));
    ga->segment_count = 0;
    seg_count = 0;

    for (i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface;
        jz_guard_auto_segment_t *seg;
        char subnet[JZ_CONFIG_STR_SHORT];
        char *slash;
        struct in_addr addr;
        char *endptr;
        long prefix_long;
        int prefix_len;
        int host_bits;
        uint32_t mask;
        uint64_t total_hosts;
        uint32_t ifindex;

        iface = &cfg->system.interfaces[i];
        if (strcmp(iface->role, "monitor") != 0)
            continue;
        if (iface->name[0] == '\0' || iface->subnet[0] == '\0')
            continue;
        if (seg_count >= JZ_GUARD_AUTO_MAX_SEGMENTS)
            break;

        ifindex = if_nametoindex(iface->name);
        if (ifindex == 0) {
            jz_log_warn("guard_auto skip monitor iface=%s: if_nametoindex failed", iface->name);
            continue;
        }

        memcpy(subnet, iface->subnet, sizeof(subnet));
        subnet[sizeof(subnet) - 1] = '\0';
        slash = strchr(subnet, '/');
        if (!slash) {
            jz_log_warn("guard_auto skip monitor iface=%s: invalid subnet '%s'", iface->name, iface->subnet);
            continue;
        }
        *slash = '\0';

        if (inet_pton(AF_INET, subnet, &addr) != 1) {
            jz_log_warn("guard_auto skip monitor iface=%s: invalid subnet ip '%s'", iface->name, subnet);
            continue;
        }

        prefix_long = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0' || prefix_long < 0 || prefix_long > 32) {
            jz_log_warn("guard_auto skip monitor iface=%s: invalid prefix in '%s'", iface->name, iface->subnet);
            continue;
        }
        prefix_len = (int)prefix_long;

        if (prefix_len == 0)
            mask = 0;
        else
            mask = htonl(~((1u << (32 - prefix_len)) - 1u));

        seg = &ga->segments[seg_count];
        seg->ifindex = ifindex;
        seg->subnet_mask = mask;
        seg->subnet_addr = addr.s_addr & seg->subnet_mask;

        host_bits = 32 - prefix_len;
        if (host_bits <= 1) {
            seg->subnet_total = 0;
        } else {
            total_hosts = (1ULL << host_bits) - 2ULL;
            if (total_hosts > (uint64_t)INT_MAX)
                seg->subnet_total = INT_MAX;
            else
                seg->subnet_total = (int)total_hosts;
        }

        seg->deploy_cursor = 0;
        seg->host_ip = 0;
        seg->current_dynamic = 0;

        seg->auto_discover = (iface->guard_auto_discover != -1)
            ? (iface->guard_auto_discover != 0)
            : cfg->guards.dynamic.auto_discover;
        seg->max_entries = (iface->guard_max_entries != -1)
            ? iface->guard_max_entries
            : cfg->guards.dynamic.max_entries;
        seg->ttl_hours = (iface->guard_ttl_hours != -1)
            ? iface->guard_ttl_hours
            : cfg->guards.dynamic.ttl_hours;
        seg->max_ratio = (iface->guard_max_ratio != -1)
            ? clamp_ratio(iface->guard_max_ratio)
            : clamp_ratio(cfg->guards.max_ratio);

        seg->warmup_ready = false;
        seg->warmup_logged = false;
        seg->created_ns = get_monotonic_ns();
        seg->warmup_mode = (iface->guard_warmup_mode >= 0)
            ? iface->guard_warmup_mode
            : JZ_WARMUP_NORMAL;

        {
            const char *mode_str;
            switch (seg->warmup_mode) {
            case JZ_WARMUP_FAST:  mode_str = "fast"; break;
            case JZ_WARMUP_BURST: mode_str = "burst"; break;
            default:              mode_str = "normal"; break;
            }
            jz_log_info("guard_auto seg ifindex=%u: warmup gate active "
                        "(mode=%s), guards blocked until discovery completes",
                        seg->ifindex, mode_str);
        }

        seg_count++;
    }

    ga->segment_count = seg_count;
    return (seg_count > 0) ? 0 : -1;
}

static bool jz_guard_auto_is_frozen_segment(const jz_guard_auto_t *ga,
                                            const jz_guard_auto_segment_t *seg,
                                            uint32_t ip)
{
    int i;
    uint32_t gateway;

    if (!ga || !ga->config || !seg)
        return false;

    gateway = seg->subnet_addr | htonl(1u);
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

static int jz_guard_auto_deploy_segment(jz_guard_auto_t *ga,
                                        jz_guard_auto_segment_t *seg,
                                        uint32_t ip)
{
    int seg_max;
    int ret;
    char reply[256];
    uint8_t fake_mac[6];

    if (!ga || !seg || !ga->initialized || !ga->guard_mgr)
        return -1;

    if (jz_guard_auto_is_frozen_segment(ga, seg, ip))
        return -1;

    seg_max = max_allowed_dynamic_segment(seg);
    if (seg->current_dynamic >= seg_max) {
        jz_log_warn("guard_auto deploy blocked by segment ratio: ifindex=%u current=%d allowed=%d",
                    seg->ifindex, seg->current_dynamic, seg_max);
        return -1;
    }

    generate_fake_mac(ga, ip, fake_mac);

    ret = jz_guard_mgr_add(ga->guard_mgr, ip, seg->ifindex, fake_mac,
                           JZ_GUARD_DYNAMIC, 0, reply, sizeof(reply));
    if (ret < 0)
        return -1;
    if (strncmp(reply, "guard_add:ok", strlen("guard_add:ok")) != 0)
        return -1;

    seg->current_dynamic++;
    return 0;
}

static void recount_dynamic_by_segment(jz_guard_auto_t *ga)
{
    int i;
    int j;

    if (!ga || !ga->guard_mgr)
        return;

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++)
        ga->segments[i].current_dynamic = 0;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *entry;

        entry = &ga->guard_mgr->dynamic_entries[i];
        if (!entry->enabled || entry->guard_type != JZ_GUARD_DYNAMIC)
            continue;

        for (j = 0; j < ga->segment_count && j < JZ_GUARD_AUTO_MAX_SEGMENTS; j++) {
            if (ga->segments[j].ifindex == entry->ifindex &&
                ip_in_segment(&ga->segments[j], entry->ip)) {
                ga->segments[j].current_dynamic++;
                break;
            }
        }
    }
}

int jz_guard_auto_init(jz_guard_auto_t *ga, jz_guard_mgr_t *gm, const jz_config_t *cfg)
{
    int i;

    if (!ga || !gm || !cfg)
        return -1;

    memset(ga, 0, sizeof(*ga));
    ga->guard_mgr = gm;
    ga->config = cfg;

    if (parse_monitor_subnets(ga, cfg) < 0) {
        jz_log_error("guard_auto init failed: monitor subnet parse error");
        return -1;
    }

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++)
        ga->segments[i].deploy_cursor = subnet_first_host(&ga->segments[i]);

    refresh_segment_host_ips(ga);
    recount_dynamic_by_segment(ga);
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
    int total_deployed;
    int seg_i;
    bool any_enabled;

    if (!ga || !ga->initialized)
        return -1;

    any_enabled = false;
    for (seg_i = 0; seg_i < ga->segment_count && seg_i < JZ_GUARD_AUTO_MAX_SEGMENTS; seg_i++) {
        if (ga->segments[seg_i].auto_discover) {
            any_enabled = true;
            break;
        }
    }
    if (!any_enabled)
        return 0;

    now_ns = get_monotonic_ns();
    interval_ns = (uint64_t)JZ_GUARD_AUTO_EVAL_INTERVAL * 1000000000ULL;
    if (ga->last_eval_ns != 0 && (now_ns - ga->last_eval_ns) < interval_ns)
        return 0;

    ga->last_eval_ns = now_ns;

    refresh_segment_host_ips(ga);
    recount_dynamic_by_segment(ga);

    /* Sweep: evict dynamic guards that now overlap with discovered devices */
    for (seg_i = 0; seg_i < ga->segment_count && seg_i < JZ_GUARD_AUTO_MAX_SEGMENTS; seg_i++) {
        int j;

        for (j = 0; j < JZ_GUARD_MGR_MAX_DYNAMIC; j++) {
            const jz_guard_entry_user_t *entry;

            entry = &ga->guard_mgr->dynamic_entries[j];
            if (!entry->enabled || entry->guard_type != JZ_GUARD_DYNAMIC)
                continue;
            if (entry->ifindex != ga->segments[seg_i].ifindex)
                continue;
            if (!ip_in_segment(&ga->segments[seg_i], entry->ip))
                continue;
            if (is_ip_online(ga, &ga->segments[seg_i], entry->ip))
                jz_guard_auto_evict_ip(ga, entry->ip, entry->ifindex);
        }
    }

    recount_dynamic_by_segment(ga);

    total_deployed = 0;
    for (seg_i = 0; seg_i < ga->segment_count && seg_i < JZ_GUARD_AUTO_MAX_SEGMENTS; seg_i++) {
        jz_guard_auto_segment_t *seg;
        int seg_max;
        int deployed;
        int scanned;

        seg = &ga->segments[seg_i];
        if (!seg->auto_discover || seg->subnet_total <= 0)
            continue;

        if (!seg->warmup_ready) {
            const jz_discovery_iface_t *diface = NULL;

            if (ga->discovery)
                diface = jz_discovery_iface_by_ifindex(ga->discovery, seg->ifindex);

            if (!diface) {
                jz_log_warn("guard_auto seg ifindex=%u: no discovery interface "
                            "(no IP assigned?), blocking guard deployment",
                            seg->ifindex);
                continue;
            }
            if (!diface->first_pass_done) {
                if (!seg->warmup_logged) {
                    jz_log_info("guard_auto seg ifindex=%u: waiting for discovery "
                                "first pass (mode=%d, passes=%d)",
                                seg->ifindex, diface->warmup_mode,
                                diface->scan_pass_count);
                    seg->warmup_logged = true;
                } else {
                    jz_log_debug("guard_auto seg ifindex=%u: still waiting for "
                                 "discovery first pass (mode=%d, passes=%d)",
                                 seg->ifindex, diface->warmup_mode,
                                 diface->scan_pass_count);
                }
                continue;
            }
            seg->warmup_ready = true;
            jz_log_info("guard_auto seg ifindex=%u: warmup complete, "
                        "enabling guard deployment", seg->ifindex);
        }

        seg_max = max_allowed_dynamic_segment(seg);
        if (seg->current_dynamic >= seg_max) {
            jz_log_debug("guard_auto seg ifindex=%u ratio limit: current=%d allowed=%d",
                         seg->ifindex, seg->current_dynamic, seg_max);
            continue;
        }

        if (seg->deploy_cursor == 0)
            seg->deploy_cursor = subnet_first_host(seg);

        deployed = 0;
        scanned = 0;
        while (deployed < JZ_GUARD_AUTO_DEPLOY_BATCH &&
               seg->current_dynamic + deployed < seg_max &&
               scanned < seg->subnet_total) {
            uint32_t ip;

            ip = seg->deploy_cursor;
            seg->deploy_cursor = next_host_ip(seg, ip);
            scanned++;

            if (ip == seg->host_ip)
                continue;
            if (jz_guard_auto_is_frozen_segment(ga, seg, ip))
                continue;
            if (is_ip_online(ga, seg, ip))
                continue;
            if (is_ip_existing_dynamic(ga, seg, ip))
                continue;

            if (jz_guard_auto_deploy_segment(ga, seg, ip) == 0) {
                deployed++;
                total_deployed++;
            }
        }
    }

    if (total_deployed > 0)
        jz_log_info("guard_auto: deployed %d dynamic guards across %d segments",
                    total_deployed, ga->segment_count);

    return total_deployed;
}

bool jz_guard_auto_is_frozen(const jz_guard_auto_t *ga, uint32_t ip)
{
    int i;

    if (!ga)
        return false;

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        if (jz_guard_auto_is_frozen_segment(ga, &ga->segments[i], ip))
            return true;
    }

    return false;
}

int jz_guard_auto_deploy(jz_guard_auto_t *ga, uint32_t ip)
{
    jz_guard_auto_segment_t *seg;

    if (!ga || !ga->initialized || !ga->guard_mgr)
        return -1;

    seg = find_segment_for_ip(ga, ip, 0);
    if (!seg)
        return -1;

    return jz_guard_auto_deploy_segment(ga, seg, ip);
}

int jz_guard_auto_check_conflict(jz_guard_auto_t *ga, uint32_t ip, const uint8_t mac[6])
{
    int i;
    char reply[256];

    if (!ga || !ga->initialized || !ga->guard_mgr || !mac)
        return -1;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *entry;
        jz_guard_auto_segment_t *seg;

        entry = &ga->guard_mgr->dynamic_entries[i];
        if (!entry->enabled)
            continue;
        if (entry->guard_type != JZ_GUARD_DYNAMIC)
            continue;
        if (entry->ip != ip)
            continue;

        seg = find_segment_for_ip(ga, ip, entry->ifindex);
        if (!seg)
            continue;
        if (entry->ifindex != seg->ifindex)
            continue;

        if (memcmp(entry->mac, mac, 6) == 0)
            return 0;

        if (jz_guard_mgr_remove(ga->guard_mgr, ip, entry->ifindex, reply, sizeof(reply)) < 0)
            return -1;
        if (strncmp(reply, "guard_remove:ok", strlen("guard_remove:ok")) != 0)
            return -1;

        if (seg->current_dynamic > 0)
            seg->current_dynamic--;

        {
            struct in_addr addr;
            char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";
            char real_mac[18] = "00:00:00:00:00:00";

            addr.s_addr = ip;
            if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                snprintf(ipbuf, sizeof(ipbuf), "0.0.0.0");
            mac_to_text(mac, real_mac, sizeof(real_mac));
            jz_log_info("guard_auto: conflict detected ip=%s ifindex=%u real_mac=%s — removing dynamic guard",
                        ipbuf, entry->ifindex, real_mac);
        }

        return 1;
    }

    return 0;
}

int jz_guard_auto_evict_ip(jz_guard_auto_t *ga, uint32_t ip, uint32_t ifindex)
{
    int i;
    char reply[256];

    if (!ga || !ga->initialized || !ga->guard_mgr || ip == 0 || ifindex == 0)
        return 0;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *entry;
        jz_guard_auto_segment_t *seg;

        entry = &ga->guard_mgr->dynamic_entries[i];
        if (!entry->enabled)
            continue;
        if (entry->guard_type != JZ_GUARD_DYNAMIC)
            continue;
        if (entry->ip != ip || entry->ifindex != ifindex)
            continue;

        seg = find_segment_for_ip(ga, ip, ifindex);

        if (jz_guard_mgr_remove(ga->guard_mgr, ip, ifindex, reply, sizeof(reply)) < 0)
            return -1;
        if (strncmp(reply, "guard_remove:ok", strlen("guard_remove:ok")) != 0)
            return -1;

        if (seg && seg->current_dynamic > 0)
            seg->current_dynamic--;

        {
            struct in_addr addr;
            char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";

            addr.s_addr = ip;
            if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                snprintf(ipbuf, sizeof(ipbuf), "0.0.0.0");
            jz_log_info("guard_auto: evicted dynamic guard ip=%s ifindex=%u (device discovered)",
                        ipbuf, ifindex);
        }

        return 1;
    }

    return 0;
}

int jz_guard_auto_list_json(const jz_guard_auto_t *ga, char *buf, size_t buf_size)
{
    int n;
    int off;
    int i;
    int frozen_count;
    int online_devices;
    int static_count;
    int free;
    int total_dynamic;
    int total_subnet;
    int total_max_allowed;
    int global_ratio;
    int global_ttl;
    bool global_enabled;

    if (!ga || !buf || buf_size == 0)
        return -1;

    frozen_count = ga->config ? ga->config->guards.frozen_ip_count : 0;
    static_count = ga->config ? ga->config->guards.static_count : 0;
    online_devices = ga->discovery ? ga->discovery->device_count : 0;
    free = free_ips(ga);
    total_dynamic = total_current_dynamic(ga);
    total_subnet = total_subnet_hosts(ga);
    global_ratio = ga->config ? ga->config->guards.max_ratio : 0;
    global_ttl = ga->config ? ga->config->guards.dynamic.ttl_hours : 24;
    global_enabled = ga->config ? ga->config->guards.dynamic.auto_discover : false;

    total_max_allowed = 0;
    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++)
        total_max_allowed += max_allowed_dynamic_segment(&ga->segments[i]);

    off = 0;
    n = snprintf(buf + off, buf_size - (size_t)off,
                 "{\"max_ratio\":%d,\"segment_count\":%d,\"subnet_total\":%d,"
                 "\"max_allowed\":%d,\"current_dynamic\":%d,\"frozen_count\":%d,"
                 "\"static_count\":%d,\"online_devices\":%d,\"free_ips\":%d,"
                 "\"enabled\":%s,\"scan_interval\":%d,\"segments\":[",
                 global_ratio, ga->segment_count, total_subnet,
                 total_max_allowed, total_dynamic, frozen_count,
                 static_count, online_devices, free,
                 global_enabled ? "true" : "false", global_ttl);
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size - (size_t)off)
        return (int)(buf_size - 1);
    off += n;

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++) {
        const jz_guard_auto_segment_t *seg = &ga->segments[i];
        const char *warmup_str;
        int disc_passes = 0;

        if (ga->discovery) {
            const jz_discovery_iface_t *diface;
            diface = jz_discovery_iface_by_ifindex(ga->discovery, seg->ifindex);
            if (diface)
                disc_passes = diface->scan_pass_count;
        }

        switch (seg->warmup_mode) {
        case JZ_WARMUP_FAST:  warmup_str = "fast"; break;
        case JZ_WARMUP_BURST: warmup_str = "burst"; break;
        default:              warmup_str = "normal"; break;
        }

        n = snprintf(buf + off, buf_size - (size_t)off,
                     "%s{\"ifindex\":%u,\"subnet_total\":%d,\"current_dynamic\":%d,"
                     "\"max_allowed\":%d,\"auto_discover\":%s,"
                     "\"max_ratio\":%d,\"max_entries\":%d,\"ttl_hours\":%d,"
                     "\"warmup_ready\":%s,\"warmup_mode\":\"%s\","
                     "\"discovery_passes\":%d}",
                     (i == 0) ? "" : ",",
                     seg->ifindex,
                     seg->subnet_total,
                     seg->current_dynamic,
                     max_allowed_dynamic_segment(seg),
                     seg->auto_discover ? "true" : "false",
                     seg->max_ratio,
                     seg->max_entries,
                     seg->ttl_hours,
                     seg->warmup_ready ? "true" : "false",
                     warmup_str,
                     disc_passes);
        if (n < 0)
            return -1;
        if ((size_t)n >= buf_size - (size_t)off)
            return (int)(buf_size - 1);
        off += n;
    }

    n = snprintf(buf + off, buf_size - (size_t)off, "]}");
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size - (size_t)off)
        return (int)(buf_size - 1);
    off += n;

    return off;
}

void jz_guard_auto_update_config(jz_guard_auto_t *ga, const jz_config_t *cfg)
{
    int i;

    if (!ga || !cfg)
        return;

    ga->config = cfg;
    if (parse_monitor_subnets(ga, cfg) < 0) {
        jz_log_warn("guard_auto config update: monitor subnet parse error");
        return;
    }

    for (i = 0; i < ga->segment_count && i < JZ_GUARD_AUTO_MAX_SEGMENTS; i++)
        ga->segments[i].deploy_cursor = subnet_first_host(&ga->segments[i]);

    refresh_segment_host_ips(ga);
    recount_dynamic_by_segment(ga);
}

void jz_guard_auto_set_discovery(jz_guard_auto_t *ga, const jz_discovery_t *disc)
{
    if (!ga)
        return;

    ga->discovery = disc;
    refresh_segment_host_ips(ga);
}
