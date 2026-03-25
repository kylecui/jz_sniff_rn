/* SPDX-License-Identifier: MIT */
/*
 * guard_mgr.c - Guard table manager for sniffd.
 *
 * Populates guard-related BPF maps from config, handles runtime guard
 * add/remove/list operations, and expires dynamic guards by TTL.
 */

#include "guard_mgr.h"
#include "log.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>

/* ── Pin Paths ────────────────────────────────────────────────── */

#define BPF_PIN_STATIC_GUARDS   "/sys/fs/bpf/jz/jz_static_guards"
#define BPF_PIN_DYNAMIC_GUARDS  "/sys/fs/bpf/jz/jz_dynamic_guards"
#define BPF_PIN_WHITELIST       "/sys/fs/bpf/jz/jz_whitelist"
#define BPF_PIN_DHCP_EXCEPTION  "/sys/fs/bpf/jz/jz_dhcp_exception"

/* ── BPF Value Mirrors ────────────────────────────────────────── */

struct bpf_guard_entry {
    uint32_t ip_addr;
    uint8_t  fake_mac[6];
    uint8_t  guard_type;
    uint8_t  enabled;
    uint16_t vlan_id;
    uint16_t flags;
    uint64_t created_at;
    uint64_t last_hit;
    uint64_t hit_count;
};

struct bpf_whitelist_entry {
    uint32_t ip_addr;
    uint8_t  mac[6];
    uint8_t  match_mac;
    uint8_t  enabled;
    uint64_t created_at;
};

struct bpf_dhcp_exception_key {
    uint8_t  mac[6];
    uint8_t  _pad[2];
};

/* ── Helpers ──────────────────────────────────────────────────── */

/* monotonic clock in ns */
static uint64_t get_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* open pinned map fd — try namespaced path, fall back to flat */
static int open_bpf_map(const char *path)
{
    int fd;

    fd = bpf_obj_get(path);
    if (fd >= 0)
        return fd;

    const char *name = strrchr(path, '/');
    if (name) {
        char flat[256];
        snprintf(flat, sizeof(flat), "/sys/fs/bpf%s", name);
        fd = bpf_obj_get(flat);
        if (fd >= 0)
            return fd;
    }

    jz_log_warn("Cannot open pinned map %s: %s", path, strerror(errno));
    return -1;
}

/* network-order ipv4 to text */
static void ip_to_text(uint32_t ip, char *buf, size_t buf_size)
{
    struct in_addr addr;

    if (!buf || buf_size == 0)
        return;
    addr.s_addr = ip;
    if (!inet_ntop(AF_INET, &addr, buf, (socklen_t)buf_size))
        snprintf(buf, buf_size, "0.0.0.0");
}

/* push static guard entry */
static int push_static_guard(jz_guard_mgr_t *gm, const jz_config_guard_static_t *src)
{
    struct in_addr addr;
    struct bpf_guard_entry value;
    uint32_t key;

    if (!gm || !src || gm->static_map_fd < 0)
        return -1;
    if (inet_pton(AF_INET, src->ip, &addr) != 1) {
        jz_log_error("Invalid static guard IP '%s'", src->ip);
        return -1;
    }

    memset(&value, 0, sizeof(value));
    value.ip_addr = addr.s_addr;
    value.guard_type = JZ_GUARD_STATIC;
    value.enabled = 1;
    value.vlan_id = (src->vlan < 0) ? 0U : (uint16_t)src->vlan;
    value.created_at = get_monotonic_ns();

    if (src->mac[0] != '\0') {
        if (sscanf(src->mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &value.fake_mac[0], &value.fake_mac[1], &value.fake_mac[2],
                   &value.fake_mac[3], &value.fake_mac[4], &value.fake_mac[5]) != 6) {
            jz_log_error("Invalid static guard MAC '%s'", src->mac);
            return -1;
        }
    }

    key = value.ip_addr;
    if (bpf_map_update_elem(gm->static_map_fd, &key, &value, BPF_ANY) < 0) {
        jz_log_error("bpf_map_update_elem(static:%s) failed: %s", src->ip, strerror(errno));
        return -1;
    }
    return 0;
}

/* push whitelist entry */
static int push_whitelist_entry(jz_guard_mgr_t *gm, const jz_config_whitelist_t *src)
{
    struct in_addr addr;
    struct bpf_whitelist_entry value;
    uint32_t key;

    if (!gm || !src || gm->whitelist_map_fd < 0)
        return -1;
    if (inet_pton(AF_INET, src->ip, &addr) != 1) {
        jz_log_error("Invalid whitelist IP '%s'", src->ip);
        return -1;
    }

    memset(&value, 0, sizeof(value));
    value.ip_addr = addr.s_addr;
    value.match_mac = src->match_mac ? 1U : 0U;
    value.enabled = 1U;
    value.created_at = get_monotonic_ns();

    if (src->mac[0] != '\0') {
        if (sscanf(src->mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &value.mac[0], &value.mac[1], &value.mac[2],
                   &value.mac[3], &value.mac[4], &value.mac[5]) != 6) {
            jz_log_error("Invalid whitelist MAC '%s'", src->mac);
            return -1;
        }
    }

    key = value.ip_addr;
    if (bpf_map_update_elem(gm->whitelist_map_fd, &key, &value, BPF_ANY) < 0) {
        jz_log_error("bpf_map_update_elem(whitelist:%s) failed: %s", src->ip, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── Public API ───────────────────────────────────────────────── */

int jz_guard_mgr_init(jz_guard_mgr_t *gm, const jz_config_t *cfg)
{
    if (!gm || !cfg)
        return -1;

    memset(gm, 0, sizeof(*gm));
    gm->static_map_fd = -1;
    gm->dynamic_map_fd = -1;
    gm->whitelist_map_fd = -1;
    gm->dhcp_exception_map_fd = -1;

    gm->static_map_fd = open_bpf_map(BPF_PIN_STATIC_GUARDS);
    gm->dynamic_map_fd = open_bpf_map(BPF_PIN_DYNAMIC_GUARDS);
    gm->whitelist_map_fd = open_bpf_map(BPF_PIN_WHITELIST);
    gm->dhcp_exception_map_fd = open_bpf_map(BPF_PIN_DHCP_EXCEPTION);

    gm->auto_discover = cfg->guards.dynamic.auto_discover;
    gm->max_dynamic = cfg->guards.dynamic.max_entries;
    if (gm->max_dynamic <= 0 || gm->max_dynamic > JZ_GUARD_MGR_MAX_DYNAMIC)
        gm->max_dynamic = JZ_GUARD_MGR_MAX_DYNAMIC;

    if (cfg->guards.dynamic.ttl_hours <= 0)
        gm->default_ttl_sec = 0;
    else
        gm->default_ttl_sec = (uint32_t)cfg->guards.dynamic.ttl_hours * 3600U;

    gm->initialized = true;
    (void)jz_guard_mgr_load_config(gm, cfg);
    jz_log_info("Guard manager initialized: %d static, %d whitelist, auto_discover=%d",
                cfg->guards.static_count, cfg->guards.whitelist_count,
                gm->auto_discover ? 1 : 0);
    return 0;
}

int jz_guard_mgr_load_config(jz_guard_mgr_t *gm, const jz_config_t *cfg)
{
    int i;
    int errors;

    if (!gm || !cfg)
        return -1;

    if (gm->static_map_fd < 0)
        gm->static_map_fd = open_bpf_map(BPF_PIN_STATIC_GUARDS);
    if (gm->dynamic_map_fd < 0)
        gm->dynamic_map_fd = open_bpf_map(BPF_PIN_DYNAMIC_GUARDS);
    if (gm->whitelist_map_fd < 0)
        gm->whitelist_map_fd = open_bpf_map(BPF_PIN_WHITELIST);
    if (gm->dhcp_exception_map_fd < 0)
        gm->dhcp_exception_map_fd = open_bpf_map(BPF_PIN_DHCP_EXCEPTION);

    errors = 0;
    for (i = 0; i < cfg->guards.static_count; i++) {
        if (push_static_guard(gm, &cfg->guards.static_entries[i]) < 0)
            errors++;
    }
    for (i = 0; i < cfg->guards.whitelist_count; i++) {
        if (push_whitelist_entry(gm, &cfg->guards.whitelist[i]) < 0)
            errors++;
    }

    jz_log_info("Loaded %d static guards, %d whitelist entries",
                cfg->guards.static_count, cfg->guards.whitelist_count);
    return errors;
}

int jz_guard_mgr_tick(jz_guard_mgr_t *gm)
{
    uint64_t now_ns;
    uint64_t interval_ns;
    int i;
    int expired;

    if (!gm || !gm->initialized)
        return -1;

    now_ns = get_monotonic_ns();
    interval_ns = (uint64_t)JZ_GUARD_MGR_EXPIRY_CHECK_SEC * 1000000000ULL;
    if (gm->last_expiry_check_ns != 0 &&
        (now_ns - gm->last_expiry_check_ns) < interval_ns)
        return 0;

    gm->last_expiry_check_ns = now_ns;
    expired = 0;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        jz_guard_entry_user_t *entry;
        uint64_t expire_ns;
        char ipbuf[INET_ADDRSTRLEN];

        entry = &gm->dynamic_entries[i];
        if (!entry->enabled || entry->ttl_sec == 0)
            continue;

        expire_ns = entry->created_at + ((uint64_t)entry->ttl_sec * 1000000000ULL);
        if (expire_ns >= now_ns)
            continue;

        if (gm->dynamic_map_fd >= 0) {
            if (bpf_map_delete_elem(gm->dynamic_map_fd, &entry->ip) < 0 && errno != ENOENT) {
                jz_log_error("bpf_map_delete_elem(dynamic) failed: %s", strerror(errno));
                continue;
            }
        }

        ip_to_text(entry->ip, ipbuf, sizeof(ipbuf));
        jz_log_info("Expired dynamic guard ip=%s", ipbuf);

        memset(entry, 0, sizeof(*entry));
        if (gm->dynamic_count > 0)
            gm->dynamic_count--;
        expired++;
    }
    return expired;
}

int jz_guard_mgr_add(jz_guard_mgr_t *gm, uint32_t ip, const uint8_t *mac,
                     uint8_t guard_type, uint16_t vlan_id,
                     char *reply, size_t reply_size)
{
    struct bpf_guard_entry value;
    char ipbuf[INET_ADDRSTRLEN];
    int slot;
    int i;
    int n;

    if (!gm || !mac || !reply || reply_size == 0)
        return -1;

    ip_to_text(ip, ipbuf, sizeof(ipbuf));
    memset(&value, 0, sizeof(value));
    value.ip_addr = ip;
    memcpy(value.fake_mac, mac, sizeof(value.fake_mac));
    value.guard_type = guard_type;
    value.enabled = 1;
    value.vlan_id = vlan_id;
    value.created_at = get_monotonic_ns();

    if (guard_type == JZ_GUARD_DYNAMIC) {
        if (gm->dynamic_count >= gm->max_dynamic || gm->dynamic_count >= JZ_GUARD_MGR_MAX_DYNAMIC) {
            n = snprintf(reply, reply_size, "guard_add:error dynamic table full");
            return (n < 0) ? -1 : n;
        }

        if (gm->dynamic_map_fd < 0)
            gm->dynamic_map_fd = open_bpf_map(BPF_PIN_DYNAMIC_GUARDS);
        if (gm->dynamic_map_fd < 0) {
            n = snprintf(reply, reply_size, "guard_add:error dynamic map unavailable");
            return (n < 0) ? -1 : n;
        }

        if (bpf_map_update_elem(gm->dynamic_map_fd, &ip, &value, BPF_ANY) < 0) {
            jz_log_error("bpf_map_update_elem(dynamic:%s) failed: %s", ipbuf, strerror(errno));
            n = snprintf(reply, reply_size, "guard_add:error map update failed");
            return (n < 0) ? -1 : n;
        }

        slot = -1;
        for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
            if (!gm->dynamic_entries[i].enabled) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            (void)bpf_map_delete_elem(gm->dynamic_map_fd, &ip);
            n = snprintf(reply, reply_size, "guard_add:error dynamic table full");
            return (n < 0) ? -1 : n;
        }

        gm->dynamic_entries[slot].ip = ip;
        memcpy(gm->dynamic_entries[slot].mac, mac, sizeof(gm->dynamic_entries[slot].mac));
        gm->dynamic_entries[slot].guard_type = JZ_GUARD_DYNAMIC;
        gm->dynamic_entries[slot].enabled = 1;
        gm->dynamic_entries[slot].vlan_id = vlan_id;
        gm->dynamic_entries[slot].created_at = value.created_at;
        gm->dynamic_entries[slot].ttl_sec = gm->default_ttl_sec;
        gm->dynamic_count++;

        n = snprintf(reply, reply_size, "guard_add:ok ip:%s type:dynamic", ipbuf);
        return (n < 0) ? -1 : n;
    }

    if (guard_type != JZ_GUARD_STATIC) {
        n = snprintf(reply, reply_size, "guard_add:error invalid type");
        return (n < 0) ? -1 : n;
    }

    if (gm->static_map_fd < 0)
        gm->static_map_fd = open_bpf_map(BPF_PIN_STATIC_GUARDS);
    if (gm->static_map_fd < 0) {
        n = snprintf(reply, reply_size, "guard_add:error static map unavailable");
        return (n < 0) ? -1 : n;
    }

    if (bpf_map_update_elem(gm->static_map_fd, &ip, &value, BPF_ANY) < 0) {
        jz_log_error("bpf_map_update_elem(static:%s) failed: %s", ipbuf, strerror(errno));
        n = snprintf(reply, reply_size, "guard_add:error map update failed");
        return (n < 0) ? -1 : n;
    }

    n = snprintf(reply, reply_size, "guard_add:ok ip:%s type:static", ipbuf);
    return (n < 0) ? -1 : n;
}

int jz_guard_mgr_remove(jz_guard_mgr_t *gm, uint32_t ip,
                        char *reply, size_t reply_size)
{
    int i;
    int removed;
    int n;
    char ipbuf[INET_ADDRSTRLEN];

    if (!gm || !reply || reply_size == 0)
        return -1;

    ip_to_text(ip, ipbuf, sizeof(ipbuf));
    removed = 0;

    if (gm->static_map_fd >= 0) {
        if (bpf_map_delete_elem(gm->static_map_fd, &ip) == 0)
            removed = 1;
        else if (errno != ENOENT)
            jz_log_error("bpf_map_delete_elem(static:%s) failed: %s", ipbuf, strerror(errno));
    }
    if (gm->dynamic_map_fd >= 0) {
        if (bpf_map_delete_elem(gm->dynamic_map_fd, &ip) == 0)
            removed = 1;
        else if (errno != ENOENT)
            jz_log_error("bpf_map_delete_elem(dynamic:%s) failed: %s", ipbuf, strerror(errno));
    }

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        if (gm->dynamic_entries[i].enabled && gm->dynamic_entries[i].ip == ip) {
            memset(&gm->dynamic_entries[i], 0, sizeof(gm->dynamic_entries[i]));
            if (gm->dynamic_count > 0)
                gm->dynamic_count--;
            removed = 1;
            break;
        }
    }

    if (removed)
        n = snprintf(reply, reply_size, "guard_remove:ok ip:%s", ipbuf);
    else
        n = snprintf(reply, reply_size, "guard_remove:error not found");
    return (n < 0) ? -1 : n;
}

int jz_guard_mgr_list(const jz_guard_mgr_t *gm,
                      char *reply, size_t reply_size)
{
    int i;
    int off;
    uint64_t now_ns;

    if (!gm || !reply || reply_size == 0)
        return -1;

    off = snprintf(reply, reply_size, "guards dynamic_count=%d\n", gm->dynamic_count);
    if (off < 0)
        return -1;
    if ((size_t)off >= reply_size)
        return (int)(reply_size - 1);

    now_ns = get_monotonic_ns();
    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *entry;
        char ipbuf[INET_ADDRSTRLEN];
        uint32_t ttl_left;
        uint64_t elapsed_sec;
        int n;

        entry = &gm->dynamic_entries[i];
        if (!entry->enabled)
            continue;

        ip_to_text(entry->ip, ipbuf, sizeof(ipbuf));
        if (entry->ttl_sec == 0) {
            ttl_left = 0;
        } else {
            elapsed_sec = (now_ns > entry->created_at)
                ? (now_ns - entry->created_at) / 1000000000ULL : 0;
            ttl_left = (elapsed_sec >= entry->ttl_sec)
                ? 0 : (entry->ttl_sec - (uint32_t)elapsed_sec);
        }

        n = snprintf(reply + off, reply_size - (size_t)off,
                     "ip=%s type=dynamic ttl_remaining=%us\n", ipbuf, ttl_left);
        if (n < 0)
            return -1;
        if ((size_t)n >= reply_size - (size_t)off)
            return off + (int)(reply_size - (size_t)off - 1);
        off += n;
    }
    return off;
}

void jz_guard_mgr_update_config(jz_guard_mgr_t *gm, const jz_config_t *cfg)
{
    if (!gm || !cfg)
        return;

    gm->auto_discover = cfg->guards.dynamic.auto_discover;
    gm->max_dynamic = cfg->guards.dynamic.max_entries;
    if (gm->max_dynamic <= 0 || gm->max_dynamic > JZ_GUARD_MGR_MAX_DYNAMIC)
        gm->max_dynamic = JZ_GUARD_MGR_MAX_DYNAMIC;

    if (cfg->guards.dynamic.ttl_hours <= 0)
        gm->default_ttl_sec = 0;
    else
        gm->default_ttl_sec = (uint32_t)cfg->guards.dynamic.ttl_hours * 3600U;

    jz_log_info("Guard config updated: ttl=%ds, auto_discover=%d, max=%d",
                (int)gm->default_ttl_sec, gm->auto_discover ? 1 : 0, gm->max_dynamic);
}

void jz_guard_mgr_destroy(jz_guard_mgr_t *gm)
{
    if (!gm)
        return;

    if (gm->static_map_fd >= 0)
        close(gm->static_map_fd);
    if (gm->dynamic_map_fd >= 0)
        close(gm->dynamic_map_fd);
    if (gm->whitelist_map_fd >= 0)
        close(gm->whitelist_map_fd);
    if (gm->dhcp_exception_map_fd >= 0)
        close(gm->dhcp_exception_map_fd);

    memset(gm, 0, sizeof(*gm));
    jz_log_info("Guard manager destroyed");
}
