/* SPDX-License-Identifier: MIT */

#include "policy_mgr.h"
#include "log.h"
#include "config_map.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>

#define BPF_PIN_FLOW_POLICY "/sys/fs/bpf/jz/jz_flow_policy"

static int open_bpf_map(const char *path)
{
    int fd;
    const char *name;

    fd = bpf_obj_get(path);
    if (fd >= 0)
        return fd;

    name = strrchr(path, '/');
    if (name) {
        char flat[256];

        (void)snprintf(flat, sizeof(flat), "/sys/fs/bpf%s", name);
        fd = bpf_obj_get(flat);
        if (fd >= 0)
            return fd;
    }

    jz_log_warn("Cannot open pinned map %s: %s", path, strerror(errno));
    return -1;
}

static uint64_t get_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static uint64_t now_unix_sec(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec;
}

static void ip_to_text(uint32_t ip, char *buf, size_t buf_size)
{
    struct in_addr addr;

    if (!buf || buf_size == 0)
        return;

    addr.s_addr = ip;
    if (!inet_ntop(AF_INET, &addr, buf, (socklen_t)buf_size))
        (void)snprintf(buf, buf_size, "0.0.0.0");
}

static void build_flow_key(const jz_policy_entry_user_t *entry, struct jz_flow_key *key)
{
    if (!entry || !key)
        return;

    memset(key, 0, sizeof(*key));
    key->src_ip = entry->src_ip;
    key->dst_ip = entry->dst_ip;
    key->src_port = entry->src_port;
    key->dst_port = entry->dst_port;
    key->proto = entry->proto;
}

static void build_flow_policy(const jz_policy_entry_user_t *entry,
                              struct jz_flow_policy *value,
                              int index)
{
    if (!entry || !value)
        return;

    memset(value, 0, sizeof(*value));
    value->action = entry->action;
    value->redirect_port = entry->redirect_port;
    value->mirror_port = entry->mirror_port;
    if (index <= 0)
        value->priority = 0;
    else if (index >= 255)
        value->priority = 255;
    else
        value->priority = (uint8_t)index;
    value->flags = 0;
    value->created_at = now_unix_sec();
    value->hit_count = 0;
    value->byte_count = 0;
}

static int deploy_to_bpf(jz_policy_mgr_t *pm, const jz_policy_entry_user_t *entry, int index)
{
    struct jz_flow_key key;
    struct jz_flow_policy value;

    if (!pm || !entry)
        return -1;

    if (pm->flow_policy_map_fd < 0)
        pm->flow_policy_map_fd = open_bpf_map(BPF_PIN_FLOW_POLICY);
    if (pm->flow_policy_map_fd < 0)
        return -1;

    build_flow_key(entry, &key);
    build_flow_policy(entry, &value, index);

    if (bpf_map_update_elem(pm->flow_policy_map_fd, &key, &value, BPF_ANY) < 0) {
        jz_log_error("bpf_map_update_elem(flow_policy:id=%u) failed: %s",
                     entry->id, strerror(errno));
        return -1;
    }
    return 0;
}

static int remove_from_bpf(jz_policy_mgr_t *pm, const jz_policy_entry_user_t *entry)
{
    struct jz_flow_key key;

    if (!pm || !entry)
        return -1;

    if (pm->flow_policy_map_fd < 0)
        pm->flow_policy_map_fd = open_bpf_map(BPF_PIN_FLOW_POLICY);
    if (pm->flow_policy_map_fd < 0)
        return 0;

    build_flow_key(entry, &key);
    if (bpf_map_delete_elem(pm->flow_policy_map_fd, &key) < 0 && errno != ENOENT)
        jz_log_error("bpf_map_delete_elem(flow_policy:id=%u) failed: %s",
                     entry->id, strerror(errno));
    return 0;
}

static const char *proto_to_text(uint8_t proto)
{
    if (proto == 6)
        return "tcp";
    if (proto == 17)
        return "udp";
    return "any";
}

static int proto_from_text(const char *text, uint8_t *proto)
{
    if (!text || !proto)
        return -1;

    if (text[0] == '\0' || strcmp(text, "*") == 0 || strcasecmp(text, "any") == 0) {
        *proto = 0;
        return 0;
    }
    if (strcasecmp(text, "tcp") == 0) {
        *proto = 6;
        return 0;
    }
    if (strcasecmp(text, "udp") == 0) {
        *proto = 17;
        return 0;
    }
    return -1;
}

static const char *action_to_text(uint8_t action)
{
    if (action == JZ_ACTION_PASS)
        return "pass";
    if (action == JZ_ACTION_DROP)
        return "drop";
    if (action == JZ_ACTION_REDIRECT)
        return "redirect";
    if (action == JZ_ACTION_MIRROR)
        return "mirror";
    if (action == JZ_ACTION_REDIRECT_MIRROR)
        return "redirect_mirror";
    return "pass";
}

static int action_from_text(const char *text, uint8_t *action)
{
    if (!text || !action)
        return -1;

    if (text[0] == '\0' || strcmp(text, "*") == 0 || strcasecmp(text, "pass") == 0) {
        *action = JZ_ACTION_PASS;
        return 0;
    }
    if (strcasecmp(text, "drop") == 0) {
        *action = JZ_ACTION_DROP;
        return 0;
    }
    if (strcasecmp(text, "redirect") == 0) {
        *action = JZ_ACTION_REDIRECT;
        return 0;
    }
    if (strcasecmp(text, "mirror") == 0) {
        *action = JZ_ACTION_MIRROR;
        return 0;
    }
    if (strcasecmp(text, "redirect_mirror") == 0 ||
        strcasecmp(text, "redirect-mirror") == 0) {
        *action = JZ_ACTION_REDIRECT_MIRROR;
        return 0;
    }
    return -1;
}

static int parse_ip_or_wildcard(const char *text, uint32_t *ip)
{
    struct in_addr addr;

    if (!text || !ip)
        return -1;

    if (text[0] == '\0' || strcmp(text, "*") == 0 || strcmp(text, "0.0.0.0") == 0) {
        *ip = 0;
        return 0;
    }

    if (inet_pton(AF_INET, text, &addr) != 1)
        return -1;
    *ip = addr.s_addr;
    return 0;
}

static int append_json(char *buf, size_t buf_size, int *off, const char *fmt, ...)
{
    int n;
    va_list ap;

    if (!buf || !off || !fmt || buf_size == 0)
        return -1;
    if (*off < 0 || (size_t)(*off) >= buf_size)
        return -1;

    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - (size_t)(*off), fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size - (size_t)(*off)) {
        *off = (int)(buf_size - 1);
        return -1;
    }
    *off += n;
    return 0;
}

static int append_json_escaped(char *buf, size_t buf_size, int *off, const char *text)
{
    size_t i;

    if (!buf || !off || !text || buf_size == 0)
        return -1;

    for (i = 0; text[i] != '\0'; i++) {
        unsigned char ch;

        ch = (unsigned char)text[i];
        if (ch == '"' || ch == '\\') {
            if (append_json(buf, buf_size, off, "\\%c", ch) < 0)
                return -1;
        } else if (ch < 0x20U) {
            if (append_json(buf, buf_size, off, " ") < 0)
                return -1;
        } else {
            if (append_json(buf, buf_size, off, "%c", ch) < 0)
                return -1;
        }
    }
    return 0;
}

int jz_policy_mgr_init(jz_policy_mgr_t *pm, const jz_config_t *cfg)
{
    if (!pm)
        return -1;

    memset(pm, 0, sizeof(*pm));
    pm->flow_policy_map_fd = -1;
    pm->next_id = 1;
    pm->initialized = true;

    if (cfg)
        (void)jz_policy_mgr_load_config(pm, cfg);
    return 0;
}

void jz_policy_mgr_destroy(jz_policy_mgr_t *pm)
{
    if (!pm)
        return;

    if (pm->flow_policy_map_fd >= 0)
        close(pm->flow_policy_map_fd);
    memset(pm, 0, sizeof(*pm));
    pm->flow_policy_map_fd = -1;
}

int jz_policy_mgr_tick(jz_policy_mgr_t *pm)
{
    uint64_t now_ns;
    uint64_t interval_ns;
    int expired;
    int i;

    if (!pm || !pm->initialized)
        return -1;

    now_ns = get_monotonic_ns();
    interval_ns = (uint64_t)JZ_POLICY_MGR_EXPIRY_CHECK_SEC * 1000000000ULL;
    if (pm->last_expiry_check_ns != 0 &&
        (now_ns - pm->last_expiry_check_ns) < interval_ns)
        return 0;

    pm->last_expiry_check_ns = now_ns;
    expired = 0;
    i = 0;
    while (i < pm->count) {
        uint64_t ttl_ns;
        uint32_t id;

        if (pm->entries[i].ttl_sec == 0) {
            i++;
            continue;
        }

        ttl_ns = (uint64_t)pm->entries[i].ttl_sec * 1000000000ULL;
        if ((now_ns - pm->entries[i].created_at) <= ttl_ns) {
            i++;
            continue;
        }

        id = pm->entries[i].id;
        (void)remove_from_bpf(pm, &pm->entries[i]);
        if (i < pm->count - 1) {
            memmove(&pm->entries[i], &pm->entries[i + 1],
                    (size_t)(pm->count - i - 1) * sizeof(pm->entries[0]));
        }
        memset(&pm->entries[pm->count - 1], 0, sizeof(pm->entries[0]));
        pm->count--;
        expired++;
        jz_log_info("policy %u expired", id);
    }

    return expired;
}

int jz_policy_mgr_add(jz_policy_mgr_t *pm, const jz_policy_entry_user_t *entry)
{
    jz_policy_entry_user_t new_entry;
    uint32_t id;

    if (!pm || !entry || !pm->initialized)
        return -1;
    if (pm->count < 0 || pm->count >= JZ_POLICY_MGR_MAX_POLICIES)
        return -1;

    memset(&new_entry, 0, sizeof(new_entry));
    new_entry = *entry;

    id = pm->next_id;
    pm->next_id++;
    new_entry.id = id;
    new_entry.enabled = true;
    new_entry.created_at = get_monotonic_ns();

    if (deploy_to_bpf(pm, &new_entry, pm->count) < 0)
        return -1;

    pm->entries[pm->count] = new_entry;
    pm->count++;
    return (int)id;
}

int jz_policy_mgr_remove(jz_policy_mgr_t *pm, uint32_t id)
{
    int i;

    if (!pm || !pm->initialized)
        return -1;

    for (i = 0; i < pm->count; i++) {
        if (pm->entries[i].id != id)
            continue;

        (void)remove_from_bpf(pm, &pm->entries[i]);
        if (i < pm->count - 1) {
            memmove(&pm->entries[i], &pm->entries[i + 1],
                    (size_t)(pm->count - i - 1) * sizeof(pm->entries[0]));
        }
        memset(&pm->entries[pm->count - 1], 0, sizeof(pm->entries[0]));
        pm->count--;
        return 0;
    }

    return -1;
}

int jz_policy_mgr_update(jz_policy_mgr_t *pm, uint32_t id, const jz_policy_entry_user_t *entry)
{
    int i;
    jz_policy_entry_user_t updated;

    if (!pm || !entry || !pm->initialized)
        return -1;

    for (i = 0; i < pm->count; i++) {
        if (pm->entries[i].id != id)
            continue;

        (void)remove_from_bpf(pm, &pm->entries[i]);

        memset(&updated, 0, sizeof(updated));
        updated = *entry;
        updated.id = pm->entries[i].id;
        updated.is_auto = pm->entries[i].is_auto;
        updated.created_at = pm->entries[i].created_at;

        if (deploy_to_bpf(pm, &updated, i) < 0)
            return -1;

        pm->entries[i] = updated;
        return 0;
    }

    return -1;
}

const jz_policy_entry_user_t *jz_policy_mgr_find(const jz_policy_mgr_t *pm, uint32_t id)
{
    int i;

    if (!pm || !pm->initialized)
        return NULL;

    for (i = 0; i < pm->count; i++) {
        if (pm->entries[i].id == id)
            return &pm->entries[i];
    }

    return NULL;
}

int jz_policy_mgr_list_json(const jz_policy_mgr_t *pm, char *buf, size_t buf_size)
{
    int off;
    int i;

    if (!pm || !buf || buf_size == 0)
        return -1;

    off = 0;
    if (append_json(buf, buf_size, &off, "{\"policies\":[") < 0)
        return -1;

    for (i = 0; i < pm->count; i++) {
        const jz_policy_entry_user_t *e;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        e = &pm->entries[i];
        ip_to_text(e->src_ip, src_ip, sizeof(src_ip));
        ip_to_text(e->dst_ip, dst_ip, sizeof(dst_ip));

        if (i > 0 && append_json(buf, buf_size, &off, ",") < 0)
            return -1;
        if (append_json(buf, buf_size, &off, "{\"id\":%u,\"name\":\"", e->id) < 0)
            return -1;
        if (append_json_escaped(buf, buf_size, &off, e->name) < 0)
            return -1;
        if (append_json(buf, buf_size, &off,
                        "\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
                        "\"src_port\":%u,\"dst_port\":%u,"
                        "\"proto\":\"%s\",\"action\":\"%s\","
                        "\"redirect_port\":%u,\"mirror_port\":%u,"
                        "\"auto\":%s,\"enabled\":%s,\"ttl_sec\":%u}",
                        src_ip,
                        dst_ip,
                        (unsigned int)e->src_port,
                        (unsigned int)e->dst_port,
                        proto_to_text(e->proto),
                        action_to_text(e->action),
                        (unsigned int)e->redirect_port,
                        (unsigned int)e->mirror_port,
                        e->is_auto ? "true" : "false",
                        e->enabled ? "true" : "false",
                        (unsigned int)e->ttl_sec) < 0)
            return -1;
    }

    if (append_json(buf, buf_size, &off, "],\"total\":%d}", pm->count) < 0)
        return -1;

    return off;
}

int jz_policy_mgr_load_config(jz_policy_mgr_t *pm, const jz_config_t *cfg)
{
    int i;
    int loaded;

    if (!pm || !cfg || !pm->initialized)
        return -1;

    loaded = 0;
    for (i = 0; i < cfg->policy_count; i++) {
        const jz_config_policy_t *src;
        jz_policy_entry_user_t entry;
        int id;

        if (pm->count >= JZ_POLICY_MGR_MAX_POLICIES)
            break;

        src = &cfg->policies[i];
        memset(&entry, 0, sizeof(entry));

        if (parse_ip_or_wildcard(src->src_ip, &entry.src_ip) < 0) {
            jz_log_error("Invalid policy src_ip '%s'", src->src_ip);
            continue;
        }
        if (parse_ip_or_wildcard(src->dst_ip, &entry.dst_ip) < 0) {
            jz_log_error("Invalid policy dst_ip '%s'", src->dst_ip);
            continue;
        }
        if (src->src_port < 0 || src->src_port > 65535 ||
            src->dst_port < 0 || src->dst_port > 65535) {
            jz_log_error("Invalid policy ports src=%d dst=%d", src->src_port, src->dst_port);
            continue;
        }
        if (src->redirect_port < 0 || src->redirect_port > 255 ||
            src->mirror_port < 0 || src->mirror_port > 255) {
            jz_log_error("Invalid policy redirect/mirror ports r=%d m=%d",
                         src->redirect_port, src->mirror_port);
            continue;
        }
        if (proto_from_text(src->proto, &entry.proto) < 0) {
            jz_log_error("Invalid policy proto '%s'", src->proto);
            continue;
        }
        if (action_from_text(src->action, &entry.action) < 0) {
            jz_log_error("Invalid policy action '%s'", src->action);
            continue;
        }

        entry.src_port = (uint16_t)src->src_port;
        entry.dst_port = (uint16_t)src->dst_port;
        entry.redirect_port = (uint8_t)src->redirect_port;
        entry.mirror_port = (uint8_t)src->mirror_port;
        entry.is_auto = false;
        entry.ttl_sec = 0;
        (void)snprintf(entry.name, sizeof(entry.name), "cfg-%d", i + 1);

        id = jz_policy_mgr_add(pm, &entry);
        if (id < 0) {
            jz_log_error("Failed adding policy index=%d to BPF", i);
            continue;
        }

        loaded++;
    }

    jz_log_info("Loaded %d/%d policies", loaded, cfg->policy_count);
    return loaded;
}

void jz_policy_mgr_update_config(jz_policy_mgr_t *pm, const jz_config_t *cfg)
{
    (void)pm;
    (void)cfg;
    jz_log_info("Policy config update requested; hot-reload behavior pending");
}
