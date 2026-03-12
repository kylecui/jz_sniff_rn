/* SPDX-License-Identifier: MIT */

#include "config_diff.h"
#include "config.h"
#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sqlite3.h>

#define SECTION_COUNT 9

typedef struct diff_stats {
    int guards_added;
    int guards_removed;
    int guards_modified;
    int policies_added;
    int policies_removed;
    int policies_modified;
    int system_modified;
} diff_stats_t;

static const char *section_roots[SECTION_COUNT] = {
    "system", "modules", "guards", "fake_mac_pool", "policies",
    "threats", "collector", "uploader", "api"
};

static int append_fmt(char *dst, size_t dst_len, size_t *off, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!dst || !off || *off >= dst_len)
        return -1;

    va_start(ap, fmt);
    n = vsnprintf(dst + *off, dst_len - *off, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= (dst_len - *off)) {
        dst[dst_len - 1] = '\0';
        *off = dst_len - 1;
        return -1;
    }

    *off += (size_t)n;
    return 0;
}

static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0;
    size_t o = 0;

    if (!dst || dst_len == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;

    while (src[i] && o + 1 < dst_len) {
        unsigned char c = (unsigned char)src[i++];
        if (c == '\\' || c == '"') {
            if (o + 2 >= dst_len)
                break;
            dst[o++] = '\\';
            dst[o++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            if (o + 2 >= dst_len)
                break;
            dst[o++] = '\\';
            dst[o++] = (c == '\n') ? 'n' : (c == '\r') ? 'r' : 't';
        } else if (c < 0x20) {
            if (o + 6 >= dst_len)
                break;
            snprintf(dst + o, dst_len - o, "\\u%04x", (unsigned)c);
            o += 6;
        } else {
            dst[o++] = (char)c;
        }
    }

    dst[o] = '\0';
}

static int section_index(const char *section)
{
    int i;
    for (i = 0; i < SECTION_COUNT; ++i) {
        size_t n = strlen(section_roots[i]);
        if (strncmp(section, section_roots[i], n) == 0)
            return i;
    }
    return -1;
}

static int add_diff_entry(jz_config_diff_t *diff,
                          int changed[SECTION_COUNT],
                          const char *section,
                          const char *action,
                          const char *key,
                          const char *old_value,
                          const char *new_value)
{
    jz_config_diff_entry_t *entry;
    int idx;

    if (!diff || !section || !action || !key || !old_value || !new_value)
        return -1;
    if (diff->count >= JZ_CONFIG_MAX_DIFF_ENTRIES)
        return -1;

    entry = &diff->entries[diff->count++];
    snprintf(entry->section, sizeof(entry->section), "%s", section);
    snprintf(entry->action, sizeof(entry->action), "%s", action);
    snprintf(entry->key, sizeof(entry->key), "%s", key);
    snprintf(entry->old_value, sizeof(entry->old_value), "%s", old_value);
    snprintf(entry->new_value, sizeof(entry->new_value), "%s", new_value);

    idx = section_index(section);
    if (idx >= 0)
        changed[idx] = 1;
    return 0;
}

static int cmp_str_field(jz_config_diff_t *diff,
                         int changed[SECTION_COUNT],
                         const char *section,
                         const char *key,
                         const char *old_v,
                         const char *new_v)
{
    const char *a = old_v ? old_v : "";
    const char *b = new_v ? new_v : "";
    if (strcmp(a, b) == 0)
        return 0;
    return add_diff_entry(diff, changed, section, "modified", key, a, b);
}

static int cmp_int_field(jz_config_diff_t *diff,
                         int changed[SECTION_COUNT],
                         const char *section,
                         const char *key,
                         int old_v,
                         int new_v)
{
    char old_s[32];
    char new_s[32];

    if (old_v == new_v)
        return 0;
    snprintf(old_s, sizeof(old_s), "%d", old_v);
    snprintf(new_s, sizeof(new_s), "%d", new_v);
    return add_diff_entry(diff, changed, section, "modified", key, old_s, new_s);
}

static int find_static_guard_by_ip(const jz_config_guards_t *guards, const char *ip)
{
    int i;
    for (i = 0; i < guards->static_count; ++i) {
        if (strcmp(guards->static_entries[i].ip, ip) == 0)
            return i;
    }
    return -1;
}

static int find_whitelist_by_ip(const jz_config_guards_t *guards, const char *ip)
{
    int i;
    for (i = 0; i < guards->whitelist_count; ++i) {
        if (strcmp(guards->whitelist[i].ip, ip) == 0)
            return i;
    }
    return -1;
}

static int find_pattern_by_id(const jz_config_threats_t *threats, const char *id)
{
    int i;
    for (i = 0; i < threats->pattern_count; ++i) {
        if (strcmp(threats->patterns[i].id, id) == 0)
            return i;
    }
    return -1;
}

static int policy_equal(const jz_config_policy_t *a, const jz_config_policy_t *b)
{
    return strcmp(a->src_ip, b->src_ip) == 0 &&
           strcmp(a->dst_ip, b->dst_ip) == 0 &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           strcmp(a->proto, b->proto) == 0 &&
           strcmp(a->action, b->action) == 0 &&
           a->redirect_port == b->redirect_port &&
           a->mirror_port == b->mirror_port;
}

static int summarize_diff(jz_config_diff_t *diff,
                          const int changed[SECTION_COUNT],
                          const diff_stats_t *stats)
{
    size_t off = 0;
    int i;
    int listed = 0;

    if (append_fmt(diff->summary, sizeof(diff->summary), &off,
                   "%d sections changed", diff->sections_changed) != 0)
        return -1;

    if (stats->guards_added > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ": %d guards added", stats->guards_added);
    if (stats->guards_removed > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   "%s%d guards removed", (stats->guards_added > 0) ? ", " : ": ", stats->guards_removed);
    if (stats->guards_modified > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ", %d guards modified", stats->guards_modified);
    if (stats->policies_added > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ", %d policies added", stats->policies_added);
    if (stats->policies_removed > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ", %d policies removed", stats->policies_removed);
    if (stats->policies_modified > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ", %d policies modified", stats->policies_modified);
    if (stats->system_modified > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   ", %d system fields modified", stats->system_modified);

    if (diff->count > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off, " (sections: ");

    for (i = 0; i < SECTION_COUNT; ++i) {
        if (!changed[i])
            continue;
        append_fmt(diff->summary, sizeof(diff->summary), &off,
                   "%s%s", listed ? ", " : "", section_roots[i]);
        listed = 1;
    }

    if (diff->count > 0)
        append_fmt(diff->summary, sizeof(diff->summary), &off, ")");
    return 0;
}

static int format_timestamp(char out[32])
{
    time_t now = time(NULL);
    struct tm tm_now;

    if (now == (time_t)-1)
        return -1;
#if defined(_WIN32)
    if (localtime_s(&tm_now, &now) != 0)
        return -1;
#else
    if (localtime_r(&now, &tm_now) == NULL)
        return -1;
#endif
    if (strftime(out, 32, "%Y-%m-%d %H:%M:%S", &tm_now) == 0)
        return -1;
    return 0;
}

int jz_config_diff(const jz_config_t *old_cfg, const jz_config_t *new_cfg, jz_config_diff_t *diff)
{
    typedef struct { const char *s; const char *k; const char *o; const char *n; int *counter; } str_cmp_t;
    typedef struct { const char *s; const char *k; int o; int n; int *counter; } int_cmp_t;
    jz_config_t empty_cfg;
    int changed[SECTION_COUNT] = {0};
    diff_stats_t stats = {0};
    int i;

    if (!new_cfg || !diff)
        return -1;

    memset(&empty_cfg, 0, sizeof(empty_cfg));
    memset(diff, 0, sizeof(*diff));
    if (!old_cfg)
        old_cfg = &empty_cfg;

    {
        str_cmp_t sc[] = {
            {"system", "device_id", old_cfg->system.device_id, new_cfg->system.device_id, &stats.system_modified},
            {"system", "log_level", old_cfg->system.log_level, new_cfg->system.log_level, &stats.system_modified},
            {"system", "data_dir", old_cfg->system.data_dir, new_cfg->system.data_dir, &stats.system_modified},
            {"system", "run_dir", old_cfg->system.run_dir, new_cfg->system.run_dir, &stats.system_modified},
            {"modules.traffic_weaver", "default_action", old_cfg->modules.traffic_weaver.default_action, new_cfg->modules.traffic_weaver.default_action, NULL},
            {"fake_mac_pool", "prefix", old_cfg->fake_mac_pool.prefix, new_cfg->fake_mac_pool.prefix, NULL},
            {"threats", "blacklist_file", old_cfg->threats.blacklist_file, new_cfg->threats.blacklist_file, NULL},
            {"collector", "db_path", old_cfg->collector.db_path, new_cfg->collector.db_path, NULL},
            {"uploader", "platform_url", old_cfg->uploader.platform_url, new_cfg->uploader.platform_url, NULL},
            {"uploader", "tls_cert", old_cfg->uploader.tls_cert, new_cfg->uploader.tls_cert, NULL},
            {"uploader", "tls_key", old_cfg->uploader.tls_key, new_cfg->uploader.tls_key, NULL},
            {"api", "listen", old_cfg->api.listen, new_cfg->api.listen, NULL},
            {"api", "tls_cert", old_cfg->api.tls_cert, new_cfg->api.tls_cert, NULL},
            {"api", "tls_key", old_cfg->api.tls_key, new_cfg->api.tls_key, NULL}
        };
        for (i = 0; i < (int)(sizeof(sc) / sizeof(sc[0])); ++i) {
            if (cmp_str_field(diff, changed, sc[i].s, sc[i].k, sc[i].o, sc[i].n) != 0)
                return -1;
            if (sc[i].counter && strcmp(sc[i].o, sc[i].n) != 0)
                (*sc[i].counter)++;
        }
    }

    {
        int_cmp_t ic[] = {
            {"modules.guard_classifier", "enabled", old_cfg->modules.guard_classifier.enabled, new_cfg->modules.guard_classifier.enabled, NULL},
            {"modules.guard_classifier", "stage", old_cfg->modules.guard_classifier.stage, new_cfg->modules.guard_classifier.stage, NULL},
            {"modules.arp_honeypot", "enabled", old_cfg->modules.arp_honeypot.common.enabled, new_cfg->modules.arp_honeypot.common.enabled, NULL},
            {"modules.arp_honeypot", "stage", old_cfg->modules.arp_honeypot.common.stage, new_cfg->modules.arp_honeypot.common.stage, NULL},
            {"modules.arp_honeypot", "rate_limit_pps", old_cfg->modules.arp_honeypot.rate_limit_pps, new_cfg->modules.arp_honeypot.rate_limit_pps, NULL},
            {"modules.arp_honeypot", "log_all", old_cfg->modules.arp_honeypot.log_all, new_cfg->modules.arp_honeypot.log_all, NULL},
            {"modules.icmp_honeypot", "enabled", old_cfg->modules.icmp_honeypot.common.enabled, new_cfg->modules.icmp_honeypot.common.enabled, NULL},
            {"modules.icmp_honeypot", "stage", old_cfg->modules.icmp_honeypot.common.stage, new_cfg->modules.icmp_honeypot.common.stage, NULL},
            {"modules.icmp_honeypot", "ttl", old_cfg->modules.icmp_honeypot.ttl, new_cfg->modules.icmp_honeypot.ttl, NULL},
            {"modules.icmp_honeypot", "rate_limit_pps", old_cfg->modules.icmp_honeypot.rate_limit_pps, new_cfg->modules.icmp_honeypot.rate_limit_pps, NULL},
            {"modules.sniffer_detect", "enabled", old_cfg->modules.sniffer_detect.common.enabled, new_cfg->modules.sniffer_detect.common.enabled, NULL},
            {"modules.sniffer_detect", "stage", old_cfg->modules.sniffer_detect.common.stage, new_cfg->modules.sniffer_detect.common.stage, NULL},
            {"modules.sniffer_detect", "probe_interval_sec", old_cfg->modules.sniffer_detect.probe_interval_sec, new_cfg->modules.sniffer_detect.probe_interval_sec, NULL},
            {"modules.sniffer_detect", "probe_count", old_cfg->modules.sniffer_detect.probe_count, new_cfg->modules.sniffer_detect.probe_count, NULL},
            {"modules.traffic_weaver", "enabled", old_cfg->modules.traffic_weaver.common.enabled, new_cfg->modules.traffic_weaver.common.enabled, NULL},
            {"modules.traffic_weaver", "stage", old_cfg->modules.traffic_weaver.common.stage, new_cfg->modules.traffic_weaver.common.stage, NULL},
            {"modules.bg_collector", "enabled", old_cfg->modules.bg_collector.common.enabled, new_cfg->modules.bg_collector.common.enabled, NULL},
            {"modules.bg_collector", "stage", old_cfg->modules.bg_collector.common.stage, new_cfg->modules.bg_collector.common.stage, NULL},
            {"modules.bg_collector", "sample_rate", old_cfg->modules.bg_collector.sample_rate, new_cfg->modules.bg_collector.sample_rate, NULL},
            {"modules.bg_collector", "protocols.arp", old_cfg->modules.bg_collector.protocols.arp, new_cfg->modules.bg_collector.protocols.arp, NULL},
            {"modules.bg_collector", "protocols.dhcp", old_cfg->modules.bg_collector.protocols.dhcp, new_cfg->modules.bg_collector.protocols.dhcp, NULL},
            {"modules.bg_collector", "protocols.mdns", old_cfg->modules.bg_collector.protocols.mdns, new_cfg->modules.bg_collector.protocols.mdns, NULL},
            {"modules.bg_collector", "protocols.ssdp", old_cfg->modules.bg_collector.protocols.ssdp, new_cfg->modules.bg_collector.protocols.ssdp, NULL},
            {"modules.bg_collector", "protocols.lldp", old_cfg->modules.bg_collector.protocols.lldp, new_cfg->modules.bg_collector.protocols.lldp, NULL},
            {"modules.bg_collector", "protocols.cdp", old_cfg->modules.bg_collector.protocols.cdp, new_cfg->modules.bg_collector.protocols.cdp, NULL},
            {"modules.bg_collector", "protocols.stp", old_cfg->modules.bg_collector.protocols.stp, new_cfg->modules.bg_collector.protocols.stp, NULL},
            {"modules.bg_collector", "protocols.igmp", old_cfg->modules.bg_collector.protocols.igmp, new_cfg->modules.bg_collector.protocols.igmp, NULL},
            {"modules.threat_detect", "enabled", old_cfg->modules.threat_detect.enabled, new_cfg->modules.threat_detect.enabled, NULL},
            {"modules.threat_detect", "stage", old_cfg->modules.threat_detect.stage, new_cfg->modules.threat_detect.stage, NULL},
            {"modules.forensics", "enabled", old_cfg->modules.forensics.common.enabled, new_cfg->modules.forensics.common.enabled, NULL},
            {"modules.forensics", "stage", old_cfg->modules.forensics.common.stage, new_cfg->modules.forensics.common.stage, NULL},
            {"modules.forensics", "max_payload_bytes", old_cfg->modules.forensics.max_payload_bytes, new_cfg->modules.forensics.max_payload_bytes, NULL},
            {"modules.forensics", "sample_rate", old_cfg->modules.forensics.sample_rate, new_cfg->modules.forensics.sample_rate, NULL},
            {"guards.dynamic", "auto_discover", old_cfg->guards.dynamic.auto_discover, new_cfg->guards.dynamic.auto_discover, &stats.guards_modified},
            {"guards.dynamic", "max_entries", old_cfg->guards.dynamic.max_entries, new_cfg->guards.dynamic.max_entries, &stats.guards_modified},
            {"guards.dynamic", "ttl_hours", old_cfg->guards.dynamic.ttl_hours, new_cfg->guards.dynamic.ttl_hours, &stats.guards_modified},
            {"fake_mac_pool", "count", old_cfg->fake_mac_pool.count, new_cfg->fake_mac_pool.count, NULL},
            {"collector", "max_db_size_mb", old_cfg->collector.max_db_size_mb, new_cfg->collector.max_db_size_mb, NULL},
            {"collector", "dedup_window_sec", old_cfg->collector.dedup_window_sec, new_cfg->collector.dedup_window_sec, NULL},
            {"collector", "rate_limit_eps", old_cfg->collector.rate_limit_eps, new_cfg->collector.rate_limit_eps, NULL},
            {"uploader", "enabled", old_cfg->uploader.enabled, new_cfg->uploader.enabled, NULL},
            {"uploader", "interval_sec", old_cfg->uploader.interval_sec, new_cfg->uploader.interval_sec, NULL},
            {"uploader", "batch_size", old_cfg->uploader.batch_size, new_cfg->uploader.batch_size, NULL},
            {"uploader", "compress", old_cfg->uploader.compress, new_cfg->uploader.compress, NULL},
            {"api", "enabled", old_cfg->api.enabled, new_cfg->api.enabled, NULL},
            {"api", "auth_token_count", old_cfg->api.auth_token_count, new_cfg->api.auth_token_count, NULL}
        };
        for (i = 0; i < (int)(sizeof(ic) / sizeof(ic[0])); ++i) {
            if (cmp_int_field(diff, changed, ic[i].s, ic[i].k, ic[i].o, ic[i].n) != 0)
                return -1;
            if (ic[i].counter && ic[i].o != ic[i].n)
                (*ic[i].counter)++;
        }
    }

    for (i = 0; i < old_cfg->guards.static_count; ++i) {
        int ni = find_static_guard_by_ip(&new_cfg->guards, old_cfg->guards.static_entries[i].ip);
        if (ni < 0) {
            if (add_diff_entry(diff, changed, "guards.static", "removed", old_cfg->guards.static_entries[i].ip,
                               old_cfg->guards.static_entries[i].mac, "") != 0) return -1;
            stats.guards_removed++;
        } else if (strcmp(old_cfg->guards.static_entries[i].mac, new_cfg->guards.static_entries[ni].mac) != 0 ||
                   old_cfg->guards.static_entries[i].vlan != new_cfg->guards.static_entries[ni].vlan) {
            char ov[64], nv[64];
            snprintf(ov, sizeof(ov), "mac=%s,vlan=%d", old_cfg->guards.static_entries[i].mac, old_cfg->guards.static_entries[i].vlan);
            snprintf(nv, sizeof(nv), "mac=%s,vlan=%d", new_cfg->guards.static_entries[ni].mac, new_cfg->guards.static_entries[ni].vlan);
            if (add_diff_entry(diff, changed, "guards.static", "modified", old_cfg->guards.static_entries[i].ip, ov, nv) != 0) return -1;
            stats.guards_modified++;
        }
    }
    for (i = 0; i < new_cfg->guards.static_count; ++i) {
        if (find_static_guard_by_ip(&old_cfg->guards, new_cfg->guards.static_entries[i].ip) < 0) {
            if (add_diff_entry(diff, changed, "guards.static", "added", new_cfg->guards.static_entries[i].ip,
                               "", new_cfg->guards.static_entries[i].mac) != 0) return -1;
            stats.guards_added++;
        }
    }

    for (i = 0; i < old_cfg->guards.whitelist_count; ++i) {
        int ni = find_whitelist_by_ip(&new_cfg->guards, old_cfg->guards.whitelist[i].ip);
        if (ni < 0) {
            if (add_diff_entry(diff, changed, "guards.whitelist", "removed", old_cfg->guards.whitelist[i].ip,
                               old_cfg->guards.whitelist[i].mac, "") != 0) return -1;
            stats.guards_removed++;
        } else if (strcmp(old_cfg->guards.whitelist[i].mac, new_cfg->guards.whitelist[ni].mac) != 0 ||
                   old_cfg->guards.whitelist[i].match_mac != new_cfg->guards.whitelist[ni].match_mac) {
            char ov[64], nv[64];
            snprintf(ov, sizeof(ov), "mac=%s,match_mac=%d", old_cfg->guards.whitelist[i].mac, old_cfg->guards.whitelist[i].match_mac ? 1 : 0);
            snprintf(nv, sizeof(nv), "mac=%s,match_mac=%d", new_cfg->guards.whitelist[ni].mac, new_cfg->guards.whitelist[ni].match_mac ? 1 : 0);
            if (add_diff_entry(diff, changed, "guards.whitelist", "modified", old_cfg->guards.whitelist[i].ip, ov, nv) != 0) return -1;
            stats.guards_modified++;
        }
    }
    for (i = 0; i < new_cfg->guards.whitelist_count; ++i) {
        if (find_whitelist_by_ip(&old_cfg->guards, new_cfg->guards.whitelist[i].ip) < 0) {
            if (add_diff_entry(diff, changed, "guards.whitelist", "added", new_cfg->guards.whitelist[i].ip,
                               "", new_cfg->guards.whitelist[i].mac) != 0) return -1;
            stats.guards_added++;
        }
    }

    for (i = 0; i < old_cfg->policy_count || i < new_cfg->policy_count; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "index:%d", i);
        if (i >= old_cfg->policy_count) {
            if (add_diff_entry(diff, changed, "policies", "added", key, "", "present") != 0) return -1;
            stats.policies_added++;
        } else if (i >= new_cfg->policy_count) {
            if (add_diff_entry(diff, changed, "policies", "removed", key, "present", "") != 0) return -1;
            stats.policies_removed++;
        } else if (!policy_equal(&old_cfg->policies[i], &new_cfg->policies[i])) {
            if (add_diff_entry(diff, changed, "policies", "modified", key, old_cfg->policies[i].action, new_cfg->policies[i].action) != 0) return -1;
            stats.policies_modified++;
        }
    }

    for (i = 0; i < old_cfg->threats.pattern_count; ++i) {
        int ni = find_pattern_by_id(&new_cfg->threats, old_cfg->threats.patterns[i].id);
        if (ni < 0) {
            if (add_diff_entry(diff, changed, "threats.patterns", "removed", old_cfg->threats.patterns[i].id,
                               old_cfg->threats.patterns[i].action, "") != 0) return -1;
        } else if (old_cfg->threats.patterns[i].dst_port != new_cfg->threats.patterns[ni].dst_port ||
                   strcmp(old_cfg->threats.patterns[i].proto, new_cfg->threats.patterns[ni].proto) != 0 ||
                   strcmp(old_cfg->threats.patterns[i].threat_level, new_cfg->threats.patterns[ni].threat_level) != 0 ||
                   strcmp(old_cfg->threats.patterns[i].action, new_cfg->threats.patterns[ni].action) != 0 ||
                   strcmp(old_cfg->threats.patterns[i].description, new_cfg->threats.patterns[ni].description) != 0) {
            if (add_diff_entry(diff, changed, "threats.patterns", "modified", old_cfg->threats.patterns[i].id,
                               old_cfg->threats.patterns[i].action, new_cfg->threats.patterns[ni].action) != 0) return -1;
        }
    }
    for (i = 0; i < new_cfg->threats.pattern_count; ++i) {
        if (find_pattern_by_id(&old_cfg->threats, new_cfg->threats.patterns[i].id) < 0) {
            if (add_diff_entry(diff, changed, "threats.patterns", "added", new_cfg->threats.patterns[i].id,
                               "", new_cfg->threats.patterns[i].action) != 0) return -1;
        }
    }

    for (i = 0; i < SECTION_COUNT; ++i)
        diff->sections_changed += changed[i];
    summarize_diff(diff, changed, &stats);
    return 0;
}

int jz_config_audit_log(jz_db_t *db,
                        const char *action,
                        const char *actor,
                        const jz_config_diff_t *diff,
                        const char *result)
{
    char timestamp[32];
    char target[128] = "";
    char details[1024];
    int seen[SECTION_COUNT] = {0};
    size_t off = 0;
    int i;

    if (!db || !action || !actor || !result)
        return -1;

    if (format_timestamp(timestamp) != 0)
        return -1;

    if (diff) {
        for (i = 0; i < diff->count; ++i) {
            int idx = section_index(diff->entries[i].section);
            if (idx >= 0)
                seen[idx] = 1;
        }
        for (i = 0; i < SECTION_COUNT; ++i) {
            if (!seen[i])
                continue;
            append_fmt(target, sizeof(target), &off, "%s%s", (off > 0) ? ", " : "", section_roots[i]);
        }
    }
    if (target[0] == '\0')
        snprintf(target, sizeof(target), "config");

    off = 0;
    append_fmt(details, sizeof(details), &off, "{\"changes\":[");
    if (diff) {
        for (i = 0; i < diff->count; ++i) {
            char s[96], a[48], k[192];
            json_escape(diff->entries[i].section, s, sizeof(s));
            json_escape(diff->entries[i].action, a, sizeof(a));
            json_escape(diff->entries[i].key, k, sizeof(k));
            append_fmt(details, sizeof(details), &off,
                       "%s{\"section\":\"%s\",\"action\":\"%s\",\"key\":\"%s\"}",
                       (i == 0) ? "" : ",", s, a, k);
        }
        {
            char sum[600];
            json_escape(diff->summary, sum, sizeof(sum));
            append_fmt(details, sizeof(details), &off, "],\"summary\":\"%s\"}", sum);
        }
    } else {
        append_fmt(details, sizeof(details), &off, "],\"summary\":\"\"}");
    }

    return jz_db_insert_audit(db, timestamp, action, actor, target, details, result);
}

int jz_config_audit_query(jz_db_t *db,
                          const char *since,
                          const char *until,
                          const char *action_filter,
                          jz_audit_entry_t **results,
                          int *count)
{
    const char *sql =
        "SELECT * FROM audit_log WHERE timestamp >= ? AND timestamp <= ? "
        "AND (action = ? OR ? IS NULL) ORDER BY timestamp DESC";
    const char *since_v = since ? since : "0000-01-01 00:00:00";
    const char *until_v = until ? until : "9999-12-31 23:59:59";
    sqlite3_stmt *stmt = NULL;
    jz_audit_entry_t *out = NULL;
    int n = 0;
    int cap = 0;
    int rc;

    if (!db || !db->db || !results || !count)
        return -1;

    *results = NULL;
    *count = 0;

    rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, since_v, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, until_v, -1, SQLITE_STATIC);
    if (action_filter) {
        sqlite3_bind_text(stmt, 3, action_filter, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, action_filter, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_null(stmt, 4);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *ts;
        const char *act;
        const char *actor;
        const char *target;
        const char *details;
        const char *result;
        if (n == cap) {
            int new_cap = (cap == 0) ? 16 : cap * 2;
            jz_audit_entry_t *tmp = realloc(out, (size_t)new_cap * sizeof(*tmp));
            if (!tmp) {
                free(out);
                sqlite3_finalize(stmt);
                return -1;
            }
            out = tmp;
            cap = new_cap;
        }

        ts = (const char *)sqlite3_column_text(stmt, 1);
        act = (const char *)sqlite3_column_text(stmt, 2);
        actor = (const char *)sqlite3_column_text(stmt, 3);
        target = (const char *)sqlite3_column_text(stmt, 4);
        details = (const char *)sqlite3_column_text(stmt, 5);
        result = (const char *)sqlite3_column_text(stmt, 6);

        snprintf(out[n].timestamp, sizeof(out[n].timestamp), "%s", ts ? ts : "");
        snprintf(out[n].action, sizeof(out[n].action), "%s", act ? act : "");
        snprintf(out[n].actor, sizeof(out[n].actor), "%s", actor ? actor : "");
        snprintf(out[n].target, sizeof(out[n].target), "%s", target ? target : "");
        snprintf(out[n].details, sizeof(out[n].details), "%s", details ? details : "");
        snprintf(out[n].result, sizeof(out[n].result), "%s", result ? result : "");
        n++;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        free(out);
        return -1;
    }

    *results = out;
    *count = n;
    return n;
}

void jz_config_audit_free(jz_audit_entry_t *results)
{
    free(results);
}
