/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include <ctype.h>
#include <limits.h>
#include <netinet/in.h>

#include "config.h"
#include "config_map.h"
#include "log.h"

#define JZ_MAP_MAX_STATIC_GUARDS      256
#define JZ_MAP_MAX_WHITELIST          256
#define JZ_MAP_MAX_POLICIES           512
#define JZ_MAP_MAX_THREAT_PATTERNS    512
#define JZ_MAP_MAX_THREAT_BLACKLIST   65536
#define JZ_MAP_MAX_FAKE_MACS          256
#define JZ_MAP_MAX_BG_FILTERS         64

#define JZ_ETH_P_ARP                  0x0806
#define JZ_ETH_P_LLDP                 0x88CC

static uint64_t now_unix_sec(void)
{
    time_t t = time(NULL);
    if (t < 0)
        return 0;
    return (uint64_t)t;
}

static int str_ieq(const char *a, const char *b)
{
    unsigned char ca;
    unsigned char cb;

    if (!a || !b)
        return 0;

    while (*a && *b) {
        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb))
            return 0;
        a++;
        b++;
    }

    return (*a == '\0' && *b == '\0') ? 1 : 0;
}

static int clamp_u16(int value)
{
    if (value < 0)
        return 0;
    if (value > 65535)
        return 65535;
    return value;
}

static int clamp_u8(int value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return value;
}

static int parse_u32_decimal(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (!s || !out || s[0] == '\0')
        return -1;

    value = strtoul(s, &end, 10);
    if (end == s || *end != '\0')
        return -1;
    if (value > UINT_MAX)
        return -1;

    *out = (uint32_t)value;
    return 0;
}

static int parse_u8_decimal(const char *s, uint8_t *out)
{
    uint32_t value;

    if (!s || !out)
        return -1;

    if (parse_u32_decimal(s, &value) != 0)
        return -1;

    if (value > 255)
        return -1;

    *out = (uint8_t)value;
    return 0;
}

static int parse_ip(const char *str, uint32_t *ip)
{
    struct in_addr addr;

    if (!str || !ip)
        return -1;
    if (str[0] == '\0')
        return -1;

    if (inet_pton(AF_INET, str, &addr) != 1)
        return -1;

    *ip = addr.s_addr;
    return 0;
}

static int parse_ip_with_wildcard(const char *str, uint32_t *ip)
{
    if (!ip)
        return -1;

    if (!str || str[0] == '\0' || str_ieq(str, "0.0.0.0") || str_ieq(str, "any")) {
        *ip = 0;
        return 0;
    }

    return parse_ip(str, ip);
}

static int parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int b0;
    unsigned int b1;
    unsigned int b2;
    unsigned int b3;
    unsigned int b4;
    unsigned int b5;
    char extra;
    int n;

    if (!str || !mac)
        return -1;

    n = sscanf(str,
               "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &b0, &b1, &b2, &b3, &b4, &b5, &extra);
    if (n != 6)
        return -1;

    if (b0 > 0xFF || b1 > 0xFF || b2 > 0xFF ||
        b3 > 0xFF || b4 > 0xFF || b5 > 0xFF)
        return -1;

    mac[0] = (uint8_t)b0;
    mac[1] = (uint8_t)b1;
    mac[2] = (uint8_t)b2;
    mac[3] = (uint8_t)b3;
    mac[4] = (uint8_t)b4;
    mac[5] = (uint8_t)b5;

    return 0;
}

static int parse_mac_prefix(const char *prefix, uint8_t oui[3])
{
    unsigned int b0;
    unsigned int b1;
    unsigned int b2;
    char extra;
    int n;

    if (!prefix || !oui)
        return -1;

    n = sscanf(prefix, "%2x:%2x:%2x%c", &b0, &b1, &b2, &extra);
    if (n != 3)
        return -1;

    if (b0 > 0xFF || b1 > 0xFF || b2 > 0xFF)
        return -1;

    oui[0] = (uint8_t)b0;
    oui[1] = (uint8_t)b1;
    oui[2] = (uint8_t)b2;

    return 0;
}

static int proto_str_to_num(const char *s)
{
    uint8_t numeric = 0;

    if (!s || s[0] == '\0' || str_ieq(s, "any"))
        return 0;

    if (str_ieq(s, "tcp"))
        return IPPROTO_TCP;

    if (str_ieq(s, "udp"))
        return IPPROTO_UDP;

    if (str_ieq(s, "icmp"))
        return IPPROTO_ICMP;

    if (parse_u8_decimal(s, &numeric) == 0)
        return (int)numeric;

    return -1;
}

static int action_str_to_num(const char *s)
{
    uint8_t numeric = 0;

    if (!s || s[0] == '\0')
        return JZ_ACTION_PASS;

    if (str_ieq(s, "pass"))
        return JZ_ACTION_PASS;

    if (str_ieq(s, "drop"))
        return JZ_ACTION_DROP;

    if (str_ieq(s, "redirect"))
        return JZ_ACTION_REDIRECT;

    if (str_ieq(s, "mirror"))
        return JZ_ACTION_MIRROR;

    if (str_ieq(s, "redirect_mirror"))
        return JZ_ACTION_REDIRECT_MIRROR;

    if (parse_u8_decimal(s, &numeric) == 0 && numeric <= JZ_ACTION_REDIRECT_MIRROR)
        return (int)numeric;

    return -1;
}

static int threat_level_str_to_num(const char *s)
{
    uint8_t numeric = 0;

    if (!s || s[0] == '\0')
        return -1;

    if (str_ieq(s, "low"))
        return 1;

    if (str_ieq(s, "medium"))
        return 2;

    if (str_ieq(s, "high"))
        return 3;

    if (str_ieq(s, "critical"))
        return 4;

    if (parse_u8_decimal(s, &numeric) == 0 && numeric >= 1 && numeric <= 4)
        return (int)numeric;

    return -1;
}

static int threat_action_str_to_num(const char *s)
{
    uint8_t numeric = 0;

    if (!s || s[0] == '\0')
        return -1;

    if (str_ieq(s, "log_only"))
        return 0;

    if (str_ieq(s, "log_drop"))
        return 1;

    if (str_ieq(s, "log_redirect"))
        return 2;

    if (parse_u8_decimal(s, &numeric) == 0 && numeric <= 2)
        return (int)numeric;

    return -1;
}

static void trim_in_place(char *s)
{
    char *start;
    char *end;

    if (!s)
        return;

    start = s;
    while (*start && isspace((unsigned char)*start))
        start++;

    if (start != s)
        memmove(s, start, strlen(start) + 1U);

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;

    *end = '\0';
}

static int parse_pattern_id(const char *id, uint32_t *pattern_id)
{
    char *end = NULL;
    unsigned long value;

    if (!id || !pattern_id || id[0] == '\0')
        return -1;

    value = strtoul(id, &end, 0);
    if (end == id || *end != '\0')
        return -1;
    if (value > UINT_MAX)
        return -1;

    *pattern_id = (uint32_t)value;
    return 0;
}

static int add_bg_filter(jz_config_map_batch_t *batch,
                         uint32_t bg_proto,
                         uint16_t ethertype,
                         uint16_t udp_port,
                         uint8_t capture,
                         uint8_t sample_rate,
                         uint8_t include_payload)
{
    int idx;
    struct jz_bg_filter_entry *entry;

    if (!batch)
        return -1;

    if (batch->bg_filters.count < 0 || batch->bg_filters.count >= JZ_MAP_MAX_BG_FILTERS)
        return -1;

    idx = batch->bg_filters.count;
    entry = &batch->bg_filters.values[idx];

    memset(entry, 0, sizeof(*entry));
    entry->ethertype = ethertype;
    entry->udp_port = udp_port;
    entry->capture = capture;
    entry->sample_rate = sample_rate;
    entry->include_payload = include_payload;

    batch->bg_filters.keys[idx] = bg_proto;
    batch->bg_filters.count++;

    return 0;
}

static int translate_guards(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    uint64_t ts;
    int i;

    if (!cfg || !batch)
        return -1;

    if (cfg->guards.static_count < 0 || cfg->guards.static_count > JZ_MAP_MAX_STATIC_GUARDS)
        return -1;

    ts = now_unix_sec();

    for (i = 0; i < cfg->guards.static_count; i++) {
        const jz_config_guard_static_t *src = &cfg->guards.static_entries[i];
        struct jz_guard_entry *dst = &batch->static_guards.values[batch->static_guards.count];
        uint32_t ip;

        if (parse_ip(src->ip, &ip) != 0)
            return -1;

        memset(dst, 0, sizeof(*dst));
        dst->ip_addr = ip;
        dst->guard_type = JZ_GUARD_STATIC;
        dst->enabled = cfg->modules.guard_classifier.enabled ? 1U : 0U;

        if (src->mac[0] != '\0') {
            if (parse_mac(src->mac, dst->fake_mac) != 0)
                return -1;
        }

        if (src->vlan < 0 || src->vlan > 4095)
            return -1;

        dst->vlan_id = (uint16_t)src->vlan;
        dst->flags = 0;
        dst->created_at = ts;
        dst->last_hit = 0;
        dst->hit_count = 0;

        batch->static_guards.keys[batch->static_guards.count] = ip;
        batch->static_guards.count++;
    }

    return 0;
}

static int translate_whitelist(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    uint64_t ts;
    int i;

    if (!cfg || !batch)
        return -1;

    if (cfg->guards.whitelist_count < 0 || cfg->guards.whitelist_count > JZ_MAP_MAX_WHITELIST)
        return -1;

    ts = now_unix_sec();

    for (i = 0; i < cfg->guards.whitelist_count; i++) {
        const jz_config_whitelist_t *src = &cfg->guards.whitelist[i];
        struct jz_whitelist_entry *dst = &batch->whitelist.values[batch->whitelist.count];
        uint32_t ip;

        if (parse_ip(src->ip, &ip) != 0)
            return -1;

        memset(dst, 0, sizeof(*dst));
        dst->ip_addr = ip;
        dst->match_mac = src->match_mac ? 1U : 0U;
        dst->enabled = 1;
        dst->created_at = ts;

        if (src->mac[0] != '\0') {
            if (parse_mac(src->mac, dst->mac) != 0)
                return -1;
        } else if (src->match_mac) {
            return -1;
        }

        batch->whitelist.keys[batch->whitelist.count] = ip;
        batch->whitelist.count++;
    }

    return 0;
}

static int policy_priority_for_index(int index, int total)
{
    int priority;

    if (index < 0 || total <= 0)
        return 0;

    priority = total - index;
    if (priority < 0)
        priority = 0;
    if (priority > 255)
        priority = 255;

    return priority;
}

static int translate_policies(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    uint64_t ts;
    int i;

    if (!cfg || !batch)
        return -1;

    if (cfg->policy_count < 0 || cfg->policy_count > JZ_MAP_MAX_POLICIES)
        return -1;

    ts = now_unix_sec();

    for (i = 0; i < cfg->policy_count; i++) {
        const jz_config_policy_t *src = &cfg->policies[i];
        struct jz_flow_key *key = &batch->policies.keys[batch->policies.count];
        struct jz_flow_policy *value = &batch->policies.values[batch->policies.count];
        int proto_num;
        int action_num;

        memset(key, 0, sizeof(*key));
        memset(value, 0, sizeof(*value));

        if (parse_ip_with_wildcard(src->src_ip, &key->src_ip) != 0)
            return -1;

        if (parse_ip_with_wildcard(src->dst_ip, &key->dst_ip) != 0)
            return -1;

        if (src->src_port < 0 || src->src_port > 65535)
            return -1;
        if (src->dst_port < 0 || src->dst_port > 65535)
            return -1;

        key->src_port = (uint16_t)src->src_port;
        key->dst_port = (uint16_t)src->dst_port;

        proto_num = proto_str_to_num(src->proto);
        if (proto_num < 0)
            return -1;
        key->proto = (uint8_t)proto_num;

        action_num = action_str_to_num(src->action);
        if (action_num < 0)
            return -1;

        if (src->redirect_port < 0 || src->redirect_port > 255)
            return -1;
        if (src->mirror_port < 0 || src->mirror_port > 255)
            return -1;

        value->action = (uint8_t)action_num;
        value->redirect_port = (uint8_t)src->redirect_port;
        value->mirror_port = (uint8_t)src->mirror_port;
        value->priority = (uint8_t)policy_priority_for_index(i, cfg->policy_count);
        value->flags = 0;
        value->created_at = ts;
        value->hit_count = 0;
        value->byte_count = 0;

        batch->policies.count++;
    }

    return 0;
}

static int translate_threats(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    int i;

    if (!cfg || !batch)
        return -1;

    if (cfg->threats.pattern_count < 0 || cfg->threats.pattern_count > JZ_MAP_MAX_THREAT_PATTERNS)
        return -1;

    for (i = 0; i < cfg->threats.pattern_count; i++) {
        const jz_config_threat_pattern_t *src = &cfg->threats.patterns[i];
        struct jz_threat_pattern *dst = &batch->threat_patterns.values[batch->threat_patterns.count];
        uint32_t pattern_id;
        int proto_num;
        int level_num;
        int action_num;

        memset(dst, 0, sizeof(*dst));

        if (parse_pattern_id(src->id, &pattern_id) != 0)
            return -1;

        if (src->dst_port < 0 || src->dst_port > 65535)
            return -1;

        proto_num = proto_str_to_num(src->proto);
        if (proto_num < 0)
            return -1;

        level_num = threat_level_str_to_num(src->threat_level);
        if (level_num < 0)
            return -1;

        action_num = threat_action_str_to_num(src->action);
        if (action_num < 0)
            return -1;

        dst->src_ip = 0;
        dst->dst_ip = 0;
        dst->dst_port = (uint16_t)src->dst_port;
        dst->proto = (uint8_t)proto_num;
        dst->threat_level = (uint8_t)level_num;
        dst->pattern_id = pattern_id;
        dst->action = (uint8_t)action_num;

        snprintf(dst->description, sizeof(dst->description), "%s", src->description);

        batch->threat_patterns.keys[batch->threat_patterns.count] = pattern_id;
        batch->threat_patterns.count++;
    }

    return 0;
}

static int translate_module_configs(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    if (!cfg || !batch)
        return -1;

    memset(&batch->arp_config, 0, sizeof(batch->arp_config));
    batch->arp_config.enabled = cfg->modules.arp_honeypot.common.enabled ? 1U : 0U;
    batch->arp_config.log_all = cfg->modules.arp_honeypot.log_all ? 1U : 0U;
    batch->arp_config.rate_limit_pps = (uint16_t)clamp_u16(cfg->modules.arp_honeypot.rate_limit_pps);
    batch->arp_config._pad = 0;

    memset(&batch->icmp_config, 0, sizeof(batch->icmp_config));
    batch->icmp_config.enabled = cfg->modules.icmp_honeypot.common.enabled ? 1U : 0U;
    if (cfg->modules.icmp_honeypot.ttl <= 0)
        batch->icmp_config.ttl = 64;
    else
        batch->icmp_config.ttl = (uint8_t)clamp_u8(cfg->modules.icmp_honeypot.ttl);
    batch->icmp_config.rate_limit_pps = (uint16_t)clamp_u16(cfg->modules.icmp_honeypot.rate_limit_pps);
    batch->icmp_config._pad = 0;

    memset(&batch->sample_config, 0, sizeof(batch->sample_config));
    batch->sample_config.enabled = cfg->modules.forensics.common.enabled ? 1U : 0U;
    batch->sample_config._pad = 0;
    batch->sample_config.max_payload_bytes =
        (uint16_t)clamp_u16(cfg->modules.forensics.max_payload_bytes);

    if (cfg->modules.forensics.sample_rate < 0)
        batch->sample_config.sample_rate = 0;
    else
        batch->sample_config.sample_rate = (uint32_t)cfg->modules.forensics.sample_rate;

    return 0;
}

static int translate_bg_filters(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    uint8_t sample_rate;
    uint8_t include_payload;

    if (!cfg || !batch)
        return -1;

    sample_rate = (uint8_t)clamp_u8(cfg->modules.bg_collector.sample_rate);
    if (sample_rate == 0)
        sample_rate = 1;

    include_payload = cfg->modules.forensics.common.enabled ? 1U : 0U;

    if (cfg->modules.bg_collector.protocols.arp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_ARP, JZ_ETH_P_ARP, 0, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.dhcp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_DHCP, 0, 67, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.mdns) {
        if (add_bg_filter(batch, JZ_BG_PROTO_MDNS, 0, 5353, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.ssdp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_SSDP, 0, 1900, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.lldp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_LLDP, JZ_ETH_P_LLDP, 0, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.cdp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_CDP, 0, 0, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.stp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_STP, 0, 0, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    if (cfg->modules.bg_collector.protocols.igmp) {
        if (add_bg_filter(batch, JZ_BG_PROTO_IGMP, 0, 0, 1, sample_rate, include_payload) != 0)
            return -1;
    }

    return 0;
}

int jz_config_generate_macs(const char *prefix, int count, jz_config_map_batch_t *batch)
{
    uint8_t oui[3];
    int i;

    if (!batch)
        return -1;

    if (count < 0 || count > JZ_MAP_MAX_FAKE_MACS)
        return -1;

    if (count > 0) {
        if (!prefix || parse_mac_prefix(prefix, oui) != 0)
            return -1;
    } else {
        oui[0] = 0;
        oui[1] = 0;
        oui[2] = 0;
    }

    memset(&batch->fake_macs, 0, sizeof(batch->fake_macs));

    for (i = 0; i < count; i++) {
        struct jz_fake_mac *dst = &batch->fake_macs.entries[i];
        uint32_t tail = (uint32_t)(i + 1);

        memset(dst, 0, sizeof(*dst));
        dst->mac[0] = oui[0];
        dst->mac[1] = oui[1];
        dst->mac[2] = oui[2];
        dst->mac[3] = (uint8_t)((tail >> 16) & 0xFFU);
        dst->mac[4] = (uint8_t)((tail >> 8) & 0xFFU);
        dst->mac[5] = (uint8_t)(tail & 0xFFU);
        dst->in_use = 1;
        dst->_pad = 0;
        dst->assigned_ip = 0;
    }

    batch->fake_macs.count = count;
    return 0;
}

int jz_config_load_blacklist(const char *path, jz_config_map_batch_t *batch)
{
    FILE *fp;
    char line[256];
    uint64_t ts;

    if (!path || !batch)
        return -1;

    if (path[0] == '\0')
        return 0;

    if (batch->threat_blacklist.count < 0 ||
        batch->threat_blacklist.count > JZ_MAP_MAX_THREAT_BLACKLIST)
        return -1;

    fp = fopen(path, "r");
    if (!fp)
        return 0;   /* missing file = empty blacklist, not fatal */

    ts = now_unix_sec();

    while (fgets(line, sizeof(line), fp) != NULL) {
        uint32_t ip;
        int idx;

        trim_in_place(line);

        if (line[0] == '\0')
            continue;
        if (line[0] == '#')
            continue;

        if (parse_ip(line, &ip) != 0) {
            fclose(fp);
            return -1;
        }

        if (batch->threat_blacklist.count >= JZ_MAP_MAX_THREAT_BLACKLIST)
            break;

        idx = batch->threat_blacklist.count;
        batch->threat_blacklist.keys[idx] = ip;
        batch->threat_blacklist.values[idx] = ts;
        batch->threat_blacklist.count++;
    }

    fclose(fp);
    return 0;
}

int jz_config_to_maps(const jz_config_t *cfg, jz_config_map_batch_t *batch)
{
    if (!cfg || !batch)
        return -1;

    memset(batch, 0, sizeof(*batch));

    if (translate_guards(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_guards failed");
        return -1;
    }

    if (translate_whitelist(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_whitelist failed");
        return -1;
    }

    if (translate_policies(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_policies failed");
        return -1;
    }

    if (translate_threats(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_threats failed");
        return -1;
    }

    if (translate_module_configs(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_module_configs failed");
        return -1;
    }

    if (translate_bg_filters(cfg, batch) != 0) {
        jz_log_error("config_to_maps: translate_bg_filters failed");
        return -1;
    }

    if (jz_config_generate_macs(cfg->fake_mac_pool.prefix,
                                cfg->fake_mac_pool.count,
                                batch) != 0) {
        jz_log_error("config_to_maps: generate_macs failed (prefix=%s, count=%d)",
                     cfg->fake_mac_pool.prefix ? cfg->fake_mac_pool.prefix : "NULL",
                     cfg->fake_mac_pool.count);
        return -1;
    }

    if (cfg->threats.blacklist_file[0] != '\0') {
        if (jz_config_load_blacklist(cfg->threats.blacklist_file, batch) != 0) {
            jz_log_error("config_to_maps: load_blacklist failed (%s)",
                         cfg->threats.blacklist_file);
            return -1;
        }
    }

    return 0;
}
