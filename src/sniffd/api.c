/* SPDX-License-Identifier: MIT */
/* api.c - REST API HTTPS server for sniffd. */

#include "api.h"

#if __has_include(<mongoose.h>)
#include <mongoose.h>
#elif __has_include("../../third_party/mongoose/mongoose.h")
#include "../../third_party/mongoose/mongoose.h"
#else
#include <mongoose.h>
#endif

#if __has_include(<cJSON.h>)
#include <cJSON.h>
#elif __has_include("../../third_party/cjson/cJSON.h")
#include "../../third_party/cjson/cJSON.h"
#else
#include <cJSON.h>
#endif

#include "bpf_loader.h"
#include "discovery.h"
#include "guard_auto.h"
#include "guard_mgr.h"
#include "policy_mgr.h"
#include "config.h"
#include "config_map.h"
#include "db.h"
#include "log.h"
#include "ipc.h"

#include <bpf/bpf.h>
#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#define JZ_API_VERSION "0.8.0"

#ifndef JZ_WWW_ROOT
#define JZ_WWW_ROOT "/usr/share/jz/www"
#endif

typedef struct {
    bool tls_ok;
} jz_api_conn_state_t;

struct jz_bpf_guard_entry {
    uint32_t ip_addr;
    uint8_t fake_mac[6];
    uint8_t guard_type;
    uint8_t enabled;
    uint16_t vlan_id;
    uint16_t flags;
    uint64_t created_at;
    uint64_t last_hit;
    uint64_t hit_count;
};

struct jz_bpf_whitelist_entry {
    uint32_t ip_addr;
    uint8_t mac[6];
    uint8_t match_mac;
    uint8_t enabled;
    uint64_t created_at;
};

static time_t g_api_start_ts;

static int read_file_to_pem(const char *path, char **out_buf)
{
    if (!path || !path[0] || !out_buf)
        return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buf = (char *) malloc((size_t) sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t) sz, fp);
    fclose(fp);

    if (nread != (size_t) sz) {
        free(buf);
        return -1;
    }

    buf[sz] = '\0';
    *out_buf = buf;
    return 0;
}

static int api_mg_str_to_cstr(struct mg_str s, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return -1;
    if (!s.buf || s.len == 0) {
        out[0] = '\0';
        return 0;
    }
    if (s.len >= out_len)
        return -1;
    memcpy(out, s.buf, s.len);
    out[s.len] = '\0';
    return 0;
}

static void api_mac_to_text(const uint8_t mac[6], char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    (void) snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void api_ip_to_text(uint32_t ip, char *out, size_t out_len)
{
    struct in_addr addr;

    if (!out || out_len == 0)
        return;
    addr.s_addr = ip;
    if (!inet_ntop(AF_INET, &addr, out, (socklen_t) out_len))
        (void) snprintf(out, out_len, "0.0.0.0");
}

static bool api_auth_check(struct mg_http_message *hm, const jz_api_t *api)
{
    const char *need;
    size_t need_len;
    struct mg_str *hdr;
    const char *prefix = "Bearer ";
    size_t prefix_len = 7;

    if (!hm || !api)
        return false;

    need = api->auth_token;
    if (!need || need[0] == '\0')
        return true;

    need_len = strlen(need);
    hdr = mg_http_get_header(hm, "Authorization");
    if (!hdr || !hdr->buf || hdr->len <= prefix_len)
        return false;
    if (memcmp(hdr->buf, prefix, prefix_len) != 0)
        return false;
    if (hdr->len != prefix_len + need_len)
        return false;
    return memcmp(hdr->buf + prefix_len, need, need_len) == 0;
}

static void api_json_reply(struct mg_connection *c, int status, cJSON *json)
{
    char *payload;

    if (!c) {
        cJSON_Delete(json);
        return;
    }

    payload = cJSON_PrintUnformatted(json);
    if (!payload) {
        cJSON_Delete(json);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n",
                      "{\"error\":\"json encode failed\"}\n");
        return;
    }

    mg_http_reply(c, status,
                  "Content-Type: application/json\r\n",
                  "%s\n", payload);
    cJSON_free(payload);
    cJSON_Delete(json);
}

/* forward declaration – defined after frozen/config handlers */
static void api_audit_log(jz_api_t *api, const char *action, const char *target,
                          const char *details, const char *result);

static void api_error_reply(struct mg_connection *c, int status, const char *message)
{
    cJSON *root = cJSON_CreateObject();

    if (!root) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n",
                      "{\"error\":\"oom\"}\n");
        return;
    }
    cJSON_AddStringToObject(root, "error", message ? message : "error");
    api_json_reply(c, status, root);
}

static int api_parse_query_int(struct mg_http_message *hm, const char *name, int default_val)
{
    char buf[32];
    char *end = NULL;
    long v;

    if (!hm || !name)
        return default_val;
    if (mg_http_get_var(&hm->query, name, buf, sizeof(buf)) <= 0)
        return default_val;

    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0')
        return default_val;
    if (v < INT32_MIN || v > INT32_MAX)
        return default_val;
    return (int) v;
}

static int api_parse_query_str(struct mg_http_message *hm, const char *name,
                               char *out, size_t out_len)
{
    int n;

    if (!hm || !name || !out || out_len == 0)
        return -1;
    n = mg_http_get_var(&hm->query, name, out, out_len);
    if (n <= 0) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

static cJSON *api_parse_body_json(const struct mg_http_message *hm)
{
    char *tmp;
    cJSON *root;

    if (!hm || hm->body.len == 0 || !hm->body.buf)
        return NULL;

    tmp = (char *) malloc(hm->body.len + 1);
    if (!tmp)
        return NULL;
    memcpy(tmp, hm->body.buf, hm->body.len);
    tmp[hm->body.len] = '\0';

    root = cJSON_Parse(tmp);
    free(tmp);
    return root;
}

static int api_db_open_readonly(const jz_api_t *api, sqlite3 **out_db)
{
    const char *path = NULL;

    if (!api || !out_db || !api->db)
        return -1;

    if (api->db->path[0])
        path = api->db->path;
    else if (api->db->db)
        path = sqlite3_db_filename(api->db->db, "main");

    if (!path || !path[0])
        return -1;

    if (sqlite3_open_v2(path, out_db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return -1;

    return 0;
}

static int api_query_db(jz_api_t *api, const char *sql, ...)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    va_list ap;
    int idx = 1;
    const char *s;
    int rc;
    int out = -1;

    if (!api || !sql)
        return -1;

    if (api_db_open_readonly(api, &db) < 0)
        return -1;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto done;

    va_start(ap, sql);
    for (;;) {
        s = va_arg(ap, const char *);
        if (!s)
            break;
        (void) sqlite3_bind_text(stmt, idx++, s, -1, SQLITE_TRANSIENT);
    }
    va_end(ap);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        out = sqlite3_column_int(stmt, 0);

done:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);
    return out;
}

static cJSON *api_guard_entry_json(uint32_t ip, const uint8_t mac[6], uint8_t guard_type,
                                   uint8_t enabled, uint16_t vlan_id,
                                   uint64_t created_at_ns, uint32_t ttl_sec)
{
    cJSON *obj = cJSON_CreateObject();
    char ipbuf[INET_ADDRSTRLEN];
    char macbuf[18];

    if (!obj)
        return NULL;

    api_ip_to_text(ip, ipbuf, sizeof(ipbuf));
    api_mac_to_text(mac, macbuf, sizeof(macbuf));

    cJSON_AddStringToObject(obj, "ip", ipbuf);
    cJSON_AddStringToObject(obj, "mac", macbuf);
    cJSON_AddStringToObject(obj, "type", (guard_type == JZ_GUARD_STATIC) ? "static" : "dynamic");
    cJSON_AddBoolToObject(obj, "enabled", enabled ? 1 : 0);
    cJSON_AddNumberToObject(obj, "vlan", vlan_id);
    cJSON_AddNumberToObject(obj, "created_at_ns", (double) created_at_ns);
    if (ttl_sec > 0)
        cJSON_AddNumberToObject(obj, "ttl_sec", ttl_sec);
    return obj;
}

static int api_add_static_guards_to_array(const jz_guard_mgr_t *gm, cJSON *arr)
{
    uint32_t key;
    uint32_t next_key;
    const uint32_t *key_ptr = NULL;
    int count = 0;

    if (!gm || !arr || gm->static_map_fd < 0)
        return 0;

    while (bpf_map_get_next_key(gm->static_map_fd, key_ptr, &next_key) == 0) {
        struct jz_bpf_guard_entry val;
        if (bpf_map_lookup_elem(gm->static_map_fd, &next_key, &val) == 0) {
            cJSON *obj = api_guard_entry_json(next_key, val.fake_mac, val.guard_type,
                                              val.enabled, val.vlan_id,
                                              val.created_at, 0);
            if (obj)
                cJSON_AddItemToArray(arr, obj);
            count++;
        }
        key = next_key;
        key_ptr = &key;
    }

    return count;
}

static int api_add_dynamic_guards_to_array(const jz_guard_mgr_t *gm, cJSON *arr)
{
    int i;
    int count = 0;

    if (!gm || !arr)
        return 0;

    for (i = 0; i < JZ_GUARD_MGR_MAX_DYNAMIC; i++) {
        const jz_guard_entry_user_t *e = &gm->dynamic_entries[i];
        cJSON *obj;
        if (!e->enabled)
            continue;
        obj = api_guard_entry_json(e->ip, e->mac, e->guard_type,
                                   e->enabled, e->vlan_id,
                                   e->created_at, e->ttl_sec);
        if (obj)
            cJSON_AddItemToArray(arr, obj);
        count++;
    }

    return count;
}

static int api_add_whitelist_to_array(const jz_guard_mgr_t *gm, cJSON *arr)
{
    uint32_t key;
    uint32_t next_key;
    const uint32_t *key_ptr = NULL;
    int count = 0;

    if (!gm || !arr || gm->whitelist_map_fd < 0)
        return 0;

    while (bpf_map_get_next_key(gm->whitelist_map_fd, key_ptr, &next_key) == 0) {
        struct jz_bpf_whitelist_entry val;
        if (bpf_map_lookup_elem(gm->whitelist_map_fd, &next_key, &val) == 0) {
            cJSON *obj = cJSON_CreateObject();
            char ipbuf[INET_ADDRSTRLEN];
            char macbuf[18];
            if (obj) {
                api_ip_to_text(next_key, ipbuf, sizeof(ipbuf));
                api_mac_to_text(val.mac, macbuf, sizeof(macbuf));
                cJSON_AddStringToObject(obj, "ip", ipbuf);
                cJSON_AddStringToObject(obj, "mac", macbuf);
                cJSON_AddBoolToObject(obj, "match_mac", val.match_mac ? 1 : 0);
                cJSON_AddBoolToObject(obj, "enabled", val.enabled ? 1 : 0);
                cJSON_AddNumberToObject(obj, "created_at_ns", (double) val.created_at);
                cJSON_AddItemToArray(arr, obj);
            }
            count++;
        }
        key = next_key;
        key_ptr = &key;
    }

    return count;
}

static int api_guard_op_add(jz_api_t *api, uint32_t ip, const uint8_t mac[6],
                            uint8_t guard_type, uint16_t vlan_id)
{
    char reply[512];
    int rc;

    if (!api || !api->guard_mgr)
        return -1;

    rc = jz_guard_mgr_add(api->guard_mgr, ip, mac, guard_type, vlan_id,
                          reply, sizeof(reply));
    if (rc < 0)
        return -1;
    if (strstr(reply, "error"))
        return -1;
    return 0;
}

static int api_guard_op_remove(jz_api_t *api, uint32_t ip)
{
    char reply[512];
    int rc;

    if (!api || !api->guard_mgr)
        return -1;

    rc = jz_guard_mgr_remove(api->guard_mgr, ip, reply, sizeof(reply));
    if (rc < 0)
        return -1;
    if (strstr(reply, "error"))
        return -1;
    return 0;
}

static int api_parse_ipv4(const char *ip_str, uint32_t *out_ip)
{
    struct in_addr addr;
    if (!ip_str || !out_ip)
        return -1;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -1;
    *out_ip = addr.s_addr;
    return 0;
}

static int api_parse_mac(const char *mac_str, uint8_t out_mac[6])
{
    if (!mac_str || !out_mac)
        return -1;
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out_mac[0], &out_mac[1], &out_mac[2],
               &out_mac[3], &out_mac[4], &out_mac[5]) != 6) {
        return -1;
    }
    return 0;
}

static int api_configd_request(const char *req, jz_ipc_msg_t *reply)
{
    jz_ipc_client_t cli;
    int rc;

    if (!req || !reply)
        return -1;

    rc = jz_ipc_client_connect(&cli, JZ_IPC_SOCK_CONFIGD, JZ_IPC_DEFAULT_TIMEOUT_MS);
    if (rc < 0)
        return -1;

    rc = jz_ipc_client_request(&cli, req, (uint32_t) strlen(req), reply);
    jz_ipc_client_close(&cli);
    return rc;
}

static cJSON *api_add_module_enabled_stage(cJSON *parent, const char *name,
                                           bool enabled, int stage)
{
    cJSON *obj;

    if (!parent || !name)
        return NULL;
    obj = cJSON_AddObjectToObject(parent, name);
    if (!obj)
        return NULL;
    cJSON_AddBoolToObject(obj, "enabled", enabled ? 1 : 0);
    cJSON_AddNumberToObject(obj, "stage", stage);
    return obj;
}

static void api_add_config_modules_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *modules;
    cJSON *arp;
    cJSON *icmp;
    cJSON *sniffer;
    cJSON *traffic;
    cJSON *bg;
    cJSON *forensics;
    cJSON *protos;

    if (!root || !cfg)
        return;

    modules = cJSON_AddObjectToObject(root, "modules");
    if (!modules)
        return;

    (void) api_add_module_enabled_stage(modules,
                                        "guard_classifier",
                                        cfg->modules.guard_classifier.enabled,
                                        cfg->modules.guard_classifier.stage);

    arp = api_add_module_enabled_stage(modules,
                                       "arp_honeypot",
                                       cfg->modules.arp_honeypot.common.enabled,
                                       cfg->modules.arp_honeypot.common.stage);
    if (arp) {
        cJSON_AddNumberToObject(arp, "rate_limit_pps", cfg->modules.arp_honeypot.rate_limit_pps);
        cJSON_AddBoolToObject(arp, "log_all", cfg->modules.arp_honeypot.log_all ? 1 : 0);
    }

    icmp = api_add_module_enabled_stage(modules,
                                        "icmp_honeypot",
                                        cfg->modules.icmp_honeypot.common.enabled,
                                        cfg->modules.icmp_honeypot.common.stage);
    if (icmp) {
        cJSON_AddNumberToObject(icmp, "ttl", cfg->modules.icmp_honeypot.ttl);
        cJSON_AddNumberToObject(icmp, "rate_limit_pps", cfg->modules.icmp_honeypot.rate_limit_pps);
    }

    sniffer = api_add_module_enabled_stage(modules,
                                           "sniffer_detect",
                                           cfg->modules.sniffer_detect.common.enabled,
                                           cfg->modules.sniffer_detect.common.stage);
    if (sniffer) {
        cJSON_AddNumberToObject(sniffer, "probe_interval_sec", cfg->modules.sniffer_detect.probe_interval_sec);
        cJSON_AddNumberToObject(sniffer, "probe_count", cfg->modules.sniffer_detect.probe_count);
    }

    traffic = api_add_module_enabled_stage(modules,
                                           "traffic_weaver",
                                           cfg->modules.traffic_weaver.common.enabled,
                                           cfg->modules.traffic_weaver.common.stage);
    if (traffic)
        cJSON_AddStringToObject(traffic, "default_action", cfg->modules.traffic_weaver.default_action);

    bg = api_add_module_enabled_stage(modules,
                                      "bg_collector",
                                      cfg->modules.bg_collector.common.enabled,
                                      cfg->modules.bg_collector.common.stage);
    if (bg) {
        cJSON_AddNumberToObject(bg, "sample_rate", cfg->modules.bg_collector.sample_rate);
        protos = cJSON_AddObjectToObject(bg, "protocols");
        if (protos) {
            cJSON_AddBoolToObject(protos, "arp", cfg->modules.bg_collector.protocols.arp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "dhcp", cfg->modules.bg_collector.protocols.dhcp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "mdns", cfg->modules.bg_collector.protocols.mdns ? 1 : 0);
            cJSON_AddBoolToObject(protos, "ssdp", cfg->modules.bg_collector.protocols.ssdp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "lldp", cfg->modules.bg_collector.protocols.lldp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "cdp", cfg->modules.bg_collector.protocols.cdp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "stp", cfg->modules.bg_collector.protocols.stp ? 1 : 0);
            cJSON_AddBoolToObject(protos, "igmp", cfg->modules.bg_collector.protocols.igmp ? 1 : 0);
        }
    }

    (void) api_add_module_enabled_stage(modules,
                                        "threat_detect",
                                        cfg->modules.threat_detect.enabled,
                                        cfg->modules.threat_detect.stage);

    forensics = api_add_module_enabled_stage(modules,
                                             "forensics",
                                             cfg->modules.forensics.common.enabled,
                                             cfg->modules.forensics.common.stage);
    if (forensics) {
        cJSON_AddNumberToObject(forensics, "max_payload_bytes", cfg->modules.forensics.max_payload_bytes);
        cJSON_AddNumberToObject(forensics, "sample_rate", cfg->modules.forensics.sample_rate);
    }
}

static void api_add_config_guards_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *guards;
    cJSON *static_arr;
    cJSON *wl_arr;
    cJSON *dyn;
    int i;

    if (!root || !cfg)
        return;

    guards = cJSON_AddObjectToObject(root, "guards");
    if (!guards)
        return;

    static_arr = cJSON_AddArrayToObject(guards, "static");
    for (i = 0; i < cfg->guards.static_count; i++) {
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "ip", cfg->guards.static_entries[i].ip);
        cJSON_AddStringToObject(o, "mac", cfg->guards.static_entries[i].mac);
        cJSON_AddNumberToObject(o, "vlan", cfg->guards.static_entries[i].vlan);
        cJSON_AddItemToArray(static_arr, o);
    }

    dyn = cJSON_AddObjectToObject(guards, "dynamic");
    if (dyn) {
        cJSON_AddBoolToObject(dyn, "auto_discover", cfg->guards.dynamic.auto_discover ? 1 : 0);
        cJSON_AddNumberToObject(dyn, "max_entries", cfg->guards.dynamic.max_entries);
        cJSON_AddNumberToObject(dyn, "ttl_hours", cfg->guards.dynamic.ttl_hours);
    }

    wl_arr = cJSON_AddArrayToObject(guards, "whitelist");
    for (i = 0; i < cfg->guards.whitelist_count; i++) {
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "ip", cfg->guards.whitelist[i].ip);
        cJSON_AddStringToObject(o, "mac", cfg->guards.whitelist[i].mac);
        cJSON_AddBoolToObject(o, "match_mac", cfg->guards.whitelist[i].match_mac ? 1 : 0);
        cJSON_AddItemToArray(wl_arr, o);
    }
}

static void api_add_config_policies_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *arr;
    int i;

    if (!root || !cfg)
        return;

    arr = cJSON_AddArrayToObject(root, "policies");
    for (i = 0; i < cfg->policy_count; i++) {
        const jz_config_policy_t *p = &cfg->policies[i];
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "src_ip", p->src_ip);
        cJSON_AddStringToObject(o, "dst_ip", p->dst_ip);
        cJSON_AddNumberToObject(o, "src_port", p->src_port);
        cJSON_AddNumberToObject(o, "dst_port", p->dst_port);
        cJSON_AddStringToObject(o, "proto", p->proto);
        cJSON_AddStringToObject(o, "action", p->action);
        cJSON_AddNumberToObject(o, "redirect_port", p->redirect_port);
        cJSON_AddNumberToObject(o, "mirror_port", p->mirror_port);
        cJSON_AddItemToArray(arr, o);
    }
}

static void api_add_config_threats_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *threats;
    cJSON *arr;
    int i;

    if (!root || !cfg)
        return;

    threats = cJSON_AddObjectToObject(root, "threats");
    if (!threats)
        return;

    cJSON_AddStringToObject(threats, "blacklist_file", cfg->threats.blacklist_file);
    arr = cJSON_AddArrayToObject(threats, "patterns");
    for (i = 0; i < cfg->threats.pattern_count; i++) {
        const jz_config_threat_pattern_t *p = &cfg->threats.patterns[i];
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "id", p->id);
        cJSON_AddNumberToObject(o, "dst_port", p->dst_port);
        cJSON_AddStringToObject(o, "proto", p->proto);
        cJSON_AddStringToObject(o, "threat_level", p->threat_level);
        cJSON_AddStringToObject(o, "action", p->action);
        cJSON_AddStringToObject(o, "description", p->description);
        cJSON_AddItemToArray(arr, o);
    }
}

static void api_add_config_collector_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *collector;

    if (!root || !cfg)
        return;

    collector = cJSON_AddObjectToObject(root, "collector");
    if (!collector)
        return;

    cJSON_AddStringToObject(collector, "db_path", cfg->collector.db_path);
    cJSON_AddNumberToObject(collector, "max_db_size_mb", cfg->collector.max_db_size_mb);
    cJSON_AddNumberToObject(collector, "dedup_window_sec", cfg->collector.dedup_window_sec);
    cJSON_AddNumberToObject(collector, "rate_limit_eps", cfg->collector.rate_limit_eps);
}

static void api_add_config_uploader_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *uploader;

    if (!root || !cfg)
        return;

    uploader = cJSON_AddObjectToObject(root, "uploader");
    if (!uploader)
        return;

    cJSON_AddBoolToObject(uploader, "enabled", cfg->uploader.enabled ? 1 : 0);
    cJSON_AddStringToObject(uploader, "platform_url", cfg->uploader.platform_url);
    cJSON_AddNumberToObject(uploader, "interval_sec", cfg->uploader.interval_sec);
    cJSON_AddNumberToObject(uploader, "batch_size", cfg->uploader.batch_size);
    cJSON_AddStringToObject(uploader, "tls_cert", cfg->uploader.tls_cert);
    cJSON_AddStringToObject(uploader, "tls_key", cfg->uploader.tls_key);
    cJSON_AddBoolToObject(uploader, "compress", cfg->uploader.compress ? 1 : 0);
}

static void api_add_config_api_json(cJSON *root, const jz_config_t *cfg)
{
    cJSON *api_cfg;
    cJSON *arr;
    int i;

    if (!root || !cfg)
        return;

    api_cfg = cJSON_AddObjectToObject(root, "api");
    if (!api_cfg)
        return;

    cJSON_AddBoolToObject(api_cfg, "enabled", cfg->api.enabled ? 1 : 0);
    cJSON_AddStringToObject(api_cfg, "listen", cfg->api.listen);
    cJSON_AddStringToObject(api_cfg, "tls_cert", cfg->api.tls_cert);
    cJSON_AddStringToObject(api_cfg, "tls_key", cfg->api.tls_key);

    arr = cJSON_AddArrayToObject(api_cfg, "auth_tokens");
    for (i = 0; i < cfg->api.auth_token_count; i++) {
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "token", cfg->api.auth_tokens[i].token);
        cJSON_AddStringToObject(o, "role", cfg->api.auth_tokens[i].role);
        cJSON_AddItemToArray(arr, o);
    }
}

static cJSON *api_config_to_json(const jz_config_t *cfg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *system;
    cJSON *fake_mac_pool;

    if (!root || !cfg) {
        cJSON_Delete(root);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "version", cfg->version);

    system = cJSON_AddObjectToObject(root, "system");
    cJSON_AddStringToObject(system, "device_id", cfg->system.device_id);
    cJSON_AddStringToObject(system, "log_level", cfg->system.log_level);
    cJSON_AddStringToObject(system, "data_dir", cfg->system.data_dir);
    cJSON_AddStringToObject(system, "run_dir", cfg->system.run_dir);

    api_add_config_modules_json(root, cfg);
    api_add_config_guards_json(root, cfg);

    fake_mac_pool = cJSON_AddObjectToObject(root, "fake_mac_pool");
    if (fake_mac_pool) {
        cJSON_AddStringToObject(fake_mac_pool, "prefix", cfg->fake_mac_pool.prefix);
        cJSON_AddNumberToObject(fake_mac_pool, "count", cfg->fake_mac_pool.count);
    }

    api_add_config_policies_json(root, cfg);
    api_add_config_threats_json(root, cfg);
    api_add_config_collector_json(root, cfg);
    api_add_config_uploader_json(root, cfg);
    api_add_config_api_json(root, cfg);

    return root;
}

static void handle_health(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;
    (void) api;

    root = cJSON_CreateObject();
    if (!root) {
        api_error_reply(c, 500, "oom");
        return;
    }
    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddStringToObject(root, "version", JZ_API_VERSION);
    api_json_reply(c, 200, root);
}

static void handle_status(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *modules;
    cJSON *guards;
    int i;
    time_t now = time(NULL);
    long uptime = 0;

    (void) hm;
    if (!api) {
        api_error_reply(c, 500, "api not available");
        return;
    }

    if (g_api_start_ts > 0 && now > g_api_start_ts)
        uptime = (long) (now - g_api_start_ts);

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddNumberToObject(root, "uptime_sec", (double) uptime);
    cJSON_AddBoolToObject(root, "api_enabled", api->enabled ? 1 : 0);

    modules = cJSON_AddObjectToObject(root, "modules");
    cJSON_AddNumberToObject(modules, "loaded_count",
                            api->loader ? api->loader->loaded_count : 0);
    if (api->loader) {
        int enabled = 0;
        for (i = 0; i < JZ_MOD_COUNT; i++) {
            if (api->loader->modules[i].enabled)
                enabled++;
        }
        cJSON_AddNumberToObject(modules, "enabled_count", enabled);
    } else {
        cJSON_AddNumberToObject(modules, "enabled_count", 0);
    }

    guards = cJSON_AddObjectToObject(root, "guards");
    cJSON_AddNumberToObject(guards, "dynamic_count",
                            api->guard_mgr ? api->guard_mgr->dynamic_count : 0);
    cJSON_AddBoolToObject(guards, "auto_discover",
                          (api->guard_mgr && api->guard_mgr->auto_discover) ? 1 : 0);
    api_json_reply(c, 200, root);
}

static void handle_modules(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int i;

    (void) hm;
    if (!api || !api->loader) {
        api_error_reply(c, 500, "loader not available");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "modules");
    for (i = 0; i < JZ_MOD_COUNT; i++) {
        const jz_bpf_module_t *m = &api->loader->modules[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", m->name ? m->name : "");
        cJSON_AddNumberToObject(o, "stage", m->stage);
        cJSON_AddBoolToObject(o, "loaded", m->loaded ? 1 : 0);
        cJSON_AddBoolToObject(o, "enabled", m->enabled ? 1 : 0);
        cJSON_AddItemToArray(arr, o);
    }

    {
        cJSON *ifaces = cJSON_AddArrayToObject(root, "interfaces");
        for (i = 0; i < api->loader->xdp_iface_count; i++) {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "name", api->loader->xdp_iface_names[i]);
            cJSON_AddNumberToObject(entry, "ifindex", api->loader->xdp_ifindexes[i]);
            cJSON_AddItemToArray(ifaces, entry);
        }
    }

    api_json_reply(c, 200, root);
}

static void handle_module_reload(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                 struct mg_str mod_name)
{
    char name[128];
    int id;
    bool was_enabled;
    cJSON *root;

    (void) hm;
    if (!api || !api->loader) {
        api_error_reply(c, 500, "BPF loader not initialized (are BPF modules installed?)");
        return;
    }

    if (api_mg_str_to_cstr(mod_name, name, sizeof(name)) < 0) {
        api_error_reply(c, 400, "invalid module name");
        return;
    }

    id = jz_bpf_loader_find(api->loader, name);
    if (id < 0 || id >= JZ_MOD_COUNT) {
        api_error_reply(c, 404, "module not found");
        return;
    }

    was_enabled = api->loader->modules[id].enabled;
    jz_log_info("api: reloading module '%s' (id=%d, was_enabled=%d)", name, id, was_enabled);

    if (jz_bpf_loader_unload(api->loader, (jz_mod_id_t) id) < 0) {
        jz_log_error("api: failed to unload module '%s'", name);
        api_error_reply(c, 500, "reload failed: unload error");
        return;
    }

    if (jz_bpf_loader_load(api->loader, (jz_mod_id_t) id) < 0) {
        jz_log_error("api: failed to reload module '%s'", name);
        api_error_reply(c, 500, "reload failed: load error");
        return;
    }

    if (was_enabled && jz_bpf_loader_enable(api->loader, (jz_mod_id_t) id, true) < 0) {
        jz_log_error("api: failed to re-enable module '%s' after reload", name);
        api_error_reply(c, 500, "reload failed: re-enable error");
        return;
    }

    jz_log_info("api: module '%s' reloaded successfully", name);
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "reloaded");
    cJSON_AddStringToObject(root, "module", name);
    api_json_reply(c, 200, root);
}

static void handle_guards_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int static_count;
    int dynamic_count;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "guards");
    static_count = api_add_static_guards_to_array(api->guard_mgr, arr);
    dynamic_count = api_add_dynamic_guards_to_array(api->guard_mgr, arr);
    cJSON_AddNumberToObject(root, "count", static_count + dynamic_count);
    api_json_reply(c, 200, root);
}

static void handle_guards_static_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int count;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "guards");
    count = api_add_static_guards_to_array(api->guard_mgr, arr);
    cJSON_AddNumberToObject(root, "count", count);
    api_json_reply(c, 200, root);
}

static void handle_guards_static_add(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *ip_j;
    cJSON *mac_j;
    cJSON *vlan_j;
    uint32_t ip;
    uint8_t mac[6] = {0};
    uint16_t vlan = 0;
    char ip_buf[INET_ADDRSTRLEN];
    cJSON *root;

    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    ip_j = cJSON_GetObjectItemCaseSensitive(body, "ip");
    mac_j = cJSON_GetObjectItemCaseSensitive(body, "mac");
    vlan_j = cJSON_GetObjectItemCaseSensitive(body, "vlan");

    if (!cJSON_IsString(ip_j) || !ip_j->valuestring ||
        api_parse_ipv4(ip_j->valuestring, &ip) < 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    snprintf(ip_buf, sizeof(ip_buf), "%s", ip_j->valuestring);

    if (cJSON_IsString(mac_j) && mac_j->valuestring && mac_j->valuestring[0]) {
        if (api_parse_mac(mac_j->valuestring, mac) < 0) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "invalid mac");
            return;
        }
    }

    if (cJSON_IsNumber(vlan_j) && vlan_j->valueint >= 0 && vlan_j->valueint <= 4095)
        vlan = (uint16_t) vlan_j->valueint;

    cJSON_Delete(body);

    if (api_guard_op_add(api, ip, mac, JZ_GUARD_STATIC, vlan) < 0) {
        api_error_reply(c, 500, "failed to add static guard");
        return;
    }

    api_audit_log(api, "guard_static_add", ip_buf, NULL, "success");
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "added");
    api_json_reply(c, 201, root);
}

static void handle_guards_static_del(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                     struct mg_str ip_cap)
{
    char ip_str[64];
    uint32_t ip;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    if (api_mg_str_to_cstr(ip_cap, ip_str, sizeof(ip_str)) < 0 ||
        api_parse_ipv4(ip_str, &ip) < 0) {
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    if (api_guard_op_remove(api, ip) < 0) {
        api_error_reply(c, 404, "guard not found");
        return;
    }

    api_audit_log(api, "guard_static_del", ip_str, NULL, "success");
    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_guards_dynamic_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int count;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "guards");
    count = api_add_dynamic_guards_to_array(api->guard_mgr, arr);
    cJSON_AddNumberToObject(root, "count", count);
    api_json_reply(c, 200, root);
}

static void handle_guards_dynamic_del(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                      struct mg_str ip_cap)
{
    char ip_str[64];
    uint32_t ip;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    if (api_mg_str_to_cstr(ip_cap, ip_str, sizeof(ip_str)) < 0 ||
        api_parse_ipv4(ip_str, &ip) < 0) {
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    if (api_guard_op_remove(api, ip) < 0) {
        api_error_reply(c, 404, "guard not found");
        return;
    }

    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_whitelist_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int count;

    (void) hm;
    if (!api || !api->guard_mgr) {
        api_error_reply(c, 500, "guard manager unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "whitelist");
    count = api_add_whitelist_to_array(api->guard_mgr, arr);
    cJSON_AddNumberToObject(root, "count", count);
    api_json_reply(c, 200, root);
}

static void handle_whitelist_add(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *ip_j;
    cJSON *mac_j;
    uint32_t ip;
    struct jz_bpf_whitelist_entry val;
    char ip_buf[INET_ADDRSTRLEN];

    if (!api || !api->guard_mgr || api->guard_mgr->whitelist_map_fd < 0) {
        api_error_reply(c, 500, "whitelist map unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    ip_j = cJSON_GetObjectItemCaseSensitive(body, "ip");
    mac_j = cJSON_GetObjectItemCaseSensitive(body, "mac");

    if (!cJSON_IsString(ip_j) || !ip_j->valuestring ||
        api_parse_ipv4(ip_j->valuestring, &ip) < 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    snprintf(ip_buf, sizeof(ip_buf), "%s", ip_j->valuestring);

    memset(&val, 0, sizeof(val));
    val.ip_addr = ip;
    val.enabled = 1;
    if (cJSON_IsString(mac_j) && mac_j->valuestring && mac_j->valuestring[0]) {
        if (api_parse_mac(mac_j->valuestring, val.mac) < 0) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "invalid mac");
            return;
        }
        val.match_mac = 1;
    }

    cJSON_Delete(body);

    if (bpf_map_update_elem(api->guard_mgr->whitelist_map_fd, &ip, &val, BPF_ANY) < 0) {
        api_error_reply(c, 500, "failed to update whitelist map");
        return;
    }

    api_audit_log(api, "whitelist_add", ip_buf, NULL, "success");
    api_json_reply(c, 201, cJSON_CreateObject());
}

static void handle_whitelist_del(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                 struct mg_str ip_cap)
{
    char ip_str[64];
    uint32_t ip;

    (void) hm;
    if (!api || !api->guard_mgr || api->guard_mgr->whitelist_map_fd < 0) {
        api_error_reply(c, 500, "whitelist map unavailable");
        return;
    }

    if (api_mg_str_to_cstr(ip_cap, ip_str, sizeof(ip_str)) < 0 ||
        api_parse_ipv4(ip_str, &ip) < 0) {
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    if (bpf_map_delete_elem(api->guard_mgr->whitelist_map_fd, &ip) < 0) {
        api_error_reply(c, 404, "whitelist entry not found");
        return;
    }

    api_audit_log(api, "whitelist_del", ip_str, NULL, "success");
    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_policies_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char buf[8192];
    (void) hm;

    if (!api->policy_mgr) {
        api_error_reply(c, 503, "policy manager unavailable");
        return;
    }

    if (jz_policy_mgr_list_json(api->policy_mgr, buf, sizeof(buf)) < 0) {
        api_error_reply(c, 500, "failed to serialize policies");
        return;
    }

    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", buf);
}

static void handle_policies_add(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *j;
    jz_policy_entry_user_t entry;
    cJSON *root;
    int id;

    if (!api || !api->policy_mgr) {
        api_error_reply(c, 503, "policy manager unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    memset(&entry, 0, sizeof(entry));
    entry.enabled = true;

    j = cJSON_GetObjectItemCaseSensitive(body, "name");
    if (cJSON_IsString(j) && j->valuestring)
        snprintf(entry.name, sizeof(entry.name), "%s", j->valuestring);

    j = cJSON_GetObjectItemCaseSensitive(body, "src_ip");
    if (cJSON_IsString(j) && j->valuestring)
        api_parse_ipv4(j->valuestring, &entry.src_ip);

    j = cJSON_GetObjectItemCaseSensitive(body, "dst_ip");
    if (cJSON_IsString(j) && j->valuestring)
        api_parse_ipv4(j->valuestring, &entry.dst_ip);

    j = cJSON_GetObjectItemCaseSensitive(body, "src_port");
    if (cJSON_IsNumber(j))
        entry.src_port = (uint16_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "dst_port");
    if (cJSON_IsNumber(j))
        entry.dst_port = (uint16_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "proto");
    if (cJSON_IsString(j) && j->valuestring) {
        if (strcasecmp(j->valuestring, "tcp") == 0) entry.proto = 6;
        else if (strcasecmp(j->valuestring, "udp") == 0) entry.proto = 17;
    }

    j = cJSON_GetObjectItemCaseSensitive(body, "action");
    if (cJSON_IsString(j) && j->valuestring) {
        if (strcasecmp(j->valuestring, "drop") == 0) entry.action = JZ_ACTION_DROP;
        else if (strcasecmp(j->valuestring, "redirect") == 0) entry.action = JZ_ACTION_REDIRECT;
        else if (strcasecmp(j->valuestring, "mirror") == 0) entry.action = JZ_ACTION_MIRROR;
        else if (strcasecmp(j->valuestring, "redirect_mirror") == 0) entry.action = JZ_ACTION_REDIRECT_MIRROR;
        else entry.action = JZ_ACTION_PASS;
    }

    j = cJSON_GetObjectItemCaseSensitive(body, "redirect_port");
    if (cJSON_IsNumber(j))
        entry.redirect_port = (uint8_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "mirror_port");
    if (cJSON_IsNumber(j))
        entry.mirror_port = (uint8_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "ttl_sec");
    if (cJSON_IsNumber(j))
        entry.ttl_sec = (uint32_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "enabled");
    if (cJSON_IsBool(j))
        entry.enabled = cJSON_IsTrue(j);

    cJSON_Delete(body);

    id = jz_policy_mgr_add(api->policy_mgr, &entry);
    if (id < 0) {
        api_error_reply(c, 500, "failed to add policy");
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "added");
    cJSON_AddNumberToObject(root, "id", id);
    api_json_reply(c, 201, root);
}

static void handle_policies_update(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                   struct mg_str id_cap)
{
    cJSON *body;
    cJSON *j;
    jz_policy_entry_user_t entry;
    const jz_policy_entry_user_t *existing;
    char id_str[32];
    uint32_t id;

    if (!api || !api->policy_mgr) {
        api_error_reply(c, 503, "policy manager unavailable");
        return;
    }

    api_mg_str_to_cstr(id_cap, id_str, sizeof(id_str));
    id = (uint32_t)strtoul(id_str, NULL, 10);

    existing = jz_policy_mgr_find(api->policy_mgr, id);
    if (!existing) {
        api_error_reply(c, 404, "policy not found");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    memcpy(&entry, existing, sizeof(entry));

    j = cJSON_GetObjectItemCaseSensitive(body, "name");
    if (cJSON_IsString(j) && j->valuestring)
        snprintf(entry.name, sizeof(entry.name), "%s", j->valuestring);

    j = cJSON_GetObjectItemCaseSensitive(body, "src_ip");
    if (cJSON_IsString(j) && j->valuestring)
        api_parse_ipv4(j->valuestring, &entry.src_ip);

    j = cJSON_GetObjectItemCaseSensitive(body, "dst_ip");
    if (cJSON_IsString(j) && j->valuestring)
        api_parse_ipv4(j->valuestring, &entry.dst_ip);

    j = cJSON_GetObjectItemCaseSensitive(body, "src_port");
    if (cJSON_IsNumber(j))
        entry.src_port = (uint16_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "dst_port");
    if (cJSON_IsNumber(j))
        entry.dst_port = (uint16_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "proto");
    if (cJSON_IsString(j) && j->valuestring) {
        if (strcasecmp(j->valuestring, "tcp") == 0) entry.proto = 6;
        else if (strcasecmp(j->valuestring, "udp") == 0) entry.proto = 17;
        else entry.proto = 0;
    }

    j = cJSON_GetObjectItemCaseSensitive(body, "action");
    if (cJSON_IsString(j) && j->valuestring) {
        if (strcasecmp(j->valuestring, "drop") == 0) entry.action = JZ_ACTION_DROP;
        else if (strcasecmp(j->valuestring, "redirect") == 0) entry.action = JZ_ACTION_REDIRECT;
        else if (strcasecmp(j->valuestring, "mirror") == 0) entry.action = JZ_ACTION_MIRROR;
        else if (strcasecmp(j->valuestring, "redirect_mirror") == 0) entry.action = JZ_ACTION_REDIRECT_MIRROR;
        else entry.action = JZ_ACTION_PASS;
    }

    j = cJSON_GetObjectItemCaseSensitive(body, "redirect_port");
    if (cJSON_IsNumber(j))
        entry.redirect_port = (uint8_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "mirror_port");
    if (cJSON_IsNumber(j))
        entry.mirror_port = (uint8_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "ttl_sec");
    if (cJSON_IsNumber(j))
        entry.ttl_sec = (uint32_t)j->valueint;

    j = cJSON_GetObjectItemCaseSensitive(body, "enabled");
    if (cJSON_IsBool(j))
        entry.enabled = cJSON_IsTrue(j);

    cJSON_Delete(body);

    if (jz_policy_mgr_update(api->policy_mgr, id, &entry) < 0) {
        api_error_reply(c, 500, "failed to update policy");
        return;
    }

    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_policies_del(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                struct mg_str id_cap)
{
    char id_str[32];
    uint32_t id;
    (void) hm;

    if (!api || !api->policy_mgr) {
        api_error_reply(c, 503, "policy manager unavailable");
        return;
    }

    api_mg_str_to_cstr(id_cap, id_str, sizeof(id_str));
    id = (uint32_t)strtoul(id_str, NULL, 10);

    if (jz_policy_mgr_remove(api->policy_mgr, id) < 0) {
        api_error_reply(c, 404, "policy not found");
        return;
    }

    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_logs_attacks(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    char since[64] = {0};
    char until[64] = {0};
    char src_ip[64] = {0};
    int limit;
    int offset;
    char sql[1024];
    int idx = 1;

    if (!api || !api->db) {
        api_error_reply(c, 500, "db unavailable");
        return;
    }

    (void) api_parse_query_str(hm, "since", since, sizeof(since));
    (void) api_parse_query_str(hm, "until", until, sizeof(until));
    (void) api_parse_query_str(hm, "src_ip", src_ip, sizeof(src_ip));
    limit = api_parse_query_int(hm, "limit", 100);
    offset = api_parse_query_int(hm, "offset", 0);
    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    (void) snprintf(sql, sizeof(sql),
                    "SELECT id,event_type,timestamp,timestamp_ns,src_ip,src_mac,dst_ip,dst_mac,"
                    "guard_type,protocol,ifindex,threat_level,details "
                    "FROM attack_log WHERE 1=1 %s %s %s ORDER BY id DESC LIMIT ? OFFSET ?",
                    since[0] ? "AND timestamp >= ?" : "",
                    until[0] ? "AND timestamp <= ?" : "",
                    src_ip[0] ? "AND src_ip = ?" : "");

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        goto fail;

    if (since[0])
        sqlite3_bind_text(stmt, idx++, since, -1, SQLITE_TRANSIENT);
    if (until[0])
        sqlite3_bind_text(stmt, idx++, until, -1, SQLITE_TRANSIENT);
    if (src_ip[0])
        sqlite3_bind_text(stmt, idx++, src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx++, limit);
    sqlite3_bind_int(stmt, idx++, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddNumberToObject(o, "event_type", sqlite3_column_int(stmt, 1));
        cJSON_AddStringToObject(o, "timestamp", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddNumberToObject(o, "timestamp_ns", (double) sqlite3_column_int64(stmt, 3));
        cJSON_AddStringToObject(o, "src_ip", (const char *) sqlite3_column_text(stmt, 4));
        cJSON_AddStringToObject(o, "src_mac", (const char *) sqlite3_column_text(stmt, 5));
        cJSON_AddStringToObject(o, "dst_ip", (const char *) sqlite3_column_text(stmt, 6));
        cJSON_AddStringToObject(o, "dst_mac", (const char *) sqlite3_column_text(stmt, 7));
        cJSON_AddStringToObject(o, "guard_type", (const char *) sqlite3_column_text(stmt, 8));
        cJSON_AddStringToObject(o, "protocol", (const char *) sqlite3_column_text(stmt, 9));
        cJSON_AddNumberToObject(o, "ifindex", sqlite3_column_int(stmt, 10));
        cJSON_AddNumberToObject(o, "threat_level", sqlite3_column_int(stmt, 11));
        cJSON_AddStringToObject(o, "details", (const char *) sqlite3_column_text(stmt, 12));
        cJSON_AddItemToArray(arr, o);
    }

    cJSON_AddNumberToObject(root, "limit", limit);
    cJSON_AddNumberToObject(root, "offset", offset);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
    return;

fail:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);
    cJSON_Delete(root);
    api_error_reply(c, 500, "query failed");
}

static void handle_logs_sniffers(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 100);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,mac,ip,ifindex,first_seen,last_seen,response_count,probe_ip "
                           "FROM sniffer_log ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddStringToObject(o, "mac", (const char *) sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(o, "ip", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddNumberToObject(o, "ifindex", sqlite3_column_int(stmt, 3));
        cJSON_AddStringToObject(o, "first_seen", (const char *) sqlite3_column_text(stmt, 4));
        cJSON_AddStringToObject(o, "last_seen", (const char *) sqlite3_column_text(stmt, 5));
        cJSON_AddNumberToObject(o, "response_count", sqlite3_column_int(stmt, 6));
        cJSON_AddStringToObject(o, "probe_ip", (const char *) sqlite3_column_text(stmt, 7));
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_logs_background(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 100);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,period_start,period_end,protocol,packet_count,byte_count,"
                           "unique_sources,sample_data FROM bg_capture ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddStringToObject(o, "period_start", (const char *) sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(o, "period_end", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(o, "protocol", (const char *) sqlite3_column_text(stmt, 3));
        cJSON_AddNumberToObject(o, "packet_count", sqlite3_column_int(stmt, 4));
        cJSON_AddNumberToObject(o, "byte_count", sqlite3_column_int(stmt, 5));
        cJSON_AddNumberToObject(o, "unique_sources", sqlite3_column_int(stmt, 6));
        cJSON_AddStringToObject(o, "sample_data", (const char *) sqlite3_column_text(stmt, 7));
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_logs_threats(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 100);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,timestamp,src_ip,dst_ip,protocol,threat_level,details "
                           "FROM attack_log WHERE threat_level > 0 ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddStringToObject(o, "timestamp", (const char *) sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(o, "src_ip", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(o, "dst_ip", (const char *) sqlite3_column_text(stmt, 3));
        cJSON_AddStringToObject(o, "protocol", (const char *) sqlite3_column_text(stmt, 4));
        cJSON_AddNumberToObject(o, "threat_level", sqlite3_column_int(stmt, 5));
        cJSON_AddStringToObject(o, "details", (const char *) sqlite3_column_text(stmt, 6));
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_logs_audit(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 100);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,timestamp,action,actor,target,details,result "
                           "FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddStringToObject(o, "timestamp", (const char *) sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(o, "action", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(o, "actor", (const char *) sqlite3_column_text(stmt, 3));
        cJSON_AddStringToObject(o, "target", (const char *) sqlite3_column_text(stmt, 4));
        cJSON_AddStringToObject(o, "details", (const char *) sqlite3_column_text(stmt, 5));
        cJSON_AddStringToObject(o, "result", (const char *) sqlite3_column_text(stmt, 6));
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_logs_heartbeat(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 100);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 100;
    if (limit > 1000)
        limit = 1000;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,timestamp,json_data "
                           "FROM heartbeat_log ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        const char *json_text;

        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddStringToObject(o, "timestamp", (const char *) sqlite3_column_text(stmt, 1));
        json_text = (const char *) sqlite3_column_text(stmt, 2);
        if (json_text) {
            cJSON *parsed = cJSON_Parse(json_text);
            if (parsed)
                cJSON_AddItemToObject(o, "data", parsed);
            else
                cJSON_AddStringToObject(o, "data", json_text);
        }
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_stats(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *guards;
    cJSON *logs;

    (void) hm;
    root = cJSON_CreateObject();
    guards = cJSON_AddObjectToObject(root, "guards");
    cJSON_AddNumberToObject(guards, "dynamic_count",
                            (api && api->guard_mgr) ? api->guard_mgr->dynamic_count : 0);
    logs = cJSON_AddObjectToObject(root, "logs");
    cJSON_AddNumberToObject(logs, "attacks", api_query_db(api, "SELECT COUNT(*) FROM attack_log", NULL));
    cJSON_AddNumberToObject(logs, "sniffers", api_query_db(api, "SELECT COUNT(*) FROM sniffer_log", NULL));
    cJSON_AddNumberToObject(logs, "background", api_query_db(api, "SELECT COUNT(*) FROM bg_capture", NULL));
    cJSON_AddNumberToObject(logs, "audit", api_query_db(api, "SELECT COUNT(*) FROM audit_log", NULL));
    api_json_reply(c, 200, root);
}

static void handle_stats_guards(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    int static_count = 0;
    int dynamic_count = 0;

    (void) hm;
    root = cJSON_CreateObject();
    if (api && api->guard_mgr) {
        cJSON *tmp = cJSON_CreateArray();
        static_count = api_add_static_guards_to_array(api->guard_mgr, tmp);
        dynamic_count = api->guard_mgr->dynamic_count;
        cJSON_Delete(tmp);
    }
    cJSON_AddNumberToObject(root, "static_count", static_count);
    cJSON_AddNumberToObject(root, "dynamic_count", dynamic_count);
    cJSON_AddNumberToObject(root, "total", static_count + dynamic_count);
    api_json_reply(c, 200, root);
}

static void handle_stats_traffic(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;
    (void) api;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "flows", 0);
    cJSON_AddNumberToObject(root, "bytes", 0);
    cJSON_AddNumberToObject(root, "packets", 0);
    api_json_reply(c, 200, root);
}

static void handle_stats_threats(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "threat_events",
                            api_query_db(api, "SELECT COUNT(*) FROM attack_log WHERE threat_level > 0", NULL));
    cJSON_AddNumberToObject(root, "high_or_above",
                            api_query_db(api, "SELECT COUNT(*) FROM attack_log WHERE threat_level >= 3", NULL));
    api_json_reply(c, 200, root);
}

static void handle_stats_background(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "records", api_query_db(api, "SELECT COUNT(*) FROM bg_capture", NULL));
    cJSON_AddNumberToObject(root, "total_packets",
                            api_query_db(api, "SELECT COALESCE(SUM(packet_count),0) FROM bg_capture", NULL));
    cJSON_AddNumberToObject(root, "total_bytes",
                            api_query_db(api, "SELECT COALESCE(SUM(byte_count),0) FROM bg_capture", NULL));
    api_json_reply(c, 200, root);
}

static void handle_config_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }
    root = api_config_to_json(api->config);
    if (!root) {
        api_error_reply(c, 500, "failed to serialize config");
        return;
    }
    api_json_reply(c, 200, root);
}

static void handle_config_post(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char *req = NULL;
    size_t req_len;
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) api;

    if (!hm || hm->body.len == 0) {
        api_error_reply(c, 400, "missing body");
        return;
    }

    req_len = strlen("config_push:") + hm->body.len + 1;
    req = (char *) malloc(req_len);
    if (!req) {
        api_error_reply(c, 500, "oom");
        return;
    }
    (void) snprintf(req, req_len, "config_push:%.*s", (int) hm->body.len, hm->body.buf);

    if (api_configd_request(req, &reply) < 0) {
        free(req);
        api_error_reply(c, 502, "configd unavailable (is configd running?)");
        return;
    }

    free(req);
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "sent");
    cJSON_AddStringToObject(root, "reply", reply.payload);
    api_json_reply(c, 200, root);
}

static void handle_config_history(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    cJSON *root = NULL;
    cJSON *arr = NULL;
    int limit = api_parse_query_int(hm, "limit", 50);
    int offset = api_parse_query_int(hm, "offset", 0);

    if (limit <= 0)
        limit = 50;
    if (limit > 500)
        limit = 500;
    if (offset < 0)
        offset = 0;

    if (api_db_open_readonly(api, &db) < 0) {
        api_error_reply(c, 500, "database unavailable (is collectord running?)");
        return;
    }

    if (sqlite3_prepare_v2(db,
                           "SELECT id,version,config_data,source,applied_at,applied_by,rollback_from,status "
                           "FROM config_history ORDER BY id DESC LIMIT ? OFFSET ?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        api_error_reply(c, 500, "query failed");
        return;
    }
    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "rows");

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", sqlite3_column_int(stmt, 0));
        cJSON_AddNumberToObject(o, "version", sqlite3_column_int(stmt, 1));
        cJSON_AddStringToObject(o, "config_data", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(o, "source", (const char *) sqlite3_column_text(stmt, 3));
        cJSON_AddStringToObject(o, "applied_at", (const char *) sqlite3_column_text(stmt, 4));
        cJSON_AddStringToObject(o, "applied_by", (const char *) sqlite3_column_text(stmt, 5));
        if (sqlite3_column_type(stmt, 6) == SQLITE_NULL)
            cJSON_AddNullToObject(o, "rollback_from");
        else
            cJSON_AddNumberToObject(o, "rollback_from", sqlite3_column_int(stmt, 6));
        cJSON_AddStringToObject(o, "status", (const char *) sqlite3_column_text(stmt, 7));
        cJSON_AddItemToArray(arr, o);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    api_json_reply(c, 200, root);
}

static void handle_config_rollback(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *ver_j;
    int version;
    char req[128];
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) api;

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    ver_j = cJSON_GetObjectItemCaseSensitive(body, "version");
    if (!cJSON_IsNumber(ver_j) || ver_j->valueint <= 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid version");
        return;
    }
    version = ver_j->valueint;
    cJSON_Delete(body);

    (void) snprintf(req, sizeof(req), "config_rollback:%d", version);
    if (api_configd_request(req, &reply) < 0) {
        api_error_reply(c, 502, "configd unavailable (is configd running?)");
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "sent");
    cJSON_AddStringToObject(root, "reply", reply.payload);
    api_json_reply(c, 200, root);
}

static void handle_discovery_devices(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char *buf;
    int len;

    (void) hm;
    if (!api || !api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    buf = (char *) malloc(65536);
    if (!buf) {
        api_error_reply(c, 500, "oom");
        return;
    }

    len = jz_discovery_list_json(api->discovery, buf, 65536);
    if (len <= 0) {
        free(buf);
        mg_http_reply(c, 200,
                      "Content-Type: application/json\r\n",
                      "{\"devices\":[],\"total\":0}\n");
        return;
    }

    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n",
                  "%.*s\n", len, buf);
    free(buf);
}

static void handle_discovery_device_by_mac(struct mg_connection *c, struct mg_http_message *hm,
                                           jz_api_t *api, struct mg_str mac_cap)
{
    char mac_str[32];
    uint8_t mac[6];
    jz_discovery_device_t *dev;
    cJSON *root;
    char ipbuf[INET_ADDRSTRLEN];

    (void) hm;
    if (!api || !api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    if (api_mg_str_to_cstr(mac_cap, mac_str, sizeof(mac_str)) < 0 ||
        api_parse_mac(mac_str, mac) < 0) {
        api_error_reply(c, 400, "invalid mac");
        return;
    }

    dev = jz_discovery_lookup(api->discovery, mac);
    if (!dev) {
        api_error_reply(c, 404, "device not found");
        return;
    }

    root = cJSON_CreateObject();
    api_mac_to_text(dev->profile.mac, mac_str, sizeof(mac_str));
    cJSON_AddStringToObject(root, "mac", mac_str);
    api_ip_to_text(dev->profile.ip, ipbuf, sizeof(ipbuf));
    cJSON_AddStringToObject(root, "ip", ipbuf);
    cJSON_AddStringToObject(root, "vendor", dev->profile.vendor);
    cJSON_AddStringToObject(root, "os_class", dev->profile.os_class);
    cJSON_AddStringToObject(root, "device_class", dev->profile.device_class);
    cJSON_AddStringToObject(root, "hostname", dev->profile.hostname);
    cJSON_AddNumberToObject(root, "confidence", dev->profile.confidence);
    cJSON_AddNumberToObject(root, "signals", dev->profile.signals);
    cJSON_AddNumberToObject(root, "first_seen", (double) dev->profile.first_seen);
    cJSON_AddNumberToObject(root, "last_seen", (double) dev->profile.last_seen);
    api_json_reply(c, 200, root);
}

static int api_persist_config(jz_api_t *api)
{
    char *yaml;
    char *req;
    size_t req_len;
    jz_ipc_msg_t reply;
    int rc;

    yaml = jz_config_serialize(api->config);
    if (!yaml)
        return -1;

    req_len = strlen("config_push:") + strlen(yaml) + 1;
    req = (char *) malloc(req_len);
    if (!req) {
        free(yaml);
        return -1;
    }
    (void) snprintf(req, req_len, "config_push:%s", yaml);
    free(yaml);

    rc = api_configd_request(req, &reply);
    free(req);
    return rc;
}

static void api_audit_log(jz_api_t *api, const char *action, const char *target,
                          const char *details, const char *result)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *path;
    char ts[32];
    time_t now;
    struct tm tmv;

    if (!api || !api->db || !action || !result)
        return;

    path = api->db->path[0] ? api->db->path : NULL;
    if (!path)
        return;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return;

    now = time(NULL);
    if (gmtime_r(&now, &tmv))
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        snprintf(ts, sizeof(ts), "unknown");

    if (sqlite3_prepare_v2(db,
            "INSERT INTO audit_log(timestamp,action,actor,target,details,result) "
            "VALUES(?,?,?,?,?,?)", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ts, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, action, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, "api", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, target ? target : "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, details ? details : "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, result, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
}

static void handle_guards_frozen_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int i;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "frozen_ips");
    for (i = 0; i < api->config->guards.frozen_ip_count; i++) {
        cJSON *o = cJSON_CreateObject();
        if (!o)
            continue;
        cJSON_AddStringToObject(o, "ip", api->config->guards.frozen_ips[i].ip);
        cJSON_AddStringToObject(o, "reason", api->config->guards.frozen_ips[i].reason);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddNumberToObject(root, "count", api->config->guards.frozen_ip_count);
    api_json_reply(c, 200, root);
}

static void handle_guards_frozen_add(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *ip_j;
    cJSON *reason_j;
    uint32_t ip_val;
    cJSON *root;
    char ip_buf[INET_ADDRSTRLEN];

    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    ip_j = cJSON_GetObjectItemCaseSensitive(body, "ip");
    reason_j = cJSON_GetObjectItemCaseSensitive(body, "reason");

    if (!cJSON_IsString(ip_j) || !ip_j->valuestring ||
        api_parse_ipv4(ip_j->valuestring, &ip_val) < 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    snprintf(ip_buf, sizeof(ip_buf), "%s", ip_j->valuestring);

    if (!cJSON_IsString(ip_j) || !ip_j->valuestring ||
        api_parse_ipv4(ip_j->valuestring, &ip_val) < 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    if (api->config->guards.frozen_ip_count >= JZ_CONFIG_MAX_FROZEN_IPS) {
        cJSON_Delete(body);
        api_error_reply(c, 409, "frozen ip list full");
        return;
    }

    {
        int idx = api->config->guards.frozen_ip_count;
        (void) snprintf(api->config->guards.frozen_ips[idx].ip,
                        sizeof(api->config->guards.frozen_ips[idx].ip),
                        "%s", ip_j->valuestring);
        if (cJSON_IsString(reason_j) && reason_j->valuestring)
            (void) snprintf(api->config->guards.frozen_ips[idx].reason,
                            sizeof(api->config->guards.frozen_ips[idx].reason),
                            "%s", reason_j->valuestring);
        else
            api->config->guards.frozen_ips[idx].reason[0] = '\0';
        api->config->guards.frozen_ip_count++;
    }

    cJSON_Delete(body);

    if (api_persist_config(api) < 0)
        jz_log_error("frozen_add: failed to persist config to configd");

    api_audit_log(api, "guard_frozen_add", ip_buf, NULL, "success");
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "added");
    api_json_reply(c, 201, root);
}

static void handle_guards_frozen_del(struct mg_connection *c, struct mg_http_message *hm,
                                     jz_api_t *api, struct mg_str ip_cap)
{
    char ip_str[64];
    int i;
    int found = -1;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    if (api_mg_str_to_cstr(ip_cap, ip_str, sizeof(ip_str)) < 0) {
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    for (i = 0; i < api->config->guards.frozen_ip_count; i++) {
        if (strcmp(api->config->guards.frozen_ips[i].ip, ip_str) == 0) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        api_error_reply(c, 404, "frozen ip not found");
        return;
    }

    for (i = found; i < api->config->guards.frozen_ip_count - 1; i++)
        api->config->guards.frozen_ips[i] = api->config->guards.frozen_ips[i + 1];
    api->config->guards.frozen_ip_count--;

    if (api_persist_config(api) < 0)
        jz_log_error("frozen_del: failed to persist config to configd");

    api_audit_log(api, "guard_frozen_del", ip_str, NULL, "success");
    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_guards_auto_config_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char *buf;
    int len;

    (void) hm;
    if (!api || !api->guard_auto) {
        api_error_reply(c, 500, "guard auto unavailable");
        return;
    }

    buf = (char *) malloc(4096);
    if (!buf) {
        api_error_reply(c, 500, "oom");
        return;
    }

    len = jz_guard_auto_list_json(api->guard_auto, buf, 4096);
    if (len <= 0) {
        free(buf);
        mg_http_reply(c, 200,
                      "Content-Type: application/json\r\n",
                      "{}\n");
        return;
    }

    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n",
                  "%.*s\n", len, buf);
    free(buf);
}

static void handle_guards_auto_config_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *item;

    if (!api || !api->guard_auto || !api->config) {
        api_error_reply(c, 500, "guard auto unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid JSON body");
        return;
    }

    item = cJSON_GetObjectItem(body, "max_ratio");
    if (item && cJSON_IsNumber(item)) {
        int ratio = item->valueint;
        if (ratio < 0) ratio = 0;
        if (ratio > 100) ratio = 100;
        api->config->guards.max_ratio = ratio;
    }

    item = cJSON_GetObjectItem(body, "enabled");
    if (item && cJSON_IsBool(item))
        api->config->guards.dynamic.auto_discover = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(body, "scan_interval");
    if (item && cJSON_IsNumber(item) && item->valueint > 0)
        api->config->guards.dynamic.ttl_hours = item->valueint;

    jz_guard_auto_update_config(api->guard_auto, api->config);

    if (api_persist_config(api) < 0)
        jz_log_error("guards/auto/config PUT: failed to persist config");

    api_audit_log(api, "guard_auto_config_update", NULL, NULL, "success");
    handle_guards_auto_config_get(c, hm, api);
    cJSON_Delete(body);
}

static void handle_config_interfaces_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int i;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "interfaces");

    for (i = 0; i < api->config->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface = &api->config->system.interfaces[i];
        cJSON *obj = cJSON_CreateObject();

        cJSON_AddStringToObject(obj, "name", iface->name);
        cJSON_AddStringToObject(obj, "role", iface->role);
        cJSON_AddStringToObject(obj, "subnet", iface->subnet);
        cJSON_AddItemToArray(arr, obj);
    }

    cJSON_AddStringToObject(root, "mode", api->config->system.mode);
    api_json_reply(c, 200, root);
}

static void handle_config_interfaces_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *arr;
    cJSON *mode_item;
    int i;
    int count;

    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid JSON body");
        return;
    }

    arr = cJSON_GetObjectItem(body, "interfaces");
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "missing 'interfaces' array");
        return;
    }

    count = cJSON_GetArraySize(arr);
    if (count > JZ_CONFIG_MAX_INTERFACES) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "too many interfaces");
        return;
    }

    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        cJSON *name = cJSON_GetObjectItem(item, "name");
        cJSON *role = cJSON_GetObjectItem(item, "role");
        cJSON *subnet = cJSON_GetObjectItem(item, "subnet");

        if (!name || !cJSON_IsString(name) || name->valuestring[0] == '\0') {
            cJSON_Delete(body);
            api_error_reply(c, 400, "interface entry missing 'name'");
            return;
        }
        if (!role || !cJSON_IsString(role) ||
            (strcmp(role->valuestring, "monitor") != 0 &&
             strcmp(role->valuestring, "manage") != 0 &&
             strcmp(role->valuestring, "mirror") != 0)) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "invalid role (must be monitor/manage/mirror)");
            return;
        }
        if (strcmp(role->valuestring, "mirror") != 0) {
            if (!subnet || !cJSON_IsString(subnet) || !strchr(subnet->valuestring, '/')) {
                cJSON_Delete(body);
                api_error_reply(c, 400, "monitor/manage role requires CIDR subnet");
                return;
            }
        }
    }

    api->config->system.interface_count = count;
    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        jz_config_interface_t *iface = &api->config->system.interfaces[i];

        snprintf(iface->name, sizeof(iface->name), "%s",
                 cJSON_GetObjectItem(item, "name")->valuestring);
        snprintf(iface->role, sizeof(iface->role), "%s",
                 cJSON_GetObjectItem(item, "role")->valuestring);

        {
            cJSON *subnet = cJSON_GetObjectItem(item, "subnet");
            if (subnet && cJSON_IsString(subnet))
                snprintf(iface->subnet, sizeof(iface->subnet), "%s", subnet->valuestring);
            else
                iface->subnet[0] = '\0';
        }
    }

    mode_item = cJSON_GetObjectItem(body, "mode");
    if (mode_item && cJSON_IsString(mode_item) &&
        (strcmp(mode_item->valuestring, "bypass") == 0 ||
         strcmp(mode_item->valuestring, "inline") == 0)) {
        snprintf(api->config->system.mode, sizeof(api->config->system.mode),
                 "%s", mode_item->valuestring);
    }

    if (api_persist_config(api) < 0) {
        jz_log_error("config/interfaces PUT: failed to persist config");
        cJSON_Delete(body);
        api_error_reply(c, 500, "failed to persist config");
        return;
    }

    if (api->guard_auto)
        jz_guard_auto_update_config(api->guard_auto, api->config);

    api_audit_log(api, "config_interfaces_update", NULL, NULL, "success");
    cJSON_Delete(body);
    handle_config_interfaces_get(c, hm, api);
}

static void handle_config_staged_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) hm;
    (void) api;

    if (api_configd_request("config_staged", &reply) < 0) {
        api_error_reply(c, 502, "configd unavailable");
        return;
    }

    root = cJSON_Parse(reply.payload);
    if (!root) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "raw", reply.payload);
    }
    api_json_reply(c, 200, root);
}

static void handle_config_stage_post(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char *req = NULL;
    size_t req_len;
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) api;

    if (!hm || hm->body.len == 0) {
        api_error_reply(c, 400, "missing body");
        return;
    }

    req_len = strlen("config_stage:") + hm->body.len + 1;
    req = (char *) malloc(req_len);
    if (!req) {
        api_error_reply(c, 500, "oom");
        return;
    }
    (void) snprintf(req, req_len, "config_stage:%.*s", (int) hm->body.len, hm->body.buf);

    if (api_configd_request(req, &reply) < 0) {
        free(req);
        api_error_reply(c, 502, "configd unavailable");
        return;
    }

    free(req);

    if (strncmp(reply.payload, "error:", 6) == 0) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "error", reply.payload + 6);
        api_json_reply(c, 400, root);
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "staged");
    cJSON_AddStringToObject(root, "reply", reply.payload);
    api_json_reply(c, 200, root);
}

static void handle_config_commit_post(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) hm;
    (void) api;

    if (api_configd_request("config_commit", &reply) < 0) {
        api_error_reply(c, 502, "configd unavailable");
        return;
    }

    if (strncmp(reply.payload, "error:", 6) == 0) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "error", reply.payload + 6);
        api_json_reply(c, 409, root);
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "committed");
    cJSON_AddStringToObject(root, "reply", reply.payload);
    api_json_reply(c, 200, root);
}

static void handle_config_discard_post(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    jz_ipc_msg_t reply;
    cJSON *root;
    (void) hm;
    (void) api;

    if (api_configd_request("config_discard", &reply) < 0) {
        api_error_reply(c, 502, "configd unavailable");
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "discarded");
    cJSON_AddStringToObject(root, "reply", reply.payload);
    api_json_reply(c, 200, root);
}

/* ── Daemon Status (PID / running) ─────────────────────────────── */

static const char *daemon_names[] = { "sniffd", "configd", "collectord", "uploadd" };
#define DAEMON_COUNT (sizeof(daemon_names) / sizeof(daemon_names[0]))

static void handle_system_daemons(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    size_t i;

    (void) hm;
    (void) api;

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "daemons");

    for (i = 0; i < DAEMON_COUNT; i++) {
        char path[64];
        char buf[32];
        FILE *fp;
        pid_t pid = 0;
        int running = 0;
        cJSON *obj;

        snprintf(path, sizeof(path), "/run/jz/%s.pid", daemon_names[i]);
        fp = fopen(path, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp))
                pid = (pid_t) atol(buf);
            fclose(fp);
        }

        if (pid > 0 && (kill(pid, 0) == 0 || errno == EPERM))
            running = 1;

        obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name", daemon_names[i]);
        cJSON_AddNumberToObject(obj, "pid", (double) pid);
        cJSON_AddBoolToObject(obj, "running", running);
        cJSON_AddItemToArray(arr, obj);
    }

    api_json_reply(c, 200, root);
}

static void handle_system_restart(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                  struct mg_str daemon_name)
{
    char daemon[32];
    pid_t pid;
    cJSON *root;

    (void) hm;
    (void) api;

    if (api_mg_str_to_cstr(daemon_name, daemon, sizeof(daemon)) < 0) {
        api_error_reply(c, 400, "invalid daemon name");
        return;
    }

    if (strcmp(daemon, "sniffd") != 0 && strcmp(daemon, "configd") != 0 &&
        strcmp(daemon, "collectord") != 0 && strcmp(daemon, "uploadd") != 0) {
        api_error_reply(c, 400, "invalid daemon name");
        return;
    }

    /* Double-fork to avoid zombie: first child exits immediately,
     * grandchild is reparented to init and runs systemctl. */
    pid = fork();
    if (pid < 0) {
        api_error_reply(c, 500, "restart failed");
        return;
    }

    if (pid == 0) {
        pid_t pid2 = fork();
        if (pid2 == 0) {
            (void) execl("/bin/systemctl", "systemctl", "restart", daemon, (char *) NULL);
            _exit(127);
        }
        _exit(0);
    }

    (void) waitpid(pid, NULL, 0);

    jz_log_info("api: restart requested for %s", daemon);

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "restarting");
    cJSON_AddStringToObject(root, "daemon", daemon);
    api_json_reply(c, 200, root);
}

static void api_route_http(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    struct mg_str caps[2];

    if (mg_match(hm->uri, mg_str("/api/v1/health"), NULL) &&
        mg_match(hm->method, mg_str("GET"), NULL)) {
        handle_health(c, hm, api);
        return;
    }

    if (!api_auth_check(hm, api)) {
        api_error_reply(c, 401, "unauthorized");
        return;
    }

    if (mg_match(hm->method, mg_str("GET"), NULL)) {
        if (mg_match(hm->uri, mg_str("/api/v1/status"), NULL)) {
            handle_status(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/modules"), NULL)) {
            handle_modules(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards"), NULL)) {
            handle_guards_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/static"), NULL)) {
            handle_guards_static_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/dynamic"), NULL)) {
            handle_guards_dynamic_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/whitelist"), NULL)) {
            handle_whitelist_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/policies"), NULL)) {
            handle_policies_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/attacks"), NULL)) {
            handle_logs_attacks(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/sniffers"), NULL)) {
            handle_logs_sniffers(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/background"), NULL)) {
            handle_logs_background(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/threats"), NULL)) {
            handle_logs_threats(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/audit"), NULL)) {
            handle_logs_audit(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/logs/heartbeat"), NULL)) {
            handle_logs_heartbeat(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/stats"), NULL)) {
            handle_stats(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/stats/guards"), NULL)) {
            handle_stats_guards(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/stats/traffic"), NULL)) {
            handle_stats_traffic(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/stats/threats"), NULL)) {
            handle_stats_threats(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/stats/background"), NULL)) {
            handle_stats_background(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/interfaces"), NULL)) {
            handle_config_interfaces_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config"), NULL)) {
            handle_config_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/history"), NULL)) {
            handle_config_history(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/staged"), NULL)) {
            handle_config_staged_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/discovery/devices/*"), caps)) {
            handle_discovery_device_by_mac(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/discovery/devices"), NULL)) {
            handle_discovery_devices(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/frozen"), NULL)) {
            handle_guards_frozen_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/auto/config"), NULL)) {
            handle_guards_auto_config_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/system/daemons"), NULL)) {
            handle_system_daemons(c, hm, api);
            return;
        }
    }

    if (mg_match(hm->method, mg_str("POST"), NULL)) {
        if (mg_match(hm->uri, mg_str("/api/v1/guards/static"), NULL)) {
            handle_guards_static_add(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/whitelist"), NULL)) {
            handle_whitelist_add(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/policies"), NULL)) {
            handle_policies_add(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config"), NULL)) {
            handle_config_post(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/rollback"), NULL)) {
            handle_config_rollback(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/stage"), NULL)) {
            handle_config_stage_post(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/commit"), NULL)) {
            handle_config_commit_post(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/discard"), NULL)) {
            handle_config_discard_post(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/system/restart/*"), caps)) {
            handle_system_restart(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/modules/*/reload"), caps)) {
            handle_module_reload(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/frozen"), NULL)) {
            handle_guards_frozen_add(c, hm, api);
            return;
        }
    }

    if (mg_match(hm->method, mg_str("DELETE"), NULL)) {
        if (mg_match(hm->uri, mg_str("/api/v1/guards/static/*"), caps)) {
            handle_guards_static_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/dynamic/*"), caps)) {
            handle_guards_dynamic_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/frozen/*"), caps)) {
            handle_guards_frozen_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/whitelist/*"), caps)) {
            handle_whitelist_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/policies/*"), caps)) {
            handle_policies_del(c, hm, api, caps[0]);
            return;
        }
    }

    if (mg_match(hm->method, mg_str("PUT"), NULL)) {
        if (mg_match(hm->uri, mg_str("/api/v1/guards/auto/config"), NULL)) {
            handle_guards_auto_config_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/interfaces"), NULL)) {
            handle_config_interfaces_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/policies/*"), caps)) {
            handle_policies_update(c, hm, api, caps[0]);
            return;
        }
    }

    if (mg_match(hm->uri, mg_str("/api/*"), NULL)) {
        api_error_reply(c, 404, "not found");
        return;
    }

    {
        struct mg_http_serve_opts opts;
        memset(&opts, 0, sizeof(opts));
        opts.root_dir = JZ_WWW_ROOT;
        opts.page404 = JZ_WWW_ROOT "/index.html";
        opts.extra_headers = "Vary: Accept-Encoding\r\n";
        mg_http_serve_dir(c, hm, &opts);
    }
}

static void api_ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    jz_api_t *api = (jz_api_t *) c->fn_data;
    jz_api_conn_state_t *st = (jz_api_conn_state_t *) c->data;

    if (!api)
        return;

    if (ev == MG_EV_ACCEPT) {
        const char *cert_pem;
        const char *key_pem;
        const char *ca_pem;
        struct mg_tls_opts tls_opts;

        st->tls_ok = false;
        cert_pem = (const char *) api->tls_cert_pem;
        key_pem = (const char *) api->tls_key_pem;
        ca_pem = (const char *) api->tls_ca_pem;

        if (!cert_pem || !key_pem) {
            jz_log_error("api: missing TLS cert/key during accept");
            c->is_closing = 1;
            return;
        }

        memset(&tls_opts, 0, sizeof(tls_opts));
        tls_opts.cert = mg_str(cert_pem);
        tls_opts.key = mg_str(key_pem);
        if (ca_pem && ca_pem[0])
            tls_opts.ca = mg_str(ca_pem);

        mg_tls_init(c, &tls_opts);
        st->tls_ok = true;
        return;
    }

    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        api_route_http(c, hm, api);
        return;
    }

    if (ev == MG_EV_ERROR) {
        const char *msg = (const char *) ev_data;
        jz_log_error("api: mg error: %s", msg ? msg : "unknown");
        return;
    }
}

int jz_api_init(jz_api_t *api, int port,
                const char *tls_cert, const char *tls_key,
                const char *tls_ca, const char *auth_token)
{
    jz_bpf_loader_t *loader;
    jz_guard_mgr_t *guard_mgr;
    jz_discovery_t *discovery;
    jz_guard_auto_t *guard_auto;
    jz_policy_mgr_t *policy_mgr;
    jz_config_t *config;
    jz_db_t *db;
    char *cert_pem = NULL;
    char *key_pem = NULL;
    char *ca_pem = NULL;
    struct mg_mgr *mgr;
    struct mg_connection *lc;
    char listen[64];

    if (!api)
        return -1;

    loader = api->loader;
    guard_mgr = api->guard_mgr;
    discovery = api->discovery;
    guard_auto = api->guard_auto;
    policy_mgr = api->policy_mgr;
    config = api->config;
    db = api->db;

    memset(api, 0, sizeof(*api));
    api->loader = loader;
    api->guard_mgr = guard_mgr;
    api->discovery = discovery;
    api->guard_auto = guard_auto;
    api->policy_mgr = policy_mgr;
    api->config = config;
    api->db = db;

    api->port = port > 0 ? port : 8443;
    api->enabled = false;

    if (tls_cert)
        (void) snprintf(api->tls_cert, sizeof(api->tls_cert), "%s", tls_cert);
    if (tls_key)
        (void) snprintf(api->tls_key, sizeof(api->tls_key), "%s", tls_key);
    if (tls_ca)
        (void) snprintf(api->tls_ca, sizeof(api->tls_ca), "%s", tls_ca);
    if (auth_token)
        (void) snprintf(api->auth_token, sizeof(api->auth_token), "%s", auth_token);

    if (!api->tls_cert[0])
        return 0;

    if (read_file_to_pem(api->tls_cert, &cert_pem) < 0 ||
        !api->tls_key[0] ||
        read_file_to_pem(api->tls_key, &key_pem) < 0 ||
        (api->tls_ca[0] && read_file_to_pem(api->tls_ca, &ca_pem) < 0)) {
        free(cert_pem);
        free(key_pem);
        free(ca_pem);
        jz_log_error("api: failed to load TLS PEM files");
        return -1;
    }

    mgr = (struct mg_mgr *) calloc(1, sizeof(struct mg_mgr));
    if (!mgr) {
        free(cert_pem);
        free(key_pem);
        free(ca_pem);
        return -1;
    }

    mg_mgr_init(mgr);
    api->mgr = mgr;
    api->tls_cert_pem = cert_pem;
    api->tls_key_pem = key_pem;
    api->tls_ca_pem = ca_pem;

    (void) snprintf(listen, sizeof(listen), "https://0.0.0.0:%d", api->port);
    lc = mg_http_listen(mgr, listen, api_ev_handler, api);
    if (!lc) {
        jz_log_error("api: failed to listen on %s", listen);
        mg_mgr_free(mgr);
        free(mgr);
        free(cert_pem);
        free(key_pem);
        free(ca_pem);
        api->mgr = NULL;
        api->tls_cert_pem = NULL;
        api->tls_key_pem = NULL;
        api->tls_ca_pem = NULL;
        return -1;
    }

    g_api_start_ts = time(NULL);
    api->enabled = true;
    jz_log_info("api: listening on %s", listen);
    return 0;
}

void jz_api_poll(jz_api_t *api, int timeout_ms)
{
    if (!api || !api->enabled || !api->mgr)
        return;
    mg_mgr_poll((struct mg_mgr *) api->mgr, timeout_ms);
}

void jz_api_destroy(jz_api_t *api)
{
    if (!api)
        return;

    if (api->mgr) {
        mg_mgr_free((struct mg_mgr *) api->mgr);
        free(api->mgr);
        api->mgr = NULL;
    }

    free(api->tls_cert_pem);
    free(api->tls_key_pem);
    free(api->tls_ca_pem);
    api->tls_cert_pem = NULL;
    api->tls_key_pem = NULL;
    api->tls_ca_pem = NULL;
    api->enabled = false;
}
