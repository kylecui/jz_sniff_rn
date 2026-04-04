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
#include "arp_spoof.h"
#include "capture_mgr.h"
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
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>

#ifndef JZ_VERSION
#define JZ_VERSION "0.0.0-dev"
#endif
#define JZ_API_VERSION JZ_VERSION

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

struct bpf_guard_key {
    uint32_t ip_addr;
    uint32_t ifindex;
};

struct jz_bpf_whitelist_entry {
    uint32_t ip_addr;
    uint8_t mac[6];
    uint8_t match_mac;
    uint8_t enabled;
    uint64_t created_at;
};

struct bpf_dhcp_exception_key {
    uint8_t mac[6];
    uint8_t _pad[2];
};

static time_t g_api_start_ts;

static int api_persist_config(jz_api_t *api);

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
                                   uint64_t created_at_ns, uint32_t ttl_sec,
                                   uint32_t ifindex)
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
    cJSON_AddNumberToObject(obj, "ifindex", ifindex);
    if (ifindex > 0) {
        char ifname[IF_NAMESIZE];
        if (if_indextoname(ifindex, ifname))
            cJSON_AddStringToObject(obj, "interface", ifname);
    }
    if (ttl_sec > 0)
        cJSON_AddNumberToObject(obj, "ttl_sec", ttl_sec);
    return obj;
}

static int api_add_static_guards_to_array(const jz_guard_mgr_t *gm, cJSON *arr)
{
    struct bpf_guard_key key;
    struct bpf_guard_key next_key;
    const struct bpf_guard_key *key_ptr = NULL;
    int count = 0;

    if (!gm || !arr || gm->static_map_fd < 0)
        return 0;

    while (bpf_map_get_next_key(gm->static_map_fd, key_ptr, &next_key) == 0) {
        struct jz_bpf_guard_entry val;
        if (bpf_map_lookup_elem(gm->static_map_fd, &next_key, &val) == 0) {
            cJSON *obj = api_guard_entry_json(next_key.ip_addr, val.fake_mac, val.guard_type,
                                              val.enabled, val.vlan_id,
                                              val.created_at, 0, next_key.ifindex);
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
                                   e->created_at, e->ttl_sec, e->ifindex);
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

static int api_guard_op_add(jz_api_t *api, uint32_t ip, uint32_t ifindex, const uint8_t mac[6],
                            uint8_t guard_type, uint16_t vlan_id)
{
    char reply[512];
    int rc;

    if (!api || !api->guard_mgr)
        return -1;

    rc = jz_guard_mgr_add(api->guard_mgr, ip, ifindex, mac, guard_type, vlan_id,
                          reply, sizeof(reply));
    if (rc < 0)
        return -1;
    if (strstr(reply, "error"))
        return -1;
    return 0;
}

static int api_guard_op_remove(jz_api_t *api, uint32_t ip, uint32_t ifindex)
{
    char reply[512];
    int rc;

    if (!api || !api->guard_mgr)
        return -1;

    rc = jz_guard_mgr_remove(api->guard_mgr, ip, ifindex, reply, sizeof(reply));
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
    cJSON_AddStringToObject(system, "mode", cfg->system.mode);

    {
        cJSON *ifaces = cJSON_AddArrayToObject(system, "interfaces");
        int ii;
        for (ii = 0; ii < cfg->system.interface_count &&
             ii < JZ_CONFIG_MAX_INTERFACES; ii++) {
            const jz_config_interface_t *iface = &cfg->system.interfaces[ii];
            cJSON *obj = cJSON_CreateObject();

            cJSON_AddStringToObject(obj, "name", iface->name);
            cJSON_AddStringToObject(obj, "role", iface->role);
            cJSON_AddStringToObject(obj, "subnet", iface->subnet);
            cJSON_AddStringToObject(obj, "address", iface->address);
            cJSON_AddStringToObject(obj, "gateway", iface->gateway);
            cJSON_AddStringToObject(obj, "dns1", iface->dns1);
            cJSON_AddStringToObject(obj, "dns2", iface->dns2);

            {
                int vi;
                cJSON *varr = cJSON_AddArrayToObject(obj, "vlans");
                for (vi = 0; vi < iface->vlan_count &&
                     vi < JZ_CONFIG_MAX_VLANS; vi++) {
                    cJSON *vo = cJSON_CreateObject();
                    cJSON_AddNumberToObject(vo, "id", iface->vlans[vi].id);
                    cJSON_AddStringToObject(vo, "name", iface->vlans[vi].name);
                    cJSON_AddStringToObject(vo, "subnet", iface->vlans[vi].subnet);
                    cJSON_AddItemToArray(varr, vo);
                }
            }

            {
                cJSON *dyn = cJSON_AddObjectToObject(obj, "dynamic");
                cJSON_AddNumberToObject(dyn, "auto_discover",
                                         iface->guard_auto_discover);
                cJSON_AddNumberToObject(dyn, "max_entries",
                                         iface->guard_max_entries);
                cJSON_AddNumberToObject(dyn, "ttl_hours",
                                         iface->guard_ttl_hours);
                cJSON_AddNumberToObject(dyn, "max_ratio",
                                         iface->guard_max_ratio);
                cJSON_AddNumberToObject(dyn, "warmup_mode",
                                         iface->guard_warmup_mode);
            }

            cJSON_AddItemToArray(ifaces, obj);
        }
    }

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
            const char *ifname = api->loader->xdp_iface_names[i];
            const char *role = "";
            int j;

            cJSON_AddStringToObject(entry, "name", ifname);
            cJSON_AddNumberToObject(entry, "ifindex", api->loader->xdp_ifindexes[i]);

            if (api->config) {
                for (j = 0; j < api->config->system.interface_count; j++) {
                    if (strcmp(api->config->system.interfaces[j].name, ifname) == 0) {
                        role = api->config->system.interfaces[j].role;
                        break;
                    }
                }
            }
            cJSON_AddStringToObject(entry, "role", role);
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

    if (api_guard_op_add(api, ip, 0, mac, JZ_GUARD_STATIC, vlan) < 0) {
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

    if (api_guard_op_remove(api, ip, 0) < 0) {
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

    if (api_guard_op_remove(api, ip, 0) < 0) {
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

/* ---------- DHCP Exception handlers ---------- */

static void handle_dhcp_exception_list(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    struct bpf_dhcp_exception_key key;
    struct bpf_dhcp_exception_key next_key;
    const struct bpf_dhcp_exception_key *key_ptr = NULL;
    int count = 0;
    int fd;

    (void) hm;
    if (!api || !api->guard_mgr || api->guard_mgr->dhcp_exception_map_fd < 0) {
        api_error_reply(c, 500, "dhcp exception map unavailable");
        return;
    }

    fd = api->guard_mgr->dhcp_exception_map_fd;
    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "exceptions");

    while (bpf_map_get_next_key(fd, key_ptr, &next_key) == 0) {
        struct jz_bpf_whitelist_entry val;
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
            cJSON *obj = cJSON_CreateObject();
            if (obj) {
                char macbuf[18];
                char ipbuf[INET_ADDRSTRLEN];
                api_mac_to_text(next_key.mac, macbuf, sizeof(macbuf));
                api_ip_to_text(val.ip_addr, ipbuf, sizeof(ipbuf));
                cJSON_AddStringToObject(obj, "mac", macbuf);
                cJSON_AddStringToObject(obj, "ip", ipbuf);
                cJSON_AddNumberToObject(obj, "created_at_ns", (double) val.created_at);
                cJSON_AddItemToArray(arr, obj);
            }
            count++;
        }
        key = next_key;
        key_ptr = &key;
    }

    cJSON_AddNumberToObject(root, "count", count);
    api_json_reply(c, 200, root);
}

static void handle_dhcp_exception_add(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *ip_j;
    uint32_t ip;
    struct bpf_dhcp_exception_key dk;
    struct jz_bpf_whitelist_entry val;
    jz_discovery_device_t *dev;
    char ip_buf[INET_ADDRSTRLEN];
    int fd;

    if (!api || !api->guard_mgr || api->guard_mgr->dhcp_exception_map_fd < 0) {
        api_error_reply(c, 500, "dhcp exception map unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid json body");
        return;
    }

    ip_j = cJSON_GetObjectItemCaseSensitive(body, "ip");
    if (!cJSON_IsString(ip_j) || !ip_j->valuestring ||
        api_parse_ipv4(ip_j->valuestring, &ip) < 0) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "invalid ip");
        return;
    }

    snprintf(ip_buf, sizeof(ip_buf), "%s", ip_j->valuestring);
    cJSON_Delete(body);

    if (!api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    dev = jz_discovery_lookup_by_ip(api->discovery, ip, 0);
    if (!dev) {
        api_error_reply(c, 404, "device not found in discovery table - ensure DHCP server is online");
        return;
    }

    memset(&dk, 0, sizeof(dk));
    memcpy(dk.mac, dev->profile.mac, 6);

    memset(&val, 0, sizeof(val));
    val.ip_addr = ip;
    memcpy(val.mac, dev->profile.mac, 6);
    val.match_mac = 1;
    val.enabled = 1;
    val.created_at = (uint64_t) time(NULL) * 1000000000ULL;

    fd = api->guard_mgr->dhcp_exception_map_fd;
    if (bpf_map_update_elem(fd, &dk, &val, BPF_ANY) < 0) {
        api_error_reply(c, 500, "failed to update dhcp exception map");
        return;
    }

    if (api->config &&
        api->config->guards.dhcp_exception_count < JZ_CONFIG_MAX_DHCP_EXCEPTIONS) {
        jz_config_dhcp_exception_t *de =
            &api->config->guards.dhcp_exceptions[api->config->guards.dhcp_exception_count];
        snprintf(de->ip, sizeof(de->ip), "%s", ip_buf);
        api_mac_to_text(dev->profile.mac, de->mac, sizeof(de->mac));
        api->config->guards.dhcp_exception_count++;
        api_persist_config(api);
    }

    {
        cJSON *result = cJSON_CreateObject();
        char macbuf[18];
        api_mac_to_text(dev->profile.mac, macbuf, sizeof(macbuf));
        cJSON_AddStringToObject(result, "ip", ip_buf);
        cJSON_AddStringToObject(result, "mac", macbuf);
        cJSON_AddStringToObject(result, "status", "added");
        api_audit_log(api, "dhcp_exception_add", ip_buf, macbuf, "success");
        api_json_reply(c, 201, result);
    }
}

static void handle_dhcp_exception_del(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api,
                                      struct mg_str mac_cap)
{
    char mac_str[64];
    struct bpf_dhcp_exception_key dk;
    int fd;

    (void) hm;
    if (!api || !api->guard_mgr || api->guard_mgr->dhcp_exception_map_fd < 0) {
        api_error_reply(c, 500, "dhcp exception map unavailable");
        return;
    }

    if (api_mg_str_to_cstr(mac_cap, mac_str, sizeof(mac_str)) < 0) {
        api_error_reply(c, 400, "invalid mac");
        return;
    }

    memset(&dk, 0, sizeof(dk));
    if (api_parse_mac(mac_str, dk.mac) < 0) {
        api_error_reply(c, 400, "invalid mac format");
        return;
    }

    fd = api->guard_mgr->dhcp_exception_map_fd;
    if (bpf_map_delete_elem(fd, &dk) < 0) {
        api_error_reply(c, 404, "dhcp exception not found");
        return;
    }

    if (api->config) {
        int j, n = api->config->guards.dhcp_exception_count;
        for (j = 0; j < n; j++) {
            uint8_t stored_mac[6];
            if (sscanf(api->config->guards.dhcp_exceptions[j].mac,
                       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &stored_mac[0], &stored_mac[1], &stored_mac[2],
                       &stored_mac[3], &stored_mac[4], &stored_mac[5]) == 6 &&
                memcmp(stored_mac, dk.mac, 6) == 0) {
                if (j < n - 1)
                    api->config->guards.dhcp_exceptions[j] =
                        api->config->guards.dhcp_exceptions[n - 1];
                api->config->guards.dhcp_exception_count--;
                api_persist_config(api);
                break;
            }
        }
    }

    api_audit_log(api, "dhcp_exception_del", mac_str, NULL, "success");
    api_json_reply(c, 200, cJSON_CreateObject());
}

static void handle_dhcp_alerts(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    jz_discovery_device_t *servers[32];
    int count;
    int i;
    cJSON *root;
    cJSON *arr;
    int fd;

    (void) hm;
    if (!api || !api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    count = jz_discovery_find_dhcp_servers(api->discovery, servers, 32);

    fd = (api->guard_mgr && api->guard_mgr->dhcp_exception_map_fd >= 0)
         ? api->guard_mgr->dhcp_exception_map_fd : -1;

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "servers");

    for (i = 0; i < count; i++) {
        cJSON *obj = cJSON_CreateObject();
        if (obj) {
            char ipbuf[INET_ADDRSTRLEN];
            char macbuf[18];
            bool is_protected = false;

            api_ip_to_text(servers[i]->profile.ip, ipbuf, sizeof(ipbuf));
            api_mac_to_text(servers[i]->profile.mac, macbuf, sizeof(macbuf));

            if (fd >= 0) {
                struct bpf_dhcp_exception_key dk;
                struct jz_bpf_whitelist_entry val;
                memset(&dk, 0, sizeof(dk));
                memcpy(dk.mac, servers[i]->profile.mac, 6);
                if (bpf_map_lookup_elem(fd, &dk, &val) == 0)
                    is_protected = true;
            }

            cJSON_AddStringToObject(obj, "ip", ipbuf);
            cJSON_AddStringToObject(obj, "mac", macbuf);
            cJSON_AddStringToObject(obj, "vendor", servers[i]->profile.vendor);
            cJSON_AddNumberToObject(obj, "first_seen", (double) servers[i]->profile.first_seen);
            cJSON_AddBoolToObject(obj, "protected", is_protected ? 1 : 0);
            cJSON_AddNumberToObject(obj, "ifindex", (double) servers[i]->ifindex);
            {
                char ifname[IF_NAMESIZE];
                if (if_indextoname(servers[i]->ifindex, ifname))
                    cJSON_AddStringToObject(obj, "interface", ifname);
                else
                    cJSON_AddStringToObject(obj, "interface", "");
            }
            cJSON_AddItemToArray(arr, obj);
        }
    }

    cJSON_AddNumberToObject(root, "total", count);
    api_json_reply(c, 200, root);
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
                    "guard_type,protocol,ifindex,threat_level,details,COALESCE(vlan_id,0),"
                    "COALESCE(src_port,0),COALESCE(dst_port,0) "
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
        cJSON_AddNumberToObject(o, "vlan_id", sqlite3_column_int(stmt, 13));
        cJSON_AddNumberToObject(o, "src_port", sqlite3_column_int(stmt, 14));
        cJSON_AddNumberToObject(o, "dst_port", sqlite3_column_int(stmt, 15));
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
                           "unique_sources,sample_data,vlan_id,src_ip,dst_ip,src_mac,dst_mac "
                           "FROM bg_capture ORDER BY id DESC LIMIT ? OFFSET ?",
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
        cJSON_AddStringToObject(o, "period_end", (const char *) sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(o, "protocol", (const char *) sqlite3_column_text(stmt, 3));
        cJSON_AddNumberToObject(o, "packet_count", sqlite3_column_int(stmt, 4));
        cJSON_AddNumberToObject(o, "byte_count", sqlite3_column_int(stmt, 5));
        cJSON_AddNumberToObject(o, "unique_sources", sqlite3_column_int(stmt, 6));
        cJSON_AddStringToObject(o, "sample_data", sqlite3_column_text(stmt, 7) ? (const char *) sqlite3_column_text(stmt, 7) : "");
        cJSON_AddNumberToObject(o, "vlan_id", sqlite3_column_int(stmt, 8));
        cJSON_AddStringToObject(o, "src_ip", sqlite3_column_text(stmt, 9) ? (const char *) sqlite3_column_text(stmt, 9) : "");
        cJSON_AddStringToObject(o, "dst_ip", sqlite3_column_text(stmt, 10) ? (const char *) sqlite3_column_text(stmt, 10) : "");
        cJSON_AddStringToObject(o, "src_mac", sqlite3_column_text(stmt, 11) ? (const char *) sqlite3_column_text(stmt, 11) : "");
        cJSON_AddStringToObject(o, "dst_mac", sqlite3_column_text(stmt, 12) ? (const char *) sqlite3_column_text(stmt, 12) : "");
        {
            char details[64];
            snprintf(details, sizeof(details), "%d pkt / %d bytes",
                     sqlite3_column_int(stmt, 4), sqlite3_column_int(stmt, 5));
            cJSON_AddStringToObject(o, "details", details);
        }
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
                           "SELECT id,timestamp,src_ip,dst_ip,protocol,threat_level,details,"
                           "COALESCE(vlan_id,0),COALESCE(src_port,0),COALESCE(dst_port,0) "
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
        cJSON_AddNumberToObject(o, "vlan_id", sqlite3_column_int(stmt, 7));
        cJSON_AddNumberToObject(o, "src_port", sqlite3_column_int(stmt, 8));
        cJSON_AddNumberToObject(o, "dst_port", sqlite3_column_int(stmt, 9));
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
    int static_count = 0;
    int dynamic_count = 0;
    int whitelist_count = 0;
    int attacks_total;
    int attacks_today;

    (void) hm;
    root = cJSON_CreateObject();

    if (api && api->guard_mgr) {
        cJSON *tmp = cJSON_CreateArray();
        static_count = api_add_static_guards_to_array(api->guard_mgr, tmp);
        dynamic_count = api->guard_mgr->dynamic_count;
        whitelist_count = api->config
            ? api->config->guards.whitelist_count : 0;
        cJSON_Delete(tmp);
    }

    cJSON_AddNumberToObject(root, "guards_total", static_count + dynamic_count);
    cJSON_AddNumberToObject(root, "guards_static", static_count);
    cJSON_AddNumberToObject(root, "guards_dynamic", dynamic_count);
    cJSON_AddNumberToObject(root, "whitelist_total", whitelist_count);

    attacks_total = (int)api_query_db(api, "SELECT COUNT(*) FROM attack_log", NULL);
    attacks_today = (int)api_query_db(api,
        "SELECT COUNT(*) FROM attack_log WHERE timestamp >= strftime('%s','now','start of day')", NULL);
    cJSON_AddNumberToObject(root, "attacks_total", attacks_total);
    cJSON_AddNumberToObject(root, "attacks_today", attacks_today);

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

static void handle_discovery_vlans(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    char *buf;
    int len;

    (void) hm;
    if (!api || !api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    buf = (char *) malloc(4096);
    if (!buf) {
        api_error_reply(c, 500, "oom");
        return;
    }

    len = jz_discovery_list_vlans(api->discovery, buf, 4096);
    if (len <= 0) {
        free(buf);
        mg_http_reply(c, 200,
                      "Content-Type: application/json\r\n",
                      "{\"vlans\":[],\"total\":0}\n");
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

    dev = jz_discovery_lookup(api->discovery, mac, 0);
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

    /* Evict from dynamic guards if this IP is currently an active guard */
    if (api->guard_mgr) {
        char reply[256];

        if (jz_guard_mgr_remove(api->guard_mgr, ip_val, 0, reply, sizeof(reply)) >= 0 &&
            strncmp(reply, "guard_remove:ok", 15) == 0) {
            jz_log_info("frozen_add: evicted dynamic guard %s", ip_buf);
        }
    }

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

static void handle_discovery_config_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "aggressive_mode", api->config->discovery.aggressive_mode);
    cJSON_AddNumberToObject(root, "dhcp_probe_interval_sec", api->config->discovery.dhcp_probe_interval_sec);
    api_json_reply(c, 200, root);
}

static void handle_discovery_config_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *item;

    if (!api || !api->config || !api->discovery) {
        api_error_reply(c, 500, "discovery unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid JSON body");
        return;
    }

    item = cJSON_GetObjectItem(body, "aggressive_mode");
    if (item && cJSON_IsBool(item))
        api->config->discovery.aggressive_mode = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(body, "dhcp_probe_interval_sec");
    if (item && cJSON_IsNumber(item)) {
        int val = item->valueint;
        if (val < 10) val = 10;
        api->config->discovery.dhcp_probe_interval_sec = val;
    }

    jz_discovery_update_config(api->discovery, api->config);

    if (api_persist_config(api) < 0)
        jz_log_error("discovery/config PUT: failed to persist config");

    api_audit_log(api, "discovery_config_update", NULL, NULL, "success");
    handle_discovery_config_get(c, hm, api);
    cJSON_Delete(body);
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

    item = cJSON_GetObjectItem(body, "warmup_mode");
    if (item && cJSON_IsString(item)) {
        const char *ws = item->valuestring;
        if (strcmp(ws, "normal") == 0)      api->config->guards.dynamic.warmup_mode = 0;
        else if (strcmp(ws, "fast") == 0)    api->config->guards.dynamic.warmup_mode = 1;
        else if (strcmp(ws, "burst") == 0)   api->config->guards.dynamic.warmup_mode = 2;
    } else if (item && cJSON_IsNumber(item)) {
        int wm = item->valueint;
        if (wm >= 0 && wm <= 2)
            api->config->guards.dynamic.warmup_mode = wm;
    }

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
        cJSON_AddStringToObject(obj, "address", iface->address);
        cJSON_AddStringToObject(obj, "gateway", iface->gateway);
        cJSON_AddStringToObject(obj, "dns1", iface->dns1);
        cJSON_AddStringToObject(obj, "dns2", iface->dns2);

        {
            int vi;
            cJSON *varr = cJSON_AddArrayToObject(obj, "vlans");
            for (vi = 0; vi < iface->vlan_count && vi < JZ_CONFIG_MAX_VLANS; vi++) {
                cJSON *vo = cJSON_CreateObject();
                cJSON_AddNumberToObject(vo, "id", iface->vlans[vi].id);
                cJSON_AddStringToObject(vo, "name", iface->vlans[vi].name);
                cJSON_AddStringToObject(vo, "subnet", iface->vlans[vi].subnet);
                cJSON_AddItemToArray(varr, vo);
            }
        }

        {
            cJSON *dyn = cJSON_AddObjectToObject(obj, "dynamic");
            cJSON_AddNumberToObject(dyn, "auto_discover", iface->guard_auto_discover);
            cJSON_AddNumberToObject(dyn, "max_entries", iface->guard_max_entries);
            cJSON_AddNumberToObject(dyn, "ttl_hours", iface->guard_ttl_hours);
            cJSON_AddNumberToObject(dyn, "max_ratio", iface->guard_max_ratio);
            cJSON_AddNumberToObject(dyn, "warmup_mode", iface->guard_warmup_mode);
        }

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
            /* manage role accepts "dhcp" as a special subnet value */
            bool manage_dhcp = strcmp(role->valuestring, "manage") == 0 &&
                               subnet && cJSON_IsString(subnet) &&
                               strcmp(subnet->valuestring, "dhcp") == 0;
            if (!manage_dhcp &&
                (!subnet || !cJSON_IsString(subnet) || !strchr(subnet->valuestring, '/'))) {
                cJSON_Delete(body);
                api_error_reply(c, 400, "monitor/manage role requires CIDR subnet (or 'dhcp' for manage)");
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
        {
            cJSON *addr = cJSON_GetObjectItem(item, "address");
            if (addr && cJSON_IsString(addr))
                snprintf(iface->address, sizeof(iface->address), "%s", addr->valuestring);
            else
                iface->address[0] = '\0';
        }
        {
            cJSON *gw = cJSON_GetObjectItem(item, "gateway");
            if (gw && cJSON_IsString(gw))
                snprintf(iface->gateway, sizeof(iface->gateway), "%s", gw->valuestring);
            else
                iface->gateway[0] = '\0';
        }
        {
            cJSON *d1 = cJSON_GetObjectItem(item, "dns1");
            if (d1 && cJSON_IsString(d1))
                snprintf(iface->dns1, sizeof(iface->dns1), "%s", d1->valuestring);
            else
                iface->dns1[0] = '\0';
        }
        {
            cJSON *d2 = cJSON_GetObjectItem(item, "dns2");
            if (d2 && cJSON_IsString(d2))
                snprintf(iface->dns2, sizeof(iface->dns2), "%s", d2->valuestring);
            else
                iface->dns2[0] = '\0';
        }
        {
            cJSON *varr = cJSON_GetObjectItem(item, "vlans");
            iface->vlan_count = 0;
            if (varr && cJSON_IsArray(varr)) {
                int vc = cJSON_GetArraySize(varr);
                int vi;
                if (vc > JZ_CONFIG_MAX_VLANS)
                    vc = JZ_CONFIG_MAX_VLANS;
                for (vi = 0; vi < vc; vi++) {
                    cJSON *vitem = cJSON_GetArrayItem(varr, vi);
                    cJSON *vid = cJSON_GetObjectItem(vitem, "id");
                    cJSON *vname = cJSON_GetObjectItem(vitem, "name");
                    cJSON *vsub = cJSON_GetObjectItem(vitem, "subnet");
                    jz_config_vlan_t *v = &iface->vlans[vi];
                    v->id = (vid && cJSON_IsNumber(vid)) ? vid->valueint : 0;
                    if (vname && cJSON_IsString(vname))
                        snprintf(v->name, sizeof(v->name), "%s", vname->valuestring);
                    else
                        v->name[0] = '\0';
                    if (vsub && cJSON_IsString(vsub))
                        snprintf(v->subnet, sizeof(v->subnet), "%s", vsub->valuestring);
                    else
                        v->subnet[0] = '\0';
                }
                iface->vlan_count = vc;
            }
        }
        {
            cJSON *dyn = cJSON_GetObjectItem(item, "dynamic");
            iface->guard_auto_discover = -1;
            iface->guard_max_entries = -1;
            iface->guard_ttl_hours = -1;
            iface->guard_max_ratio = -1;
            iface->guard_warmup_mode = -1;
            if (dyn && cJSON_IsObject(dyn)) {
                cJSON *ad = cJSON_GetObjectItem(dyn, "auto_discover");
                cJSON *me = cJSON_GetObjectItem(dyn, "max_entries");
                cJSON *th = cJSON_GetObjectItem(dyn, "ttl_hours");
                cJSON *mr = cJSON_GetObjectItem(dyn, "max_ratio");
                cJSON *wm = cJSON_GetObjectItem(dyn, "warmup_mode");
                if (ad && cJSON_IsNumber(ad))
                    iface->guard_auto_discover = ad->valueint;
                if (me && cJSON_IsNumber(me))
                    iface->guard_max_entries = me->valueint;
                if (th && cJSON_IsNumber(th))
                    iface->guard_ttl_hours = th->valueint;
                if (mr && cJSON_IsNumber(mr))
                    iface->guard_max_ratio = mr->valueint;
                if (wm && cJSON_IsNumber(wm))
                    iface->guard_warmup_mode = wm->valueint;
            }
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

static void handle_config_arp_spoof_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
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
    cJSON_AddBoolToObject(root, "enabled", api->config->arp_spoof.enabled);
    cJSON_AddNumberToObject(root, "interval_sec", api->config->arp_spoof.interval_sec);

    arr = cJSON_AddArrayToObject(root, "targets");
    for (i = 0; i < api->config->arp_spoof.target_count &&
                i < JZ_CONFIG_MAX_ARP_SPOOF_TARGETS; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "target_ip",
                                api->config->arp_spoof.targets[i].target_ip);
        cJSON_AddStringToObject(obj, "gateway_ip",
                                api->config->arp_spoof.targets[i].gateway_ip);
        cJSON_AddItemToArray(arr, obj);
    }

    api_json_reply(c, 200, root);
}

static void handle_config_arp_spoof_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *enabled_item;
    cJSON *interval_item;
    cJSON *targets_arr;
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

    enabled_item = cJSON_GetObjectItem(body, "enabled");
    if (enabled_item && cJSON_IsBool(enabled_item))
        api->config->arp_spoof.enabled = cJSON_IsTrue(enabled_item);

    interval_item = cJSON_GetObjectItem(body, "interval_sec");
    if (interval_item && cJSON_IsNumber(interval_item)) {
        int val = interval_item->valueint;
        if (val < 1) val = 1;
        if (val > 300) val = 300;
        api->config->arp_spoof.interval_sec = val;
    }

    targets_arr = cJSON_GetObjectItem(body, "targets");
    if (targets_arr && cJSON_IsArray(targets_arr)) {
        count = cJSON_GetArraySize(targets_arr);
        if (count > JZ_CONFIG_MAX_ARP_SPOOF_TARGETS) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "too many ARP spoof targets");
            return;
        }

        api->config->arp_spoof.target_count = count;
        for (i = 0; i < count; i++) {
            cJSON *item = cJSON_GetArrayItem(targets_arr, i);
            cJSON *tip = cJSON_GetObjectItem(item, "target_ip");
            cJSON *gip = cJSON_GetObjectItem(item, "gateway_ip");
            jz_config_arp_spoof_target_t *t = &api->config->arp_spoof.targets[i];

            if (!tip || !cJSON_IsString(tip) || !gip || !cJSON_IsString(gip)) {
                cJSON_Delete(body);
                api_error_reply(c, 400, "target entry requires target_ip and gateway_ip");
                return;
            }

            {
                struct in_addr addr;
                if (inet_pton(AF_INET, tip->valuestring, &addr) != 1 ||
                    inet_pton(AF_INET, gip->valuestring, &addr) != 1) {
                    cJSON_Delete(body);
                    api_error_reply(c, 400, "invalid IP address in target entry");
                    return;
                }
            }

            snprintf(t->target_ip, sizeof(t->target_ip), "%s", tip->valuestring);
            snprintf(t->gateway_ip, sizeof(t->gateway_ip), "%s", gip->valuestring);
        }
    }

    if (api_persist_config(api) < 0) {
        jz_log_error("config/arp_spoof PUT: failed to persist config");
        cJSON_Delete(body);
        api_error_reply(c, 500, "failed to persist config");
        return;
    }

    if (api->arp_spoof)
        jz_arp_spoof_update_config(api->arp_spoof, api->config);

    api_audit_log(api, "config_arp_spoof_update", NULL, NULL, "success");
    cJSON_Delete(body);
    handle_config_arp_spoof_get(c, hm, api);
}

/* ---------- Log transport config (syslog / mqtt / https) ---------- */

static void handle_config_log_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *syslog_obj;
    cJSON *mqtt_obj;
    cJSON *https_obj;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "format", api->config->log.format);
    cJSON_AddNumberToObject(root, "heartbeat_interval_sec",
                            api->config->log.heartbeat_interval_sec);

    /* syslog transport */
    syslog_obj = cJSON_AddObjectToObject(root, "syslog");
    cJSON_AddBoolToObject(syslog_obj, "enabled", api->config->log.syslog.enabled);
    cJSON_AddStringToObject(syslog_obj, "format", api->config->log.syslog.format);
    cJSON_AddStringToObject(syslog_obj, "server", api->config->log.syslog.server);
    cJSON_AddNumberToObject(syslog_obj, "port", api->config->log.syslog.port);
    cJSON_AddBoolToObject(syslog_obj, "tls", api->config->log.syslog.tls);
    cJSON_AddStringToObject(syslog_obj, "tls_ca", api->config->log.syslog.tls_ca);
    cJSON_AddStringToObject(syslog_obj, "tls_cert", api->config->log.syslog.tls_cert);
    cJSON_AddStringToObject(syslog_obj, "tls_key", api->config->log.syslog.tls_key);
    cJSON_AddStringToObject(syslog_obj, "facility", api->config->log.syslog.facility);

    /* mqtt transport */
    mqtt_obj = cJSON_AddObjectToObject(root, "mqtt");
    cJSON_AddBoolToObject(mqtt_obj, "enabled", api->config->log.mqtt.enabled);
    cJSON_AddStringToObject(mqtt_obj, "format", api->config->log.mqtt.format);
    cJSON_AddStringToObject(mqtt_obj, "broker", api->config->log.mqtt.broker);
    cJSON_AddBoolToObject(mqtt_obj, "tls", api->config->log.mqtt.tls);
    cJSON_AddStringToObject(mqtt_obj, "tls_ca", api->config->log.mqtt.tls_ca);
    cJSON_AddStringToObject(mqtt_obj, "client_id", api->config->log.mqtt.client_id);
    cJSON_AddStringToObject(mqtt_obj, "topic_prefix", api->config->log.mqtt.topic_prefix);
    cJSON_AddNumberToObject(mqtt_obj, "qos", api->config->log.mqtt.qos);
    cJSON_AddNumberToObject(mqtt_obj, "keepalive_sec", api->config->log.mqtt.keepalive_sec);
    cJSON_AddNumberToObject(mqtt_obj, "heartbeat_interval_sec",
                            api->config->log.mqtt.heartbeat_interval_sec);
    cJSON_AddNumberToObject(mqtt_obj, "heartbeat_max_devices",
                            api->config->log.mqtt.heartbeat_max_devices);

    /* https transport */
    https_obj = cJSON_AddObjectToObject(root, "https");
    cJSON_AddBoolToObject(https_obj, "enabled", api->config->log.https.enabled);
    cJSON_AddStringToObject(https_obj, "url", api->config->log.https.url);
    cJSON_AddStringToObject(https_obj, "tls_cert", api->config->log.https.tls_cert);
    cJSON_AddStringToObject(https_obj, "tls_key", api->config->log.https.tls_key);
    cJSON_AddNumberToObject(https_obj, "interval_sec", api->config->log.https.interval_sec);
    cJSON_AddNumberToObject(https_obj, "batch_size", api->config->log.https.batch_size);
    cJSON_AddBoolToObject(https_obj, "compress", api->config->log.https.compress);

    api_json_reply(c, 200, root);
}

static void handle_config_log_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *item;
    cJSON *sub;

    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid JSON body");
        return;
    }

    /* global log fields */
    item = cJSON_GetObjectItem(body, "format");
    if (item && cJSON_IsString(item))
        snprintf(api->config->log.format, sizeof(api->config->log.format),
                 "%s", item->valuestring);

    item = cJSON_GetObjectItem(body, "heartbeat_interval_sec");
    if (item && cJSON_IsNumber(item)) {
        int val = item->valueint;
        if (val < 60) val = 60;
        if (val > 86400) val = 86400;
        api->config->log.heartbeat_interval_sec = val;
    }

    /* syslog transport */
    sub = cJSON_GetObjectItem(body, "syslog");
    if (sub && cJSON_IsObject(sub)) {
        item = cJSON_GetObjectItem(sub, "enabled");
        if (item && cJSON_IsBool(item))
            api->config->log.syslog.enabled = cJSON_IsTrue(item);

        item = cJSON_GetObjectItem(sub, "format");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.format,
                     sizeof(api->config->log.syslog.format),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "facility");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.facility,
                     sizeof(api->config->log.syslog.facility),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "server");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.server,
                     sizeof(api->config->log.syslog.server),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "port");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 1) val = 514;
            if (val > 65535) val = 65535;
            api->config->log.syslog.port = val;
        }

        item = cJSON_GetObjectItem(sub, "tls");
        if (item && cJSON_IsBool(item))
            api->config->log.syslog.tls = cJSON_IsTrue(item);

        item = cJSON_GetObjectItem(sub, "tls_ca");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.tls_ca,
                     sizeof(api->config->log.syslog.tls_ca),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "tls_cert");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.tls_cert,
                     sizeof(api->config->log.syslog.tls_cert),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "tls_key");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.syslog.tls_key,
                     sizeof(api->config->log.syslog.tls_key),
                     "%s", item->valuestring);
    }

    /* mqtt transport */
    sub = cJSON_GetObjectItem(body, "mqtt");
    if (sub && cJSON_IsObject(sub)) {
        item = cJSON_GetObjectItem(sub, "enabled");
        if (item && cJSON_IsBool(item))
            api->config->log.mqtt.enabled = cJSON_IsTrue(item);

        item = cJSON_GetObjectItem(sub, "format");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.mqtt.format,
                     sizeof(api->config->log.mqtt.format),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "broker");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.mqtt.broker,
                     sizeof(api->config->log.mqtt.broker),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "tls");
        if (item && cJSON_IsBool(item))
            api->config->log.mqtt.tls = cJSON_IsTrue(item);

        item = cJSON_GetObjectItem(sub, "tls_ca");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.mqtt.tls_ca,
                     sizeof(api->config->log.mqtt.tls_ca),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "client_id");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.mqtt.client_id,
                     sizeof(api->config->log.mqtt.client_id),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "topic_prefix");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.mqtt.topic_prefix,
                     sizeof(api->config->log.mqtt.topic_prefix),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "qos");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 0) val = 0;
            if (val > 2) val = 2;
            api->config->log.mqtt.qos = val;
        }

        item = cJSON_GetObjectItem(sub, "keepalive_sec");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 10) val = 10;
            if (val > 3600) val = 3600;
            api->config->log.mqtt.keepalive_sec = val;
        }

        item = cJSON_GetObjectItem(sub, "heartbeat_interval_sec");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 10) val = 10;
            if (val > 86400) val = 86400;
            api->config->log.mqtt.heartbeat_interval_sec = val;
        }

        item = cJSON_GetObjectItem(sub, "heartbeat_max_devices");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 0) val = 0;
            if (val > 10000) val = 10000;
            api->config->log.mqtt.heartbeat_max_devices = val;
        }
    }

    /* https transport */
    sub = cJSON_GetObjectItem(body, "https");
    if (sub && cJSON_IsObject(sub)) {
        item = cJSON_GetObjectItem(sub, "enabled");
        if (item && cJSON_IsBool(item))
            api->config->log.https.enabled = cJSON_IsTrue(item);

        item = cJSON_GetObjectItem(sub, "url");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.https.url,
                     sizeof(api->config->log.https.url),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "tls_cert");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.https.tls_cert,
                     sizeof(api->config->log.https.tls_cert),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "tls_key");
        if (item && cJSON_IsString(item))
            snprintf(api->config->log.https.tls_key,
                     sizeof(api->config->log.https.tls_key),
                     "%s", item->valuestring);

        item = cJSON_GetObjectItem(sub, "interval_sec");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 5) val = 5;
            if (val > 86400) val = 86400;
            api->config->log.https.interval_sec = val;
        }

        item = cJSON_GetObjectItem(sub, "batch_size");
        if (item && cJSON_IsNumber(item)) {
            int val = item->valueint;
            if (val < 1) val = 1;
            if (val > 100000) val = 100000;
            api->config->log.https.batch_size = val;
        }

        item = cJSON_GetObjectItem(sub, "compress");
        if (item && cJSON_IsBool(item))
            api->config->log.https.compress = cJSON_IsTrue(item);
    }

    if (api_persist_config(api) < 0) {
        jz_log_error("config/log PUT: failed to persist config");
        cJSON_Delete(body);
        api_error_reply(c, 500, "failed to persist config");
        return;
    }

    api_audit_log(api, "config_log_update", NULL, NULL, "success");
    cJSON_Delete(body);
    handle_config_log_get(c, hm, api);
}

static jz_config_interface_t *find_first_monitor_iface(jz_api_t *api)
{
    int i;
    for (i = 0; i < api->config->system.interface_count &&
                i < JZ_CONFIG_MAX_INTERFACES; i++) {
        if (strcmp(api->config->system.interfaces[i].role, "monitor") == 0)
            return &api->config->system.interfaces[i];
    }
    return NULL;
}

static void handle_config_vlans_get(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *arr;
    int i;
    const jz_config_interface_t *iface;

    (void) hm;
    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    iface = find_first_monitor_iface(api);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "vlans");

    if (iface) {
        for (i = 0; i < iface->vlan_count && i < JZ_CONFIG_MAX_VLANS; i++) {
            const jz_config_vlan_t *v = &iface->vlans[i];
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(obj, "id", v->id);
            cJSON_AddStringToObject(obj, "name", v->name);
            cJSON_AddStringToObject(obj, "subnet", v->subnet);
            cJSON_AddItemToArray(arr, obj);
        }
    }

    api_json_reply(c, 200, root);
}

static void handle_config_vlans_put(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *body;
    cJSON *arr;
    int i;
    int count;
    jz_config_interface_t *iface;

    if (!api || !api->config) {
        api_error_reply(c, 500, "config unavailable");
        return;
    }

    iface = find_first_monitor_iface(api);
    if (!iface) {
        api_error_reply(c, 404, "no monitor interface configured");
        return;
    }

    body = api_parse_body_json(hm);
    if (!body) {
        api_error_reply(c, 400, "invalid JSON body");
        return;
    }

    arr = cJSON_GetObjectItem(body, "vlans");
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "missing 'vlans' array");
        return;
    }

    count = cJSON_GetArraySize(arr);
    if (count > JZ_CONFIG_MAX_VLANS) {
        cJSON_Delete(body);
        api_error_reply(c, 400, "too many VLANs (max 16)");
        return;
    }

    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        cJSON *id_j = cJSON_GetObjectItem(item, "id");
        cJSON *name_j = cJSON_GetObjectItem(item, "name");
        cJSON *subnet_j = cJSON_GetObjectItem(item, "subnet");

        if (!id_j || !cJSON_IsNumber(id_j) ||
            id_j->valueint < 1 || id_j->valueint > 4094) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "invalid VLAN id (must be 1-4094)");
            return;
        }
        if (!name_j || !cJSON_IsString(name_j) || !name_j->valuestring[0]) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "VLAN entry missing 'name'");
            return;
        }
        if (!subnet_j || !cJSON_IsString(subnet_j) || !strchr(subnet_j->valuestring, '/')) {
            cJSON_Delete(body);
            api_error_reply(c, 400, "VLAN entry requires CIDR subnet");
            return;
        }

        {
            int j;
            for (j = 0; j < i; j++) {
                cJSON *prev = cJSON_GetArrayItem(arr, j);
                cJSON *prev_id = cJSON_GetObjectItem(prev, "id");
                if (prev_id && cJSON_IsNumber(prev_id) &&
                    prev_id->valueint == id_j->valueint) {
                    cJSON_Delete(body);
                    api_error_reply(c, 400, "duplicate VLAN id");
                    return;
                }
            }
        }
    }

    iface->vlan_count = count;
    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        jz_config_vlan_t *v = &iface->vlans[i];

        v->id = cJSON_GetObjectItem(item, "id")->valueint;
        snprintf(v->name, sizeof(v->name), "%s",
                 cJSON_GetObjectItem(item, "name")->valuestring);
        snprintf(v->subnet, sizeof(v->subnet), "%s",
                 cJSON_GetObjectItem(item, "subnet")->valuestring);
    }

    if (api_persist_config(api) < 0) {
        jz_log_error("config/vlans PUT: failed to persist config");
        cJSON_Delete(body);
        api_error_reply(c, 500, "failed to persist config");
        return;
    }

    api_audit_log(api, "config_vlans_update", NULL, NULL, "success");
    cJSON_Delete(body);
    handle_config_vlans_get(c, hm, api);
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

/* ── Interface Runtime Status (getifaddrs) ─────────────────────── */

static bool is_rswitch_internal_iface(const char *name)
{
    if (!name)
        return false;
    return strncmp(name, "veth_voq", 8) == 0 ||
           strcmp(name, "mgmt-br") == 0 ||
           strcmp(name, "mgmt0") == 0 ||
           strncmp(name, "rswitch", 7) == 0;
}

static void handle_system_interfaces(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    struct ifaddrs *ifap = NULL, *ifa;
    cJSON *root, *arr;
    int sock_fd;

    (void) hm;
    (void) api;

    if (getifaddrs(&ifap) < 0) {
        api_error_reply(c, 500, "getifaddrs failed");
        return;
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    root = cJSON_CreateObject();
    arr = cJSON_AddArrayToObject(root, "interfaces");

    /* Iterate: emit one entry per AF_INET address (skip loopback). */
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        char addr_buf[INET_ADDRSTRLEN];
        char mask_buf[INET_ADDRSTRLEN];
        struct ifreq ifr;
        cJSON *obj;
        int ifidx;

        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (is_rswitch_internal_iface(ifa->ifa_name)) continue;

        inet_ntop(AF_INET,
                  &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr,
                  addr_buf, sizeof(addr_buf));
        if (ifa->ifa_netmask)
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr,
                      mask_buf, sizeof(mask_buf));
        else
            snprintf(mask_buf, sizeof(mask_buf), "0.0.0.0");

        ifidx = (int) if_nametoindex(ifa->ifa_name);

        obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name", ifa->ifa_name);
        cJSON_AddNumberToObject(obj, "ifindex", (double) ifidx);
        cJSON_AddStringToObject(obj, "ip", addr_buf);
        cJSON_AddStringToObject(obj, "netmask", mask_buf);
        cJSON_AddBoolToObject(obj, "up", (ifa->ifa_flags & IFF_UP) ? 1 : 0);
        cJSON_AddBoolToObject(obj, "running", (ifa->ifa_flags & IFF_RUNNING) ? 1 : 0);

        /* MTU via ioctl */
        if (sock_fd >= 0) {
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            if (ioctl(sock_fd, SIOCGIFMTU, &ifr) == 0)
                cJSON_AddNumberToObject(obj, "mtu", (double) ifr.ifr_mtu);
        }

        cJSON_AddItemToArray(arr, obj);
    }

    /* Also emit interfaces with no IPv4 (link up but no address). */
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        int already = 0;
        struct ifaddrs *check;

        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (is_rswitch_internal_iface(ifa->ifa_name)) continue;
        for (check = ifap; check; check = check->ifa_next) {
            if (!check->ifa_addr) continue;
            if (check->ifa_addr->sa_family == AF_INET &&
                strcmp(check->ifa_name, ifa->ifa_name) == 0) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        {
            struct ifreq ifr;
            cJSON *obj;
            int ifidx = (int) if_nametoindex(ifa->ifa_name);

            obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "name", ifa->ifa_name);
            cJSON_AddNumberToObject(obj, "ifindex", (double) ifidx);
            cJSON_AddNullToObject(obj, "ip");
            cJSON_AddNullToObject(obj, "netmask");
            cJSON_AddBoolToObject(obj, "up", (ifa->ifa_flags & IFF_UP) ? 1 : 0);
            cJSON_AddBoolToObject(obj, "running", (ifa->ifa_flags & IFF_RUNNING) ? 1 : 0);

            if (sock_fd >= 0) {
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                if (ioctl(sock_fd, SIOCGIFMTU, &ifr) == 0)
                    cJSON_AddNumberToObject(obj, "mtu", (double) ifr.ifr_mtu);
            }

            cJSON_AddItemToArray(arr, obj);
        }
    }

    freeifaddrs(ifap);
    if (sock_fd >= 0) close(sock_fd);

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

/* ── Packet Capture Handlers ──────────────────────────────────── */

static void handle_capture_status(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;

    if (!api->capture_mgr || !api->capture_mgr->initialized) {
        api_error_reply(c, 503, "capture manager not initialized");
        return;
    }

    jz_capture_info_t infos[JZ_CAPTURE_MAX_FILES];
    int count = jz_capture_mgr_list(infos, JZ_CAPTURE_MAX_FILES);

    root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "active", api->capture_mgr->active);
    if (api->capture_mgr->active) {
        cJSON_AddStringToObject(root, "filename", api->capture_mgr->writer.path);
        cJSON_AddNumberToObject(root, "bytes_written",
                                (double)api->capture_mgr->writer.bytes_written);
        cJSON_AddNumberToObject(root, "pkt_count",
                                (double)api->capture_mgr->writer.pkt_count);
        cJSON_AddNumberToObject(root, "max_bytes",
                                (double)api->capture_mgr->max_bytes);
    }

    cJSON *arr = cJSON_AddArrayToObject(root, "captures");
    for (int i = 0; i < count; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "filename", infos[i].filename);
        cJSON_AddNumberToObject(obj, "size_bytes", (double)infos[i].size_bytes);
        cJSON_AddNumberToObject(obj, "created", (double)infos[i].created);
        cJSON_AddItemToArray(arr, obj);
    }

    api_json_reply(c, 200, root);
}

static void handle_capture_start(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    cJSON *body = NULL;
    uint64_t max_bytes = 0;

    if (!api->capture_mgr || !api->capture_mgr->initialized) {
        api_error_reply(c, 503, "capture manager not initialized");
        return;
    }

    if (hm->body.len > 0) {
        body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
        if (body) {
            cJSON *mb = cJSON_GetObjectItem(body, "max_bytes");
            if (mb && cJSON_IsNumber(mb) && mb->valuedouble > 0)
                max_bytes = (uint64_t)mb->valuedouble;
            cJSON_Delete(body);
        }
    }

    if (jz_capture_mgr_start(api->capture_mgr, max_bytes) < 0) {
        api_error_reply(c, 500, "failed to start capture");
        return;
    }

    jz_db_t audit_db;
    if (api->db && api->db->path[0] && jz_db_open(&audit_db, api->db->path) == 0) {
        char ts[32];
        time_t now = time(NULL);
        struct tm tmv;
        if (gmtime_r(&now, &tmv))
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        else
            snprintf(ts, sizeof(ts), "unknown");
        char detail[128];
        snprintf(detail, sizeof(detail), "max_bytes=%llu",
                 (unsigned long long)(max_bytes ? max_bytes : JZ_CAPTURE_DEFAULT_MAX_BYTES));
        jz_db_insert_audit(&audit_db, ts, "capture_start", "api", "capture", detail, "ok");
        jz_db_close(&audit_db);
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "started");
    cJSON_AddStringToObject(root, "filename", api->capture_mgr->writer.path);
    api_json_reply(c, 200, root);
}

static void handle_capture_stop(struct mg_connection *c, struct mg_http_message *hm, jz_api_t *api)
{
    cJSON *root;
    (void) hm;

    if (!api->capture_mgr || !api->capture_mgr->initialized) {
        api_error_reply(c, 503, "capture manager not initialized");
        return;
    }

    if (!api->capture_mgr->active) {
        api_error_reply(c, 400, "no active capture");
        return;
    }

    jz_capture_mgr_stop(api->capture_mgr);

    jz_db_t audit_db;
    if (api->db && api->db->path[0] && jz_db_open(&audit_db, api->db->path) == 0) {
        char ts[32];
        time_t now = time(NULL);
        struct tm tmv;
        if (gmtime_r(&now, &tmv))
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        else
            snprintf(ts, sizeof(ts), "unknown");
        jz_db_insert_audit(&audit_db, ts, "capture_stop", "api", "capture", "", "ok");
        jz_db_close(&audit_db);
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "stopped");
    api_json_reply(c, 200, root);
}

static void handle_capture_download(struct mg_connection *c, struct mg_http_message *hm,
                                     jz_api_t *api, struct mg_str filename_str)
{
    char filename[128];
    char path[384];
    (void) api;

    if (api_mg_str_to_cstr(filename_str, filename, sizeof(filename)) < 0) {
        api_error_reply(c, 400, "invalid filename");
        return;
    }

    if (strchr(filename, '/') || strchr(filename, '\\') || strstr(filename, "..")) {
        api_error_reply(c, 400, "invalid filename");
        return;
    }

    snprintf(path, sizeof(path), "%s/%s", JZ_CAPTURE_DIR, filename);

    struct mg_http_serve_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.mime_types = "pcap=application/octet-stream";
    opts.extra_headers = "Content-Disposition: attachment\r\n";
    mg_http_serve_file(c, hm, path, &opts);
}

static void handle_capture_delete(struct mg_connection *c, struct mg_http_message *hm,
                                   jz_api_t *api, struct mg_str filename_str)
{
    char filename[128];
    cJSON *root;
    (void) hm;

    if (api_mg_str_to_cstr(filename_str, filename, sizeof(filename)) < 0) {
        api_error_reply(c, 400, "invalid filename");
        return;
    }

    if (jz_capture_mgr_delete(filename) < 0) {
        api_error_reply(c, 404, "file not found or cannot delete");
        return;
    }

    jz_db_t audit_db;
    if (api->db && api->db->path[0] && jz_db_open(&audit_db, api->db->path) == 0) {
        char ts[32];
        time_t now = time(NULL);
        struct tm tmv;
        if (gmtime_r(&now, &tmv))
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        else
            snprintf(ts, sizeof(ts), "unknown");
        jz_db_insert_audit(&audit_db, ts, "capture_delete", "api", "capture", filename, "ok");
        jz_db_close(&audit_db);
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "deleted");
    cJSON_AddStringToObject(root, "filename", filename);
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
        if (mg_match(hm->uri, mg_str("/api/v1/dhcp_exceptions"), NULL)) {
            handle_dhcp_exception_list(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/alerts/dhcp"), NULL)) {
            handle_dhcp_alerts(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/config/arp_spoof"), NULL)) {
            handle_config_arp_spoof_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/vlans"), NULL)) {
            handle_config_vlans_get(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/log"), NULL)) {
            handle_config_log_get(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/discovery/vlans"), NULL)) {
            handle_discovery_vlans(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/discovery/config"), NULL)) {
            handle_discovery_config_get(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/system/interfaces"), NULL)) {
            handle_system_interfaces(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/captures"), NULL)) {
            handle_capture_status(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/captures/*/download"), caps)) {
            handle_capture_download(c, hm, api, caps[0]);
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
        if (mg_match(hm->uri, mg_str("/api/v1/dhcp_exceptions"), NULL)) {
            handle_dhcp_exception_add(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/captures/start"), NULL)) {
            handle_capture_start(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/captures/stop"), NULL)) {
            handle_capture_stop(c, hm, api);
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
        if (mg_match(hm->uri, mg_str("/api/v1/dhcp_exceptions/*"), caps)) {
            handle_dhcp_exception_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/policies/*"), caps)) {
            handle_policies_del(c, hm, api, caps[0]);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/captures/*"), caps)) {
            handle_capture_delete(c, hm, api, caps[0]);
            return;
        }
    }

    if (mg_match(hm->method, mg_str("PUT"), NULL)) {
        if (mg_match(hm->uri, mg_str("/api/v1/discovery/config"), NULL)) {
            handle_discovery_config_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/guards/auto/config"), NULL)) {
            handle_guards_auto_config_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/interfaces"), NULL)) {
            handle_config_interfaces_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/arp_spoof"), NULL)) {
            handle_config_arp_spoof_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/vlans"), NULL)) {
            handle_config_vlans_put(c, hm, api);
            return;
        }
        if (mg_match(hm->uri, mg_str("/api/v1/config/log"), NULL)) {
            handle_config_log_put(c, hm, api);
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
    jz_arp_spoof_t *arp_spoof;
    jz_capture_mgr_t *capture_mgr;
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
    arp_spoof = api->arp_spoof;
    capture_mgr = api->capture_mgr;

    memset(api, 0, sizeof(*api));
    api->loader = loader;
    api->guard_mgr = guard_mgr;
    api->discovery = discovery;
    api->guard_auto = guard_auto;
    api->policy_mgr = policy_mgr;
    api->config = config;
    api->db = db;
    api->arp_spoof = arp_spoof;
    api->capture_mgr = capture_mgr;

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
