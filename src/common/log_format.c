/* SPDX-License-Identifier: MIT */
/* log_format.c -- V1/V2 log format engine. */

#include "log_format.h"
#include <linux/types.h>
#include "jz_events.h"
#include "jz_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "cJSON.h"

static atomic_uint_fast64_t g_seq = 0;

static void ip4_str(__u32 ip, char *buf, size_t size)
{
    if (!buf || size == 0) {
        return;
    }

    if (!inet_ntop(AF_INET, &ip, buf, (socklen_t)size)) {
        snprintf(buf, size, "0.0.0.0");
    }
}

static void mac_str(const __u8 mac[6], char *buf, size_t size)
{
    if (!buf || size == 0) {
        return;
    }

    if (!mac) {
        snprintf(buf, size, "00:00:00:00:00:00");
        return;
    }

    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void iso8601_now(char *buf, size_t size)
{
    struct timespec ts;
    struct tm tm;
    size_t n;
    long gmtoff;
    char sign;
    long tz_h;
    long tz_m;

    if (!buf || size == 0) {
        return;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(buf, size, "1970-01-01T00:00:00.000000000+00:00");
        return;
    }

    if (!localtime_r(&ts.tv_sec, &tm)) {
        snprintf(buf, size, "1970-01-01T00:00:00.000000000+00:00");
        return;
    }

    n = strftime(buf, size, "%Y-%m-%dT%H:%M:%S", &tm);
    if (n == 0 || n >= size) {
        if (size > 0) {
            buf[0] = '\0';
        }
        return;
    }

    gmtoff = (long)tm.tm_gmtoff;
    sign = (gmtoff >= 0) ? '+' : '-';
    if (gmtoff < 0) {
        gmtoff = -gmtoff;
    }
    tz_h = gmtoff / 3600;
    tz_m = (gmtoff % 3600) / 60;

    snprintf(buf + n, size - n, ".%09ld%c%02ld:%02ld",
             ts.tv_nsec, sign, tz_h, tz_m);
}

static cJSON *v2_envelope(const char *device_id, uint64_t seq, const char *type)
{
    cJSON *root;
    char ts[64];

    if (!device_id || !type) {
        return NULL;
    }

    iso8601_now(ts, sizeof(ts));

    root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }

    cJSON_AddNumberToObject(root, "v", 2);
    cJSON_AddStringToObject(root, "device_id", device_id);
    cJSON_AddNumberToObject(root, "seq", (double)seq);
    cJSON_AddStringToObject(root, "ts", ts);
    cJSON_AddStringToObject(root, "type", type);
    cJSON_AddNullToObject(root, "data");

    return root;
}

static const char *threat_action_str(__u8 action)
{
    switch (action) {
    case 0:
        return "log_only";
    case 1:
        return "log_drop";
    case 2:
        return "log_redirect";
    default:
        return "unknown";
    }
}

static const char *policy_action_str(__u8 action)
{
    switch (action) {
    case JZ_ACTION_PASS:
        return "pass";
    case JZ_ACTION_DROP:
        return "drop";
    case JZ_ACTION_REDIRECT:
        return "redirect";
    case JZ_ACTION_MIRROR:
        return "mirror";
    case JZ_ACTION_REDIRECT_MIRROR:
        return "redirect_mirror";
    default:
        return "unknown";
    }
}

uint64_t jz_log_next_seq(void)
{
    return atomic_fetch_add_explicit(&g_seq, 1, memory_order_relaxed) + 1;
}

int jz_log_v1_attack(char *buf, size_t bufsz,
                     const char *device_id,
                     const struct jz_event_attack *ev)
{
    char src_ip_s[INET_ADDRSTRLEN];
    char guard_ip_s[INET_ADDRSTRLEN];
    char src_mac_s[18];
    int ethertype;
    int ip_proto;
    int n;

    if (!buf || bufsz == 0 || !device_id || !ev) {
        return -1;
    }

    ip4_str(ev->hdr.src_ip, src_ip_s, sizeof(src_ip_s));
    ip4_str(ev->guarded_ip, guard_ip_s, sizeof(guard_ip_s));
    mac_str(ev->hdr.src_mac, src_mac_s, sizeof(src_mac_s));

    ethertype = (ev->protocol == 1) ? 0x0806 : 0x0800;
    ip_proto = (ev->protocol == 2) ? 1 : 0;

    n = snprintf(buf, bufsz,
                 "syslog_version=1.10.0,"
                 "dev_serial=%s,"
                 "log_type=1,"
                 "sub_type=1,"
                 "attack_mac=%s,"
                 "attack_ip=%s,"
                 "response_ip=%s,"
                 "response_port=0,"
                 "line_id=%u,"
                 "Iface_type=1,"
                 "Vlan_id=0,"
                 "log_time=%ld,"
                 "eth_type=%d,"
                 "ip_type=%d",
                 device_id, src_mac_s, src_ip_s, guard_ip_s,
                 ev->hdr.ifindex,
                 (long)(ev->hdr.timestamp_ns / 1000000000ULL),
                 ethertype, ip_proto);

    return (n >= 0 && (size_t)n < bufsz) ? n : -1;
}

int jz_log_v1_heartbeat(char *buf, size_t bufsz,
                        const char *device_id,
                        const jz_heartbeat_data_t *hb)
{
    char time_str[32];
    time_t now = time(NULL);
    struct tm tm;
    int n;

    if (!buf || bufsz == 0 || !device_id || !hb) {
        return -1;
    }

    if (!localtime_r(&now, &tm)) {
        return -1;
    }
    if (strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
        return -1;
    }

    n = snprintf(buf, bufsz,
                 "syslog_version=1.10.0,"
                 "dev_serial=%s,"
                 "log_type=2,"
                 "sentry_count=%d,"
                 "real_host_count=%d,"
                 "dev_start_time=%ld,"
                 "dev_end_time=%ld,"
                 "time=%s",
                 device_id,
                 hb->total_guards,
                 hb->online_devices,
                 hb->daemon_start_epoch,
                 (long)now,
                 time_str);

    return (n >= 0 && (size_t)n < bufsz) ? n : -1;
}

char *jz_log_v2_attack(const char *device_id, uint64_t seq,
                       const struct jz_event_attack *ev)
{
    cJSON *root;
    cJSON *data;
    char *json_str;
    char ip_s[INET_ADDRSTRLEN];
    char guard_ip_s[INET_ADDRSTRLEN];
    char mac_s[18];
    char guard_mac_s[18];

    if (!device_id || !ev) {
        return NULL;
    }

    root = v2_envelope(device_id, seq, "attack");
    if (!root) {
        return NULL;
    }

    data = cJSON_CreateObject();
    if (!data) {
        cJSON_Delete(root);
        return NULL;
    }

    ip4_str(ev->hdr.src_ip, ip_s, sizeof(ip_s));
    mac_str(ev->hdr.src_mac, mac_s, sizeof(mac_s));
    ip4_str(ev->guarded_ip, guard_ip_s, sizeof(guard_ip_s));
    mac_str(ev->fake_mac, guard_mac_s, sizeof(guard_mac_s));

    cJSON_AddStringToObject(data, "src_ip", ip_s);
    cJSON_AddStringToObject(data, "src_mac", mac_s);
    cJSON_AddStringToObject(data, "guard_ip", guard_ip_s);
    cJSON_AddStringToObject(data, "guard_mac", guard_mac_s);
    cJSON_AddStringToObject(data, "guard_type",
                            ev->guard_type == JZ_GUARD_STATIC ? "static" : "dynamic");
    cJSON_AddStringToObject(data, "protocol",
                            ev->protocol == 1 ? "arp" : "icmp");
    cJSON_AddNumberToObject(data, "dst_port", 0);
    cJSON_AddNumberToObject(data, "ifindex", ev->hdr.ifindex);
    cJSON_AddNumberToObject(data, "vlan_id", 0);
    cJSON_AddNumberToObject(data, "ethertype",
                            ev->protocol == 1 ? 0x0806 : 0x0800);
    cJSON_AddNumberToObject(data, "ip_proto",
                            ev->protocol == 2 ? 1 : 0);

    cJSON_ReplaceItemInObject(root, "data", data);

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *jz_log_v2_sniffer(const char *device_id, uint64_t seq,
                        const struct jz_event_sniffer *ev)
{
    cJSON *root;
    cJSON *data;
    char *json_str;
    char suspect_mac_s[18];
    char suspect_ip_s[INET_ADDRSTRLEN];
    char probe_ip_s[INET_ADDRSTRLEN];

    if (!device_id || !ev) {
        return NULL;
    }

    root = v2_envelope(device_id, seq, "sniffer");
    if (!root) {
        return NULL;
    }

    data = cJSON_CreateObject();
    if (!data) {
        cJSON_Delete(root);
        return NULL;
    }

    mac_str(ev->suspect_mac, suspect_mac_s, sizeof(suspect_mac_s));
    ip4_str(ev->suspect_ip, suspect_ip_s, sizeof(suspect_ip_s));
    ip4_str(ev->probe_ip, probe_ip_s, sizeof(probe_ip_s));

    cJSON_AddStringToObject(data, "suspect_mac", suspect_mac_s);
    cJSON_AddStringToObject(data, "suspect_ip", suspect_ip_s);
    cJSON_AddStringToObject(data, "probe_ip", probe_ip_s);
    cJSON_AddNumberToObject(data, "ifindex", ev->hdr.ifindex);
    cJSON_AddNumberToObject(data, "response_count", ev->response_count);

    cJSON_ReplaceItemInObject(root, "data", data);

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *jz_log_v2_threat(const char *device_id, uint64_t seq,
                       const struct jz_event_threat *ev)
{
    cJSON *root;
    cJSON *data;
    char *json_str;
    char src_ip_s[INET_ADDRSTRLEN];
    char dst_ip_s[INET_ADDRSTRLEN];
    char desc[sizeof(ev->description) + 1];

    if (!device_id || !ev) {
        return NULL;
    }

    root = v2_envelope(device_id, seq, "threat");
    if (!root) {
        return NULL;
    }

    data = cJSON_CreateObject();
    if (!data) {
        cJSON_Delete(root);
        return NULL;
    }

    ip4_str(ev->hdr.src_ip, src_ip_s, sizeof(src_ip_s));
    ip4_str(ev->hdr.dst_ip, dst_ip_s, sizeof(dst_ip_s));
    memcpy(desc, ev->description, sizeof(ev->description));
    desc[sizeof(ev->description)] = '\0';

    cJSON_AddNumberToObject(data, "pattern_id", ev->pattern_id);
    cJSON_AddNumberToObject(data, "threat_level", ev->threat_level);
    cJSON_AddStringToObject(data, "action_taken", threat_action_str(ev->action_taken));
    cJSON_AddStringToObject(data, "description", desc);
    cJSON_AddStringToObject(data, "src_ip", src_ip_s);
    cJSON_AddStringToObject(data, "dst_ip", dst_ip_s);
    cJSON_AddNumberToObject(data, "ifindex", ev->hdr.ifindex);

    cJSON_ReplaceItemInObject(root, "data", data);

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *jz_log_v2_policy(const char *device_id, uint64_t seq,
                       const struct jz_event_policy *ev)
{
    cJSON *root;
    cJSON *data;
    char *json_str;
    char src_ip_s[INET_ADDRSTRLEN];
    char dst_ip_s[INET_ADDRSTRLEN];

    if (!device_id || !ev) {
        return NULL;
    }

    root = v2_envelope(device_id, seq, "policy");
    if (!root) {
        return NULL;
    }

    data = cJSON_CreateObject();
    if (!data) {
        cJSON_Delete(root);
        return NULL;
    }

    ip4_str(ev->flow.src_ip, src_ip_s, sizeof(src_ip_s));
    ip4_str(ev->flow.dst_ip, dst_ip_s, sizeof(dst_ip_s));

    cJSON_AddNumberToObject(data, "policy_id", ev->policy_id);
    cJSON_AddStringToObject(data, "action", policy_action_str(ev->action));
    cJSON_AddStringToObject(data, "src_ip", src_ip_s);
    cJSON_AddStringToObject(data, "dst_ip", dst_ip_s);
    cJSON_AddNumberToObject(data, "src_port", ev->flow.src_port);
    cJSON_AddNumberToObject(data, "dst_port", ev->flow.dst_port);
    cJSON_AddNumberToObject(data, "proto", ev->flow.proto);
    cJSON_AddNumberToObject(data, "ifindex", ev->hdr.ifindex);

    cJSON_ReplaceItemInObject(root, "data", data);

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *jz_log_v2_heartbeat(const char *device_id, uint64_t seq,
                          const char *heartbeat_json)
{
    cJSON *root;
    cJSON *data;
    char *json_str;

    if (!device_id || !heartbeat_json) {
        return NULL;
    }

    root = v2_envelope(device_id, seq, "heartbeat");
    if (!root) {
        return NULL;
    }

    data = cJSON_Parse(heartbeat_json);
    if (!data) {
        cJSON_Delete(root);
        return NULL;
    }

    cJSON_ReplaceItemInObject(root, "data", data);

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}
