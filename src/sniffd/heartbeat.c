/* SPDX-License-Identifier: MIT */
/* heartbeat.c — Periodic heartbeat data assembly. */

#include "heartbeat.h"
#include "log.h"
#include "log_format.h"
#include "../collectord/syslog_export.h"

#include <cJSON.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JZ_HEARTBEAT_MAX_DEVICES_CAP 200

/* Allow sniffd builds that do not link collectord syslog module. */
extern int jz_syslog_send(const char *msg) __attribute__((weak));

typedef struct heartbeat_device_ref {
    const device_profile_t *profile;
} heartbeat_device_ref_t;

static uint64_t realtime_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

static void profile_field_copy(char *dst, size_t dst_sz,
                               const char *src, size_t src_cap)
{
    size_t i;

    if (!dst || dst_sz == 0) {
        return;
    }
    if (!src || src_cap == 0) {
        dst[0] = '\0';
        return;
    }

    i = 0;
    while (i + 1 < dst_sz && i < src_cap && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static const char *non_empty_or_unknown(const char *s)
{
    return (s && s[0] != '\0') ? s : "Unknown";
}

static void ip4_to_str(uint32_t ip, char *buf, size_t bufsz)
{
    struct in_addr addr;

    if (!buf || bufsz == 0) {
        return;
    }

    if (ip == 0) {
        snprintf(buf, bufsz, "0.0.0.0");
        return;
    }

    addr.s_addr = ip;
    if (!inet_ntop(AF_INET, &addr, buf, bufsz)) {
        snprintf(buf, bufsz, "0.0.0.0");
    }
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t bufsz)
{
    if (!mac || !buf || bufsz == 0) {
        return;
    }
    (void)snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void epoch_to_iso8601(uint32_t epoch_sec, char *buf, size_t bufsz)
{
    time_t t;
    struct tm tmv;

    if (!buf || bufsz == 0) {
        return;
    }

    if (epoch_sec == 0) {
        buf[0] = '\0';
        return;
    }

    t = (time_t)epoch_sec;
    if (!gmtime_r(&t, &tmv)) {
        buf[0] = '\0';
        return;
    }

    if (strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) {
        buf[0] = '\0';
    }
}

static void add_count_field(cJSON *obj, const char *key)
{
    cJSON *existing;
    int cur;

    if (!obj || !key || key[0] == '\0') {
        return;
    }

    existing = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(existing)) {
        cur = existing->valueint;
        cJSON_SetIntValue(existing, cur + 1);
    } else {
        cJSON_AddNumberToObject(obj, key, 1);
    }
}

static int compare_profile_ref_desc(const void *a, const void *b)
{
    const heartbeat_device_ref_t *da = (const heartbeat_device_ref_t *)a;
    const heartbeat_device_ref_t *db = (const heartbeat_device_ref_t *)b;
    const device_profile_t *pa = da->profile;
    const device_profile_t *pb = db->profile;

    if (pa->confidence != pb->confidence) {
        return (int)pb->confidence - (int)pa->confidence;
    }
    if (pa->last_seen != pb->last_seen) {
        return (pb->last_seen > pa->last_seen) ? 1 : -1;
    }

    return memcmp(pa->mac, pb->mac, sizeof(pa->mac));
}

static void add_topology_and_devices(cJSON *root, const jz_heartbeat_t *hb,
                                     int *identified_out,
                                     int *unidentified_out)
{
    cJSON *topology;
    cJSON *by_class;
    cJSON *by_os;
    cJSON *by_vendor;
    cJSON *devices;
    heartbeat_device_ref_t *refs;
    size_t ref_cap;
    size_t ref_count;
    int identified;
    int unidentified;
    int max_devices;
    int i;

    if (identified_out) {
        *identified_out = 0;
    }
    if (unidentified_out) {
        *unidentified_out = 0;
    }
    if (!root || !hb || !hb->discovery) {
        return;
    }

    topology = cJSON_CreateObject();
    by_class = cJSON_CreateObject();
    by_os = cJSON_CreateObject();
    by_vendor = cJSON_CreateObject();
    devices = cJSON_CreateArray();
    if (!topology || !by_class || !by_os || !by_vendor || !devices) {
        cJSON_Delete(topology);
        cJSON_Delete(by_class);
        cJSON_Delete(by_os);
        cJSON_Delete(by_vendor);
        cJSON_Delete(devices);
        return;
    }

    max_devices = JZ_HEARTBEAT_MAX_DEVICES_CAP;
    if (hb->config) {
        int configured = hb->config->log.mqtt.heartbeat_max_devices;
        if (configured > 0 && configured < max_devices) {
            max_devices = configured;
        }
    }

    ref_cap = (hb->discovery->device_count > 0) ?
              (size_t)hb->discovery->device_count : 64U;
    refs = calloc(ref_cap, sizeof(*refs));
    ref_count = 0;
    identified = 0;
    unidentified = 0;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        const jz_discovery_device_t *node = hb->discovery->buckets[i];
        while (node) {
            const device_profile_t *p = &node->profile;
            char class_buf[sizeof(p->device_class) + 1];
            char os_buf[sizeof(p->os_class) + 1];
            char vendor_buf[sizeof(p->vendor) + 1];

            if (p->confidence > 0) {
                identified++;
            } else {
                unidentified++;
            }

            profile_field_copy(class_buf, sizeof(class_buf),
                               p->device_class, sizeof(p->device_class));
            profile_field_copy(os_buf, sizeof(os_buf),
                               p->os_class, sizeof(p->os_class));
            profile_field_copy(vendor_buf, sizeof(vendor_buf),
                               p->vendor, sizeof(p->vendor));

            add_count_field(by_class, non_empty_or_unknown(class_buf));
            add_count_field(by_os, non_empty_or_unknown(os_buf));
            add_count_field(by_vendor, non_empty_or_unknown(vendor_buf));

            if (refs && max_devices > 0) {
                if (ref_count >= ref_cap) {
                    size_t new_cap = ref_cap + 128U;
                    heartbeat_device_ref_t *tmp =
                        realloc(refs, new_cap * sizeof(*refs));
                    if (!tmp) {
                        free(refs);
                        refs = NULL;
                    } else {
                        refs = tmp;
                        ref_cap = new_cap;
                    }
                }
                if (refs) {
                    refs[ref_count].profile = p;
                    ref_count++;
                }
            }

            node = node->next;
        }
    }

    cJSON_AddNumberToObject(topology, "total_identified", identified);
    cJSON_AddNumberToObject(topology, "total_unidentified", unidentified);
    cJSON_AddItemToObject(topology, "by_class", by_class);
    cJSON_AddItemToObject(topology, "by_os", by_os);
    cJSON_AddItemToObject(topology, "by_vendor", by_vendor);

    if (refs && ref_count > 1) {
        qsort(refs, ref_count, sizeof(*refs), compare_profile_ref_desc);
    }

    if (refs && max_devices > 0) {
        size_t out_n = (size_t)max_devices;
        if (out_n > ref_count) {
            out_n = ref_count;
        }

        for (size_t k = 0; k < out_n; k++) {
            const device_profile_t *p = refs[k].profile;
            cJSON *dev = cJSON_CreateObject();
            char ip_s[INET_ADDRSTRLEN];
            char mac_s[18];
            char first_seen_s[32];
            char last_seen_s[32];
            char vendor_buf[sizeof(p->vendor) + 1];
            char os_buf[sizeof(p->os_class) + 1];
            char class_buf[sizeof(p->device_class) + 1];
            char host_buf[sizeof(p->hostname) + 1];

            if (!dev) {
                continue;
            }

            ip4_to_str(p->ip, ip_s, sizeof(ip_s));
            mac_to_str(p->mac, mac_s, sizeof(mac_s));
            epoch_to_iso8601(p->first_seen, first_seen_s, sizeof(first_seen_s));
            epoch_to_iso8601(p->last_seen, last_seen_s, sizeof(last_seen_s));
            profile_field_copy(vendor_buf, sizeof(vendor_buf), p->vendor,
                               sizeof(p->vendor));
            profile_field_copy(os_buf, sizeof(os_buf), p->os_class,
                               sizeof(p->os_class));
            profile_field_copy(class_buf, sizeof(class_buf), p->device_class,
                               sizeof(p->device_class));
            profile_field_copy(host_buf, sizeof(host_buf), p->hostname,
                               sizeof(p->hostname));

            cJSON_AddStringToObject(dev, "ip", ip_s);
            cJSON_AddStringToObject(dev, "mac", mac_s);
            cJSON_AddNumberToObject(dev, "vlan", p->vlan);
            cJSON_AddStringToObject(dev, "vendor", vendor_buf);
            cJSON_AddStringToObject(dev, "os_class", os_buf);
            cJSON_AddStringToObject(dev, "device_class", class_buf);
            cJSON_AddStringToObject(dev, "hostname", host_buf);
            cJSON_AddNumberToObject(dev, "confidence", p->confidence);
            cJSON_AddStringToObject(dev, "first_seen", first_seen_s);
            cJSON_AddStringToObject(dev, "last_seen", last_seen_s);

            cJSON_AddItemToArray(devices, dev);
        }
    }

    free(refs);
    cJSON_AddItemToObject(root, "network_topology", topology);
    cJSON_AddItemToObject(root, "devices", devices);

    if (identified_out) {
        *identified_out = identified;
    }
    if (unidentified_out) {
        *unidentified_out = unidentified;
    }
}

int jz_heartbeat_init(jz_heartbeat_t *hb, const jz_config_t *cfg,
                      const jz_bpf_loader_t *loader,
                      const jz_guard_mgr_t *guard_mgr,
                      const jz_discovery_t *discovery)
{
    if (!hb || !cfg)
        return -1;

    memset(hb, 0, sizeof(*hb));
    hb->config = cfg;
    hb->loader = loader;
    hb->guard_mgr = guard_mgr;
    hb->discovery = discovery;
    hb->interval_sec = cfg->log.heartbeat_interval_sec;
    if (hb->interval_sec <= 0)
        hb->interval_sec = 1800;
    hb->daemon_start_epoch = (uint64_t)time(NULL);
    hb->last_tick_sec = 0;
    hb->initialized = true;

    jz_log_info("heartbeat: init interval=%ds", hb->interval_sec);
    return 0;
}

static int count_modules_loaded(const jz_bpf_loader_t *loader)
{
    if (!loader)
        return 0;
    return loader->loaded_count;
}

static int count_modules_failed(const jz_bpf_loader_t *loader)
{
    int failed = 0;

    if (!loader)
        return 0;

    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        const jz_bpf_module_t *m = &loader->modules[i];
        if (m->name[0] && !m->loaded)
            failed++;
    }
    return failed;
}

static int count_static_guards(const jz_guard_mgr_t *gm)
{
    if (!gm || !gm->initialized)
        return 0;

    int count = 0;
    for (int i = 0; i < gm->dynamic_count; i++) {
        if (gm->dynamic_entries[i].guard_type == JZ_GUARD_STATIC)
            count++;
    }
    return count;
}

static cJSON *build_module_array(const jz_bpf_loader_t *loader)
{
    cJSON *arr = cJSON_CreateArray();

    if (!arr || !loader)
        return arr;

    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        const jz_bpf_module_t *m = &loader->modules[i];
        if (!m->name[0])
            continue;

        cJSON *obj = cJSON_CreateObject();
        if (!obj)
            continue;

        cJSON_AddStringToObject(obj, "name", m->name);
        cJSON_AddBoolToObject(obj, "loaded", m->loaded);
        cJSON_AddBoolToObject(obj, "enabled", m->enabled);
        cJSON_AddNumberToObject(obj, "stage", m->stage);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

char *jz_heartbeat_tick(jz_heartbeat_t *hb)
{
    uint64_t now;
    cJSON *root;
    cJSON *modules;
    char *json;
    int modules_loaded;
    int modules_failed;
    int static_guards;
    int dynamic_guards;
    int device_count;
    int identified_devices;
    int unidentified_devices;

    if (!hb || !hb->initialized)
        return NULL;

    now = realtime_sec();
    if (hb->last_tick_sec > 0 &&
        (now - hb->last_tick_sec) < (uint64_t)hb->interval_sec)
        return NULL;

    hb->last_tick_sec = now;

    modules_loaded = count_modules_loaded(hb->loader);
    modules_failed = count_modules_failed(hb->loader);
    static_guards = count_static_guards(hb->guard_mgr);
    dynamic_guards = hb->guard_mgr ? hb->guard_mgr->dynamic_count : 0;
    device_count = hb->discovery ? hb->discovery->device_count : 0;

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    cJSON_AddNumberToObject(root, "static_guards", static_guards);
    cJSON_AddNumberToObject(root, "dynamic_guards", dynamic_guards);
    cJSON_AddNumberToObject(root, "total_guards",
                            static_guards + dynamic_guards);
    cJSON_AddNumberToObject(root, "online_devices", device_count);
    cJSON_AddNumberToObject(root, "modules_loaded", modules_loaded);
    cJSON_AddNumberToObject(root, "modules_failed", modules_failed);
    cJSON_AddNumberToObject(root, "uptime_sec",
                            (double)(now - hb->daemon_start_epoch));
    cJSON_AddNumberToObject(root, "daemon_start_epoch",
                            (double)hb->daemon_start_epoch);

    modules = build_module_array(hb->loader);
    if (modules)
        cJSON_AddItemToObject(root, "modules", modules);

    add_topology_and_devices(root, hb, &identified_devices, &unidentified_devices);

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json && hb->config && hb->config->log.syslog.enabled && jz_syslog_send) {
        char syslog_buf[512];
        const char *device_id = hb->config->system.device_id[0] ?
                                hb->config->system.device_id : "unknown";
        jz_heartbeat_data_t v1_hb;
        int slen;

        memset(&v1_hb, 0, sizeof(v1_hb));
        v1_hb.static_guards = static_guards;
        v1_hb.dynamic_guards = dynamic_guards;
        v1_hb.total_guards = static_guards + dynamic_guards;
        v1_hb.online_devices = device_count;
        v1_hb.modules_loaded = modules_loaded;
        v1_hb.modules_failed = modules_failed;
        v1_hb.uptime_sec = (long)(now - hb->daemon_start_epoch);
        v1_hb.daemon_start_epoch = (long)hb->daemon_start_epoch;

        slen = jz_log_v1_heartbeat(syslog_buf, sizeof(syslog_buf), device_id, &v1_hb);
        if (slen > 0) {
            (void)jz_syslog_send(syslog_buf);
        }
    }

    if (json)
        jz_log_info("heartbeat: assembled (%d guards, %d devices [%d id/%d unid], %d modules)",
                    static_guards + dynamic_guards, device_count,
                    identified_devices, unidentified_devices,
                    modules_loaded);
    return json;
}

void jz_heartbeat_update_config(jz_heartbeat_t *hb, const jz_config_t *cfg)
{
    if (!hb || !cfg)
        return;
    hb->config = cfg;
    hb->interval_sec = cfg->log.heartbeat_interval_sec;
    if (hb->interval_sec <= 0)
        hb->interval_sec = 1800;
}

void jz_heartbeat_destroy(jz_heartbeat_t *hb)
{
    if (!hb)
        return;
    hb->initialized = false;
}
