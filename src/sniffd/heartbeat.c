/* SPDX-License-Identifier: MIT */
/* heartbeat.c — Periodic heartbeat data assembly. */

#include "heartbeat.h"
#include "log.h"

#include <cJSON.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t realtime_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
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

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json)
        jz_log_info("heartbeat: assembled (%d guards, %d devices, %d modules)",
                     static_guards + dynamic_guards, device_count,
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
