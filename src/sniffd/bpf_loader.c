/* SPDX-License-Identifier: MIT */
/*
 * bpf_loader.c - BPF module loader implementation for sniffd.
 *
 * Uses libbpf to load compiled BPF object files and register programs
 * in the rSwitch pipeline via the rs_progs map.
 */


#include "bpf_loader.h"
#include "log.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── Module Definitions ───────────────────────────────────────── */

/* Default BPF pin path */
#define JZ_BPF_PIN_PATH  "/sys/fs/bpf/jz"

/* rSwitch program registration map */
#define RS_PROGS_PIN     "/sys/fs/bpf/rs_progs"

static const struct {
    const char *name;
    const char *obj_file;
    int         stage;
} module_defs[JZ_MOD_COUNT] = {
    [JZ_MOD_GUARD_CLASSIFIER] = { "guard_classifier",  "jz_guard_classifier.bpf.o",  21 },
    [JZ_MOD_ARP_HONEYPOT]     = { "arp_honeypot",      "jz_arp_honeypot.bpf.o",      22 },
    [JZ_MOD_ICMP_HONEYPOT]    = { "icmp_honeypot",     "jz_icmp_honeypot.bpf.o",     23 },
    [JZ_MOD_SNIFFER_DETECT]   = { "sniffer_detect",    "jz_sniffer_detect.bpf.o",    24 },
    [JZ_MOD_TRAFFIC_WEAVER]   = { "traffic_weaver",    "jz_traffic_weaver.bpf.o",    25 },
    [JZ_MOD_BG_COLLECTOR]     = { "bg_collector",      "jz_bg_collector.bpf.o",      26 },
    [JZ_MOD_THREAT_DETECT]    = { "threat_detect",     "jz_threat_detect.bpf.o",     27 },
    [JZ_MOD_FORENSICS]        = { "forensics",         "jz_forensics.bpf.o",         28 },
};

/* ── Internal Helpers ─────────────────────────────────────────── */

/* Route libbpf messages to jz_log so errors are visible in syslog
 * (daemon mode redirects stderr to /dev/null). */
static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt,
                            va_list ap)
{
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    switch (level) {
    case LIBBPF_WARN:
        jz_log_warn("libbpf: %s", buf);
        break;
    case LIBBPF_INFO:
        jz_log_info("libbpf: %s", buf);
        break;
    case LIBBPF_DEBUG:
        jz_log_debug("libbpf: %s", buf);
        break;
    }
    return 0;
}

/* Ensure pin directory exists. */
static int ensure_pin_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -1;  /* exists but not a directory */
    }
    if (mkdir(path, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Register BPF program fd in rs_progs map at a consecutive slot.
 * rSwitch assigns ingress slots as 0, 1, 2, ... (ascending).
 * The stage number is for ordering only — not for map keys.
 * Returns the assigned slot number on success, -1 on error. */
static int next_slot = 0;

static int register_in_rswitch(int prog_fd, int stage)
{
    int map_fd = bpf_obj_get(RS_PROGS_PIN);
    if (map_fd < 0) {
        jz_log_warn("Cannot open rs_progs map at %s: %s",
                     RS_PROGS_PIN, strerror(errno));
        return -1;
    }

    int assigned = next_slot;
    uint32_t key = (uint32_t)assigned;
    int ret = bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
    close(map_fd);

    if (ret < 0) {
        jz_log_error("Failed to register stage %d at slot %d in rs_progs: %s",
                      stage, assigned, strerror(errno));
        return -1;
    }

    jz_log_info("Registered stage %d at rs_progs slot %d", stage, assigned);
    next_slot++;
    return assigned;
}

static int unregister_from_rswitch(int slot)
{
    int map_fd = bpf_obj_get(RS_PROGS_PIN);
    if (map_fd < 0)
        return -1;

    uint32_t key = (uint32_t)slot;
    int ret = bpf_map_delete_elem(map_fd, &key);
    close(map_fd);

    return ret;
}

/* ── Public API ───────────────────────────────────────────────── */

int jz_bpf_loader_init(jz_bpf_loader_t *loader, const char *bpf_dir)
{
    if (!loader || !bpf_dir)
        return -1;

    libbpf_set_print(libbpf_print_cb);

    memset(loader, 0, sizeof(*loader));
    snprintf(loader->bpf_dir, sizeof(loader->bpf_dir), "%s", bpf_dir);
    snprintf(loader->pin_path, sizeof(loader->pin_path), "%s", JZ_BPF_PIN_PATH);

    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        loader->modules[i].name     = module_defs[i].name;
        loader->modules[i].obj_file = module_defs[i].obj_file;
        loader->modules[i].stage    = module_defs[i].stage;
        loader->modules[i].slot     = -1;
        loader->modules[i].loaded   = false;
        loader->modules[i].enabled  = false;
        loader->modules[i].bpf_obj  = NULL;
        loader->modules[i].prog_fd  = -1;
    }

    loader->initialized = true;
    loader->loaded_count = 0;

    return 0;
}

int jz_bpf_loader_load(jz_bpf_loader_t *loader, jz_mod_id_t mod_id)
{
    if (!loader || !loader->initialized)
        return -1;
    if (mod_id < 0 || mod_id >= JZ_MOD_COUNT)
        return -1;

    jz_bpf_module_t *mod = &loader->modules[mod_id];
    if (mod->loaded) {
        jz_log_warn("Module %s already loaded", mod->name);
        return 0;
    }

    /* Build full path to object file */
    char obj_path[512];
    snprintf(obj_path, sizeof(obj_path), "%s/%s",
             loader->bpf_dir, mod->obj_file);

    /* Check file exists */
    if (access(obj_path, R_OK) < 0) {
        jz_log_error("BPF object not found: %s", obj_path);
        return -1;
    }

    /* Ensure pin directory */
    if (ensure_pin_dir(loader->pin_path) < 0) {
        jz_log_error("Cannot create pin directory: %s", loader->pin_path);
        return -1;
    }

    /* Open BPF object */
    struct bpf_object *obj = bpf_object__open(obj_path);
    if (!obj) {
        jz_log_error("Failed to open BPF object %s: %s",
                      obj_path, strerror(errno));
        return -1;
    }

    /* LIBBPF_PIN_BY_NAME maps get an internal pin_path derived from the
     * object name.  If that path doesn't match what bpf_map__pin()
     * receives, the pin call fails with -EINVAL.  Override every map's
     * pin_path to our canonical directory before load so that post-load
     * bpf_map__pin(map, NULL) always succeeds.
     *
     * We handle two families of maps:
     *   jz_*  — our own maps, pinned under /sys/fs/bpf/jz/<name>
     *   rs_*  — rSwitch shared maps, pinned flat at /sys/fs/bpf/<name>
     *
     * For rs_* maps, a stale pin from a different rSwitch version may
     * have a mismatched value_size (e.g. rs_ctx_map).  If reuse_fd
     * fails we unlink the stale pin and let libbpf create a fresh one. */
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        if (!map_name)
            continue;
        /* Skip internal ELF section maps (.rodata, .bss, .data) */
        if (strchr(map_name, '.'))
            continue;

        int is_jz = (strncmp(map_name, "jz_", 3) == 0);
        int is_rs = (strncmp(map_name, "rs_", 3) == 0);
        if (!is_jz && !is_rs)
            continue;

        /* jz_* maps pin under our subdirectory; rs_* maps pin flat */
        char pin[512];
        if (is_jz)
            snprintf(pin, sizeof(pin), "%s/%s", loader->pin_path, map_name);
        else
            snprintf(pin, sizeof(pin), "/sys/fs/bpf/%s", map_name);

        bpf_map__set_pin_path(map, pin);

        int existing_fd = bpf_obj_get(pin);
        if (existing_fd >= 0) {
            if (bpf_map__reuse_fd(map, existing_fd) < 0) {
                jz_log_warn("Cannot reuse pinned map %s: %s — removing stale pin",
                             map_name, strerror(errno));
                close(existing_fd);
                if (unlink(pin) < 0)
                    jz_log_warn("Failed to unlink stale pin %s: %s",
                                 pin, strerror(errno));
            } else {
                close(existing_fd);
            }
        }

        /* Clean any flat-namespace duplicate for jz_* maps (libbpf's
         * LIBBPF_PIN_BY_NAME may have left one at /sys/fs/bpf/<name>) */
        if (is_jz) {
            char flat[512];
            snprintf(flat, sizeof(flat), "/sys/fs/bpf/%s", map_name);
            unlink(flat);
        }
    }

    /* Load (verify + load into kernel) */
    if (bpf_object__load(obj) < 0) {
        jz_log_error("Failed to load BPF object %s: %s",
                      obj_path, strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    /* Find the main program (bpf_program__next for libbpf < 0.7 compat) */
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        jz_log_error("No BPF program found in %s", obj_path);
        bpf_object__close(obj);
        return -1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        jz_log_error("Invalid program fd for %s", mod->name);
        bpf_object__close(obj);
        return -1;
    }

    /* Pin maps that aren't already pinned (reused maps are already on disk) */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        if (!map_name)
            continue;
        if (strncmp(map_name, "jz_", 3) != 0 &&
            strncmp(map_name, "rs_", 3) != 0)
            continue;

        const char *cur_pin = bpf_map__pin_path(map);
        if (!cur_pin)
            continue;

        int check_fd = bpf_obj_get(cur_pin);
        if (check_fd >= 0) {
            close(check_fd);
            continue;
        }

        if (bpf_map__pin(map, NULL) < 0) {
            jz_log_warn("Failed to pin map %s at %s: %s",
                         map_name, cur_pin, strerror(errno));
        }
    }

    mod->bpf_obj = obj;
    mod->prog_fd = prog_fd;
    mod->loaded = true;
    loader->loaded_count++;

    jz_log_info("Loaded BPF module: %s (stage %d)", mod->name, mod->stage);
    return 0;
}

int jz_bpf_loader_load_all(jz_bpf_loader_t *loader)
{
    if (!loader || !loader->initialized)
        return -1;

    int loaded = 0;
    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        if (jz_bpf_loader_load(loader, (jz_mod_id_t)i) == 0)
            loaded++;
        else
            jz_log_warn("Skipping module %s (load failed)",
                         loader->modules[i].name);
    }

    jz_log_info("Loaded %d/%d BPF modules", loaded, JZ_MOD_COUNT);
    return loaded;
}

int jz_bpf_loader_unload(jz_bpf_loader_t *loader, jz_mod_id_t mod_id)
{
    if (!loader || !loader->initialized)
        return -1;
    if (mod_id < 0 || mod_id >= JZ_MOD_COUNT)
        return -1;

    jz_bpf_module_t *mod = &loader->modules[mod_id];
    if (!mod->loaded)
        return 0;

    /* Unregister from rSwitch if enabled */
    if (mod->enabled) {
        unregister_from_rswitch(mod->slot);
        mod->enabled = false;
        mod->slot = -1;
    }

    /* Close BPF object (also closes prog_fd) */
    if (mod->bpf_obj) {
        bpf_object__close((struct bpf_object *)mod->bpf_obj);
        mod->bpf_obj = NULL;
    }

    mod->prog_fd = -1;
    mod->loaded = false;
    loader->loaded_count--;

    jz_log_info("Unloaded BPF module: %s", mod->name);
    return 0;
}

int jz_bpf_loader_enable(jz_bpf_loader_t *loader, jz_mod_id_t mod_id,
                         bool enable)
{
    if (!loader || !loader->initialized)
        return -1;
    if (mod_id < 0 || mod_id >= JZ_MOD_COUNT)
        return -1;

    jz_bpf_module_t *mod = &loader->modules[mod_id];
    if (!mod->loaded) {
        jz_log_error("Cannot enable unloaded module: %s", mod->name);
        return -1;
    }

    if (enable == mod->enabled)
        return 0;  /* Already in desired state */

    if (enable) {
        int assigned = register_in_rswitch(mod->prog_fd, mod->stage);
        if (assigned < 0)
            return -1;
        mod->slot = assigned;
        mod->enabled = true;
        jz_log_info("Enabled BPF module: %s (stage %d, slot %d)",
                     mod->name, mod->stage, mod->slot);
    } else {
        if (unregister_from_rswitch(mod->slot) < 0)
            return -1;
        mod->slot = -1;
        mod->enabled = false;
        jz_log_info("Disabled BPF module: %s", mod->name);
    }

    return 0;
}

const jz_bpf_module_t *jz_bpf_loader_get_module(const jz_bpf_loader_t *loader,
                                                  jz_mod_id_t mod_id)
{
    if (!loader || mod_id < 0 || mod_id >= JZ_MOD_COUNT)
        return NULL;
    return &loader->modules[mod_id];
}

int jz_bpf_loader_find(const jz_bpf_loader_t *loader, const char *name)
{
    if (!loader || !name)
        return -1;

    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        if (strcmp(loader->modules[i].name, name) == 0)
            return i;
    }
    return -1;
}

int jz_bpf_loader_attach_xdp(jz_bpf_loader_t *loader, const int *ifindexes,
                             const char names[][32], int count)
{
    if (!loader || !loader->initialized || !ifindexes || !names)
        return -1;
    if (count < 0 || count > JZ_MAX_BUSINESS_IFACES)
        return -1;
    if (count == 0) {
        loader->xdp_iface_count = 0;
        return 0;
    }

    int prog_fd = loader->modules[0].prog_fd;
    if (prog_fd < 0) {
        jz_log_error("Cannot attach XDP: guard_classifier not loaded");
        return -1;
    }

    loader->xdp_iface_count = 0;
    for (int i = 0; i < count; i++) {
        if (ifindexes[i] <= 0)
            continue;

        if (bpf_xdp_attach(ifindexes[i], prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            jz_log_error("Failed to attach XDP to %s (ifindex %d): %s",
                         names[i], ifindexes[i], strerror(errno));
            jz_bpf_loader_detach_xdp(loader);
            return -1;
        }

        int pos = loader->xdp_iface_count;
        loader->xdp_ifindexes[pos] = ifindexes[i];
        snprintf(loader->xdp_iface_names[pos],
                 sizeof(loader->xdp_iface_names[pos]), "%s", names[i]);
        loader->xdp_iface_count++;

        jz_log_info("Attached XDP entry program to %s (ifindex %d)",
                    loader->xdp_iface_names[pos], ifindexes[i]);
    }

    return 0;
}

int jz_bpf_loader_ensure_xdp(jz_bpf_loader_t *loader,
                             const char (*want_names)[32],
                             const int *want_ifindexes,
                             int want_count)
{
    int i;
    int j;
    int added = 0;
    int prog_fd;

    if (!loader || !loader->initialized || !want_names || !want_ifindexes)
        return -1;
    if (want_count <= 0)
        return 0;

    prog_fd = loader->modules[0].prog_fd;
    if (prog_fd < 0) {
        jz_log_error("ensure_xdp: guard_classifier not loaded");
        return -1;
    }

    jz_log_info("ensure_xdp: reconciling %d wanted ifaces (currently %d attached)",
                want_count, loader->xdp_iface_count);

    for (i = 0; i < want_count; i++) {
        bool already = false;

        if (want_ifindexes[i] <= 0)
            continue;

        for (j = 0; j < loader->xdp_iface_count; j++) {
            if (loader->xdp_ifindexes[j] == want_ifindexes[i]) {
                already = true;
                break;
            }
        }

        if (already)
            continue;

        if (loader->xdp_iface_count >= JZ_MAX_BUSINESS_IFACES) {
            jz_log_warn("ensure_xdp: max interfaces reached, skipping %s",
                        want_names[i]);
            continue;
        }

        if (bpf_xdp_attach(want_ifindexes[i], prog_fd,
                            XDP_FLAGS_SKB_MODE, NULL) < 0) {
            jz_log_error("ensure_xdp: attach XDP to %s (ifindex %d): %s",
                         want_names[i], want_ifindexes[i], strerror(errno));
            continue;
        }

        {
            int pos = loader->xdp_iface_count;
            loader->xdp_ifindexes[pos] = want_ifindexes[i];
            snprintf(loader->xdp_iface_names[pos],
                     sizeof(loader->xdp_iface_names[pos]), "%s",
                     want_names[i]);
            loader->xdp_iface_count++;
            added++;
            jz_log_info("ensure_xdp: attached XDP to %s (ifindex %d)",
                        want_names[i], want_ifindexes[i]);
        }
    }

    /* Detach interfaces no longer in the wanted set */
    for (j = loader->xdp_iface_count - 1; j >= 0; j--) {
        bool wanted = false;

        for (i = 0; i < want_count; i++) {
            if (loader->xdp_ifindexes[j] == want_ifindexes[i]) {
                wanted = true;
                break;
            }
        }

        if (!wanted) {
            jz_log_info("ensure_xdp: detaching XDP from %s (ifindex %d, no longer configured)",
                        loader->xdp_iface_names[j], loader->xdp_ifindexes[j]);
            bpf_xdp_detach(loader->xdp_ifindexes[j], XDP_FLAGS_SKB_MODE, NULL);

            /* Shift remaining entries down */
            int last = loader->xdp_iface_count - 1;
            if (j < last) {
                loader->xdp_ifindexes[j] = loader->xdp_ifindexes[last];
                memcpy(loader->xdp_iface_names[j],
                       loader->xdp_iface_names[last],
                       sizeof(loader->xdp_iface_names[j]));
            }
            loader->xdp_ifindexes[last] = 0;
            loader->xdp_iface_names[last][0] = '\0';
            loader->xdp_iface_count--;
        }
    }

    return added;
}

void jz_bpf_loader_detach_xdp(jz_bpf_loader_t *loader)
{
    if (!loader)
        return;

    for (int i = 0; i < loader->xdp_iface_count; i++) {
        if (loader->xdp_ifindexes[i] <= 0)
            continue;

        if (bpf_xdp_detach(loader->xdp_ifindexes[i], XDP_FLAGS_SKB_MODE, NULL) < 0) {
            jz_log_warn("Failed to detach XDP from %s (ifindex %d): %s",
                        loader->xdp_iface_names[i], loader->xdp_ifindexes[i],
                        strerror(errno));
        } else {
            jz_log_info("Detached XDP from %s (ifindex %d)",
                        loader->xdp_iface_names[i], loader->xdp_ifindexes[i]);
        }

        loader->xdp_ifindexes[i] = 0;
        loader->xdp_iface_names[i][0] = '\0';
    }

    loader->xdp_iface_count = 0;
}

void jz_bpf_loader_destroy(jz_bpf_loader_t *loader)
{
    if (!loader)
        return;

    jz_bpf_loader_detach_xdp(loader);

    for (int i = 0; i < JZ_MOD_COUNT; i++) {
        if (loader->modules[i].loaded)
            jz_bpf_loader_unload(loader, (jz_mod_id_t)i);
    }

    loader->initialized = false;
}
