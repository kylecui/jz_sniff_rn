/* SPDX-License-Identifier: MIT */
/*
 * bpf_loader.h - BPF module loader for sniffd.
 *
 * Loads all jz_sniff_rn BPF programs via libbpf, pins maps under
 * /sys/fs/bpf/jz/, and provides module enable/disable control.
 */

#ifndef JZ_BPF_LOADER_H
#define JZ_BPF_LOADER_H

#include <stdbool.h>
#include <stdint.h>

/* ── BPF Module Identifiers ── */
typedef enum {
    JZ_MOD_GUARD_CLASSIFIER = 0,
    JZ_MOD_ARP_HONEYPOT,
    JZ_MOD_ICMP_HONEYPOT,
    JZ_MOD_SNIFFER_DETECT,
    JZ_MOD_TRAFFIC_WEAVER,
    JZ_MOD_BG_COLLECTOR,
    JZ_MOD_THREAT_DETECT,
    JZ_MOD_FORENSICS,
    JZ_MOD_COUNT
} jz_mod_id_t;

/* ── Per-Module State ── */
typedef struct jz_bpf_module {
    const char *name;
    const char *obj_file;
    int         stage;
    int         slot;         /* assigned rs_progs slot (-1 = unassigned) */
    bool        loaded;
    bool        enabled;
    void       *bpf_obj;
    int         prog_fd;
} jz_bpf_module_t;

/* ── Loader Context ── */
typedef struct jz_bpf_loader {
    jz_bpf_module_t modules[JZ_MOD_COUNT];
    char    bpf_dir[256];     /* directory containing .bpf.o files */
    char    pin_path[256];    /* /sys/fs/bpf/jz/ */
    bool    initialized;
    int     loaded_count;
} jz_bpf_loader_t;

/* Initialize loader context. bpf_dir is the directory containing
 * compiled BPF object files (e.g. "build/bpf" or "/etc/jz/bpf").
 * Returns 0 on success, -1 on error. */
int jz_bpf_loader_init(jz_bpf_loader_t *loader, const char *bpf_dir);

/* Load all BPF modules. Pins maps under /sys/fs/bpf/jz/.
 * Returns number of successfully loaded modules, -1 on fatal error. */
int jz_bpf_loader_load_all(jz_bpf_loader_t *loader);

/* Load a single module by ID. Returns 0 on success, -1 on error. */
int jz_bpf_loader_load(jz_bpf_loader_t *loader, jz_mod_id_t mod_id);

/* Unload a single module. Returns 0 on success, -1 on error. */
int jz_bpf_loader_unload(jz_bpf_loader_t *loader, jz_mod_id_t mod_id);

/* Enable/disable a module in the pipeline (sets rs_progs map entry).
 * Returns 0 on success, -1 on error. */
int jz_bpf_loader_enable(jz_bpf_loader_t *loader, jz_mod_id_t mod_id,
                         bool enable);

/* Get module info by ID. Returns NULL if invalid. */
const jz_bpf_module_t *jz_bpf_loader_get_module(const jz_bpf_loader_t *loader,
                                                  jz_mod_id_t mod_id);

/* Get module ID by name. Returns -1 if not found. */
int jz_bpf_loader_find(const jz_bpf_loader_t *loader, const char *name);

/* Unload all modules and clean up. */
void jz_bpf_loader_destroy(jz_bpf_loader_t *loader);

#endif /* JZ_BPF_LOADER_H */
