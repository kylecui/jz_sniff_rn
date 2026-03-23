/* SPDX-License-Identifier: MIT */
/*
 * staged.h - UCI-style in-memory staged config changes for configd.
 */

#ifndef JZ_STAGED_H
#define JZ_STAGED_H

#include "../common/config.h"
#include <time.h>

#define JZ_STAGED_MAX_CHANGES  64
#define JZ_STAGED_DEFAULT_TTL  300  /* seconds */

typedef struct jz_staged_change {
    char section[64];
    char *json;
    time_t staged_at;
} jz_staged_change_t;

typedef struct jz_staged {
    jz_staged_change_t changes[JZ_STAGED_MAX_CHANGES];
    int count;
    int ttl_sec;
    time_t last_stage_time;
} jz_staged_t;

/* Initialize staged config area. ttl_sec=0 uses default (300s). */
void jz_staged_init(jz_staged_t *s, int ttl_sec);

/* Free all staged changes and reset. */
void jz_staged_destroy(jz_staged_t *s);

/* Stage a section change. json is copied (caller keeps ownership).
 * If section already staged, replaces the previous value.
 * Returns 0 on success, -1 on error (full, or malloc fail). */
int jz_staged_add(jz_staged_t *s, const char *section, const char *json);

/* Get number of staged changes. */
int jz_staged_count(const jz_staged_t *s);

/* Serialize all staged changes to a JSON string.
 * Returns heap-allocated string, caller must free(). NULL on error.
 * Format: {"count":N,"ttl":300,"age_sec":42,"changes":[{"section":"guards","json":{...}},...]} */
char *jz_staged_serialize(const jz_staged_t *s);

/* Merge all staged changes into a YAML config body string.
 * Takes the current config, applies staged JSON patches per-section,
 * and returns the merged YAML. Caller must free().
 * Returns NULL on error. */
char *jz_staged_merge(const jz_staged_t *s, const jz_config_t *current);

/* Discard all staged changes. */
void jz_staged_discard(jz_staged_t *s);

/* Check TTL expiry. Returns 1 if expired and changes were discarded, 0 otherwise.
 * Call this periodically (e.g. in main loop). */
int jz_staged_check_expiry(jz_staged_t *s);

#endif /* JZ_STAGED_H */
