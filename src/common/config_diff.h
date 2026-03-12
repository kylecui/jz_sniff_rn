/* SPDX-License-Identifier: MIT */

#ifndef JZ_CONFIG_DIFF_H
#define JZ_CONFIG_DIFF_H

#include <stdint.h>

/* Forward declarations. */
typedef struct jz_config jz_config_t;
typedef struct jz_db jz_db_t;

/* A single diff entry describing one change. */
typedef struct jz_config_diff_entry {
    char section[32];
    char action[16];
    char key[128];
    char old_value[256];
    char new_value[256];
} jz_config_diff_entry_t;

/* Diff result. */
#define JZ_CONFIG_MAX_DIFF_ENTRIES 256
typedef struct jz_config_diff {
    jz_config_diff_entry_t entries[JZ_CONFIG_MAX_DIFF_ENTRIES];
    int count;
    int sections_changed;
    char summary[512];
} jz_config_diff_t;

/* Query audit log entries. */
typedef struct jz_audit_entry {
    char timestamp[32];
    char action[32];
    char actor[64];
    char target[128];
    char details[1024];
    char result[16];
} jz_audit_entry_t;

/* Compute diff between two configs.
 * old_cfg can be NULL (treat as empty - everything in new_cfg is "added").
 * Returns 0 on success, -1 on error. */
int jz_config_diff(const jz_config_t *old_cfg,
                   const jz_config_t *new_cfg,
                   jz_config_diff_t *diff);

/* Log a config change to the audit_log table.
 * action: "config_push", "config_reload", "config_rollback", etc.
 * actor: "cli:admin", "api:token:xyz", "remote:platform", "system"
 * diff: the computed diff (can be NULL for simple entries)
 * result: "success" or "failure"
 * Returns 0 on success, -1 on error. */
int jz_config_audit_log(jz_db_t *db,
                        const char *action,
                        const char *actor,
                        const jz_config_diff_t *diff,
                        const char *result);

/* Query audit log entries.
 * Caller must free results with jz_config_audit_free().
 * Returns number of entries found, or -1 on error. */
int jz_config_audit_query(jz_db_t *db,
                          const char *since,
                          const char *until,
                          const char *action_filter,
                          jz_audit_entry_t **results,
                          int *count);

void jz_config_audit_free(jz_audit_entry_t *results);

#endif /* JZ_CONFIG_DIFF_H */
