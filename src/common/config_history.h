/* SPDX-License-Identifier: MIT */
/*
 * config_history.h - Config version history tracking and rollback APIs.
 */

#ifndef JZ_CONFIG_HISTORY_H
#define JZ_CONFIG_HISTORY_H

#include "db.h"
#include <stdint.h>

#define JZ_CONFIG_HISTORY_MAX_DATA       65536
#define JZ_CONFIG_HISTORY_SOURCE_LEN     32
#define JZ_CONFIG_HISTORY_TIME_LEN       32
#define JZ_CONFIG_HISTORY_ACTOR_LEN      64
#define JZ_CONFIG_HISTORY_STATUS_LEN     16

/* A single config version record */
typedef struct jz_config_version {
    int version;                                        /* monotonically increasing version number */
    char config_data[JZ_CONFIG_HISTORY_MAX_DATA];      /* full YAML config snapshot (up to 64KB) */
    char source[JZ_CONFIG_HISTORY_SOURCE_LEN];         /* "local", "remote", "cli" */
    char applied_at[JZ_CONFIG_HISTORY_TIME_LEN];       /* ISO 8601 timestamp */
    char applied_by[JZ_CONFIG_HISTORY_ACTOR_LEN];      /* "cli:admin", "api:token:xyz", "system" */
    int rollback_from;                                 /* if rollback, source version (0 if not rollback) */
    char status[JZ_CONFIG_HISTORY_STATUS_LEN];         /* "applied", "rolled_back", "failed" */
} jz_config_version_t;

/* Version list for query results */
typedef struct jz_config_version_list {
    jz_config_version_t *versions;                     /* dynamically allocated array */
    int count;
    int capacity;
} jz_config_version_list_t;

/*
 * Initialize the config history subsystem.
 * Creates config_history table if not exists.
 * db must be an open jz_db_t handle.
 * Returns 0 on success, -1 on error.
 */
int jz_config_history_init(jz_db_t *db);

/*
 * Get the current (latest) config version number.
 * Returns version number, or 0 if no versions exist, -1 on error.
 */
int jz_config_history_current_version(jz_db_t *db);

/*
 * Save a new config version.
 * version: the new version number (must be > current)
 * config_yaml: full YAML text of the config
 * source: "local", "remote", or "cli"
 * applied_by: actor identifier
 * Returns 0 on success, -1 on error.
 */
int jz_config_history_save(jz_db_t *db, int version,
                           const char *config_yaml,
                           const char *source,
                           const char *applied_by);

/*
 * Get a specific config version by number.
 * Populates the out struct. Returns 0 on success, -1 if not found.
 */
int jz_config_history_get(jz_db_t *db, int version,
                          jz_config_version_t *out);

/*
 * List config versions (newest first).
 * limit: max number of versions to return (0 = all)
 * Caller must free the result with jz_config_version_list_free().
 */
int jz_config_history_list(jz_db_t *db, int limit,
                           jz_config_version_list_t *out);

/*
 * Rollback to a previous config version.
 * Creates a NEW version entry with rollback_from set.
 * Returns the new version number on success, -1 on error.
 * The config_yaml output parameter receives the rolled-back config text.
 * config_yaml must be at least 65536 bytes.
 */
int jz_config_history_rollback(jz_db_t *db, int target_version,
                               const char *actor,
                               char *config_yaml, int yaml_buflen);

/*
 * Prune old versions, keeping only the last N.
 * Returns number of versions deleted, or -1 on error.
 */
int jz_config_history_prune(jz_db_t *db, int keep_count);

/* Free a version list. */
void jz_config_version_list_free(jz_config_version_list_t *list);

#endif /* JZ_CONFIG_HISTORY_H */
