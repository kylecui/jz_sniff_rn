/* SPDX-License-Identifier: MIT */
/*
 * config_history.c - Config version history tracking and rollback.
 */

#include "config_history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

static const char *CONFIG_HISTORY_SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS config_history ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    version INTEGER NOT NULL UNIQUE,"
    "    config_data TEXT NOT NULL,"
    "    source TEXT NOT NULL,"
    "    applied_at TEXT NOT NULL,"
    "    applied_by TEXT,"
    "    rollback_from INTEGER,"
    "    status TEXT DEFAULT 'applied',"
    "    created_at TEXT DEFAULT (datetime('now'))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_config_history_version ON config_history(version);";

static int validate_db(const jz_db_t *db)
{
    if (!db || !db->db || !db->initialized)
        return -1;
    return 0;
}

static void safe_copy(char *dst, size_t dst_len, const unsigned char *src)
{
    if (!dst || dst_len == 0)
        return;

    if (!src) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_len, "%s", (const char *)src);
}

static int now_iso8601(char *out, size_t out_len)
{
    time_t now;
    struct tm tm_now;

    if (!out || out_len == 0)
        return -1;

    now = time(NULL);
    if (now == (time_t)-1)
        return -1;

#if defined(_WIN32)
    if (gmtime_s(&tm_now, &now) != 0)
        return -1;
#else
    if (!gmtime_r(&now, &tm_now))
        return -1;
#endif

    if (strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm_now) == 0)
        return -1;

    return 0;
}

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "config_history: SQL error: %s\n",
                errmsg ? errmsg : sqlite3_errmsg(db));
        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

static int prepare_stmt(sqlite3 *db, sqlite3_stmt **stmt, const char *sql)
{
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "config_history: sqlite3_prepare_v2 failed: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}

static int list_grow(jz_config_version_list_t *list)
{
    int new_capacity;
    jz_config_version_t *new_versions;

    if (!list)
        return -1;

    if (list->capacity <= 0)
        new_capacity = 16;
    else
        new_capacity = list->capacity * 2;

    new_versions = realloc(list->versions,
                           (size_t)new_capacity * sizeof(*new_versions));
    if (!new_versions) {
        fprintf(stderr, "config_history: realloc failed while growing list\n");
        return -1;
    }

    list->versions = new_versions;
    list->capacity = new_capacity;
    return 0;
}

static int fill_version_from_stmt(sqlite3_stmt *stmt, jz_config_version_t *out)
{
    const unsigned char *config_data;
    int config_len;

    if (!stmt || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    out->version = sqlite3_column_int(stmt, 0);

    config_data = sqlite3_column_text(stmt, 1);
    config_len = sqlite3_column_bytes(stmt, 1);
    if (!config_data || config_len < 0 || config_len >= JZ_CONFIG_HISTORY_MAX_DATA) {
        fprintf(stderr,
                "config_history: invalid config_data length for version %d\n",
                out->version);
        return -1;
    }

    memcpy(out->config_data, config_data, (size_t)config_len);
    out->config_data[config_len] = '\0';

    safe_copy(out->source, sizeof(out->source), sqlite3_column_text(stmt, 2));
    safe_copy(out->applied_at, sizeof(out->applied_at), sqlite3_column_text(stmt, 3));
    safe_copy(out->applied_by, sizeof(out->applied_by), sqlite3_column_text(stmt, 4));

    if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
        out->rollback_from = 0;
    else
        out->rollback_from = sqlite3_column_int(stmt, 5);

    safe_copy(out->status, sizeof(out->status), sqlite3_column_text(stmt, 6));

    return 0;
}

int jz_config_history_init(jz_db_t *db)
{
    if (validate_db(db) != 0)
        return -1;

    return exec_sql(db->db, CONFIG_HISTORY_SCHEMA_SQL);
}

int jz_config_history_current_version(jz_db_t *db)
{
    const char *sql =
        "SELECT MAX(version) FROM config_history WHERE status = 'applied'";
    sqlite3_stmt *stmt = NULL;
    int rc;
    int version = 0;

    if (validate_db(db) != 0)
        return -1;

    if (prepare_stmt(db->db, &stmt, sql) != 0)
        return -1;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL)
            version = sqlite3_column_int(stmt, 0);
    } else {
        fprintf(stderr, "config_history: sqlite3_step failed: %s\n",
                sqlite3_errmsg(db->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return version;
}

int jz_config_history_save(jz_db_t *db, int version,
                           const char *config_yaml,
                           const char *source,
                           const char *applied_by)
{
    char applied_at[JZ_CONFIG_HISTORY_TIME_LEN];
    int current_version;

    if (validate_db(db) != 0)
        return -1;

    if (version <= 0 || !config_yaml || !source || !applied_by)
        return -1;

    if (strlen(config_yaml) >= JZ_CONFIG_HISTORY_MAX_DATA)
        return -1;

    current_version = jz_config_history_current_version(db);
    if (current_version < 0)
        return -1;

    if (version <= current_version) {
        fprintf(stderr,
                "config_history: version %d must be greater than current %d\n",
                version, current_version);
        return -1;
    }

    if (now_iso8601(applied_at, sizeof(applied_at)) != 0) {
        fprintf(stderr, "config_history: failed to generate applied_at timestamp\n");
        return -1;
    }

    if (jz_db_insert_config(db,
                            version,
                            config_yaml,
                            source,
                            applied_at,
                            applied_by,
                            0,
                            "applied") != 0) {
        fprintf(stderr, "config_history: insert failed: %s\n",
                sqlite3_errmsg(db->db));
        return -1;
    }

    return 0;
}

int jz_config_history_get(jz_db_t *db, int version,
                          jz_config_version_t *out)
{
    const char *sql =
        "SELECT version, config_data, source, applied_at, applied_by, rollback_from, status "
        "FROM config_history WHERE version = ?";
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (validate_db(db) != 0 || version <= 0 || !out)
        return -1;

    if (prepare_stmt(db->db, &stmt, sql) != 0)
        return -1;

    sqlite3_bind_int(stmt, 1, version);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (fill_version_from_stmt(stmt, out) != 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
        sqlite3_finalize(stmt);
        return 0;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "config_history: sqlite3_step failed: %s\n",
                sqlite3_errmsg(db->db));
    }

    sqlite3_finalize(stmt);
    return -1;
}

int jz_config_history_list(jz_db_t *db, int limit,
                           jz_config_version_list_t *out)
{
    const char *sql_all =
        "SELECT version, config_data, source, applied_at, applied_by, rollback_from, status "
        "FROM config_history ORDER BY version DESC";
    const char *sql_limited =
        "SELECT version, config_data, source, applied_at, applied_by, rollback_from, status "
        "FROM config_history ORDER BY version DESC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (validate_db(db) != 0 || !out || limit < 0)
        return -1;

    memset(out, 0, sizeof(*out));

    if (limit == 0) {
        if (prepare_stmt(db->db, &stmt, sql_all) != 0)
            return -1;
    } else {
        if (prepare_stmt(db->db, &stmt, sql_limited) != 0)
            return -1;
        sqlite3_bind_int(stmt, 1, limit);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (out->count >= out->capacity) {
            if (list_grow(out) != 0) {
                sqlite3_finalize(stmt);
                jz_config_version_list_free(out);
                return -1;
            }
        }

        if (fill_version_from_stmt(stmt, &out->versions[out->count]) != 0) {
            sqlite3_finalize(stmt);
            jz_config_version_list_free(out);
            return -1;
        }

        out->count++;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "config_history: sqlite3_step failed: %s\n",
                sqlite3_errmsg(db->db));
        sqlite3_finalize(stmt);
        jz_config_version_list_free(out);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int jz_config_history_rollback(jz_db_t *db, int target_version,
                               const char *actor,
                               char *config_yaml, int yaml_buflen)
{
    const char *select_sql =
        "SELECT config_data FROM config_history WHERE version = ?";
    const char *update_status_sql =
        "UPDATE config_history SET status = 'rolled_back' WHERE version = ?";
    sqlite3_stmt *stmt = NULL;
    const unsigned char *target_data;
    int target_len;
    int rc;
    int current_version;
    int new_version;
    char applied_at[JZ_CONFIG_HISTORY_TIME_LEN];

    if (validate_db(db) != 0 || target_version <= 0 || !actor || !config_yaml)
        return -1;

    if (yaml_buflen < JZ_CONFIG_HISTORY_MAX_DATA)
        return -1;

    if (prepare_stmt(db->db, &stmt, select_sql) != 0)
        return -1;

    sqlite3_bind_int(stmt, 1, target_version);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "config_history: sqlite3_step failed: %s\n",
                    sqlite3_errmsg(db->db));
        }
        sqlite3_finalize(stmt);
        return -1;
    }

    target_data = sqlite3_column_text(stmt, 0);
    target_len = sqlite3_column_bytes(stmt, 0);
    if (!target_data || target_len < 0 || target_len >= yaml_buflen) {
        fprintf(stderr,
                "config_history: target config too large for rollback buffer\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    memcpy(config_yaml, target_data, (size_t)target_len);
    config_yaml[target_len] = '\0';

    sqlite3_finalize(stmt);

    if (exec_sql(db->db, "BEGIN IMMEDIATE TRANSACTION;") != 0)
        return -1;

    current_version = jz_config_history_current_version(db);
    if (current_version < 0)
        goto rollback_error;

    new_version = current_version + 1;

    if (now_iso8601(applied_at, sizeof(applied_at)) != 0) {
        fprintf(stderr, "config_history: failed to generate applied_at timestamp\n");
        goto rollback_error;
    }

    if (jz_db_insert_config(db,
                            new_version,
                            config_yaml,
                            "cli",
                            applied_at,
                            actor,
                            target_version,
                            "applied") != 0) {
        fprintf(stderr, "config_history: rollback insert failed: %s\n",
                sqlite3_errmsg(db->db));
        goto rollback_error;
    }

    if (current_version > 0) {
        if (prepare_stmt(db->db, &stmt, update_status_sql) != 0)
            goto rollback_error;

        sqlite3_bind_int(stmt, 1, current_version);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "config_history: rollback status update failed: %s\n",
                    sqlite3_errmsg(db->db));
            sqlite3_finalize(stmt);
            goto rollback_error;
        }

        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    if (exec_sql(db->db, "COMMIT;") != 0)
        goto rollback_error;

    return new_version;

rollback_error:
    if (stmt)
        sqlite3_finalize(stmt);
    exec_sql(db->db, "ROLLBACK;");
    return -1;
}

int jz_config_history_prune(jz_db_t *db, int keep_count)
{
    const char *sql =
        "DELETE FROM config_history "
        "WHERE version IN ("
        "    SELECT version FROM config_history "
        "    ORDER BY version DESC LIMIT -1 OFFSET ?"
        ")";
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (validate_db(db) != 0 || keep_count < 0)
        return -1;

    if (prepare_stmt(db->db, &stmt, sql) != 0)
        return -1;

    sqlite3_bind_int(stmt, 1, keep_count);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "config_history: prune failed: %s\n",
                sqlite3_errmsg(db->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return sqlite3_changes(db->db);
}

void jz_config_version_list_free(jz_config_version_list_t *list)
{
    if (!list)
        return;

    free(list->versions);
    list->versions = NULL;
    list->count = 0;
    list->capacity = 0;
}
