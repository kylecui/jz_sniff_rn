/* db.c - SQLite database wrapper implementation for jz_sniff_rn */

#include "db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* -- Schema SQL -- */

static const char *SCHEMA_SQL =
    /* Attack log - records every honeypot interaction */
    "CREATE TABLE IF NOT EXISTS attack_log ("
    "    id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    event_type      INTEGER NOT NULL,"
    "    timestamp       TEXT NOT NULL,"
    "    timestamp_ns    INTEGER NOT NULL,"
    "    src_ip          TEXT NOT NULL,"
    "    src_mac         TEXT NOT NULL,"
    "    dst_ip          TEXT NOT NULL,"
    "    dst_mac         TEXT,"
    "    guard_type      TEXT NOT NULL,"
    "    protocol        TEXT NOT NULL,"
    "    ifindex         INTEGER NOT NULL,"
    "    threat_level    INTEGER DEFAULT 0,"
    "    packet_sample   BLOB,"
    "    details         TEXT,"
    "    uploaded        INTEGER DEFAULT 0,"
    "    created_at      TEXT DEFAULT (datetime('now'))"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_attack_log_timestamp ON attack_log(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_attack_log_src_ip ON attack_log(src_ip);"
    "CREATE INDEX IF NOT EXISTS idx_attack_log_uploaded ON attack_log(uploaded);"

    /* Sniffer detection log */
    "CREATE TABLE IF NOT EXISTS sniffer_log ("
    "    id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    mac             TEXT NOT NULL,"
    "    ip              TEXT,"
    "    ifindex         INTEGER NOT NULL,"
    "    first_seen      TEXT NOT NULL,"
    "    last_seen       TEXT NOT NULL,"
    "    response_count  INTEGER NOT NULL,"
    "    probe_ip        TEXT NOT NULL,"
    "    uploaded        INTEGER DEFAULT 0,"
    "    created_at      TEXT DEFAULT (datetime('now'))"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_sniffer_log_mac ON sniffer_log(mac);"

    /* Background capture summary */
    "CREATE TABLE IF NOT EXISTS bg_capture ("
    "    id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    period_start    TEXT NOT NULL,"
    "    period_end      TEXT NOT NULL,"
    "    protocol        TEXT NOT NULL,"
    "    packet_count    INTEGER NOT NULL,"
    "    byte_count      INTEGER NOT NULL,"
    "    unique_sources  INTEGER NOT NULL,"
    "    sample_data     TEXT,"
    "    uploaded        INTEGER DEFAULT 0,"
    "    created_at      TEXT DEFAULT (datetime('now'))"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_bg_capture_period ON bg_capture(period_start);"
    "CREATE INDEX IF NOT EXISTS idx_bg_capture_protocol ON bg_capture(protocol);"

    /* Configuration version history */
    "CREATE TABLE IF NOT EXISTS config_history ("
    "    id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    version         INTEGER NOT NULL UNIQUE,"
    "    config_data     TEXT NOT NULL,"
    "    source          TEXT NOT NULL,"
    "    applied_at      TEXT NOT NULL,"
    "    applied_by      TEXT,"
    "    rollback_from   INTEGER,"
    "    status          TEXT DEFAULT 'applied',"
    "    created_at      TEXT DEFAULT (datetime('now'))"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_config_history_version ON config_history(version);"

    /* Audit trail - all administrative actions */
    "CREATE TABLE IF NOT EXISTS audit_log ("
    "    id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    timestamp       TEXT NOT NULL,"
    "    action          TEXT NOT NULL,"
    "    actor           TEXT NOT NULL,"
    "    target          TEXT,"
    "    details         TEXT,"
    "    result          TEXT NOT NULL,"
    "    created_at      TEXT DEFAULT (datetime('now'))"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);"

    /* System state - persistent key-value store */
    "CREATE TABLE IF NOT EXISTS system_state ("
    "    key             TEXT PRIMARY KEY,"
    "    value           TEXT NOT NULL,"
    "    updated_at      TEXT DEFAULT (datetime('now'))"
    ");"
    ;

/* -- Helper: execute SQL with error reporting -- */

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "jz_db: SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

/* -- Lifecycle -- */

int jz_db_open(jz_db_t *ctx, const char *path)
{
    if (!ctx || !path)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    snprintf(ctx->path, sizeof(ctx->path), "%s", path);

    int rc = sqlite3_open(path, &ctx->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "jz_db: cannot open %s: %s\n",
                path, sqlite3_errmsg(ctx->db));
        return -1;
    }

    /* Enable WAL mode for concurrent read/write */
    exec_sql(ctx->db, "PRAGMA journal_mode=WAL;");

    /* Enable foreign keys */
    exec_sql(ctx->db, "PRAGMA foreign_keys=ON;");

    /* Create schema */
    if (exec_sql(ctx->db, SCHEMA_SQL) != 0) {
        fprintf(stderr, "jz_db: schema creation failed\n");
        sqlite3_close(ctx->db);
        ctx->db = NULL;
        return -1;
    }

    ctx->initialized = true;
    return 0;
}

void jz_db_close(jz_db_t *ctx)
{
    if (ctx && ctx->db) {
        sqlite3_close(ctx->db);
        ctx->db = NULL;
        ctx->initialized = false;
    }
}

/* -- Attack Log -- */

int jz_db_insert_attack(jz_db_t *ctx,
                        int event_type,
                        const char *timestamp,
                        uint64_t timestamp_ns,
                        const char *src_ip,
                        const char *src_mac,
                        const char *dst_ip,
                        const char *dst_mac,
                        const char *guard_type,
                        const char *protocol,
                        int ifindex,
                        int threat_level,
                        const void *packet_sample,
                        int sample_len,
                        const char *details)
{
    if (!ctx || !ctx->initialized)
        return -1;

    const char *sql =
        "INSERT INTO attack_log (event_type, timestamp, timestamp_ns, "
        "src_ip, src_mac, dst_ip, dst_mac, guard_type, protocol, "
        "ifindex, threat_level, packet_sample, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, event_type);
    sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)timestamp_ns);
    sqlite3_bind_text(stmt, 4, src_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, src_mac, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, dst_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, dst_mac, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, guard_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, protocol, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 10, ifindex);
    sqlite3_bind_int(stmt, 11, threat_level);

    if (packet_sample && sample_len > 0)
        sqlite3_bind_blob(stmt, 12, packet_sample, sample_len, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 12);

    sqlite3_bind_text(stmt, 13, details, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -- Sniffer Log -- */

int jz_db_insert_sniffer(jz_db_t *ctx,
                         const char *mac,
                         const char *ip,
                         int ifindex,
                         const char *first_seen,
                         const char *last_seen,
                         int response_count,
                         const char *probe_ip)
{
    if (!ctx || !ctx->initialized)
        return -1;

    const char *sql =
        "INSERT INTO sniffer_log (mac, ip, ifindex, first_seen, "
        "last_seen, response_count, probe_ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, mac, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, ifindex);
    sqlite3_bind_text(stmt, 4, first_seen, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, last_seen, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, response_count);
    sqlite3_bind_text(stmt, 7, probe_ip, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -- Background Capture -- */

int jz_db_insert_bg_capture(jz_db_t *ctx,
                            const char *period_start,
                            const char *period_end,
                            const char *protocol,
                            int packet_count,
                            int byte_count,
                            int unique_sources,
                            const char *sample_data)
{
    if (!ctx || !ctx->initialized)
        return -1;

    const char *sql =
        "INSERT INTO bg_capture (period_start, period_end, protocol, "
        "packet_count, byte_count, unique_sources, sample_data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, period_start, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, period_end, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, protocol, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, packet_count);
    sqlite3_bind_int(stmt, 5, byte_count);
    sqlite3_bind_int(stmt, 6, unique_sources);
    sqlite3_bind_text(stmt, 7, sample_data, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -- Config History -- */

int jz_db_insert_config(jz_db_t *ctx,
                        int version,
                        const char *config_data,
                        const char *source,
                        const char *applied_at,
                        const char *applied_by,
                        int rollback_from,
                        const char *status)
{
    if (!ctx || !ctx->initialized)
        return -1;

    const char *sql =
        "INSERT INTO config_history (version, config_data, source, "
        "applied_at, applied_by, rollback_from, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, version);
    sqlite3_bind_text(stmt, 2, config_data, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, applied_at, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, applied_by, -1, SQLITE_STATIC);

    if (rollback_from > 0)
        sqlite3_bind_int(stmt, 6, rollback_from);
    else
        sqlite3_bind_null(stmt, 6);

    sqlite3_bind_text(stmt, 7, status ? status : "applied", -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -- Audit Log -- */

int jz_db_insert_audit(jz_db_t *ctx,
                       const char *timestamp,
                       const char *action,
                       const char *actor,
                       const char *target,
                       const char *details,
                       const char *result)
{
    if (!ctx || !ctx->initialized)
        return -1;

    const char *sql =
        "INSERT INTO audit_log (timestamp, action, actor, target, "
        "details, result) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, actor, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, target, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, details, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, result, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -- System State -- */

int jz_db_set_state(jz_db_t *ctx, const char *key, const char *value)
{
    if (!ctx || !ctx->initialized || !key || !value)
        return -1;

    const char *sql =
        "INSERT INTO system_state (key, value, updated_at) "
        "VALUES (?, ?, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=datetime('now')";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int jz_db_get_state(jz_db_t *ctx, const char *key, char *value, int value_len)
{
    if (!ctx || !ctx->initialized || !key || !value)
        return -1;

    const char *sql = "SELECT value FROM system_state WHERE key = ?";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *val = (const char *)sqlite3_column_text(stmt, 0);
        snprintf(value, (size_t)value_len, "%s", val ? val : "");
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;  /* key not found */
}

/* -- Maintenance -- */

int jz_db_mark_uploaded(jz_db_t *ctx, const char *table, int max_id)
{
    if (!ctx || !ctx->initialized || !table)
        return -1;

    /* Whitelist of valid table names to prevent SQL injection */
    if (strcmp(table, "attack_log") != 0 &&
        strcmp(table, "sniffer_log") != 0 &&
        strcmp(table, "bg_capture") != 0) {
        fprintf(stderr, "jz_db: invalid table for mark_uploaded: %s\n", table);
        return -1;
    }

    char sql[256];
    snprintf(sql, sizeof(sql),
             "UPDATE %s SET uploaded = 1 WHERE id <= ? AND uploaded = 0",
             table);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, max_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE)
        return sqlite3_changes(ctx->db);

    return -1;
}

int jz_db_pending_count(jz_db_t *ctx, const char *table)
{
    if (!ctx || !ctx->initialized || !table)
        return -1;

    /* Whitelist of valid table names */
    if (strcmp(table, "attack_log") != 0 &&
        strcmp(table, "sniffer_log") != 0 &&
        strcmp(table, "bg_capture") != 0) {
        fprintf(stderr, "jz_db: invalid table for pending_count: %s\n", table);
        return -1;
    }

    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM %s WHERE uploaded = 0", table);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    rc = sqlite3_step(stmt);
    int count = -1;
    if (rc == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}
