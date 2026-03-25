/* db.h - SQLite database wrapper for jz_sniff_rn
 *
 * Manages persistent storage for attack logs, sniffer detection,
 * background captures, config history, audit trail, and system state.
 *
 * Database file: /var/lib/jz/jz.db (configurable)
 */

#ifndef JZ_DB_H
#define JZ_DB_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>

/* -- Database Handle -- */

typedef struct jz_db {
    sqlite3 *db;
    char     path[256];
    bool     initialized;
} jz_db_t;

/* -- Lifecycle -- */

/* Open database and create schema if needed. Returns 0 on success, -1 on error. */
int jz_db_open(jz_db_t *ctx, const char *path);

/* Close database handle. */
void jz_db_close(jz_db_t *ctx);

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
                        const char *details,
                        int vlan_id);

/* -- Sniffer Log -- */

int jz_db_insert_sniffer(jz_db_t *ctx,
                         const char *mac,
                         const char *ip,
                         int ifindex,
                         const char *first_seen,
                         const char *last_seen,
                         int response_count,
                         const char *probe_ip,
                         int vlan_id);

/* -- Background Capture -- */

int jz_db_insert_bg_capture(jz_db_t *ctx,
                            const char *period_start,
                            const char *period_end,
                            const char *protocol,
                            int packet_count,
                            int byte_count,
                            int unique_sources,
                            const char *sample_data,
                            int vlan_id,
                            const char *src_ip,
                            const char *dst_ip,
                            const char *src_mac,
                            const char *dst_mac);

/* -- Config History -- */

int jz_db_insert_config(jz_db_t *ctx,
                        int version,
                        const char *config_data,
                        const char *source,
                        const char *applied_at,
                        const char *applied_by,
                        int rollback_from,
                        const char *status);

/* -- Audit Log -- */

int jz_db_insert_audit(jz_db_t *ctx,
                       const char *timestamp,
                       const char *action,
                       const char *actor,
                       const char *target,
                       const char *details,
                       const char *result);

/* -- Heartbeat Log -- */

int jz_db_insert_heartbeat(jz_db_t *ctx,
                           const char *timestamp,
                           const char *json_data);

/* -- System State -- */

int jz_db_set_state(jz_db_t *ctx, const char *key, const char *value);
int jz_db_get_state(jz_db_t *ctx, const char *key, char *value, int value_len);

/* -- Maintenance -- */

/* Mark records as uploaded. Returns number of rows updated or -1 on error. */
int jz_db_mark_uploaded(jz_db_t *ctx, const char *table, int max_id);

/* Get count of pending (un-uploaded) records in a table. Returns count or -1. */
int jz_db_pending_count(jz_db_t *ctx, const char *table);

/* -- Query Result Structures -- */

typedef struct jz_attack_row {
    int      id;
    int      event_type;
    char     timestamp[32];
    uint64_t timestamp_ns;
    char     src_ip[46];
    char     src_mac[18];
    char     dst_ip[46];
    char     dst_mac[18];
    char     guard_type[16];
    char     protocol[8];
    int      ifindex;
    int      threat_level;
    int      vlan_id;
    char     details[256];
} jz_attack_row_t;

typedef struct jz_sniffer_row {
    int  id;
    char mac[18];
    char ip[46];
    int  ifindex;
    char first_seen[32];
    char last_seen[32];
    int  response_count;
    char probe_ip[46];
    int  vlan_id;
} jz_sniffer_row_t;

typedef struct jz_bg_capture_row {
    int  id;
    char period_start[32];
    char period_end[32];
    char protocol[16];
    int  packet_count;
    int  byte_count;
    int  unique_sources;
    int  vlan_id;
    char src_ip[16];
    char dst_ip[16];
    char src_mac[18];
    char dst_mac[18];
    char sample_data[256];
} jz_bg_capture_row_t;

/* -- Pending Record Queries -- */

/* Fetch up to max_rows pending (uploaded=0) attack records.
 * Allocates *rows via realloc; caller must free with jz_db_free_attacks().
 * Returns number of rows fetched, or -1 on error. */
int jz_db_fetch_pending_attacks(jz_db_t *ctx, int max_rows,
                                jz_attack_row_t **rows);

/* Fetch up to max_rows pending sniffer records. */
int jz_db_fetch_pending_sniffers(jz_db_t *ctx, int max_rows,
                                 jz_sniffer_row_t **rows);

/* Fetch up to max_rows pending background capture records. */
int jz_db_fetch_pending_bg_captures(jz_db_t *ctx, int max_rows,
                                    jz_bg_capture_row_t **rows);

void jz_db_free_attacks(jz_attack_row_t *rows);
void jz_db_free_sniffers(jz_sniffer_row_t *rows);
void jz_db_free_bg_captures(jz_bg_capture_row_t *rows);

/* -- Database Pruning -- */

/* Delete oldest uploaded (uploaded=1) records from all data tables.
 * Deletes up to batch_size rows per table per call.
 * Returns total number of rows deleted across all tables, or -1 on error. */
int jz_db_prune_uploaded(jz_db_t *ctx, int batch_size);

/* Delete records older than the given cutoff timestamp from all data tables.
 * Only deletes records where uploaded=1.
 * Timestamp format: ISO-8601 (e.g. "2026-03-01T00:00:00").
 * Returns total rows deleted, or -1 on error. */
int jz_db_prune_before(jz_db_t *ctx, const char *cutoff_timestamp);

#endif /* JZ_DB_H */
