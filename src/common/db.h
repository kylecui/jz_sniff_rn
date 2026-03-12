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
                        const char *details);

/* -- Sniffer Log -- */

int jz_db_insert_sniffer(jz_db_t *ctx,
                         const char *mac,
                         const char *ip,
                         int ifindex,
                         const char *first_seen,
                         const char *last_seen,
                         int response_count,
                         const char *probe_ip);

/* -- Background Capture -- */

int jz_db_insert_bg_capture(jz_db_t *ctx,
                            const char *period_start,
                            const char *period_end,
                            const char *protocol,
                            int packet_count,
                            int byte_count,
                            int unique_sources,
                            const char *sample_data);

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

/* -- System State -- */

int jz_db_set_state(jz_db_t *ctx, const char *key, const char *value);
int jz_db_get_state(jz_db_t *ctx, const char *key, char *value, int value_len);

/* -- Maintenance -- */

/* Mark records as uploaded. Returns number of rows updated or -1 on error. */
int jz_db_mark_uploaded(jz_db_t *ctx, const char *table, int max_id);

/* Get count of pending (un-uploaded) records in a table. Returns count or -1. */
int jz_db_pending_count(jz_db_t *ctx, const char *table);

#endif /* JZ_DB_H */
