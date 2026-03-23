/* SPDX-License-Identifier: MIT */
/* log_format.h -- V1/V2 log format engine for jz_sniff_rn. */

#ifndef JZ_LOG_FORMAT_H
#define JZ_LOG_FORMAT_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations — avoid including BPF headers in user-space headers */
struct jz_event_hdr;
struct jz_event_attack;
struct jz_event_sniffer;
struct jz_event_threat;
struct jz_event_bg;
struct jz_event_policy;

/* Heartbeat data passed from sniffd to log formatter */
typedef struct jz_heartbeat_data {
    int static_guards;
    int dynamic_guards;
    int total_guards;
    int online_devices;
    int frozen_ips;
    int whitelist_count;
    int modules_loaded;
    int modules_failed;
    long uptime_sec;
    long daemon_start_epoch;
    long db_size_mb;
    long attack_count_total;
    long attack_count_last_period;
} jz_heartbeat_data_t;

/* ── V1 Formatters (KV pairs for syslog) ── */

/* Format attack event as V1 KV string.
 * Returns bytes written (excluding NUL), or -1 on error. */
int jz_log_v1_attack(char *buf, size_t bufsz,
                     const char *device_id,
                     const struct jz_event_attack *ev);

/* Format heartbeat as V1 KV string. */
int jz_log_v1_heartbeat(char *buf, size_t bufsz,
                        const char *device_id,
                        const jz_heartbeat_data_t *hb);

/* ── V2 Formatters (JSON envelopes for MQTT/HTTPS) ── */

/* Format attack event as V2 JSON. Caller must free() returned string. */
char *jz_log_v2_attack(const char *device_id, uint64_t seq,
                       const struct jz_event_attack *ev);

/* Format sniffer event as V2 JSON. */
char *jz_log_v2_sniffer(const char *device_id, uint64_t seq,
                        const struct jz_event_sniffer *ev);

/* Format threat event as V2 JSON. */
char *jz_log_v2_threat(const char *device_id, uint64_t seq,
                       const struct jz_event_threat *ev);

/* Format policy event as V2 JSON. */
char *jz_log_v2_policy(const char *device_id, uint64_t seq,
                       const struct jz_event_policy *ev);

/* Format heartbeat as V2 JSON. The heartbeat_json is the already-assembled
 * data object (from sniffd heartbeat module). Caller must free(). */
char *jz_log_v2_heartbeat(const char *device_id, uint64_t seq,
                          const char *heartbeat_json);

/* Thread-safe monotonic sequence number generator. */
uint64_t jz_log_next_seq(void);

#endif /* JZ_LOG_FORMAT_H */
