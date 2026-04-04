/* SPDX-License-Identifier: MIT */
/*
 * collectord main.c - Event collector daemon for jz_sniff_rn.
 *
 * Responsibilities:
 *   - Receive events from sniffd via IPC
 *   - Deduplicate and rate-limit events within a sliding window
 *   - Persist structured events to SQLite database
 *   - Export data in JSON format for uploadd consumption
 *   - Serve IPC commands (event, query, stats, export)
 */


#include "config.h"
#include "db.h"
#include "ipc.h"
#include "log.h"

#include <cJSON.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "syslog_export.h"
#include "log_format.h"
#include <linux/types.h>
#include "jz_events.h"

/* ── Version ──────────────────────────────────────────────────── */

#ifndef JZ_VERSION
#define JZ_VERSION "0.0.0-dev"
#endif
#define COLLECTORD_VERSION  JZ_VERSION

/* ── Defaults ─────────────────────────────────────────────────── */

#define DEFAULT_CONFIG_PATH   "/etc/jz/base.yaml"
#define DEFAULT_PID_FILE      "/var/run/jz/collectord.pid"
#define DEFAULT_DB_PATH       "/var/lib/jz/jz.db"
#define DEFAULT_RUN_DIR       "/var/run/jz"

#define DEFAULT_DEDUP_WINDOW_SEC  60
#define DEFAULT_RATE_LIMIT_EPS    100   /* events per second */
#define DEFAULT_MAX_DB_SIZE_MB    512

#define JZ_EVENT_ATTACK_ARP         1
#define JZ_EVENT_ATTACK_ICMP        2
#define JZ_EVENT_SNIFFER_DETECTED   3
#define JZ_EVENT_POLICY_MATCH       4
#define JZ_EVENT_THREAT_DETECTED    5
#define JZ_EVENT_BG_CAPTURE         6
#define JZ_EVENT_CONFIG_CHANGE      7
#define JZ_EVENT_SYSTEM_STATUS      8
#define JZ_EVENT_ATTACK_TCP        10
#define JZ_EVENT_ATTACK_UDP        11

/* ── Dedup Engine ─────────────────────────────────────────────── */

#define DEDUP_HASH_SIZE     4096
#define DEDUP_KEY_LEN       64

typedef struct dedup_entry {
    char     key[DEDUP_KEY_LEN];   /* event fingerprint */
    uint64_t first_seen;           /* seconds since epoch */
    uint64_t last_seen;
    uint32_t count;                /* times seen in window */
    struct dedup_entry *next;
} dedup_entry_t;

typedef struct dedup_engine {
    dedup_entry_t *buckets[DEDUP_HASH_SIZE];
    int window_sec;
    uint32_t total_deduped;
    uint32_t total_passed;
} dedup_engine_t;

/* djb2 hash */
static uint32_t dedup_hash(const char *key)
{
    uint32_t h = 5381;
    for (const char *p = key; *p; p++)
        h = ((h << 5) + h) + (uint32_t)*p;
    return h % DEDUP_HASH_SIZE;
}

static void dedup_init(dedup_engine_t *de, int window_sec)
{
    memset(de, 0, sizeof(*de));
    de->window_sec = window_sec;
}

static void dedup_destroy(dedup_engine_t *de)
{
    for (int i = 0; i < DEDUP_HASH_SIZE; i++) {
        dedup_entry_t *e = de->buckets[i];
        while (e) {
            dedup_entry_t *next = e->next;
            free(e);
            e = next;
        }
        de->buckets[i] = NULL;
    }
}

/* Expire entries older than window. */
static void dedup_expire(dedup_engine_t *de, uint64_t now)
{
    uint64_t cutoff = (now > (uint64_t)de->window_sec)
                      ? now - (uint64_t)de->window_sec : 0;

    for (int i = 0; i < DEDUP_HASH_SIZE; i++) {
        dedup_entry_t **pp = &de->buckets[i];
        while (*pp) {
            if ((*pp)->last_seen < cutoff) {
                dedup_entry_t *old = *pp;
                *pp = old->next;
                free(old);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

/* Returns true if this event should be processed (not a dup).
 * key: event fingerprint string (caller builds from event fields). */
static bool dedup_check(dedup_engine_t *de, const char *key, uint64_t now)
{
    uint32_t idx = dedup_hash(key);

    /* Search for existing entry */
    for (dedup_entry_t *e = de->buckets[idx]; e; e = e->next) {
        if (strncmp(e->key, key, DEDUP_KEY_LEN) == 0) {
            e->last_seen = now;
            e->count++;
            de->total_deduped++;
            return false;  /* duplicate */
        }
    }

    /* New entry */
    dedup_entry_t *e = calloc(1, sizeof(*e));
    if (!e)
        return true;  /* OOM — let it through */

    snprintf(e->key, DEDUP_KEY_LEN, "%s", key);
    e->first_seen = now;
    e->last_seen = now;
    e->count = 1;
    e->next = de->buckets[idx];
    de->buckets[idx] = e;

    de->total_passed++;
    return true;  /* new event */
}

/* ── Rate Limiter ─────────────────────────────────────────────── */

typedef struct rate_limiter {
    int max_eps;           /* max events per second */
    uint64_t window_start; /* second boundary */
    int count;             /* events this second */
    uint64_t total_dropped;
} rate_limiter_t;

static void rate_limiter_init(rate_limiter_t *rl, int max_eps)
{
    memset(rl, 0, sizeof(*rl));
    rl->max_eps = max_eps;
}

static bool rate_limiter_allow(rate_limiter_t *rl, uint64_t now_sec)
{
    if (now_sec != rl->window_start) {
        rl->window_start = now_sec;
        rl->count = 0;
    }

    if (rl->count >= rl->max_eps) {
        rl->total_dropped++;
        return false;
    }

    rl->count++;
    return true;
}

/* ── Global State ─────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

static struct {
    char config_path[256];
    char pid_file[256];
    char db_path[256];
    int  max_db_size_mb;
    bool daemonize;
    bool verbose;

    jz_config_t       config;
    jz_db_t           db;
    jz_ipc_server_t   ipc;

    dedup_engine_t    dedup;
    rate_limiter_t    rate_limiter;

    /* Statistics */
    uint64_t events_received;
    uint64_t events_persisted;
    uint64_t events_deduped;
    uint64_t events_rate_limited;
    uint64_t events_errors;
    uint64_t last_expire_time;
    bool syslog_enabled;
} g_ctx;

/* ── Signal Handlers ──────────────────────────────────────────── */

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        g_running = 0;
    else if (sig == SIGHUP)
        g_reload = 1;
}

static int install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    if (sigaction(SIGINT, &sa, NULL) < 0)  return -1;
    if (sigaction(SIGHUP, &sa, NULL) < 0)  return -1;

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) return -1;

    return 0;
}

/* ── PID File ─────────────────────────────────────────────────── */

static int write_pid_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    int ret = (write(fd, buf, (size_t)len) == len) ? 0 : -1;
    close(fd);
    return ret;
}

/* ── Daemonize ────────────────────────────────────────────────── */

static int do_daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    if (setsid() < 0) return -1;

    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    if (chdir("/") < 0) return -1;

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }
    return 0;
}

/* ── Ensure Directory Exists ──────────────────────────────────── */

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(path, 0750) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ── IP/MAC Formatting Helpers ────────────────────────────────── */

static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr = { .s_addr = ip };
    inet_ntop(AF_INET, &addr, buf, (socklen_t)len);
}

static void mac_to_str(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ── Event Fingerprint ────────────────────────────────────────── */

static void event_fingerprint(uint32_t type, uint32_t src_ip,
                               uint32_t dst_ip, const uint8_t *src_mac,
                               char *out, size_t out_len)
{
    snprintf(out, out_len, "%u:%08x:%08x:%02x%02x%02x%02x%02x%02x",
             type, src_ip, dst_ip,
             src_mac[0], src_mac[1], src_mac[2],
             src_mac[3], src_mac[4], src_mac[5]);
}

/* ── Timestamp Helpers ────────────────────────────────────────── */

static uint64_t now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

static void now_iso8601(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ── Event Persistence ────────────────────────────────────────── */

/*
 * Parse a raw event IPC payload and persist to SQLite.
 * IPC payload format: "event:<type_u32>:<len_u32>:<hex_data>"
 * The hex_data encodes the jz_event_hdr followed by type-specific fields.
 *
 * For simplicity, we parse the common header and key fields inline.
 * BPF event structs use packed kernel types (__u32, __u8, etc.) which
 * match C99 fixed-width types on Linux.
 */

/* Minimum event header size: type(4) + len(4) + ts(8) + ifindex(4) +
 * vlan_id(2) + pad(2) + src_mac(6) + dst_mac(6) + src_ip(4) + dst_ip(4)
 * + 4 bytes trailing padding (for __u64 alignment of timestamp_ns)
 * = 48 bytes on x86-64 and ARM64 */
#define EVENT_HDR_LEN  48

static int persist_event(const char *payload, uint32_t payload_len)
{
    /* payload is raw binary event data forwarded by sniffd */
    if (payload_len < EVENT_HDR_LEN) {
        jz_log_warn("Event too short: %u < %d", payload_len, EVENT_HDR_LEN);
        g_ctx.events_errors++;
        return -1;
    }

    /* Parse common header fields */
    const uint8_t *p = (const uint8_t *)payload;

    uint32_t event_type;
    memcpy(&event_type, p, 4);

    uint64_t timestamp_ns;
    memcpy(&timestamp_ns, p + 8, 8);

    uint32_t ifindex;
    memcpy(&ifindex, p + 16, 4);

    uint16_t vlan_id;
    memcpy(&vlan_id, p + 20, 2);

    const uint8_t *src_mac = p + 24;
    const uint8_t *dst_mac = p + 30;

    uint32_t src_ip, dst_ip;
    memcpy(&src_ip, p + 36, 4);
    memcpy(&dst_ip, p + 40, 4);

    /* Dedup check */
    char fp[DEDUP_KEY_LEN];
    uint64_t ts = now_sec();
    event_fingerprint(event_type, src_ip, dst_ip, src_mac, fp, sizeof(fp));

    if (!dedup_check(&g_ctx.dedup, fp, ts)) {
        g_ctx.events_deduped++;
        return 0;  /* duplicate, silently skip */
    }

    /* Rate limit check */
    if (!rate_limiter_allow(&g_ctx.rate_limiter, ts)) {
        g_ctx.events_rate_limited++;
        return 0;  /* rate limited, silently skip */
    }

    /* Format strings */
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    char src_mac_str[18];
    char dst_mac_str[18];
    char timestamp[32];

    ip_to_str(src_ip, src_ip_str, sizeof(src_ip_str));
    ip_to_str(dst_ip, dst_ip_str, sizeof(dst_ip_str));
    mac_to_str(src_mac, src_mac_str, sizeof(src_mac_str));
    mac_to_str(dst_mac, dst_mac_str, sizeof(dst_mac_str));
    now_iso8601(timestamp, sizeof(timestamp));

    int rc = -1;

    switch (event_type) {
    case JZ_EVENT_ATTACK_ARP:
    case JZ_EVENT_ATTACK_ICMP:
    case JZ_EVENT_ATTACK_TCP:
    case JZ_EVENT_ATTACK_UDP: {
        const char *guard_type = "unknown";
        const char *protocol;
        int threat_level = 2;
        int src_port_val = 0;
        int dst_port_val = 0;

        switch (event_type) {
        case JZ_EVENT_ATTACK_ARP:  protocol = "ARP";  break;
        case JZ_EVENT_ATTACK_ICMP: protocol = "ICMP"; break;
        case JZ_EVENT_ATTACK_TCP:  protocol = "TCP";  break;
        default:                   protocol = "UDP";  break;
        }

        if (payload_len > EVENT_HDR_LEN) {
            uint8_t gt = p[EVENT_HDR_LEN];
            guard_type = (gt == 1) ? "static" : (gt == 2) ? "dynamic" : "unknown";
        }

        if (payload_len >= EVENT_HDR_LEN + 16) {
            uint16_t sp, dp;
            memcpy(&sp, p + EVENT_HDR_LEN + 12, 2);
            memcpy(&dp, p + EVENT_HDR_LEN + 14, 2);
            src_port_val = ntohs(sp);
            dst_port_val = ntohs(dp);
        }

        rc = jz_db_insert_attack(&g_ctx.db, (int)event_type, timestamp,
                                  timestamp_ns, src_ip_str, src_mac_str,
                                  dst_ip_str, dst_mac_str, guard_type,
                                  protocol, (int)ifindex, threat_level,
                                  NULL, 0, NULL, (int)vlan_id,
                                  src_port_val, dst_port_val);
        break;
    }

    case JZ_EVENT_SNIFFER_DETECTED: {
        char probe_ip_str[INET_ADDRSTRLEN] = "0.0.0.0";
        int response_count = 0;

        /* Parse sniffer-specific fields if available.
         * jz_event_sniffer layout after hdr: suspect_mac(6) + _pad(2) +
         * suspect_ip(4) + probe_ip(4) + response_count(4) = 20 bytes */
        if (payload_len >= EVENT_HDR_LEN + 20) {
            uint32_t probe_ip;
            memcpy(&probe_ip, p + EVENT_HDR_LEN + 12, 4);
            ip_to_str(probe_ip, probe_ip_str, sizeof(probe_ip_str));

            uint32_t resp_cnt;
            memcpy(&resp_cnt, p + EVENT_HDR_LEN + 16, 4);
            response_count = (int)resp_cnt;
        }

        rc = jz_db_insert_sniffer(&g_ctx.db, src_mac_str, src_ip_str,
                                   (int)ifindex, timestamp, timestamp,
                                   response_count, probe_ip_str,
                                   (int)vlan_id);
        break;
    }

    case JZ_EVENT_THREAT_DETECTED: {
        char details[128] = "";
        int threat_level = 2;

        if (payload_len >= EVENT_HDR_LEN + 8) {
            threat_level = p[EVENT_HDR_LEN + 4];
            if (payload_len >= EVENT_HDR_LEN + 8 + 32) {
                memcpy(details, p + EVENT_HDR_LEN + 8,
                       sizeof(details) - 1 < 32 ? sizeof(details) - 1 : 32);
                details[sizeof(details) - 1] = '\0';
            }
        }

        rc = jz_db_insert_attack(&g_ctx.db, (int)event_type, timestamp,
                                  timestamp_ns, src_ip_str, src_mac_str,
                                  dst_ip_str, dst_mac_str, "threat",
                                  "IP", (int)ifindex, threat_level,
                                  NULL, 0, details, (int)vlan_id, 0, 0);
        break;
    }

    case JZ_EVENT_BG_CAPTURE: {
        const char *protocol = "unknown";
        int pkt_count = 1;
        int byte_count = (int)payload_len;

        if (payload_len > EVENT_HDR_LEN) {
            uint8_t bg_proto = p[EVENT_HDR_LEN];
            switch (bg_proto) {
            case 1: protocol = "ARP";   break;
            case 2: protocol = "DHCP";  break;
            case 3: protocol = "mDNS";  break;
            case 4: protocol = "SSDP";  break;
            case 5: protocol = "LLDP";  break;
            case 6: protocol = "CDP";   break;
            case 7: protocol = "STP";   break;
            case 8: protocol = "IGMP";  break;
            default: protocol = "other"; break;
            }
        }

        rc = jz_db_insert_bg_capture(&g_ctx.db, timestamp, timestamp,
                                      protocol, pkt_count, byte_count,
                                      1, NULL, (int)vlan_id,
                                      src_ip_str, dst_ip_str,
                                      src_mac_str, dst_mac_str);
        break;
    }

    case JZ_EVENT_POLICY_MATCH:
        /* Policy match events are informational — log as audit */
        rc = jz_db_insert_audit(&g_ctx.db, timestamp, "policy_match",
                                 "bpf", src_ip_str, NULL, "logged");
        break;

    case JZ_EVENT_CONFIG_CHANGE:
        rc = jz_db_insert_audit(&g_ctx.db, timestamp, "config_change",
                                 "bpf", "config", NULL, "logged");
        break;

    case JZ_EVENT_SYSTEM_STATUS:
        rc = jz_db_insert_audit(&g_ctx.db, timestamp, "system_status",
                                 "bpf", "system", NULL, "logged");
        break;

    default:
        jz_log_warn("Unknown event type: %u", event_type);
        g_ctx.events_errors++;
        return -1;
    }

    if (rc == 0) {
        g_ctx.events_persisted++;
        if (g_ctx.syslog_enabled && jz_syslog_is_open() &&
            (event_type == JZ_EVENT_ATTACK_ARP ||
             event_type == JZ_EVENT_ATTACK_ICMP ||
             event_type == JZ_EVENT_ATTACK_TCP ||
             event_type == JZ_EVENT_ATTACK_UDP)) {
            if (payload_len >= sizeof(struct jz_event_attack)) {
                char syslog_buf[512];
                char device_id[64] = "unknown";
                jz_db_get_state(&g_ctx.db, "device_id",
                                device_id, sizeof(device_id));
                int slen = jz_log_v1_attack(syslog_buf, sizeof(syslog_buf),
                                             device_id,
                                             (const struct jz_event_attack *)payload);
                if (slen > 0)
                    jz_syslog_send(syslog_buf);
            }
        }
        jz_log_debug("Persisted event type=%u src=%s dst=%s",
                      event_type, src_ip_str, dst_ip_str);
    } else {
        g_ctx.events_errors++;
        jz_log_error("Failed to persist event type=%u", event_type);
    }

    return rc;
}

/* ── JSON Export ──────────────────────────────────────────────── */

/*
 * Export pending (un-uploaded) records as a JSON array.
 * Returns a malloc'd JSON string, caller must free().
 * max_records: limit export size (0 = all pending).
 */
static char *export_pending_json(int max_records)
{
    int per_table = (max_records > 0) ? (max_records / 3 + 1) : 0;

    jz_attack_row_t     *attacks  = NULL;
    jz_sniffer_row_t    *sniffers = NULL;
    jz_bg_capture_row_t *bg_caps  = NULL;

    int n_attacks  = jz_db_fetch_pending_attacks(&g_ctx.db, per_table, &attacks);
    int n_sniffers = jz_db_fetch_pending_sniffers(&g_ctx.db, per_table, &sniffers);
    int n_bg       = jz_db_fetch_pending_bg_captures(&g_ctx.db, per_table, &bg_caps);

    if (n_attacks < 0)  n_attacks  = 0;
    if (n_sniffers < 0) n_sniffers = 0;
    if (n_bg < 0)       n_bg       = 0;

    cJSON *root = cJSON_CreateObject();
    if (!root)
        goto fail;

    char device_id[64] = "unknown";
    jz_db_get_state(&g_ctx.db, "device_id", device_id, sizeof(device_id));

    char ts[32];
    now_iso8601(ts, sizeof(ts));

    cJSON_AddStringToObject(root, "device_id", device_id);
    cJSON_AddStringToObject(root, "timestamp", ts);

    cJSON *arr_attacks = cJSON_AddArrayToObject(root, "attacks");
    for (int i = 0; i < n_attacks; i++) {
        jz_attack_row_t *r = &attacks[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id",           r->id);
        cJSON_AddNumberToObject(obj, "event_type",   r->event_type);
        cJSON_AddStringToObject(obj, "timestamp",    r->timestamp);
        cJSON_AddNumberToObject(obj, "timestamp_ns", (double)r->timestamp_ns);
        cJSON_AddStringToObject(obj, "src_ip",       r->src_ip);
        cJSON_AddStringToObject(obj, "src_mac",      r->src_mac);
        cJSON_AddStringToObject(obj, "dst_ip",       r->dst_ip);
        cJSON_AddStringToObject(obj, "dst_mac",      r->dst_mac);
        cJSON_AddStringToObject(obj, "guard_type",   r->guard_type);
        cJSON_AddStringToObject(obj, "protocol",     r->protocol);
        cJSON_AddNumberToObject(obj, "ifindex",      r->ifindex);
        cJSON_AddNumberToObject(obj, "threat_level", r->threat_level);
        cJSON_AddNumberToObject(obj, "vlan_id",      r->vlan_id);
        cJSON_AddNumberToObject(obj, "src_port",     r->src_port);
        cJSON_AddNumberToObject(obj, "dst_port",     r->dst_port);
        if (r->details[0])
            cJSON_AddStringToObject(obj, "details", r->details);
        cJSON_AddItemToArray(arr_attacks, obj);
    }

    cJSON *arr_sniffers = cJSON_AddArrayToObject(root, "sniffers");
    for (int i = 0; i < n_sniffers; i++) {
        jz_sniffer_row_t *r = &sniffers[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id",             r->id);
        cJSON_AddStringToObject(obj, "mac",            r->mac);
        cJSON_AddStringToObject(obj, "ip",             r->ip);
        cJSON_AddNumberToObject(obj, "ifindex",        r->ifindex);
        cJSON_AddStringToObject(obj, "first_seen",     r->first_seen);
        cJSON_AddStringToObject(obj, "last_seen",      r->last_seen);
        cJSON_AddNumberToObject(obj, "response_count", r->response_count);
        cJSON_AddStringToObject(obj, "probe_ip",       r->probe_ip);
        cJSON_AddNumberToObject(obj, "vlan_id",        r->vlan_id);
        cJSON_AddItemToArray(arr_sniffers, obj);
    }

    cJSON *arr_bg = cJSON_AddArrayToObject(root, "bg_captures");
    for (int i = 0; i < n_bg; i++) {
        jz_bg_capture_row_t *r = &bg_caps[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id",             r->id);
        cJSON_AddStringToObject(obj, "period_start",   r->period_start);
        cJSON_AddStringToObject(obj, "period_end",     r->period_end);
        cJSON_AddStringToObject(obj, "protocol",       r->protocol);
        cJSON_AddNumberToObject(obj, "packet_count",   r->packet_count);
        cJSON_AddNumberToObject(obj, "byte_count",     r->byte_count);
        cJSON_AddNumberToObject(obj, "unique_sources", r->unique_sources);
        cJSON_AddNumberToObject(obj, "vlan_id",        r->vlan_id);
        cJSON_AddStringToObject(obj, "src_ip",         r->src_ip);
        cJSON_AddStringToObject(obj, "dst_ip",         r->dst_ip);
        cJSON_AddStringToObject(obj, "src_mac",        r->src_mac);
        cJSON_AddStringToObject(obj, "dst_mac",        r->dst_mac);
        if (r->sample_data[0])
            cJSON_AddStringToObject(obj, "sample_data", r->sample_data);
        cJSON_AddItemToArray(arr_bg, obj);
    }

    cJSON *stats = cJSON_AddObjectToObject(root, "stats");
    cJSON_AddNumberToObject(stats, "received",     (double)g_ctx.events_received);
    cJSON_AddNumberToObject(stats, "persisted",    (double)g_ctx.events_persisted);
    cJSON_AddNumberToObject(stats, "deduped",      (double)g_ctx.events_deduped);
    cJSON_AddNumberToObject(stats, "rate_limited", (double)g_ctx.events_rate_limited);
    cJSON_AddNumberToObject(stats, "errors",       (double)g_ctx.events_errors);

    char *json = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);
    jz_db_free_attacks(attacks);
    jz_db_free_sniffers(sniffers);
    jz_db_free_bg_captures(bg_caps);

    return json;

fail:
    jz_db_free_attacks(attacks);
    jz_db_free_sniffers(sniffers);
    jz_db_free_bg_captures(bg_caps);
    return NULL;
}

/* ── DB Size Check ────────────────────────────────────────────── */

static int check_db_size(void)
{
    struct stat st;
    if (stat(g_ctx.db_path, &st) < 0)
        return 0;

    int size_mb = (int)(st.st_size / (1024 * 1024));
    if (size_mb < g_ctx.max_db_size_mb)
        return 0;

    jz_log_warn("Database size %d MB exceeds limit %d MB, pruning uploaded records",
                 size_mb, g_ctx.max_db_size_mb);

    int pruned = jz_db_prune_uploaded(&g_ctx.db, 1000);
    if (pruned > 0) {
        jz_log_info("Pruned %d uploaded records from database", pruned);
    } else if (pruned == 0) {
        jz_log_warn("No uploaded records to prune — database may continue growing");
    }

    return 1;
}

/* ── IPC Command Handler ─────────────────────────────────────── */

static int ipc_handler(int client_fd, const jz_ipc_msg_t *msg, void *user_data)
{
    jz_ipc_server_t *srv = (jz_ipc_server_t *)user_data;
    const char *cmd = msg->payload;
    char reply[JZ_IPC_MAX_MSG_LEN];
    int len = 0;

    if (msg->len >= 6 && strncmp(cmd, "event:", 6) == 0) {
        /* Binary event data after "event:" prefix.
         * Fire-and-forget: sniffd does not read replies for events,
         * so sending one would fill its recv buffer and eventually
         * cause collectord to disconnect sniffd when the write fails
         * with EAGAIN on the non-blocking server fd. */
        g_ctx.events_received++;
        persist_event(cmd + 6, msg->len - 6);
        return 0;
    }
    else if (strncmp(cmd, "stats", 5) == 0) {
        int attack_pending = jz_db_pending_count(&g_ctx.db, "attack_log");
        int sniffer_pending = jz_db_pending_count(&g_ctx.db, "sniffer_log");
        if (attack_pending < 0) attack_pending = 0;
        if (sniffer_pending < 0) sniffer_pending = 0;

        len = snprintf(reply, sizeof(reply),
                       "collectord v%s "
                       "received:%lu persisted:%lu deduped:%lu "
                       "rate_limited:%lu errors:%lu "
                       "pending_attacks:%d pending_sniffers:%d",
                       COLLECTORD_VERSION,
                       (unsigned long)g_ctx.events_received,
                       (unsigned long)g_ctx.events_persisted,
                       (unsigned long)g_ctx.events_deduped,
                       (unsigned long)g_ctx.events_rate_limited,
                       (unsigned long)g_ctx.events_errors,
                       attack_pending, sniffer_pending);
    }
    else if (strncmp(cmd, "export", 6) == 0) {
        int max_records = 0;
        if (msg->len > 7 && cmd[6] == ':')
            max_records = atoi(cmd + 7);

        char *json = export_pending_json(max_records);
        if (json) {
            uint32_t json_len = (uint32_t)strlen(json);
            if (json_len > JZ_IPC_MAX_MSG_LEN - 1)
                json_len = JZ_IPC_MAX_MSG_LEN - 1;
            int rc = jz_ipc_server_send(srv, client_fd, json, json_len);
            free(json);
            return rc;
        } else {
            len = snprintf(reply, sizeof(reply), "error:export failed");
        }
    }
    else if (strncmp(cmd, "mark_uploaded:", 14) == 0) {
        /* mark_uploaded:<table>:<max_id> */
        char table[64] = "";
        int max_id = 0;
        if (sscanf(cmd + 14, "%63[^:]:%d", table, &max_id) == 2) {
            int updated = jz_db_mark_uploaded(&g_ctx.db, table, max_id);
            len = snprintf(reply, sizeof(reply),
                           updated >= 0 ? "marked:%d" : "error:mark failed",
                           updated);
        } else {
            len = snprintf(reply, sizeof(reply),
                           "error:invalid mark_uploaded format");
        }
    }
    else if (strncmp(cmd, "status", 6) == 0) {
        len = snprintf(reply, sizeof(reply),
                       "collectord v%s db:%s max_db:%dMB",
                       COLLECTORD_VERSION, g_ctx.db_path,
                       g_ctx.max_db_size_mb);
    }
    else if (strncmp(cmd, "version", 7) == 0) {
        len = snprintf(reply, sizeof(reply), "%s", COLLECTORD_VERSION);
    }
    else {
        len = snprintf(reply, sizeof(reply), "error:unknown command");
    }

    return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)len);
}

/* ── Configuration Reload ─────────────────────────────────────── */

static int do_reload(void)
{
    jz_log_info("Reloading configuration from %s", g_ctx.config_path);

    jz_config_t new_config;
    jz_config_defaults(&new_config);
    jz_config_errors_t errors = { .count = 0 };

    if (jz_config_load(&new_config, g_ctx.config_path, &errors) < 0) {
        jz_log_error("Config reload failed (%d errors)", errors.count);
        jz_config_free(&new_config);
        return -1;
    }

    if (jz_config_validate(&new_config, &errors) < 0) {
        jz_log_error("Config validation failed (%d errors)", errors.count);
        jz_config_free(&new_config);
        return -1;
    }

    /* Apply collector-specific settings */
    g_ctx.dedup.window_sec = new_config.collector.dedup_window_sec;
    g_ctx.rate_limiter.max_eps = new_config.collector.rate_limit_eps;
    g_ctx.max_db_size_mb = new_config.collector.max_db_size_mb;

    /* Apply log level */
    if (!g_ctx.verbose)
        jz_log_set_level(jz_log_level_from_str(new_config.system.log_level));

    if (new_config.log.syslog.enabled && !g_ctx.syslog_enabled) {
        if (jz_syslog_init(new_config.log.syslog.facility) == 0)
            g_ctx.syslog_enabled = true;
    } else if (!new_config.log.syslog.enabled && g_ctx.syslog_enabled) {
        jz_syslog_close();
        g_ctx.syslog_enabled = false;
    }

    jz_config_free(&g_ctx.config);
    memcpy(&g_ctx.config, &new_config, sizeof(jz_config_t));

    jz_log_info("Configuration reloaded successfully");
    return 0;
}

/* ── Command Line Parsing ─────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH       Config file (default: %s)\n"
        "  -d, --daemon            Run as daemon\n"
        "  -p, --pidfile PATH      PID file (default: %s)\n"
        "  --db PATH               SQLite database (default: %s)\n"
        "  --max-db-size MB        Max database size (default: %d)\n"
        "  -v, --verbose           Verbose logging\n"
        "  -V, --version           Print version\n"
        "  -h, --help              Show help\n",
        prog, DEFAULT_CONFIG_PATH, DEFAULT_PID_FILE,
        DEFAULT_DB_PATH, DEFAULT_MAX_DB_SIZE_MB);
}

static int parse_args(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        { "config",       required_argument, NULL, 'c' },
        { "daemon",       no_argument,       NULL, 'd' },
        { "pidfile",      required_argument, NULL, 'p' },
        { "db",           required_argument, NULL, 'D' },
        { "max-db-size",  required_argument, NULL, 'M' },
        { "verbose",      no_argument,       NULL, 'v' },
        { "version",      no_argument,       NULL, 'V' },
        { "help",         no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
             "%s", DEFAULT_CONFIG_PATH);
    snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
             "%s", DEFAULT_PID_FILE);
    snprintf(g_ctx.db_path, sizeof(g_ctx.db_path),
             "%s", DEFAULT_DB_PATH);
    g_ctx.max_db_size_mb = DEFAULT_MAX_DB_SIZE_MB;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dp:D:M:vVh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
                     "%s", optarg);
            break;
        case 'd':
            g_ctx.daemonize = true;
            break;
        case 'p':
            snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
                     "%s", optarg);
            break;
        case 'D':
            snprintf(g_ctx.db_path, sizeof(g_ctx.db_path),
                     "%s", optarg);
            break;
        case 'M':
            g_ctx.max_db_size_mb = atoi(optarg);
            if (g_ctx.max_db_size_mb <= 0)
                g_ctx.max_db_size_mb = DEFAULT_MAX_DB_SIZE_MB;
            break;
        case 'v':
            g_ctx.verbose = true;
            break;
        case 'V':
            printf("collectord version %s\n", COLLECTORD_VERSION);
            exit(0);
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    memset(&g_ctx, 0, sizeof(g_ctx));

    if (parse_args(argc, argv) < 0)
        return 1;

    jz_log_level_t log_level = g_ctx.verbose ? JZ_LOG_DEBUG : JZ_LOG_INFO;
    jz_log_init("collectord", log_level, true);
    jz_log_info("collectord v%s starting", COLLECTORD_VERSION);

    if (install_signals() < 0) {
        jz_log_fatal("Failed to install signal handlers");
        return 1;
    }

    /* Load configuration */
    jz_config_defaults(&g_ctx.config);
    jz_config_errors_t errors = { .count = 0 };

    if (jz_config_load(&g_ctx.config, g_ctx.config_path, &errors) < 0) {
        jz_log_fatal("Failed to load config %s", g_ctx.config_path);
        return 1;
    }

    if (!g_ctx.verbose)
        jz_log_set_level(jz_log_level_from_str(g_ctx.config.system.log_level));

    /* Apply collector settings from config (CLI overrides) */
    if (g_ctx.config.collector.db_path[0] &&
        strcmp(g_ctx.db_path, DEFAULT_DB_PATH) == 0) {
        snprintf(g_ctx.db_path, sizeof(g_ctx.db_path),
                 "%s", g_ctx.config.collector.db_path);
    }
    if (g_ctx.config.collector.max_db_size_mb > 0 &&
        g_ctx.max_db_size_mb == DEFAULT_MAX_DB_SIZE_MB) {
        g_ctx.max_db_size_mb = g_ctx.config.collector.max_db_size_mb;
    }

    int dedup_window = g_ctx.config.collector.dedup_window_sec > 0
                       ? g_ctx.config.collector.dedup_window_sec
                       : DEFAULT_DEDUP_WINDOW_SEC;
    int rate_limit = g_ctx.config.collector.rate_limit_eps > 0
                     ? g_ctx.config.collector.rate_limit_eps
                     : DEFAULT_RATE_LIMIT_EPS;

    /* Ensure runtime directories */
    if (ensure_dir(DEFAULT_RUN_DIR) < 0)
        return 1;

    /* Daemonize */
    if (g_ctx.daemonize) {
        if (do_daemonize() < 0) {
            jz_log_fatal("Failed to daemonize");
            return 1;
        }
        jz_log_set_stderr(false);
    }

    if (write_pid_file(g_ctx.pid_file) < 0) {
        jz_log_fatal("Failed to write PID file");
        return 1;
    }

    int exit_code = 0;

    /* Open database */
    if (jz_db_open(&g_ctx.db, g_ctx.db_path) < 0) {
        jz_log_fatal("Failed to open database: %s", g_ctx.db_path);
        exit_code = 1;
        goto cleanup;
    }

    /* Store device ID for export */
    if (g_ctx.config.system.device_id[0]) {
        jz_db_set_state(&g_ctx.db, "device_id",
                        g_ctx.config.system.device_id);
    }

    /* Initialize dedup engine and rate limiter */
    dedup_init(&g_ctx.dedup, dedup_window);
    rate_limiter_init(&g_ctx.rate_limiter, rate_limit);

    jz_log_info("Dedup window: %d sec, rate limit: %d eps, "
                "max DB: %d MB",
                dedup_window, rate_limit, g_ctx.max_db_size_mb);

    /* Initialize IPC server */
    if (jz_ipc_server_init(&g_ctx.ipc, JZ_IPC_SOCK_COLLECTORD, 0666,
                           ipc_handler, &g_ctx.ipc) < 0) {
        jz_log_fatal("Failed to initialize IPC server");
        exit_code = 1;
        goto cleanup;
    }

    jz_log_info("collectord ready — listening on %s", JZ_IPC_SOCK_COLLECTORD);

    if (g_ctx.config.log.syslog.enabled) {
        if (jz_syslog_init(g_ctx.config.log.syslog.facility) == 0) {
            g_ctx.syslog_enabled = true;
            jz_log_info("Syslog export enabled, facility=%s",
                        g_ctx.config.log.syslog.facility);
        }
    }

    /* ── Main Loop ── */
    g_ctx.last_expire_time = now_sec();

    while (g_running) {
        /* Poll IPC for incoming events and commands */
        jz_ipc_server_poll(&g_ctx.ipc, 100);

        /* Periodic dedup cache expiry (every 30 seconds) */
        uint64_t ts = now_sec();
        if (ts - g_ctx.last_expire_time >= 30) {
            dedup_expire(&g_ctx.dedup, ts);
            g_ctx.last_expire_time = ts;
        }

        /* Periodic DB size check (piggyback on expire cycle) */
        if (ts - g_ctx.last_expire_time == 0)
            check_db_size();

        /* Handle SIGHUP reload */
        if (g_reload) {
            g_reload = 0;
            do_reload();
        }
    }

    jz_log_info("collectord shutting down...");

cleanup:
    dedup_destroy(&g_ctx.dedup);
    jz_ipc_server_destroy(&g_ctx.ipc);
    jz_db_close(&g_ctx.db);
    jz_syslog_close();
    jz_config_free(&g_ctx.config);
    unlink(g_ctx.pid_file);
    jz_log_info("collectord stopped");
    jz_log_close();

    return exit_code;
}
