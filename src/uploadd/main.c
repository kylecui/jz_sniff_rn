/* SPDX-License-Identifier: MIT */
/*
 * uploadd main.c - Batch upload daemon for jz_sniff_rn.
 *
 * Responsibilities:
 *   - Poll collectord for pending data batches via IPC
 *   - Compress data using gzip (zlib)
 *   - Upload to management platform via HTTPS POST
 *   - Handle retry with exponential backoff
 *   - Track upload state (last successful upload timestamp)
 *   - Serve IPC commands (status, force_upload, set_platform)
 */


#include "config.h"
#include "db.h"
#include "ipc.h"
#include "log.h"

#if __has_include(<mongoose.h>)
#include <mongoose.h>
#elif __has_include("../../third_party/mongoose/mongoose.h")
#include "../../third_party/mongoose/mongoose.h"
#else
#include <mongoose.h>
#endif

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
#include <zlib.h>
#include "mqtt.h"
#include "log_format.h"

/* ── Version ──────────────────────────────────────────────────── */

#define UPLOADD_VERSION  "0.8.0"

/* ── Defaults ─────────────────────────────────────────────────── */

#define DEFAULT_CONFIG_PATH     "/etc/jz/base.yaml"
#define DEFAULT_PID_FILE        "/var/run/jz/uploadd.pid"
#define DEFAULT_RUN_DIR         "/var/run/jz"

#define DEFAULT_PLATFORM_URL    ""           /* must be configured */
#define DEFAULT_INTERVAL_SEC    300          /* 5 minutes */
#define DEFAULT_BATCH_SIZE      100
#define DEFAULT_MAX_RETRIES     5
#define DEFAULT_BACKOFF_BASE_MS 1000        /* 1 second */
#define DEFAULT_BACKOFF_MAX_MS  60000       /* 1 minute */

#define GZIP_CHUNK_SIZE         16384

/* ── Global Signal Flags ─────────────────────────────────────── */

static volatile sig_atomic_t g_running      = 1;
static volatile sig_atomic_t g_reload       = 0;
static volatile sig_atomic_t g_force_upload = 0;

/* ── Upload State ─────────────────────────────────────────────── */

typedef enum {
    UPLOAD_IDLE,
    UPLOAD_FETCHING,
    UPLOAD_COMPRESSING,
    UPLOAD_SENDING,
    UPLOAD_RETRY_WAIT,
    UPLOAD_SUCCESS,
    UPLOAD_FAILED
} upload_state_t;

static const char *upload_state_str(upload_state_t s)
{
    switch (s) {
    case UPLOAD_IDLE:        return "idle";
    case UPLOAD_FETCHING:    return "fetching";
    case UPLOAD_COMPRESSING: return "compressing";
    case UPLOAD_SENDING:     return "sending";
    case UPLOAD_RETRY_WAIT:  return "retry_wait";
    case UPLOAD_SUCCESS:     return "success";
    case UPLOAD_FAILED:      return "failed";
    default:                 return "unknown";
    }
}

/* ── Gzip Compression ─────────────────────────────────────────── */

/*
 * Compress data using gzip (zlib deflate with gzip wrapper).
 * Returns compressed buffer (caller must free), sets out_len.
 * Returns NULL on error.
 */
static uint8_t *gzip_compress(const void *data, size_t data_len,
                               size_t *out_len)
{
    if (!data || data_len == 0) {
        *out_len = 0;
        return NULL;
    }

    /* Worst case: input size + overhead */
    size_t buf_size = compressBound((uLong)data_len) + 64;
    uint8_t *out = malloc(buf_size);
    if (!out) {
        *out_len = 0;
        return NULL;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    /* windowBits = 15 + 16 = gzip format */
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(out);
        *out_len = 0;
        return NULL;
    }

    strm.next_in = (Bytef *)data;
    strm.avail_in = (uInt)data_len;
    strm.next_out = out;
    strm.avail_out = (uInt)buf_size;

    int ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        free(out);
        *out_len = 0;
        return NULL;
    }

    *out_len = strm.total_out;
    return out;
}

/* ── HTTP Upload (mongoose HTTPS client) ──────────────────────── */

#define HTTP_CONNECT_TIMEOUT_MS  10000  /* 10 seconds */
#define HTTP_RESPONSE_TIMEOUT_MS 30000  /* 30 seconds */

/*
 * Per-request state, passed as fn_data to the mongoose event handler.
 */
typedef struct {
    bool             done;         /* true when request cycle is complete */
    int              http_code;    /* HTTP status code, or -1 on error */
    const char      *url;
    const char      *tls_cert_pem; /* client cert PEM content (may be NULL) */
    const char      *tls_key_pem;  /* client key  PEM content (may be NULL) */
    const void      *body;
    size_t           body_len;
    bool             compressed;
} http_req_t;

/*
 * Read a file fully into a malloc'd buffer.  Returns NULL on error.
 */
static char *read_file_full(const char *path)
{
    if (!path || !path[0])
        return NULL;

    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 1024 * 1024) {   /* sanity cap: 1 MB */
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    buf[nread] = '\0';
    return buf;
}

/*
 * Mongoose event handler for the outbound HTTPS POST.
 */
static void upload_ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    http_req_t *req = (http_req_t *)c->fn_data;

    if (ev == MG_EV_OPEN) {
        /* Store connect deadline in c->data (8 bytes available) */
        *(uint64_t *)c->data = mg_millis() + HTTP_CONNECT_TIMEOUT_MS;
    }
    else if (ev == MG_EV_POLL) {
        if (mg_millis() > *(uint64_t *)c->data) {
            if (c->is_connecting || c->is_resolving)
                mg_error(c, "Connect timeout");
            else
                mg_error(c, "Response timeout");
        }
    }
    else if (ev == MG_EV_CONNECT) {
        /* TCP connected — set up TLS if needed, then send HTTP request */
        if (c->is_tls) {
            struct mg_tls_opts opts;
            memset(&opts, 0, sizeof(opts));
            opts.name = mg_url_host(req->url);

            /* Client certificate (mTLS) */
            if (req->tls_cert_pem)
                opts.cert = mg_str(req->tls_cert_pem);
            if (req->tls_key_pem)
                opts.key = mg_str(req->tls_key_pem);

            mg_tls_init(c, &opts);
        }

        *(uint64_t *)c->data = mg_millis() + HTTP_RESPONSE_TIMEOUT_MS;

        struct mg_str host = mg_url_host(req->url);

        mg_printf(c,
                  "POST %s HTTP/1.0\r\n"
                  "Host: %.*s\r\n"
                  "Content-Type: application/json\r\n"
                  "%s"
                  "Content-Length: %lu\r\n"
                  "\r\n",
                  mg_url_uri(req->url),
                  (int)host.len, host.buf,
                  req->compressed ? "Content-Encoding: gzip\r\n" : "",
                  (unsigned long)req->body_len);
        mg_send(c, req->body, req->body_len);
    }
    else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        req->http_code = mg_http_status(hm);
        req->done = true;
        c->is_draining = 1;
    }
    else if (ev == MG_EV_ERROR) {
        jz_log_error("HTTP client error: %s", (const char *)ev_data);
        req->http_code = -1;
        req->done = true;
    }
    else if (ev == MG_EV_CLOSE) {
        if (!req->done) {
            req->http_code = -1;
            req->done = true;
        }
    }
}

/*
 * Upload data to the management platform via native HTTPS POST.
 * Uses mongoose HTTP client with built-in TLS.
 *
 * Returns 0 on success (HTTP 2xx), -1 on error.
 */
static int http_post_upload(const char *url, const char *tls_cert_path,
                             const char *tls_key_path,
                             const void *data, size_t data_len,
                             bool compressed)
{
    if (!url || !url[0]) {
        jz_log_error("No platform URL configured");
        return -1;
    }

    /* Read TLS cert/key files if provided */
    char *cert_pem = NULL;
    char *key_pem = NULL;

    if (tls_cert_path && tls_cert_path[0]) {
        cert_pem = read_file_full(tls_cert_path);
        if (!cert_pem) {
            jz_log_error("Cannot read TLS cert: %s", tls_cert_path);
            return -1;
        }
    }
    if (tls_key_path && tls_key_path[0]) {
        key_pem = read_file_full(tls_key_path);
        if (!key_pem) {
            jz_log_error("Cannot read TLS key: %s", tls_key_path);
            free(cert_pem);
            return -1;
        }
    }

    /* Set up request state */
    http_req_t req = {
        .done          = false,
        .http_code     = -1,
        .url           = url,
        .tls_cert_pem  = cert_pem,
        .tls_key_pem   = key_pem,
        .body          = data,
        .body_len      = data_len,
        .compressed    = compressed,
    };

    /* Create event manager and connect */
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_log_set(MG_LL_NONE);   /* suppress mongoose internal logging */

    struct mg_connection *c = mg_http_connect(&mgr, url,
                                              upload_ev_handler, &req);
    if (!c) {
        jz_log_error("mg_http_connect failed for %s", url);
        mg_mgr_free(&mgr);
        free(cert_pem);
        free(key_pem);
        return -1;
    }

    /* Poll until done or global shutdown */
    while (!req.done && g_running) {
        mg_mgr_poll(&mgr, 50);
    }

    mg_mgr_free(&mgr);
    free(cert_pem);
    free(key_pem);

    if (!g_running) {
        jz_log_info("Upload aborted — shutting down");
        return -1;
    }

    if (req.http_code >= 200 && req.http_code < 300) {
        jz_log_info("Upload successful (HTTP %d)", req.http_code);
        return 0;
    }

    if (req.http_code > 0) {
        jz_log_error("Upload failed (HTTP %d)", req.http_code);
    } else {
        jz_log_error("Upload failed (connection error)");
    }
    return -1;
}

/* ── Global State (continued) ─────────────────────────────────── */

static struct {
    char config_path[256];
    char pid_file[256];
    char platform_url[256];
    char tls_cert[256];
    char tls_key[256];
    int  interval_sec;
    int  batch_size;
    bool compress;
    bool enabled;
    bool daemonize;
    bool verbose;

    jz_config_t       config;
    jz_ipc_server_t   ipc;
    jz_ipc_client_t   collectord_client;

    upload_state_t    state;
    uint64_t          last_upload_time;
    uint64_t          next_upload_time;

    /* Retry state */
    int               retry_count;
    int               max_retries;
    uint64_t          retry_wait_until;

    /* Statistics */
    uint64_t          uploads_attempted;
    uint64_t          uploads_succeeded;
    uint64_t          uploads_failed;
    uint64_t          bytes_uploaded;
    uint64_t          bytes_compressed;

    jz_mqtt_t        *mqtt;
    bool              mqtt_enabled;
    int               mqtt_reconnect_sec;
    uint64_t          mqtt_last_reconnect;
} g_ctx;

/* ── Signal Handlers ──────────────────────────────────────────── */

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        g_running = 0;
    else if (sig == SIGHUP)
        g_reload = 1;
    else if (sig == SIGUSR1)
        g_force_upload = 1;
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
    if (sigaction(SIGUSR1, &sa, NULL) < 0) return -1;

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

/* ── Exponential Backoff ──────────────────────────────────────── */

static uint64_t backoff_delay_ms(int retry_count)
{
    /* 1s, 2s, 4s, 8s, 16s, capped at 60s */
    uint64_t delay = (uint64_t)DEFAULT_BACKOFF_BASE_MS << retry_count;
    if (delay > DEFAULT_BACKOFF_MAX_MS)
        delay = DEFAULT_BACKOFF_MAX_MS;

    /* Add jitter: ±25% */
    uint64_t jitter = delay / 4;
    delay = delay - jitter + (uint64_t)(rand() % (2 * jitter + 1));

    return delay;
}

/* ── Collectord IPC Client ────────────────────────────────────── */

static int connect_collectord(void)
{
    if (g_ctx.collectord_client.connected)
        return 0;

    if (jz_ipc_client_connect(&g_ctx.collectord_client,
                               JZ_IPC_SOCK_COLLECTORD,
                               JZ_IPC_DEFAULT_TIMEOUT_MS) < 0) {
        jz_log_debug("Cannot connect to collectord — will retry");
        return -1;
    }

    jz_log_info("Connected to collectord");
    return 0;
}

static char *fetch_export_data(int batch_size)
{
    if (connect_collectord() < 0)
        return NULL;

    char req[64];
    snprintf(req, sizeof(req), "export:%d", batch_size);

    jz_ipc_msg_t reply;
    if (jz_ipc_client_request(&g_ctx.collectord_client,
                               req, (uint32_t)strlen(req),
                               &reply) < 0) {
        jz_log_error("IPC request to collectord failed");
        jz_ipc_client_close(&g_ctx.collectord_client);
        return NULL;
    }

    /* Check for error response */
    if (reply.len >= 6 && strncmp(reply.payload, "error:", 6) == 0) {
        jz_log_error("collectord export error: %.*s",
                      (int)reply.len, reply.payload);
        return NULL;
    }

    /* Return a copy of the payload */
    char *data = malloc(reply.len + 1);
    if (!data)
        return NULL;
    memcpy(data, reply.payload, reply.len);
    data[reply.len] = '\0';

    return data;
}

static int notify_uploaded(const char *table, int max_id)
{
    if (connect_collectord() < 0)
        return -1;

    char req[128];
    snprintf(req, sizeof(req), "mark_uploaded:%s:%d", table, max_id);

    jz_ipc_msg_t reply;
    if (jz_ipc_client_request(&g_ctx.collectord_client,
                               req, (uint32_t)strlen(req),
                               &reply) < 0) {
        jz_log_error("Failed to notify collectord of upload");
        return -1;
    }

    return 0;
}

/* ── Upload Cycle ─────────────────────────────────────────────── */

static int do_upload_cycle(void)
{
    if (!g_ctx.enabled) {
        jz_log_debug("Upload disabled — skipping");
        return 0;
    }

    if (!g_ctx.platform_url[0]) {
        jz_log_debug("No platform URL configured — skipping");
        return 0;
    }

    /* Fetch data from collectord */
    g_ctx.state = UPLOAD_FETCHING;
    char *json = fetch_export_data(g_ctx.batch_size);
    if (!json) {
        g_ctx.state = UPLOAD_IDLE;
        return -1;
    }

    size_t json_len = strlen(json);
    if (json_len == 0) {
        jz_log_debug("No data to upload");
        free(json);
        g_ctx.state = UPLOAD_IDLE;
        return 0;
    }

    /* Check if there's actually pending data */
    if (strstr(json, "\"total\":0")) {
        jz_log_debug("No pending records to upload");
        free(json);
        g_ctx.state = UPLOAD_IDLE;
        return 0;
    }

    g_ctx.uploads_attempted++;

    /* Compress if enabled */
    const void *upload_data = json;
    size_t upload_len = json_len;
    uint8_t *compressed = NULL;
    bool is_compressed = false;

    if (g_ctx.compress) {
        g_ctx.state = UPLOAD_COMPRESSING;
        size_t comp_len = 0;
        compressed = gzip_compress(json, json_len, &comp_len);
        if (compressed && comp_len > 0 && comp_len < json_len) {
            upload_data = compressed;
            upload_len = comp_len;
            is_compressed = true;
            g_ctx.bytes_compressed += json_len - comp_len;
            jz_log_debug("Compressed %zu → %zu bytes (%.0f%% reduction)",
                          json_len, comp_len,
                          (1.0 - (double)comp_len / (double)json_len) * 100.0);
        } else {
            /* Compression didn't help, use original */
            free(compressed);
            compressed = NULL;
        }
    }

    /* Upload */
    g_ctx.state = UPLOAD_SENDING;
    int rc = http_post_upload(g_ctx.platform_url, g_ctx.tls_cert,
                               g_ctx.tls_key, upload_data, upload_len,
                               is_compressed);

    free(compressed);
    free(json);

    if (rc == 0) {
        g_ctx.state = UPLOAD_SUCCESS;
        g_ctx.uploads_succeeded++;
        g_ctx.bytes_uploaded += upload_len;
        g_ctx.last_upload_time = now_sec();
        g_ctx.retry_count = 0;

        /* Notify collectord to mark records as uploaded */
        notify_uploaded("attack_log", 0);
        notify_uploaded("sniffer_log", 0);
        notify_uploaded("bg_capture", 0);

        char ts[32];
        now_iso8601(ts, sizeof(ts));
        jz_log_info("Upload cycle complete at %s (%zu bytes)",
                     ts, upload_len);

        g_ctx.state = UPLOAD_IDLE;
        return 0;
    }

    /* Upload failed — enter retry */
    g_ctx.uploads_failed++;
    g_ctx.retry_count++;

    if (g_ctx.retry_count >= g_ctx.max_retries) {
        jz_log_error("Upload failed after %d retries — giving up this cycle",
                     g_ctx.max_retries);
        g_ctx.state = UPLOAD_FAILED;
        g_ctx.retry_count = 0;
        return -1;
    }

    uint64_t delay = backoff_delay_ms(g_ctx.retry_count);
    g_ctx.retry_wait_until = now_sec() + delay / 1000;
    g_ctx.state = UPLOAD_RETRY_WAIT;

    jz_log_warn("Upload failed — retry %d/%d in %lu ms",
                g_ctx.retry_count, g_ctx.max_retries,
                (unsigned long)delay);

    return -1;
}

/* ── IPC Command Handler ─────────────────────────────────────── */

static int init_mqtt(void)
{
    const jz_config_log_mqtt_t *mc = &g_ctx.config.log.mqtt;
    if (!mc->enabled) {
        jz_log_info("MQTT disabled in config");
        return 0;
    }

    char host[JZ_CONFIG_STR_LONG] = "";
    int port = 1883;
    const char *broker = mc->broker;
    if (strncmp(broker, "tcp://", 6) == 0)
        broker += 6;
    const char *colon = strrchr(broker, ':');
    if (colon && colon != broker) {
        size_t hlen = (size_t)(colon - broker);
        if (hlen >= sizeof(host))
            hlen = sizeof(host) - 1;
        memcpy(host, broker, hlen);
        host[hlen] = '\0';
        port = atoi(colon + 1);
    } else {
        snprintf(host, sizeof(host), "%s", broker);
    }

    char lwt_topic[256];
    snprintf(lwt_topic, sizeof(lwt_topic), "%s/status",
             mc->topic_prefix[0] ? mc->topic_prefix : "jz");

    jz_mqtt_cfg_t cfg = {
        .broker_host   = host,
        .broker_port   = port,
        .client_id     = mc->client_id[0] ? mc->client_id : "jz-uploadd",
        .topic_prefix  = mc->topic_prefix[0] ? mc->topic_prefix : "jz",
        .qos           = mc->qos,
        .keepalive_sec = mc->keepalive_sec > 0 ? mc->keepalive_sec : 60,
        .lwt_topic     = lwt_topic,
        .lwt_message   = "{\"online\":false}",
    };

    g_ctx.mqtt = jz_mqtt_create(&cfg);
    if (!g_ctx.mqtt) {
        jz_log_error("MQTT create failed");
        return -1;
    }

    if (jz_mqtt_connect(g_ctx.mqtt) < 0) {
        jz_log_warn("MQTT initial connect failed — will retry");
    }

    g_ctx.mqtt_enabled = true;
    g_ctx.mqtt_reconnect_sec = 30;
    g_ctx.mqtt_last_reconnect = 0;
    jz_log_info("MQTT initialized: %s:%d topic=%s",
                host, port, cfg.topic_prefix);
    return 0;
}

static int ipc_handler(int client_fd, const jz_ipc_msg_t *msg, void *user_data)
{
    jz_ipc_server_t *srv = (jz_ipc_server_t *)user_data;
    const char *cmd = msg->payload;
    char reply[4096];
    int len = 0;

    if (strncmp(cmd, "status", 6) == 0) {
        char last_ts[32] = "never";
        if (g_ctx.last_upload_time > 0) {
            time_t t = (time_t)g_ctx.last_upload_time;
            struct tm tm;
            gmtime_r(&t, &tm);
            strftime(last_ts, sizeof(last_ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
        }

        len = snprintf(reply, sizeof(reply),
                       "uploadd v%s state:%s enabled:%s "
                       "platform:%s interval:%ds batch:%d compress:%s "
                       "last_upload:%s "
                       "attempted:%lu succeeded:%lu failed:%lu "
                       "bytes_up:%lu bytes_saved:%lu",
                       UPLOADD_VERSION,
                       upload_state_str(g_ctx.state),
                       g_ctx.enabled ? "yes" : "no",
                       g_ctx.platform_url[0] ? g_ctx.platform_url : "(none)",
                       g_ctx.interval_sec, g_ctx.batch_size,
                       g_ctx.compress ? "yes" : "no",
                       last_ts,
                       (unsigned long)g_ctx.uploads_attempted,
                       (unsigned long)g_ctx.uploads_succeeded,
                       (unsigned long)g_ctx.uploads_failed,
                       (unsigned long)g_ctx.bytes_uploaded,
                       (unsigned long)g_ctx.bytes_compressed);
    }
    else if (strncmp(cmd, "force_upload", 12) == 0) {
        g_force_upload = 1;
        len = snprintf(reply, sizeof(reply), "upload:scheduled");
    }
    else if (strncmp(cmd, "set_platform:", 13) == 0) {
        snprintf(g_ctx.platform_url, sizeof(g_ctx.platform_url),
                 "%.*s", (int)(msg->len - 13), cmd + 13);
        len = snprintf(reply, sizeof(reply),
                       "platform:%s", g_ctx.platform_url);
        jz_log_info("Platform URL updated: %s", g_ctx.platform_url);
    }
    else if (strncmp(cmd, "set_interval:", 13) == 0) {
        int new_interval = atoi(cmd + 13);
        if (new_interval >= 10) {
            g_ctx.interval_sec = new_interval;
            len = snprintf(reply, sizeof(reply),
                           "interval:%d", g_ctx.interval_sec);
            jz_log_info("Upload interval updated: %d sec", g_ctx.interval_sec);
        } else {
            len = snprintf(reply, sizeof(reply),
                           "error:interval must be >= 10");
        }
    }
    else if (strncmp(cmd, "enable", 6) == 0) {
        g_ctx.enabled = true;
        len = snprintf(reply, sizeof(reply), "enabled:yes");
        jz_log_info("Upload enabled");
    }
    else if (strncmp(cmd, "disable", 7) == 0) {
        g_ctx.enabled = false;
        len = snprintf(reply, sizeof(reply), "enabled:no");
        jz_log_info("Upload disabled");
    }
    else if (msg->len > 10 && strncmp(cmd, "heartbeat:", 10) == 0) {
        if (g_ctx.mqtt_enabled && g_ctx.mqtt &&
            jz_mqtt_is_connected(g_ctx.mqtt)) {
            const char *hb_json = cmd + 10;
            int hb_len = (int)(msg->len - 10);
            if (hb_len > 0) {
                const char *device_id = g_ctx.config.system.device_id;
                uint64_t seq = jz_log_next_seq();
                char *v2 = jz_log_v2_heartbeat(device_id, seq, hb_json);
                if (v2) {
                    jz_mqtt_publish(g_ctx.mqtt, "heartbeat",
                                    v2, (int)strlen(v2));
                    free(v2);
                }
            }
        }
        len = snprintf(reply, sizeof(reply), "heartbeat:ok");
    }
    else if (strncmp(cmd, "version", 7) == 0) {
        len = snprintf(reply, sizeof(reply), "%s", UPLOADD_VERSION);
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

    /* Apply uploader settings */
    g_ctx.enabled = new_config.uploader.enabled;
    g_ctx.compress = new_config.uploader.compress;

    if (new_config.uploader.platform_url[0])
        snprintf(g_ctx.platform_url, sizeof(g_ctx.platform_url),
                 "%s", new_config.uploader.platform_url);
    if (new_config.uploader.interval_sec > 0)
        g_ctx.interval_sec = new_config.uploader.interval_sec;
    if (new_config.uploader.batch_size > 0)
        g_ctx.batch_size = new_config.uploader.batch_size;
    if (new_config.uploader.tls_cert[0])
        snprintf(g_ctx.tls_cert, sizeof(g_ctx.tls_cert),
                 "%s", new_config.uploader.tls_cert);
    if (new_config.uploader.tls_key[0])
        snprintf(g_ctx.tls_key, sizeof(g_ctx.tls_key),
                 "%s", new_config.uploader.tls_key);

    /* Apply log level */
    if (!g_ctx.verbose)
        jz_log_set_level(jz_log_level_from_str(new_config.system.log_level));

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
        "  --platform-url URL      Management platform URL\n"
        "  --batch-size N          Records per batch (default: %d)\n"
        "  --interval SEC          Upload interval (default: %d)\n"
        "  --tls-cert PATH         Client TLS certificate\n"
        "  --tls-key PATH          Client TLS private key\n"
        "  --no-compress           Disable gzip compression\n"
        "  -v, --verbose           Verbose logging\n"
        "  -V, --version           Print version\n"
        "  -h, --help              Show help\n",
        prog, DEFAULT_CONFIG_PATH, DEFAULT_PID_FILE,
        DEFAULT_BATCH_SIZE, DEFAULT_INTERVAL_SEC);
}

static int parse_args(int argc, char *argv[])
{
    enum {
        OPT_PLATFORM_URL = 256,
        OPT_BATCH_SIZE,
        OPT_INTERVAL,
        OPT_TLS_CERT,
        OPT_TLS_KEY,
        OPT_NO_COMPRESS,
    };

    static const struct option long_opts[] = {
        { "config",       required_argument, NULL, 'c' },
        { "daemon",       no_argument,       NULL, 'd' },
        { "pidfile",      required_argument, NULL, 'p' },
        { "platform-url", required_argument, NULL, OPT_PLATFORM_URL },
        { "batch-size",   required_argument, NULL, OPT_BATCH_SIZE },
        { "interval",     required_argument, NULL, OPT_INTERVAL },
        { "tls-cert",     required_argument, NULL, OPT_TLS_CERT },
        { "tls-key",      required_argument, NULL, OPT_TLS_KEY },
        { "no-compress",  no_argument,       NULL, OPT_NO_COMPRESS },
        { "verbose",      no_argument,       NULL, 'v' },
        { "version",      no_argument,       NULL, 'V' },
        { "help",         no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
             "%s", DEFAULT_CONFIG_PATH);
    snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
             "%s", DEFAULT_PID_FILE);
    g_ctx.platform_url[0] = '\0';
    g_ctx.tls_cert[0] = '\0';
    g_ctx.tls_key[0] = '\0';
    g_ctx.interval_sec = DEFAULT_INTERVAL_SEC;
    g_ctx.batch_size = DEFAULT_BATCH_SIZE;
    g_ctx.max_retries = DEFAULT_MAX_RETRIES;
    g_ctx.compress = true;
    g_ctx.enabled = false;  /* must be explicitly enabled */

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dp:vVh", long_opts, NULL)) != -1) {
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
        case OPT_PLATFORM_URL:
            snprintf(g_ctx.platform_url, sizeof(g_ctx.platform_url),
                     "%s", optarg);
            break;
        case OPT_BATCH_SIZE:
            g_ctx.batch_size = atoi(optarg);
            if (g_ctx.batch_size <= 0)
                g_ctx.batch_size = DEFAULT_BATCH_SIZE;
            break;
        case OPT_INTERVAL:
            g_ctx.interval_sec = atoi(optarg);
            if (g_ctx.interval_sec < 10)
                g_ctx.interval_sec = 10;
            break;
        case OPT_TLS_CERT:
            snprintf(g_ctx.tls_cert, sizeof(g_ctx.tls_cert),
                     "%s", optarg);
            break;
        case OPT_TLS_KEY:
            snprintf(g_ctx.tls_key, sizeof(g_ctx.tls_key),
                     "%s", optarg);
            break;
        case OPT_NO_COMPRESS:
            g_ctx.compress = false;
            break;
        case 'v':
            g_ctx.verbose = true;
            break;
        case 'V':
            printf("uploadd version %s\n", UPLOADD_VERSION);
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
    g_ctx.state = UPLOAD_IDLE;

    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    if (parse_args(argc, argv) < 0)
        return 1;

    jz_log_level_t log_level = g_ctx.verbose ? JZ_LOG_DEBUG : JZ_LOG_INFO;
    jz_log_init("uploadd", log_level, true);
    jz_log_info("uploadd v%s starting", UPLOADD_VERSION);

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

    /* Apply uploader settings from config (CLI overrides) */
    if (!g_ctx.platform_url[0] && g_ctx.config.uploader.platform_url[0])
        snprintf(g_ctx.platform_url, sizeof(g_ctx.platform_url),
                 "%s", g_ctx.config.uploader.platform_url);

    if (g_ctx.interval_sec == DEFAULT_INTERVAL_SEC &&
        g_ctx.config.uploader.interval_sec > 0)
        g_ctx.interval_sec = g_ctx.config.uploader.interval_sec;

    if (g_ctx.batch_size == DEFAULT_BATCH_SIZE &&
        g_ctx.config.uploader.batch_size > 0)
        g_ctx.batch_size = g_ctx.config.uploader.batch_size;

    if (!g_ctx.tls_cert[0] && g_ctx.config.uploader.tls_cert[0])
        snprintf(g_ctx.tls_cert, sizeof(g_ctx.tls_cert),
                 "%s", g_ctx.config.uploader.tls_cert);

    if (!g_ctx.tls_key[0] && g_ctx.config.uploader.tls_key[0])
        snprintf(g_ctx.tls_key, sizeof(g_ctx.tls_key),
                 "%s", g_ctx.config.uploader.tls_key);

    /* Config-sourced enabled flag (CLI --platform-url implies enabled) */
    if (g_ctx.platform_url[0])
        g_ctx.enabled = true;
    else
        g_ctx.enabled = g_ctx.config.uploader.enabled;

    g_ctx.compress = g_ctx.config.uploader.compress || g_ctx.compress;

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

    /* Initialize IPC server */
    if (jz_ipc_server_init(&g_ctx.ipc, JZ_IPC_SOCK_UPLOADD, 0660,
                           ipc_handler, &g_ctx.ipc) < 0) {
        jz_log_fatal("Failed to initialize IPC server");
        exit_code = 1;
        goto cleanup;
    }

    jz_log_info("uploadd ready — platform:%s interval:%ds batch:%d "
                "compress:%s enabled:%s",
                g_ctx.platform_url[0] ? g_ctx.platform_url : "(none)",
                g_ctx.interval_sec, g_ctx.batch_size,
                g_ctx.compress ? "yes" : "no",
                g_ctx.enabled ? "yes" : "no");

    init_mqtt();

    /* Schedule first upload */
    g_ctx.next_upload_time = now_sec() + (uint64_t)g_ctx.interval_sec;

    /* ── Main Loop ── */
    while (g_running) {
        /* Poll IPC for commands */
        jz_ipc_server_poll(&g_ctx.ipc, 100);

        uint64_t ts = now_sec();

        if (g_ctx.mqtt_enabled && g_ctx.mqtt) {
            if (jz_mqtt_is_connected(g_ctx.mqtt)) {
                jz_mqtt_yield(g_ctx.mqtt, 0);
            } else if (ts > g_ctx.mqtt_last_reconnect + (uint64_t)g_ctx.mqtt_reconnect_sec) {
                g_ctx.mqtt_last_reconnect = ts;
                jz_mqtt_reconnect(g_ctx.mqtt);
            }
        }

        /* Handle retry backoff */
        if (g_ctx.state == UPLOAD_RETRY_WAIT) {
            if (ts >= g_ctx.retry_wait_until) {
                jz_log_info("Retrying upload (attempt %d/%d)",
                            g_ctx.retry_count + 1, g_ctx.max_retries);
                do_upload_cycle();
            }
            goto check_signals;
        }

        /* Scheduled upload */
        if (ts >= g_ctx.next_upload_time) {
            g_ctx.next_upload_time = ts + (uint64_t)g_ctx.interval_sec;
            do_upload_cycle();
        }

        /* Forced upload via SIGUSR1 or IPC */
        if (g_force_upload) {
            g_force_upload = 0;
            jz_log_info("Forced upload triggered");
            do_upload_cycle();
        }

check_signals:
        /* Handle SIGHUP reload */
        if (g_reload) {
            g_reload = 0;
            do_reload();
        }
    }

    jz_log_info("uploadd shutting down...");

cleanup:
    if (g_ctx.mqtt)
        jz_mqtt_destroy(g_ctx.mqtt);
    jz_ipc_client_close(&g_ctx.collectord_client);
    jz_ipc_server_destroy(&g_ctx.ipc);
    jz_config_free(&g_ctx.config);
    unlink(g_ctx.pid_file);
    jz_log_info("uploadd stopped");
    jz_log_close();

    return exit_code;
}
