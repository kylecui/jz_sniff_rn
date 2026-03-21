#include "remote.h"

#if __has_include(<mongoose.h>)
#include <mongoose.h>
#elif __has_include("../../third_party/mongoose/mongoose.h")
#include "../../third_party/mongoose/mongoose.h"
#else
#include <mongoose.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool tls_ok;
} jz_remote_conn_state_t;

static int remote_current_version(const jz_remote_t *remote)
{
    if (!remote)
        return 0;
    if (remote->config_version_ptr)
        return *remote->config_version_ptr;
    return remote->config_version;
}

static void remote_set_version(jz_remote_t *remote, int version)
{
    if (!remote)
        return;
    remote->config_version = version;
    if (remote->config_version_ptr)
        *remote->config_version_ptr = version;
}

static int read_file_to_pem(const char *path, char **out_buf)
{
    if (!path || !path[0] || !out_buf)
        return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buf = (char *) malloc((size_t) sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t) sz, fp);
    fclose(fp);

    if (nread != (size_t) sz) {
        free(buf);
        return -1;
    }

    buf[sz] = '\0';
    *out_buf = buf;
    return 0;
}

static int parse_header_version(struct mg_http_message *hm, int *out_version)
{
    if (!hm || !out_version)
        return -1;

    struct mg_str *hdr = mg_http_get_header(hm, "X-Config-Version");
    if (!hdr || !hdr->buf || hdr->len == 0)
        return 1;

    if (hdr->len >= 31)
        return -1;

    char buf[32];
    memcpy(buf, hdr->buf, hdr->len);
    buf[hdr->len] = '\0';

    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (end == buf || *end != '\0' || v <= 0 || v > INT32_MAX)
        return -1;

    *out_version = (int) v;
    return 0;
}

static bool is_method_uri(const struct mg_http_message *hm,
                          const char *method,
                          const char *uri)
{
    if (!hm || !method || !uri)
        return false;
    return mg_match(hm->method, mg_str(method), NULL) &&
           mg_match(hm->uri, mg_str(uri), NULL);
}

static void remote_reply_not_found(struct mg_connection *c)
{
    mg_http_reply(c, 404,
                  "Content-Type: application/json\r\n",
                  "{\"error\":\"not found\"}\n");
}

static void remote_reply_current(struct mg_connection *c, const jz_remote_t *remote)
{
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n",
                  "{\"version\":%d}\n", remote_current_version(remote));
}

static void remote_reply_rejected(struct mg_connection *c, const char *reason)
{
    mg_http_reply(c, 409,
                  "Content-Type: application/json\r\n",
                  "{\"status\":\"rejected\",\"reason\":\"%s\"}\n",
                  reason ? reason : "invalid request");
}

static void remote_handle_push(struct mg_connection *c,
                               struct mg_http_message *hm,
                               jz_remote_t *remote)
{
    int current = remote_current_version(remote);
    int header_version = 0;
    int hdr_rc = parse_header_version(hm, &header_version);
    if (hdr_rc < 0) {
        remote_reply_rejected(c, "invalid X-Config-Version header");
        return;
    }

    long raw_version = mg_json_get_long(hm->body, "$.version", -1);
    if (raw_version <= 0 || raw_version > INT32_MAX) {
        remote_reply_rejected(c, "missing or invalid version");
        return;
    }

    int version = (int) raw_version;
    if (hdr_rc == 0 && header_version != version) {
        remote_reply_rejected(c, "version header/body mismatch");
        return;
    }

    if (version <= current) {
        remote_reply_rejected(c, "stale version");
        return;
    }

    if (!remote->config_cb) {
        remote_reply_rejected(c, "config callback not set");
        return;
    }

    int rc = remote->config_cb(hm->body.buf, (int) hm->body.len,
                               version, remote->cb_data);
    if (rc < 0) {
        remote_reply_rejected(c, "apply failed");
        return;
    }

    remote_set_version(remote, version);
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n",
                  "{\"status\":\"applied\",\"version\":%d}\n",
                  version);
}

static void remote_ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
    jz_remote_t *remote = (jz_remote_t *) c->fn_data;
    jz_remote_conn_state_t *st = (jz_remote_conn_state_t *) c->data;

    if (!remote)
        return;

    if (ev == MG_EV_ACCEPT) {
        st->tls_ok = false;

        const char *cert_pem = (const char *) remote->tls_cert_pem;
        const char *key_pem = (const char *) remote->tls_key_pem;
        const char *ca_pem = (const char *) remote->tls_ca_pem;
        if (!cert_pem || !key_pem) {
            fprintf(stderr, "remote: missing TLS cert/key during accept\n");
            c->is_closing = 1;
            return;
        }

        struct mg_tls_opts tls_opts;
        memset(&tls_opts, 0, sizeof(tls_opts));
        tls_opts.cert = mg_str(cert_pem);
        tls_opts.key = mg_str(key_pem);
        if (ca_pem && ca_pem[0])
            tls_opts.ca = mg_str(ca_pem);

        mg_tls_init(c, &tls_opts);
        st->tls_ok = true;
        return;
    }

    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (is_method_uri(hm, "POST", "/api/v1/config/push")) {
            remote_handle_push(c, hm, remote);
            return;
        }

        if (is_method_uri(hm, "GET", "/api/v1/config/current")) {
            remote_reply_current(c, remote);
            return;
        }

        remote_reply_not_found(c);
        return;
    }

    if (ev == MG_EV_ERROR) {
        const char *msg = (const char *) ev_data;
        fprintf(stderr, "remote: mg error: %s\n", msg ? msg : "unknown");
        return;
    }
}

int jz_remote_set_callback(jz_remote_t *remote, jz_remote_config_cb cb, void *data)
{
    if (!remote)
        return -1;
    remote->config_cb = cb;
    remote->cb_data = data;
    return 0;
}

int jz_remote_init(jz_remote_t *remote, const char *listen_addr,
                   const char *tls_cert, const char *tls_key, const char *tls_ca)
{
    if (!remote)
        return -1;

    jz_remote_config_cb cb = remote->config_cb;
    void *cb_data = remote->cb_data;
    int *version_ptr = remote->config_version_ptr;
    int version = remote->config_version;

    memset(remote->listen_addr, 0, sizeof(remote->listen_addr));
    memset(remote->tls_cert, 0, sizeof(remote->tls_cert));
    memset(remote->tls_key, 0, sizeof(remote->tls_key));
    memset(remote->tls_ca, 0, sizeof(remote->tls_ca));
    remote->mgr = NULL;
    remote->enabled = false;
    remote->tls_cert_pem = NULL;
    remote->tls_key_pem = NULL;
    remote->tls_ca_pem = NULL;
    remote->config_cb = cb;
    remote->cb_data = cb_data;
    remote->config_version_ptr = version_ptr;
    remote->config_version = version;

    if (!tls_cert || !tls_cert[0])
        return 0;

    if (!listen_addr || !listen_addr[0])
        listen_addr = "https://0.0.0.0:8443";

    snprintf(remote->listen_addr, sizeof(remote->listen_addr), "%s", listen_addr);
    snprintf(remote->tls_cert, sizeof(remote->tls_cert), "%s", tls_cert);
    if (tls_key)
        snprintf(remote->tls_key, sizeof(remote->tls_key), "%s", tls_key);
    if (tls_ca)
        snprintf(remote->tls_ca, sizeof(remote->tls_ca), "%s", tls_ca);

    char *cert_pem = NULL;
    char *key_pem = NULL;
    char *ca_pem = NULL;

    if (read_file_to_pem(remote->tls_cert, &cert_pem) < 0) {
        fprintf(stderr, "remote: failed to read TLS cert: %s\n", remote->tls_cert);
        return -1;
    }

    if (!remote->tls_key[0] || read_file_to_pem(remote->tls_key, &key_pem) < 0) {
        fprintf(stderr, "remote: failed to read TLS key: %s\n", remote->tls_key);
        free(cert_pem);
        return -1;
    }

    if (remote->tls_ca[0] && read_file_to_pem(remote->tls_ca, &ca_pem) < 0) {
        fprintf(stderr, "remote: failed to read TLS CA: %s\n", remote->tls_ca);
        free(cert_pem);
        free(key_pem);
        return -1;
    }

    struct mg_mgr *mgr = (struct mg_mgr *) calloc(1, sizeof(struct mg_mgr));
    if (!mgr) {
        free(cert_pem);
        free(key_pem);
        free(ca_pem);
        return -1;
    }

    mg_mgr_init(mgr);

    remote->tls_cert_pem = cert_pem;
    remote->tls_key_pem = key_pem;
    remote->tls_ca_pem = ca_pem;
    remote->mgr = mgr;

    struct mg_connection *lc = mg_http_listen(mgr, remote->listen_addr,
                                              remote_ev_handler, remote);
    if (!lc) {
        fprintf(stderr, "remote: failed to listen on %s\n", remote->listen_addr);
        mg_mgr_free(mgr);
        free(mgr);
        free(cert_pem);
        free(key_pem);
        free(ca_pem);
        remote->mgr = NULL;
        remote->tls_cert_pem = NULL;
        remote->tls_key_pem = NULL;
        remote->tls_ca_pem = NULL;
        return -1;
    }

    remote->enabled = true;
    return 0;
}

void jz_remote_poll(jz_remote_t *remote, int timeout_ms)
{
    if (!remote || !remote->enabled || !remote->mgr)
        return;
    mg_mgr_poll((struct mg_mgr *) remote->mgr, timeout_ms);
}

void jz_remote_shutdown(jz_remote_t *remote)
{
    if (!remote)
        return;

    if (remote->mgr) {
        mg_mgr_free((struct mg_mgr *) remote->mgr);
        free(remote->mgr);
        remote->mgr = NULL;
    }

    free(remote->tls_cert_pem);
    free(remote->tls_key_pem);
    free(remote->tls_ca_pem);
    remote->tls_cert_pem = NULL;
    remote->tls_key_pem = NULL;
    remote->tls_ca_pem = NULL;
    remote->enabled = false;
}
