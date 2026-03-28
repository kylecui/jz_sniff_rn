/* SPDX-License-Identifier: MIT */
/*
 * configd main.c - Configuration manager daemon for jz_sniff_rn.
 *
 * Responsibilities:
 *   - Watch YAML config files for changes (inotify)
 *   - Validate config schemas and apply to BPF maps
 *   - Maintain config version history in SQLite
 *   - Support rollback to previous config versions
 *   - Serve IPC commands (config_get, config_set, config_version, etc.)
 */


#include "config.h"
#include "config_map.h"
#include "config_diff.h"
#include "config_history.h"
#include "db.h"
#include "ipc.h"
#include "log.h"
#include "remote.h"
#include "staged.h"

#include <cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>

/* ── Version ──────────────────────────────────────────────────── */

#define CONFIGD_VERSION  "0.7.0"

/* ── Defaults ─────────────────────────────────────────────────── */

#define DEFAULT_CONFIG_PATH   "/etc/jz/base.yaml"
#define DEFAULT_PID_FILE      "/var/run/jz/configd.pid"
#define DEFAULT_DB_PATH       "/var/lib/jz/jz.db"
#define DEFAULT_RUN_DIR       "/var/run/jz"
#define DEFAULT_BPF_PIN_DIR   "/sys/fs/bpf/jz"

/* ── Global State ─────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

static struct {
    char config_path[256];
    char pid_file[256];
    char db_path[256];
    bool daemonize;
    bool verbose;

    jz_config_t       config;
    jz_config_t       prev_config;
    jz_db_t           db;
    jz_ipc_server_t   ipc;
    jz_remote_t       remote;

    int               inotify_fd;
    int               watch_fd;
    int               config_version;

    char              tls_cert[256];
    char              tls_key[256];
    char              tls_ca[256];
    char              listen_addr[64];

    jz_staged_t       staged;
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

/* ── Inotify Config Watcher ───────────────────────────────────── */

static int setup_config_watch(void)
{
    g_ctx.inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_ctx.inotify_fd < 0) {
        jz_log_error("inotify_init1 failed: %s", strerror(errno));
        return -1;
    }

    g_ctx.watch_fd = inotify_add_watch(g_ctx.inotify_fd, g_ctx.config_path,
                                        IN_MODIFY | IN_CLOSE_WRITE);
    if (g_ctx.watch_fd < 0) {
        jz_log_error("inotify_add_watch(%s) failed: %s",
                      g_ctx.config_path, strerror(errno));
        close(g_ctx.inotify_fd);
        g_ctx.inotify_fd = -1;
        return -1;
    }

    jz_log_info("Watching config file: %s", g_ctx.config_path);
    return 0;
}

static bool check_config_changed(void)
{
    if (g_ctx.inotify_fd < 0)
        return false;

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    bool changed = false;

    for (;;) {
        ssize_t len = read(g_ctx.inotify_fd, buf, sizeof(buf));
        if (len <= 0)
            break;

        const struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *)ptr;
            if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE))
                changed = true;
        }
    }

    return changed;
}

/* ── Apply Config to BPF Maps ─────────────────────────────────── */

static int open_pinned_map(const char *map_name, char *pin_buf, size_t pin_size)
{
    int fd;

    snprintf(pin_buf, pin_size, "%s/%s", DEFAULT_BPF_PIN_DIR, map_name);
    fd = bpf_obj_get(pin_buf);
    if (fd >= 0)
        return fd;

    snprintf(pin_buf, pin_size, "/sys/fs/bpf/%s", map_name);
    fd = bpf_obj_get(pin_buf);
    return fd;
}

/*
 * Open pinned BPF HASH map, push key/value entries, close fd.
 * Returns -1 if map not pinned yet (non-fatal during early startup).
 */
static int push_hash_map(const char *map_name,
                         const void *keys, size_t key_size,
                         const void *values, size_t value_size,
                         int count)
{
    char pin[512];
    int fd = open_pinned_map(map_name, pin, sizeof(pin));
    if (fd < 0) {
        jz_log_warn("Cannot open pinned map %s: %s (BPF modules may not be loaded yet)",
                     map_name, strerror(errno));
        return -1;
    }

    int errors = 0;
    for (int i = 0; i < count; i++) {
        const void *k = (const char *)keys + (size_t)i * key_size;
        const void *v = (const char *)values + (size_t)i * value_size;
        if (bpf_map_update_elem(fd, k, v, BPF_ANY) < 0) {
            jz_log_error("bpf_map_update_elem(%s, entry %d) failed: %s",
                          map_name, i, strerror(errno));
            errors++;
        }
    }

    close(fd);
    if (errors > 0)
        jz_log_warn("%s: %d/%d entries failed", map_name, errors, count);
    return errors > 0 ? -1 : 0;
}

static int push_array_singleton(const char *map_name,
                                const void *value, size_t value_size)
{
    (void)value_size;
    char pin[512];
    int fd = open_pinned_map(map_name, pin, sizeof(pin));
    if (fd < 0) {
        jz_log_warn("Cannot open pinned map %s: %s",
                     map_name, strerror(errno));
        return -1;
    }

    uint32_t key = 0;
    int ret = bpf_map_update_elem(fd, &key, value, BPF_ANY);
    if (ret < 0) {
        jz_log_error("bpf_map_update_elem(%s) failed: %s",
                      map_name, strerror(errno));
    }

    close(fd);
    return ret < 0 ? -1 : 0;
}

static int push_array_map(const char *map_name,
                          const void *entries, size_t entry_size,
                          int count)
{
    char pin[512];
    int fd = open_pinned_map(map_name, pin, sizeof(pin));
    if (fd < 0) {
        jz_log_warn("Cannot open pinned map %s: %s",
                     map_name, strerror(errno));
        return -1;
    }

    int errors = 0;
    for (int i = 0; i < count; i++) {
        uint32_t key = (uint32_t)i;
        const void *v = (const char *)entries + (size_t)i * entry_size;
        if (bpf_map_update_elem(fd, &key, v, BPF_ANY) < 0) {
            jz_log_error("bpf_map_update_elem(%s, idx %d) failed: %s",
                          map_name, i, strerror(errno));
            errors++;
        }
    }

    close(fd);
    return errors > 0 ? -1 : 0;
}

static int apply_config_to_maps(const jz_config_t *cfg)
{
    jz_config_map_batch_t *batch = calloc(1, sizeof(jz_config_map_batch_t));
    if (!batch) {
        jz_log_error("Failed to allocate config map batch");
        return -1;
    }

    if (jz_config_to_maps(cfg, batch) < 0) {
        jz_log_error("Failed to translate config to BPF maps");
        free(batch);
        return -1;
    }

    /* Generate fake MACs if configured */
    if (cfg->fake_mac_pool.count > 0) {
        jz_config_generate_macs(cfg->fake_mac_pool.prefix,
                                cfg->fake_mac_pool.count, batch);
    }

    /* Load threat blacklist if configured */
    if (cfg->threats.blacklist_file[0]) {
        jz_config_load_blacklist(cfg->threats.blacklist_file, batch);
    }

    int warnings = 0;

    /* ── Push HASH maps ── */

    if (batch->static_guards.count > 0) {
        if (push_hash_map("jz_static_guards",
                          batch->static_guards.keys, sizeof(struct jz_guard_map_key),
                          batch->static_guards.values, sizeof(struct jz_guard_entry),
                          batch->static_guards.count) < 0)
            warnings++;
    }

    /* Whitelist: HASH, key=uint32(ip), value=jz_whitelist_entry */
    if (batch->whitelist.count > 0) {
        if (push_hash_map("jz_whitelist",
                          batch->whitelist.keys, sizeof(uint32_t),
                          batch->whitelist.values, sizeof(struct jz_whitelist_entry),
                          batch->whitelist.count) < 0)
            warnings++;
    }

    /* Flow policies: HASH, key=jz_flow_key, value=jz_flow_policy */
    if (batch->policies.count > 0) {
        if (push_hash_map("jz_flow_policy",
                          batch->policies.keys, sizeof(struct jz_flow_key),
                          batch->policies.values, sizeof(struct jz_flow_policy),
                          batch->policies.count) < 0)
            warnings++;
    }

    /* Threat patterns: HASH, key=uint32(pattern_id), value=jz_threat_pattern */
    if (batch->threat_patterns.count > 0) {
        if (push_hash_map("jz_threat_patterns",
                          batch->threat_patterns.keys, sizeof(uint32_t),
                          batch->threat_patterns.values, sizeof(struct jz_threat_pattern),
                          batch->threat_patterns.count) < 0)
            warnings++;
    }

    /* Threat blacklist: LRU_HASH, key=uint32(ip), value=uint64(timestamp) */
    if (batch->threat_blacklist.count > 0) {
        if (push_hash_map("jz_threat_blacklist",
                          batch->threat_blacklist.keys, sizeof(uint32_t),
                          batch->threat_blacklist.values, sizeof(uint64_t),
                          batch->threat_blacklist.count) < 0)
            warnings++;
    }

    /* Background filters: HASH, key=uint32(filter_id), value=jz_bg_filter_entry */
    if (batch->bg_filters.count > 0) {
        if (push_hash_map("jz_bg_filter",
                          batch->bg_filters.keys, sizeof(uint32_t),
                          batch->bg_filters.values, sizeof(struct jz_bg_filter_entry),
                          batch->bg_filters.count) < 0)
            warnings++;
    }

    /* ── Push ARRAY singleton maps ── */

    /* ARP config: ARRAY[1] */
    if (push_array_singleton("jz_arp_config",
                             &batch->arp_config, sizeof(struct jz_arp_config)) < 0)
        warnings++;

    /* ICMP config: ARRAY[1] */
    if (push_array_singleton("jz_icmp_config",
                             &batch->icmp_config, sizeof(struct jz_icmp_config)) < 0)
        warnings++;

    /* Forensic sample config: ARRAY[1] */
    if (push_array_singleton("jz_sample_config",
                             &batch->sample_config, sizeof(struct jz_sample_config)) < 0)
        warnings++;

    /* ── Push ARRAY multi-entry maps ── */

    /* Fake MAC pool: ARRAY[256], key=idx, value=jz_fake_mac */
    if (batch->fake_macs.count > 0) {
        if (push_array_map("jz_fake_mac_pool",
                           batch->fake_macs.entries, sizeof(struct jz_fake_mac),
                           batch->fake_macs.count) < 0)
            warnings++;
    }

    jz_log_info("Config pushed to BPF maps: %d guards, %d whitelist, %d policies, "
                 "%d threats, %d blacklist, %d bg_filters, %d fake MACs (%d map warnings)",
                 batch->static_guards.count,
                 batch->whitelist.count,
                 batch->policies.count,
                 batch->threat_patterns.count,
                 batch->threat_blacklist.count,
                 batch->bg_filters.count,
                 batch->fake_macs.count,
                 warnings);

    free(batch);
    return warnings;
}

/* ── Config Reload ────────────────────────────────────────────── */

static int do_reload(void)
{
    jz_log_info("Reloading configuration from %s", g_ctx.config_path);

    jz_config_t new_config;
    jz_config_defaults(&new_config);
    jz_config_errors_t errors = { .count = 0 };

    if (jz_config_load(&new_config, g_ctx.config_path, &errors) < 0) {
        jz_log_error("Config reload failed (%d errors)", errors.count);
        for (int i = 0; i < errors.count; i++)
            jz_log_error("  %s: %s", errors.errors[i].field,
                          errors.errors[i].message);
        jz_config_free(&new_config);
        return -1;
    }

    if (jz_config_validate(&new_config, &errors) < 0) {
        jz_log_error("Config validation failed (%d errors)", errors.count);
        jz_config_free(&new_config);
        return -1;
    }

    /* Compute diff */
    jz_config_diff_t diff;
    jz_config_diff(&g_ctx.config, &new_config, &diff);
    if (diff.count == 0) {
        jz_log_info("No config changes detected");
        jz_config_free(&new_config);
        return 0;
    }

    jz_log_info("Config changed: %d entries in %d sections",
                 diff.count, diff.sections_changed);

    /* Apply to BPF maps */
    if (apply_config_to_maps(&new_config) < 0) {
        jz_log_error("Failed to apply config to BPF maps");
        jz_config_audit_log(&g_ctx.db, "config_reload", "system",
                            &diff, "failure");
        jz_config_free(&new_config);
        return -1;
    }

    /* Save to history */
    g_ctx.config_version++;
    char *yaml = jz_config_serialize(&new_config);
    if (yaml) {
        jz_config_history_save(&g_ctx.db, g_ctx.config_version,
                               yaml, "local", "system");
        free(yaml);
    }

    /* Audit log */
    jz_config_audit_log(&g_ctx.db, "config_reload", "system",
                        &diff, "success");

    /* Swap config */
    jz_config_free(&g_ctx.prev_config);
    memcpy(&g_ctx.prev_config, &g_ctx.config, sizeof(jz_config_t));
    memcpy(&g_ctx.config, &new_config, sizeof(jz_config_t));

    /* Apply new log level */
    jz_log_set_level(jz_log_level_from_str(g_ctx.config.system.log_level));

    jz_log_info("Configuration v%d applied successfully", g_ctx.config_version);

    /* Notify sniffd to reload its in-memory config from base.yaml */
    {
        jz_ipc_client_t cli;
        jz_ipc_msg_t reply;
        if (jz_ipc_client_connect(&cli, JZ_IPC_SOCK_SNIFFD, 1000) == 0) {
            if (jz_ipc_client_request(&cli, "reload", 6, &reply) == 0)
                jz_log_info("Notified sniffd of config reload");
            else
                jz_log_warn("sniffd reload request failed");
            jz_ipc_client_close(&cli);
        } else {
            jz_log_warn("Failed to connect to sniffd for reload notification");
        }
    }

    return 0;
}

static int apply_config_body(const char *body, size_t body_len, const char *source)
{
    char tmp_path[320];
    int fd;
    ssize_t wr;
    jz_config_t new_config;
    jz_config_errors_t errors = { .count = 0 };
    jz_config_diff_t diff;
    char *yaml;

    snprintf(tmp_path, sizeof(tmp_path), "%s.push.XXXXXX", g_ctx.config_path);
    fd = mkstemp(tmp_path);
    if (fd < 0) {
        jz_log_error("config_push(%s): mkstemp failed: %s", source, strerror(errno));
        return -1;
    }

    wr = write(fd, body, body_len);
    if (wr < 0 || (size_t) wr != body_len) {
        jz_log_error("config_push(%s): write failed: %s", source, strerror(errno));
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    (void) fsync(fd);
    close(fd);

    jz_config_defaults(&new_config);
    if (jz_config_load(&new_config, tmp_path, &errors) < 0) {
        jz_log_error("config_push(%s): parse failed (%d errors)", source, errors.count);
        jz_config_free(&new_config);
        unlink(tmp_path);
        return -2;
    }

    if (jz_config_validate(&new_config, &errors) < 0) {
        jz_log_error("config_push(%s): validation failed (%d errors)", source, errors.count);
        jz_config_free(&new_config);
        unlink(tmp_path);
        return -3;
    }

    jz_config_diff(&g_ctx.config, &new_config, &diff);

    if (apply_config_to_maps(&new_config) < 0) {
        jz_log_error("config_push(%s): failed to apply to BPF maps", source);
        jz_config_audit_log(&g_ctx.db, "config_push", source, &diff, "partial");
        /* BPF maps failed but persist the YAML file anyway so config
           survives daemon restart.  Maps will be applied on next
           successful reload / restart. */
    }

    if (rename(tmp_path, g_ctx.config_path) < 0) {
        jz_log_error("config_push(%s): rename failed: %s", source, strerror(errno));
        jz_config_audit_log(&g_ctx.db, "config_push", source, &diff, "failure");
        jz_config_free(&new_config);
        unlink(tmp_path);
        return -5;
    }

    g_ctx.config_version++;
    yaml = jz_config_serialize(&new_config);
    if (yaml) {
        jz_config_history_save(&g_ctx.db, g_ctx.config_version,
                               yaml, "push", source);
        free(yaml);
    }

    jz_config_audit_log(&g_ctx.db, "config_push", source, &diff, "success");

    jz_config_free(&g_ctx.prev_config);
    memcpy(&g_ctx.prev_config, &g_ctx.config, sizeof(jz_config_t));
    memcpy(&g_ctx.config, &new_config, sizeof(jz_config_t));

    if (!g_ctx.verbose)
        jz_log_set_level(jz_log_level_from_str(g_ctx.config.system.log_level));

    jz_log_info("Config push(%s) applied: version %d", source, g_ctx.config_version);

    /* Notify sniffd to reload its in-memory config from base.yaml */
    {
        jz_ipc_client_t cli;
        jz_ipc_msg_t reply;
        if (jz_ipc_client_connect(&cli, JZ_IPC_SOCK_SNIFFD, 1000) == 0) {
            if (jz_ipc_client_request(&cli, "reload", 6, &reply) == 0)
                jz_log_info("Notified sniffd of config push");
            else
                jz_log_warn("sniffd reload request failed after config push");
            jz_ipc_client_close(&cli);
        } else {
            jz_log_warn("Failed to connect to sniffd for push notification");
        }
    }

    return 0;
}

static int remote_config_handler(const char *json, int len, int version, void *data)
{
    (void) data;

    if (!json || len <= 0)
        return -1;
    if (version <= g_ctx.config_version)
        return -1;

    if (jz_staged_count(&g_ctx.staged) > 0) {
        jz_log_info("Remote push overrides %d staged changes",
                     jz_staged_count(&g_ctx.staged));
        jz_staged_discard(&g_ctx.staged);
    }

    return apply_config_body(json, (size_t) len, "remote:platform");
}

/* ── IPC Command Handler ─────────────────────────────────────── */

static int ipc_handler(int client_fd, const jz_ipc_msg_t *msg, void *user_data)
{
    jz_ipc_server_t *srv = (jz_ipc_server_t *)user_data;
    const char *cmd = msg->payload;
    char reply[4096];
    int len = 0;

    if (strncmp(cmd, "config_version", 14) == 0) {
        len = snprintf(reply, sizeof(reply), "version:%d", g_ctx.config_version);
    }
    else if (strncmp(cmd, "config_reload", 13) == 0) {
        g_reload = 1;
        len = snprintf(reply, sizeof(reply), "reload:scheduled");
    }
    else if (strncmp(cmd, "config_rollback:", 16) == 0) {
        int target = atoi(cmd + 16);
        if (target <= 0) {
            len = snprintf(reply, sizeof(reply), "error:invalid version");
        } else {
            char yaml_buf[65536];
            int new_ver = jz_config_history_rollback(&g_ctx.db, target,
                                                     "ipc:client",
                                                     yaml_buf, sizeof(yaml_buf));
            if (new_ver > 0) {
                g_ctx.config_version = new_ver;
                g_reload = 1;
                len = snprintf(reply, sizeof(reply),
                               "rollback:ok version:%d", new_ver);
            } else {
                len = snprintf(reply, sizeof(reply), "error:rollback failed");
            }
        }
    }
    else if (strncmp(cmd, "config_diff", 11) == 0) {
        jz_config_diff_t diff;
        jz_config_diff(&g_ctx.prev_config, &g_ctx.config, &diff);
        len = snprintf(reply, sizeof(reply), "diff:%d changes in %d sections",
                       diff.count, diff.sections_changed);
    }
    else if (strncmp(cmd, "status", 6) == 0) {
        len = snprintf(reply, sizeof(reply),
                       "configd v%s config_version:%d config:%s",
                       CONFIGD_VERSION, g_ctx.config_version,
                       g_ctx.config_path);
    }
    else if (strncmp(cmd, "config_stage:", 13) == 0) {
        const char *body = cmd + 13;
        if (strlen(body) == 0) {
            len = snprintf(reply, sizeof(reply), "error:empty stage body");
        } else {
            /* Parse body JSON to extract section-level changes.
             * Expected format: {"section_name": {...}, ...} */
            cJSON *root = cJSON_Parse(body);
            if (!root) {
                len = snprintf(reply, sizeof(reply), "error:invalid JSON");
            } else {
                int staged_count = 0;
                cJSON *item;
                cJSON_ArrayForEach(item, root) {
                    char *val = cJSON_PrintUnformatted(item);
                    if (val) {
                        if (jz_staged_add(&g_ctx.staged, item->string, val) == 0)
                            staged_count++;
                        free(val);
                    }
                }
                cJSON_Delete(root);
                if (staged_count > 0)
                    len = snprintf(reply, sizeof(reply),
                                   "staged:%d sections (total %d pending)",
                                   staged_count, jz_staged_count(&g_ctx.staged));
                else
                    len = snprintf(reply, sizeof(reply),
                                   "error:no valid sections in body");
            }
        }
    }
    else if (strncmp(cmd, "config_staged", 13) == 0) {
        char *json = jz_staged_serialize(&g_ctx.staged);
        if (json) {
            len = snprintf(reply, sizeof(reply), "%s", json);
            free(json);
        } else {
            len = snprintf(reply, sizeof(reply),
                           "{\"count\":0,\"changes\":[]}");
        }
    }
    else if (strncmp(cmd, "config_commit", 13) == 0) {
        if (jz_staged_count(&g_ctx.staged) == 0) {
            len = snprintf(reply, sizeof(reply), "error:nothing staged");
        } else {
            char *merged = jz_staged_merge(&g_ctx.staged, &g_ctx.config);
            if (!merged) {
                len = snprintf(reply, sizeof(reply),
                               "error:failed to merge staged changes");
            } else {
                int rc = apply_config_body(merged, strlen(merged),
                                           "staged:commit");
                free(merged);
                if (rc == 0) {
                    jz_staged_discard(&g_ctx.staged);
                    len = snprintf(reply, sizeof(reply),
                                   "commit:ok version:%d",
                                   g_ctx.config_version);
                } else {
                    len = snprintf(reply, sizeof(reply),
                                   "error:commit failed (rc=%d)", rc);
                }
            }
        }
    }
    else if (strncmp(cmd, "config_discard", 14) == 0) {
        int n = jz_staged_count(&g_ctx.staged);
        jz_staged_discard(&g_ctx.staged);
        len = snprintf(reply, sizeof(reply), "discard:ok (%d changes cleared)", n);
    }
    else if (strncmp(cmd, "config_push:", 12) == 0) {
        const char *body = cmd + 12;
        size_t body_len = strlen(body);
        if (body_len == 0) {
            len = snprintf(reply, sizeof(reply), "error:empty config body");
        } else {
            int rc = apply_config_body(body, body_len, "ipc:api");
            if (rc == 0) {
                len = snprintf(reply, sizeof(reply),
                               "push:ok version:%d", g_ctx.config_version);
            } else if (rc == -2) {
                len = snprintf(reply, sizeof(reply),
                               "error:config parse failed");
            } else if (rc == -3) {
                len = snprintf(reply, sizeof(reply),
                               "error:config validation failed");
            } else {
                len = snprintf(reply, sizeof(reply),
                               "error:config push failed (rc=%d)", rc);
            }
        }
    }
    else if (strncmp(cmd, "version", 7) == 0) {
        len = snprintf(reply, sizeof(reply), "%s", CONFIGD_VERSION);
    }
    else {
        len = snprintf(reply, sizeof(reply), "error:unknown command");
    }

    return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)len);
}

/* ── Command Line Parsing ─────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH   Config file (default: %s)\n"
        "  -d, --daemon        Run as daemon\n"
        "  -p, --pidfile PATH  PID file (default: %s)\n"
        "  --db PATH           SQLite database (default: %s)\n"
        "  --tls-cert PATH     TLS server certificate PEM (enables remote endpoint)\n"
        "  --tls-key PATH      TLS server private key PEM\n"
        "  --tls-ca PATH       TLS CA PEM for optional mTLS client verification\n"
        "  --listen ADDR       Remote endpoint listen URL (default: https://0.0.0.0:8443)\n"
        "  -v, --verbose       Verbose logging\n"
        "  -V, --version       Print version\n"
        "  -h, --help          Show help\n",
        prog, DEFAULT_CONFIG_PATH, DEFAULT_PID_FILE, DEFAULT_DB_PATH);
}

static int parse_args(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        { "config",  required_argument, NULL, 'c' },
        { "daemon",  no_argument,       NULL, 'd' },
        { "pidfile", required_argument, NULL, 'p' },
        { "db",      required_argument, NULL, 'D' },
        { "tls-cert", required_argument, NULL, 't' },
        { "tls-key",  required_argument, NULL, 'k' },
        { "tls-ca",   required_argument, NULL, 'a' },
        { "listen",   required_argument, NULL, 'l' },
        { "verbose", no_argument,       NULL, 'v' },
        { "version", no_argument,       NULL, 'V' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
             "%s", DEFAULT_CONFIG_PATH);
    snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
             "%s", DEFAULT_PID_FILE);
    snprintf(g_ctx.db_path, sizeof(g_ctx.db_path),
             "%s", DEFAULT_DB_PATH);
    snprintf(g_ctx.listen_addr, sizeof(g_ctx.listen_addr),
             "%s", "https://0.0.0.0:8443");
    g_ctx.tls_cert[0] = '\0';
    g_ctx.tls_key[0] = '\0';
    g_ctx.tls_ca[0] = '\0';

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dp:D:t:k:a:l:vVh", long_opts, NULL)) != -1) {
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
        case 't':
            snprintf(g_ctx.tls_cert, sizeof(g_ctx.tls_cert),
                     "%s", optarg);
            break;
        case 'k':
            snprintf(g_ctx.tls_key, sizeof(g_ctx.tls_key),
                     "%s", optarg);
            break;
        case 'a':
            snprintf(g_ctx.tls_ca, sizeof(g_ctx.tls_ca),
                     "%s", optarg);
            break;
        case 'l':
            snprintf(g_ctx.listen_addr, sizeof(g_ctx.listen_addr),
                     "%s", optarg);
            break;
        case 'v':
            g_ctx.verbose = true;
            break;
        case 'V':
            printf("configd version %s\n", CONFIGD_VERSION);
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

/* ── Main ─────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.inotify_fd = -1;
    g_ctx.watch_fd = -1;

    if (parse_args(argc, argv) < 0)
        return 1;

    jz_log_level_t log_level = g_ctx.verbose ? JZ_LOG_DEBUG : JZ_LOG_INFO;
    jz_log_init("configd", log_level, true);
    jz_log_info("configd v%s starting", CONFIGD_VERSION);

    if (install_signals() < 0) {
        jz_log_fatal("Failed to install signal handlers");
        return 1;
    }

    /* Load configuration */
    jz_config_defaults(&g_ctx.config);
    jz_config_defaults(&g_ctx.prev_config);
    jz_config_errors_t errors = { .count = 0 };

    if (jz_config_load(&g_ctx.config, g_ctx.config_path, &errors) < 0) {
        jz_log_fatal("Failed to load config %s", g_ctx.config_path);
        return 1;
    }

    if (!g_ctx.verbose)
        jz_log_set_level(jz_log_level_from_str(g_ctx.config.system.log_level));

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

    /* Initialize config history */
    if (jz_config_history_init(&g_ctx.db) < 0) {
        jz_log_warn("Config history init failed — history disabled");
    }

    g_ctx.config_version = jz_config_history_current_version(&g_ctx.db);
    if (g_ctx.config_version < 0)
        g_ctx.config_version = 0;

    /* Save initial config as version 1 if no history */
    if (g_ctx.config_version == 0) {
        g_ctx.config_version = 1;
        char *yaml = jz_config_serialize(&g_ctx.config);
        if (yaml) {
            jz_config_history_save(&g_ctx.db, 1, yaml, "local", "system");
            free(yaml);
        }
    }

    /* Apply initial config to BPF maps.
     * sniffd may not have finished pinning maps yet (startup race),
     * so retry with back-off if any maps fail to open. */
    {
        int map_warnings, attempt;
        for (attempt = 0; attempt < 10; attempt++) {
            map_warnings = apply_config_to_maps(&g_ctx.config);
            if (map_warnings == 0)
                break;
            jz_log_warn("Initial map push: %d map(s) not ready, "
                        "retry %d/10 in 2s (waiting for sniffd)...",
                        map_warnings, attempt + 1);
            sleep(2);
        }
        if (map_warnings > 0)
            jz_log_error("Initial map push still has %d warnings after %d retries "
                         "— some BPF maps may be unpopulated",
                         map_warnings, attempt);
    }

    /* Set up inotify watcher */
    setup_config_watch();

    /* Initialize IPC server */
    if (jz_ipc_server_init(&g_ctx.ipc, JZ_IPC_SOCK_CONFIGD, 0660,
                           ipc_handler, &g_ctx.ipc) < 0) {
        jz_log_fatal("Failed to initialize IPC server");
        exit_code = 1;
        goto cleanup;
    }

    if (g_ctx.tls_cert[0]) {
        g_ctx.remote.config_version_ptr = &g_ctx.config_version;
        jz_remote_set_callback(&g_ctx.remote, remote_config_handler, NULL);
        if (jz_remote_init(&g_ctx.remote, g_ctx.listen_addr,
                           g_ctx.tls_cert, g_ctx.tls_key, g_ctx.tls_ca) < 0) {
            jz_log_warn("Remote config endpoint failed to start");
        } else {
            jz_log_info("Remote config endpoint listening on %s", g_ctx.listen_addr);
        }
    }

    jz_staged_init(&g_ctx.staged, 0);

    jz_log_info("configd ready — config v%d loaded", g_ctx.config_version);

    /* ── Main Loop ── */
    while (g_running) {
        jz_remote_poll(&g_ctx.remote, 0);

        /* Poll IPC */
        jz_ipc_server_poll(&g_ctx.ipc, 100);

        /* Check for config file changes */
        if (check_config_changed()) {
            jz_log_info("Config file change detected");
            /* Small delay to let editor finish writing */
            usleep(200000);
            do_reload();
        }

        /* Handle SIGHUP reload */
        if (g_reload) {
            g_reload = 0;
            do_reload();
        }

        if (jz_staged_check_expiry(&g_ctx.staged))
            jz_config_audit_log(&g_ctx.db, "staged_expired", "auto",
                                NULL, "discarded");
    }

    jz_log_info("configd shutting down...");

cleanup:
    jz_staged_destroy(&g_ctx.staged);
    if (g_ctx.inotify_fd >= 0)
        close(g_ctx.inotify_fd);
    jz_remote_shutdown(&g_ctx.remote);
    jz_ipc_server_destroy(&g_ctx.ipc);
    jz_db_close(&g_ctx.db);
    jz_config_free(&g_ctx.config);
    jz_config_free(&g_ctx.prev_config);
    unlink(g_ctx.pid_file);
    jz_log_info("configd stopped");
    jz_log_close();

    return exit_code;
}
