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

#define _GNU_SOURCE

#include "config.h"
#include "config_map.h"
#include "config_diff.h"
#include "config_history.h"
#include "db.h"
#include "ipc.h"
#include "log.h"

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

    int               inotify_fd;
    int               watch_fd;
    int               config_version;
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

    /*
     * TODO: Push batch entries to pinned BPF maps via bpf_map_update_elem.
     * For each map category in batch:
     *   1. Open pinned map fd via bpf_obj_get()
     *   2. Iterate entries and bpf_map_update_elem()
     *   3. Close fd
     *
     * This will be fully implemented when we integrate with the
     * config_map_apply module (requires pinned maps to exist).
     */

    jz_log_info("Config translated: %d guards, %d whitelist, %d policies, "
                 "%d threats, %d fake MACs",
                 batch->static_guards.count,
                 batch->whitelist.count,
                 batch->policies.count,
                 batch->threat_patterns.count,
                 batch->fake_macs.count);

    free(batch);
    return 0;
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
    return 0;
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

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dp:D:vVh", long_opts, NULL)) != -1) {
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

    /* Apply initial config to BPF maps */
    apply_config_to_maps(&g_ctx.config);

    /* Set up inotify watcher */
    setup_config_watch();

    /* Initialize IPC server */
    if (jz_ipc_server_init(&g_ctx.ipc, JZ_IPC_SOCK_CONFIGD, 0660,
                           ipc_handler, &g_ctx.ipc) < 0) {
        jz_log_fatal("Failed to initialize IPC server");
        exit_code = 1;
        goto cleanup;
    }

    jz_log_info("configd ready — config v%d loaded", g_ctx.config_version);

    /* ── Main Loop ── */
    while (g_running) {
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
    }

    jz_log_info("configd shutting down...");

cleanup:
    if (g_ctx.inotify_fd >= 0)
        close(g_ctx.inotify_fd);
    jz_ipc_server_destroy(&g_ctx.ipc);
    jz_db_close(&g_ctx.db);
    jz_config_free(&g_ctx.config);
    jz_config_free(&g_ctx.prev_config);
    unlink(g_ctx.pid_file);
    jz_log_info("configd stopped");
    jz_log_close();

    return exit_code;
}
