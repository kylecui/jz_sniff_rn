/* SPDX-License-Identifier: MIT */
/*
 * jzctl.c - Main management CLI for jz_sniff_rn.
 *
 * Communicates with daemons via IPC Unix domain sockets.
 * See design.md §4.5 for command reference.
 */

#ifndef _GNU_SOURCE
#endif

#if __has_include("ipc.h")
#include "ipc.h"
#elif __has_include("../src/common/ipc.h")
#include "../src/common/ipc.h"
#endif

#if __has_include("log.h")
#include "log.h"
#elif __has_include("../src/common/log.h")
#include "../src/common/log.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define JZCTL_VERSION            "0.1.0"
#define DEFAULT_CONFIG_PATH      "/etc/jz/base.yaml"
#define DEFAULT_TIMEOUT_MS       3000
#define DEFAULT_REPLY_SIZE       8192

#define PID_DIR                  "/var/run/jz"

enum {
    EX_OK = 0,
    EX_ERR = 1,
    EX_USAGE = 2,
};

typedef struct daemon_info {
    const char *name;
    const char *sock_path;
} daemon_info_t;

static const daemon_info_t g_daemons[] = {
    { "sniffd",    JZ_IPC_SOCK_SNIFFD },
    { "configd",   JZ_IPC_SOCK_CONFIGD },
    { "collectord", JZ_IPC_SOCK_COLLECTORD },
    { "uploadd",   JZ_IPC_SOCK_UPLOADD },
};

static inline void touch_log_api(void)
{
    (void)sizeof(jz_log_level_t);
}

static bool str_starts_with(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

static const daemon_info_t *find_daemon(const char *name)
{
    size_t i;

    if (!name)
        return NULL;

    for (i = 0; i < sizeof(g_daemons) / sizeof(g_daemons[0]); i++) {
        if (strcmp(g_daemons[i].name, name) == 0)
            return &g_daemons[i];
    }

    return NULL;
}

static void make_pid_path(const char *name, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%s/%s.pid", PID_DIR, name);
}

static int ipc_query(const char *sock_path,
                     const char *cmd,
                     char *reply,
                     int reply_size)
{
    jz_ipc_client_t cli;
    jz_ipc_msg_t msg;
    size_t copy_len;

    if (!sock_path || !cmd || !reply || reply_size <= 1) {
        errno = EINVAL;
        return -1;
    }

    if (jz_ipc_client_connect(&cli, sock_path, DEFAULT_TIMEOUT_MS) < 0)
        return -1;

    if (jz_ipc_client_request(&cli, cmd, (uint32_t)strlen(cmd), &msg) < 0) {
        jz_ipc_client_close(&cli);
        return -1;
    }

    copy_len = msg.len;
    if (copy_len > (size_t)(reply_size - 1))
        copy_len = (size_t)(reply_size - 1);

    memcpy(reply, msg.payload, copy_len);
    reply[copy_len] = '\0';

    jz_ipc_client_close(&cli);
    return 0;
}

static int print_file(const char *path)
{
    FILE *fp;
    char line[1024];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp) != NULL)
        fputs(line, stdout);

    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int read_pid(const char *pid_path, pid_t *pid)
{
    FILE *fp;
    long tmp;

    if (!pid_path || !pid)
        return -1;

    fp = fopen(pid_path, "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%ld", &tmp) != 1) {
        fclose(fp);
        errno = EINVAL;
        return -1;
    }

    fclose(fp);

    if (tmp <= 1 || tmp > 4194304L) {
        errno = EINVAL;
        return -1;
    }

    *pid = (pid_t)tmp;
    return 0;
}

static int cmd_status(void)
{
    char reply[DEFAULT_REPLY_SIZE];
    int failures = 0;
    size_t i;

    printf("jz_sniff_rn system status\n");
    printf("=======================\n");

    for (i = 0; i < sizeof(g_daemons) / sizeof(g_daemons[0]); i++) {
        if (ipc_query(g_daemons[i].sock_path, "status", reply, sizeof(reply)) < 0) {
            failures++;
            printf("%-10s: down (%s)\n", g_daemons[i].name, strerror(errno));
            continue;
        }

        printf("%-10s: %s\n", g_daemons[i].name, reply);
    }

    return failures == 0 ? EX_OK : EX_ERR;
}

static int cmd_module_list(void)
{
    char reply[JZ_IPC_MAX_MSG_LEN];

    if (ipc_query(JZ_IPC_SOCK_SNIFFD, "module_status", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: sniffd module query failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    printf("Loaded modules:\n");
    fputs(reply, stdout);
    if (reply[0] && reply[strlen(reply) - 1] != '\n')
        putchar('\n');

    return EX_OK;
}

static int cmd_module_reload(const char *name)
{
    char req[256];
    char reply[512];

    if (!name || name[0] == '\0') {
        fprintf(stderr, "error: module name required\n");
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "reload:%s", name);

    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: reload request failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    if (str_starts_with(reply, "error:")) {
        if (ipc_query(JZ_IPC_SOCK_SNIFFD, "reload", reply, sizeof(reply)) < 0) {
            fprintf(stderr, "%s\n", reply);
            return EX_ERR;
        }

        if (str_starts_with(reply, "error:")) {
            fprintf(stderr, "%s\n", reply);
            return EX_ERR;
        }
    }

    printf("module %s: %s\n", name, reply);
    return EX_OK;
}

static int cmd_stats(bool reset)
{
    char reply[1024];

    if (reset) {
        if (ipc_query(JZ_IPC_SOCK_COLLECTORD, "stats_reset", reply, sizeof(reply)) < 0) {
            fprintf(stderr, "error: stats reset request failed: %s\n", strerror(errno));
            return EX_ERR;
        }
        if (str_starts_with(reply, "error:unknown command")) {
            fprintf(stderr, "warn: collectord does not support stats reset\n");
        } else if (str_starts_with(reply, "error:")) {
            fprintf(stderr, "error: stats reset not accepted: %s\n", reply);
            return EX_ERR;
        } else {
            printf("%s\n", reply);
        }
    }

    if (ipc_query(JZ_IPC_SOCK_COLLECTORD, "stats", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: collectord stats query failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_config_show(const char *config_path)
{
    char reply[256];

    if (ipc_query(JZ_IPC_SOCK_CONFIGD, "config_version", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: configd version query failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    printf("%s\n", reply);
    printf("--- %s ---\n", config_path);

    if (print_file(config_path) < 0) {
        fprintf(stderr, "error: cannot read config file %s: %s\n",
                config_path, strerror(errno));
        return EX_ERR;
    }

    return EX_OK;
}

static int cmd_config_reload(void)
{
    char reply[256];

    if (ipc_query(JZ_IPC_SOCK_CONFIGD, "config_reload", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: config reload request failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_config_rollback(const char *version)
{
    char req[128];
    char reply[512];
    long v;
    char *end = NULL;

    if (!version || version[0] == '\0') {
        fprintf(stderr, "error: rollback version required\n");
        return EX_USAGE;
    }

    errno = 0;
    v = strtol(version, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v <= 0 || v > 2147483647L) {
        fprintf(stderr, "error: invalid rollback version '%s'\n", version);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "config_rollback:%ld", v);

    if (ipc_query(JZ_IPC_SOCK_CONFIGD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: config rollback request failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_daemon_restart(const char *name)
{
    const daemon_info_t *d;
    char pid_path[256];
    pid_t pid;

    d = find_daemon(name);
    if (!d) {
        fprintf(stderr, "error: unknown daemon '%s'\n", name ? name : "");
        return EX_USAGE;
    }

    make_pid_path(d->name, pid_path, sizeof(pid_path));
    if (read_pid(pid_path, &pid) < 0) {
        fprintf(stderr, "error: cannot read PID file %s: %s\n",
                pid_path, strerror(errno));
        return EX_ERR;
    }

    if (kill(pid, SIGHUP) < 0) {
        fprintf(stderr, "error: failed to signal %s (pid %ld): %s\n",
                d->name, (long)pid, strerror(errno));
        return EX_ERR;
    }

    printf("%s restart signal sent (pid %ld, signal SIGHUP)\n", d->name, (long)pid);
    return EX_OK;
}

static void usage(const char *prog)
{
    printf(
        "Usage: %s [global-options] <command> [args]\n"
        "\n"
        "Global options:\n"
        "  -h, --help               Show help\n"
        "  -v, --version            Show jzctl version\n"
        "  -c, --config PATH        Config path for 'config show' (default: %s)\n"
        "\n"
        "Commands:\n"
        "  status\n"
        "      System status overview (all daemons).\n"
        "\n"
        "  module list\n"
        "      List loaded BPF modules.\n"
        "\n"
        "  module reload <name>\n"
        "      Reload a specific module (scheduled by sniffd).\n"
        "\n"
        "  stats [--reset]\n"
        "      Show (and optionally reset) collector statistics.\n"
        "\n"
        "  config show\n"
        "      Show current config version and file content.\n"
        "\n"
        "  config reload\n"
        "      Trigger config reload.\n"
        "\n"
        "  config rollback <version>\n"
        "      Roll back to a previous config version.\n"
        "\n"
        "  daemon restart <name>\n"
        "      Send SIGHUP to daemon via /var/run/jz/<name>.pid\n"
        "      Valid names: sniffd, configd, collectord, uploadd\n",
        prog, DEFAULT_CONFIG_PATH
    );
}

static int parse_global_opts(int argc, char **argv, const char **config_path)
{
    int opt;

    static const struct option long_opts[] = {
        { "help",    no_argument,       NULL, 'h' },
        { "version", no_argument,       NULL, 'v' },
        { "config",  required_argument, NULL, 'c' },
        { NULL, 0, NULL, 0 }
    };

    *config_path = DEFAULT_CONFIG_PATH;

    while ((opt = getopt_long(argc, argv, "hvc:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            exit(EX_OK);
        case 'v':
            printf("jzctl version %s\n", JZCTL_VERSION);
            exit(EX_OK);
        case 'c':
            *config_path = optarg;
            break;
        default:
            return -1;
        }
    }

    return 0;
}

static int dispatch(int argc, char **argv, const char *config_path)
{
    const char *cmd;

    if (optind >= argc) {
        fprintf(stderr, "error: missing command\n");
        return EX_USAGE;
    }

    cmd = argv[optind++];

    if (strcmp(cmd, "status") == 0) {
        if (optind != argc) {
            fprintf(stderr, "error: 'status' takes no arguments\n");
            return EX_USAGE;
        }
        return cmd_status();
    }

    if (strcmp(cmd, "module") == 0) {
        if (optind >= argc) {
            fprintf(stderr, "error: missing module subcommand\n");
            return EX_USAGE;
        }

        if (strcmp(argv[optind], "list") == 0) {
            optind++;
            if (optind != argc) {
                fprintf(stderr, "error: 'module list' takes no arguments\n");
                return EX_USAGE;
            }
            return cmd_module_list();
        }

        if (strcmp(argv[optind], "reload") == 0) {
            const char *name;
            optind++;
            if (optind >= argc) {
                fprintf(stderr, "error: usage: jzctl module reload <name>\n");
                return EX_USAGE;
            }
            name = argv[optind++];
            if (optind != argc) {
                fprintf(stderr, "error: too many arguments for module reload\n");
                return EX_USAGE;
            }
            return cmd_module_reload(name);
        }

        fprintf(stderr, "error: unknown module subcommand '%s'\n", argv[optind]);
        return EX_USAGE;
    }

    if (strcmp(cmd, "stats") == 0) {
        bool reset = false;
        while (optind < argc) {
            if (strcmp(argv[optind], "--reset") == 0) {
                reset = true;
                optind++;
                continue;
            }
            fprintf(stderr, "error: unknown stats option '%s'\n", argv[optind]);
            return EX_USAGE;
        }
        return cmd_stats(reset);
    }

    if (strcmp(cmd, "config") == 0) {
        if (optind >= argc) {
            fprintf(stderr, "error: missing config subcommand\n");
            return EX_USAGE;
        }

        if (strcmp(argv[optind], "show") == 0) {
            optind++;
            if (optind != argc) {
                fprintf(stderr, "error: 'config show' takes no arguments\n");
                return EX_USAGE;
            }
            return cmd_config_show(config_path);
        }

        if (strcmp(argv[optind], "reload") == 0) {
            optind++;
            if (optind != argc) {
                fprintf(stderr, "error: 'config reload' takes no arguments\n");
                return EX_USAGE;
            }
            return cmd_config_reload();
        }

        if (strcmp(argv[optind], "rollback") == 0) {
            const char *v;
            optind++;
            if (optind >= argc) {
                fprintf(stderr, "error: usage: jzctl config rollback <version>\n");
                return EX_USAGE;
            }
            v = argv[optind++];
            if (optind != argc) {
                fprintf(stderr, "error: too many arguments for config rollback\n");
                return EX_USAGE;
            }
            return cmd_config_rollback(v);
        }

        fprintf(stderr, "error: unknown config subcommand '%s'\n", argv[optind]);
        return EX_USAGE;
    }

    if (strcmp(cmd, "daemon") == 0) {
        if (optind >= argc) {
            fprintf(stderr, "error: missing daemon subcommand\n");
            return EX_USAGE;
        }

        if (strcmp(argv[optind], "restart") == 0) {
            const char *name;
            optind++;
            if (optind >= argc) {
                fprintf(stderr, "error: usage: jzctl daemon restart <name>\n");
                return EX_USAGE;
            }
            name = argv[optind++];
            if (optind != argc) {
                fprintf(stderr, "error: too many arguments for daemon restart\n");
                return EX_USAGE;
            }
            return cmd_daemon_restart(name);
        }

        fprintf(stderr, "error: unknown daemon subcommand '%s'\n", argv[optind]);
        return EX_USAGE;
    }

    fprintf(stderr, "error: unknown command '%s'\n", cmd);
    return EX_USAGE;
}

int main(int argc, char **argv)
{
    const char *config_path;
    int rc;

    touch_log_api();

    if (parse_global_opts(argc, argv, &config_path) < 0) {
        usage(argv[0]);
        return EX_USAGE;
    }

    rc = dispatch(argc, argv, config_path);
    if (rc == EX_USAGE)
        fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);

    return rc;
}
