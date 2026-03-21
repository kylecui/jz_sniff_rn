/* SPDX-License-Identifier: MIT */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define JZGUARD_VERSION            "0.1.0"
#define DEFAULT_TIMEOUT_MS         3000
#define DEFAULT_REPLY_SIZE         8192

enum {
    EX_OK = 0,
    EX_ERR = 1,
    EX_USAGE = 2,
};

enum {
    GUARD_STATIC = 1,
    GUARD_DYNAMIC = 2,
    GUARD_WHITELIST = 3,
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

static const char *type_to_name(int type)
{
    if (type == GUARD_STATIC)
        return "static";
    if (type == GUARD_DYNAMIC)
        return "dynamic";
    if (type == GUARD_WHITELIST)
        return "whitelist";
    return "unknown";
}

static bool parse_ip(const char *s, char *norm, size_t norm_sz)
{
    struct in_addr addr;
    const char *txt;

    if (!s || !norm || norm_sz < 16)
        return false;

    if (inet_pton(AF_INET, s, &addr) != 1)
        return false;

    txt = inet_ntoa(addr);
    if (!txt)
        return false;

    snprintf(norm, norm_sz, "%s", txt);
    return true;
}

static bool parse_mac(const char *s)
{
    unsigned int b0;
    unsigned int b1;
    unsigned int b2;
    unsigned int b3;
    unsigned int b4;
    unsigned int b5;

    if (!s || s[0] == '\0')
        return false;

    if (sscanf(s,
               "%2x:%2x:%2x:%2x:%2x:%2x",
               &b0,
               &b1,
               &b2,
               &b3,
               &b4,
               &b5) != 6) {
        return false;
    }

    return b0 <= 0xff && b1 <= 0xff && b2 <= 0xff &&
           b3 <= 0xff && b4 <= 0xff && b5 <= 0xff;
}

static bool parse_vlan(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !out || s[0] == '\0')
        return false;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v > 4094UL)
        return false;

    *out = (uint32_t)v;
    return true;
}

static bool unknown_command(const char *reply)
{
    if (!reply)
        return false;

    return str_starts_with(reply, "error: unknown command") ||
           str_starts_with(reply, "error:unknown command");
}

static int cmd_list(int argc, char **argv)
{
    char reply[DEFAULT_REPLY_SIZE];
    char *saveptr = NULL;
    char *line;
    int type_filter = 0;
    bool json = false;
    bool first_json = true;
    bool printed_table = false;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --type requires a value\n");
                return EX_USAGE;
            }
            if (strcmp(argv[i], "static") == 0) {
                type_filter = GUARD_STATIC;
            } else if (strcmp(argv[i], "dynamic") == 0) {
                type_filter = GUARD_DYNAMIC;
            } else if (strcmp(argv[i], "whitelist") == 0) {
                type_filter = GUARD_WHITELIST;
                fprintf(stderr, "warn: whitelist filtering not yet supported\n");
            } else {
                fprintf(stderr, "error: invalid --type '%s'\n", argv[i]);
                return EX_USAGE;
            }
            continue;
        }

        if (strcmp(argv[i], "--format") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --format requires a value\n");
                return EX_USAGE;
            }
            if (strcmp(argv[i], "table") == 0) {
                json = false;
            } else if (strcmp(argv[i], "json") == 0) {
                json = true;
            } else {
                fprintf(stderr, "error: invalid --format '%s'\n", argv[i]);
                return EX_USAGE;
            }
            continue;
        }

        fprintf(stderr, "error: unknown list option '%s'\n", argv[i]);
        return EX_USAGE;
    }

    if (ipc_query(JZ_IPC_SOCK_SNIFFD, "guard_list", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: guard list query failed: %s\n", strerror(errno));
        return EX_ERR;
    }

    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    if (json)
        printf("[\n");

    line = strtok_r(reply, "\n", &saveptr);
    while (line) {
        char ip[64];
        char mac[32];
        int type;
        int vlan;
        int ttl;

        if (!str_starts_with(line, "guards ") &&
            sscanf(line,
                   "%63s %31s type=%d vlan=%d ttl=%d",
                   ip,
                   mac,
                   &type,
                   &vlan,
                   &ttl) == 5) {
            if (type_filter != 0 && type != type_filter) {
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
            }

            if (json) {
                printf("%s  {\"ip\":\"%s\",\"mac\":\"%s\",\"type\":\"%s\",\"vlan\":%d,\"ttl\":%d}",
                       first_json ? "" : ",\n",
                       ip,
                       mac,
                       type_to_name(type),
                       vlan,
                       ttl);
                first_json = false;
            } else {
                if (!printed_table) {
                    printf("%-16s %-17s %-10s %-6s %-8s\n",
                           "IP", "MAC", "TYPE", "VLAN", "TTL");
                    printf("%-16s %-17s %-10s %-6s %-8s\n",
                           "----------------", "-----------------", "----------", "------", "--------");
                    printed_table = true;
                }
                printf("%-16s %-17s %-10s %-6d %-8d\n",
                       ip,
                       mac,
                       type_to_name(type),
                       vlan,
                       ttl);
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    if (json)
        printf("\n]\n");
    else if (!printed_table)
        printf("No guards found.\n");

    return EX_OK;
}

static int cmd_add(int type, int argc, char **argv)
{
    const char *ip = NULL;
    const char *mac = "00:00:00:00:00:00";
    uint32_t vlan = 0;
    char ip_norm[16];
    char req[256];
    char reply[512];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --ip requires a value\n");
                return EX_USAGE;
            }
            ip = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--mac") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --mac requires a value\n");
                return EX_USAGE;
            }
            mac = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--vlan") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --vlan requires a value\n");
                return EX_USAGE;
            }
            if (!parse_vlan(argv[i], &vlan)) {
                fprintf(stderr, "error: invalid --vlan '%s'\n", argv[i]);
                return EX_USAGE;
            }
            continue;
        }
        fprintf(stderr, "error: unknown add option '%s'\n", argv[i]);
        return EX_USAGE;
    }

    if (!ip) {
        fprintf(stderr, "error: --ip is required\n");
        return EX_USAGE;
    }
    if (!parse_ip(ip, ip_norm, sizeof(ip_norm))) {
        fprintf(stderr, "error: invalid IP address '%s'\n", ip);
        return EX_USAGE;
    }
    if (!parse_mac(mac)) {
        fprintf(stderr, "error: invalid MAC address '%s'\n", mac);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "guard_add:%s:%s:%d:%u", ip_norm, mac, type, vlan);
    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: guard add request failed: %s\n", strerror(errno));
        return EX_ERR;
    }
    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_del(int argc, char **argv)
{
    const char *ip = NULL;
    char ip_norm[16];
    char req[128];
    char reply[512];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --ip requires a value\n");
                return EX_USAGE;
            }
            ip = argv[i];
            continue;
        }
        fprintf(stderr, "error: unknown del option '%s'\n", argv[i]);
        return EX_USAGE;
    }

    if (!ip) {
        fprintf(stderr, "error: --ip is required\n");
        return EX_USAGE;
    }
    if (!parse_ip(ip, ip_norm, sizeof(ip_norm))) {
        fprintf(stderr, "error: invalid IP address '%s'\n", ip);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "guard_remove:%s", ip_norm);
    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: guard remove request failed: %s\n", strerror(errno));
        return EX_ERR;
    }
    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_whitelist_add(int argc, char **argv)
{
    const char *ip = NULL;
    const char *mac = NULL;
    char ip_norm[16];
    char req[256];
    char reply[512];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --ip requires a value\n");
                return EX_USAGE;
            }
            ip = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--mac") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --mac requires a value\n");
                return EX_USAGE;
            }
            mac = argv[i];
            continue;
        }
        fprintf(stderr, "error: unknown whitelist add option '%s'\n", argv[i]);
        return EX_USAGE;
    }

    if (!ip || !mac) {
        fprintf(stderr, "error: usage: jzguard whitelist add --ip <IP> --mac <MAC>\n");
        return EX_USAGE;
    }
    if (!parse_ip(ip, ip_norm, sizeof(ip_norm))) {
        fprintf(stderr, "error: invalid IP address '%s'\n", ip);
        return EX_USAGE;
    }
    if (!parse_mac(mac)) {
        fprintf(stderr, "error: invalid MAC address '%s'\n", mac);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "whitelist_add:%s:%s", ip_norm, mac);
    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: whitelist add request failed: %s\n", strerror(errno));
        return EX_ERR;
    }
    if (unknown_command(reply)) {
        fprintf(stderr, "warn: whitelist_add not yet supported by sniffd\n");
        return EX_OK;
    }
    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_whitelist_del(int argc, char **argv)
{
    const char *ip = NULL;
    char ip_norm[16];
    char req[128];
    char reply[512];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "error: --ip requires a value\n");
                return EX_USAGE;
            }
            ip = argv[i];
            continue;
        }
        fprintf(stderr, "error: unknown whitelist del option '%s'\n", argv[i]);
        return EX_USAGE;
    }

    if (!ip) {
        fprintf(stderr, "error: usage: jzguard whitelist del --ip <IP>\n");
        return EX_USAGE;
    }
    if (!parse_ip(ip, ip_norm, sizeof(ip_norm))) {
        fprintf(stderr, "error: invalid IP address '%s'\n", ip);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "whitelist_del:%s", ip_norm);
    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: whitelist del request failed: %s\n", strerror(errno));
        return EX_ERR;
    }
    if (unknown_command(reply)) {
        fprintf(stderr, "warn: whitelist_del not yet supported by sniffd\n");
        return EX_OK;
    }
    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static int cmd_probe(int argc, char **argv)
{
    const char *sub;
    char req[64];
    char reply[DEFAULT_REPLY_SIZE];

    if (argc != 1) {
        fprintf(stderr, "error: usage: jzguard probe <start|stop|results>\n");
        return EX_USAGE;
    }

    sub = argv[0];
    if (strcmp(sub, "start") != 0 &&
        strcmp(sub, "stop") != 0 &&
        strcmp(sub, "results") != 0) {
        fprintf(stderr, "error: unknown probe subcommand '%s'\n", sub);
        return EX_USAGE;
    }

    snprintf(req, sizeof(req), "probe_%s", sub);
    if (ipc_query(JZ_IPC_SOCK_SNIFFD, req, reply, sizeof(reply)) < 0) {
        fprintf(stderr, "error: probe request failed: %s\n", strerror(errno));
        return EX_ERR;
    }
    if (unknown_command(reply)) {
        fprintf(stderr, "warn: %s not yet supported by sniffd\n", req);
        return EX_OK;
    }
    if (str_starts_with(reply, "error:")) {
        fprintf(stderr, "%s\n", reply);
        return EX_ERR;
    }

    printf("%s\n", reply);
    return EX_OK;
}

static void usage(const char *prog)
{
    printf(
        "Usage: %s [global-options] <command> [args]\n"
        "\n"
        "Global options:\n"
        "  -h, --help                                 Show help\n"
        "  -v, --version                              Show jzguard version\n"
        "\n"
        "Commands:\n"
        "  list [--type static|dynamic|whitelist] [--format table|json]\n"
        "\n"
        "  add static --ip <IP> [--mac <MAC>] [--vlan <VLAN>]\n"
        "  add dynamic --ip <IP> [--mac <MAC>] [--vlan <VLAN>]\n"
        "\n"
        "  del static --ip <IP>\n"
        "  del dynamic --ip <IP>\n"
        "\n"
        "  whitelist add --ip <IP> --mac <MAC>\n"
        "  whitelist del --ip <IP>\n"
        "\n"
        "  probe start\n"
        "  probe stop\n"
        "  probe results\n",
        prog
    );
}

static int parse_global_opts(int argc, char **argv)
{
    int opt;

    static const struct option long_opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "hv", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            exit(EX_OK);
        case 'v':
            printf("jzguard version %s\n", JZGUARD_VERSION);
            exit(EX_OK);
        default:
            return -1;
        }
    }

    return 0;
}

static int dispatch(int argc, char **argv)
{
    const char *cmd;

    if (optind >= argc) {
        fprintf(stderr, "error: missing command\n");
        return EX_USAGE;
    }

    cmd = argv[optind++];

    if (strcmp(cmd, "list") == 0)
        return cmd_list(argc - optind, &argv[optind]);

    if (strcmp(cmd, "add") == 0) {
        const char *sub;

        if (optind >= argc) {
            fprintf(stderr, "error: missing add subcommand\n");
            return EX_USAGE;
        }
        sub = argv[optind++];

        if (strcmp(sub, "static") == 0)
            return cmd_add(GUARD_STATIC, argc - optind, &argv[optind]);
        if (strcmp(sub, "dynamic") == 0)
            return cmd_add(GUARD_DYNAMIC, argc - optind, &argv[optind]);

        fprintf(stderr, "error: unknown add subcommand '%s'\n", sub);
        return EX_USAGE;
    }

    if (strcmp(cmd, "del") == 0) {
        const char *sub;

        if (optind >= argc) {
            fprintf(stderr, "error: missing del subcommand\n");
            return EX_USAGE;
        }
        sub = argv[optind++];

        if (strcmp(sub, "static") != 0 && strcmp(sub, "dynamic") != 0) {
            fprintf(stderr, "error: unknown del subcommand '%s'\n", sub);
            return EX_USAGE;
        }

        return cmd_del(argc - optind, &argv[optind]);
    }

    if (strcmp(cmd, "whitelist") == 0) {
        const char *sub;

        if (optind >= argc) {
            fprintf(stderr, "error: missing whitelist subcommand\n");
            return EX_USAGE;
        }
        sub = argv[optind++];

        if (strcmp(sub, "add") == 0)
            return cmd_whitelist_add(argc - optind, &argv[optind]);
        if (strcmp(sub, "del") == 0)
            return cmd_whitelist_del(argc - optind, &argv[optind]);

        fprintf(stderr, "error: unknown whitelist subcommand '%s'\n", sub);
        return EX_USAGE;
    }

    if (strcmp(cmd, "probe") == 0)
        return cmd_probe(argc - optind, &argv[optind]);

    fprintf(stderr, "error: unknown command '%s'\n", cmd);
    return EX_USAGE;
}

int main(int argc, char **argv)
{
    int rc;

    touch_log_api();

    if (parse_global_opts(argc, argv) < 0) {
        usage(argv[0]);
        return EX_USAGE;
    }

    rc = dispatch(argc, argv);
    if (rc == EX_USAGE)
        fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);

    return rc;
}
