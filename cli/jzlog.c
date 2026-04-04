/* SPDX-License-Identifier: MIT */
/*
 * jzlog.c - Log viewer CLI for jz_sniff_rn.
 *
 * Reads SQLite database directly for log queries.
 * See design.md §4.5 for command reference.
 */

#ifndef _GNU_SOURCE
#endif

#if __has_include("db.h")
#include "db.h"
#elif __has_include("../src/common/db.h")
#include "../src/common/db.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef JZ_VERSION
#define JZ_VERSION "0.0.0-dev"
#endif
#define JZLOG_VERSION JZ_VERSION
#define DEFAULT_DB_PATH "/var/lib/jz/jz.db"
#define DEFAULT_LIMIT 50
#define MAX_LIMIT 1000000

enum {
    EX_OK = 0,
    EX_ERR = 1,
    EX_USAGE = 2,
};

typedef enum {
    CMD_ATTACK = 0,
    CMD_SNIFFER,
    CMD_BACKGROUND,
    CMD_AUDIT,
    CMD_THREAT,
    CMD_TAIL,
} cmd_t;

typedef enum {
    FORMAT_TABLE = 0,
    FORMAT_JSON,
} output_format_t;

typedef struct {
    char db_path[256];
    const char *since;
    const char *proto;
    int threat_min;
    int limit;
    bool follow;
    output_format_t format;
} cli_opts_t;

static volatile sig_atomic_t g_running = 1;

static const char *nz(const unsigned char *s)
{
    return s ? (const char *)s : "";
}

static const char *event_name(int event_type)
{
    switch (event_type) {
    case 1: return "ARP";
    case 2: return "ICMP";
    case 3: return "SNIFF";
    case 4: return "POLICY";
    case 5: return "THREAT";
    case 6: return "BG";
    case 7: return "CONFIG";
    case 8: return "STATUS";
    case 10: return "TCP";
    case 11: return "UDP";
    default: return "OTHER";
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--db PATH] <command> [options]\n"
            "\n"
            "Commands:\n"
            "  attack [--since 2026-03-01] [--limit N] [--format json|table]\n"
            "  sniffer [--limit N] [--format json|table]\n"
            "  background [--proto arp|dhcp|mdns|lldp] [--limit N] [--format json|table]\n"
            "  audit [--since 2026-03-01] [--limit N] [--format json|table]\n"
            "  threat [--level high|critical] [--limit N] [--format json|table]\n"
            "  tail [-f] [--limit N]\n"
            "\n"
            "Global options:\n"
            "  --db PATH                SQLite path (default: %s)\n"
            "  -h, --help               Show help\n"
            "  -V, --version            Show version\n",
            prog, DEFAULT_DB_PATH);
}

static void opts_init(cli_opts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    snprintf(opts->db_path, sizeof(opts->db_path), "%s", DEFAULT_DB_PATH);
    opts->format = FORMAT_TABLE;
    opts->limit = DEFAULT_LIMIT;
    opts->threat_min = 3;
}

static int parse_limit(const char *arg, int *out)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol(arg, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v < 0 || v > MAX_LIMIT)
        return -1;

    *out = (int)v;
    return 0;
}

static int parse_format(const char *arg, output_format_t *out)
{
    if (strcmp(arg, "table") == 0) {
        *out = FORMAT_TABLE;
        return 0;
    }
    if (strcmp(arg, "json") == 0) {
        *out = FORMAT_JSON;
        return 0;
    }
    return -1;
}

static int parse_threat_level(const char *arg, int *out)
{
    if (strcasecmp(arg, "high") == 0) {
        *out = 3;
        return 0;
    }
    if (strcasecmp(arg, "critical") == 0) {
        *out = 4;
        return 0;
    }
    return -1;
}

static bool is_command(const char *s)
{
    return strcmp(s, "attack") == 0 ||
           strcmp(s, "sniffer") == 0 ||
           strcmp(s, "background") == 0 ||
           strcmp(s, "audit") == 0 ||
           strcmp(s, "threat") == 0 ||
           strcmp(s, "tail") == 0;
}

static int find_command_index(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (is_command(argv[i]))
            return i;
    }
    return -1;
}

static cmd_t parse_command_name(const char *name)
{
    if (strcmp(name, "attack") == 0)
        return CMD_ATTACK;
    if (strcmp(name, "sniffer") == 0)
        return CMD_SNIFFER;
    if (strcmp(name, "background") == 0)
        return CMD_BACKGROUND;
    if (strcmp(name, "audit") == 0)
        return CMD_AUDIT;
    if (strcmp(name, "threat") == 0)
        return CMD_THREAT;
    return CMD_TAIL;
}

static int parse_global_opts(int argc, char **argv, int cmd_idx, cli_opts_t *opts)
{
    (void)argc;
    int i;

    for (i = 1; i < cmd_idx; i++) {
        if (strcmp(argv[i], "--db") == 0) {
            if (i + 1 >= cmd_idx)
                return -1;
            snprintf(opts->db_path, sizeof(opts->db_path), "%s", argv[i + 1]);
            i++;
            continue;
        }
        return -1;
    }

    return 0;
}

static int parse_subcommand_opts(cmd_t cmd, int argc, char **argv, cli_opts_t *opts)
{
    static const struct option long_opts[] = {
        { "since", required_argument, NULL, 's' },
        { "limit", required_argument, NULL, 'l' },
        { "format", required_argument, NULL, 'o' },
        { "proto", required_argument, NULL, 'p' },
        { "level", required_argument, NULL, 't' },
        { "db", required_argument, NULL, 'D' },
        { "follow", no_argument, NULL, 'f' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    int opt;

    opterr = 0;
    optind = 1;

    while ((opt = getopt_long(argc, argv, "s:l:o:p:t:D:fh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            if (cmd != CMD_ATTACK && cmd != CMD_AUDIT)
                return -1;
            opts->since = optarg;
            break;
        case 'l':
            if (parse_limit(optarg, &opts->limit) < 0)
                return -1;
            break;
        case 'o':
            if (cmd == CMD_TAIL)
                return -1;
            if (parse_format(optarg, &opts->format) < 0)
                return -1;
            break;
        case 'p':
            if (cmd != CMD_BACKGROUND)
                return -1;
            if (strcasecmp(optarg, "arp") != 0 &&
                strcasecmp(optarg, "dhcp") != 0 &&
                strcasecmp(optarg, "mdns") != 0 &&
                strcasecmp(optarg, "lldp") != 0)
                return -1;
            opts->proto = optarg;
            break;
        case 't':
            if (cmd != CMD_THREAT)
                return -1;
            if (parse_threat_level(optarg, &opts->threat_min) < 0)
                return -1;
            break;
        case 'D':
            snprintf(opts->db_path, sizeof(opts->db_path), "%s", optarg);
            break;
        case 'f':
            if (cmd != CMD_TAIL)
                return -1;
            opts->follow = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(EX_OK);
        default:
            return -1;
        }
    }

    return 0;
}

static int db_open_readonly(jz_db_t *ctx, const char *path)
{
    int rc;

    if (!ctx || !path)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "jzlog: database file not found: %s\n", path);
        return -1;
    }

    rc = sqlite3_open_v2(path, &ctx->db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "jzlog: cannot open %s: %s\n",
                path, ctx->db ? sqlite3_errmsg(ctx->db) : "unknown");
        if (ctx->db)
            sqlite3_close(ctx->db);
        ctx->db = NULL;
        return -1;
    }

    sqlite3_busy_timeout(ctx->db, 1000);
    snprintf(ctx->path, sizeof(ctx->path), "%s", path);
    ctx->initialized = true;
    return 0;
}

static void json_escape(const unsigned char *s)
{
    const unsigned char *p = s;

    putchar('"');
    if (!p) {
        putchar('"');
        return;
    }

    while (*p) {
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20)
                printf("\\u%04x", (unsigned int)*p);
            else
                putchar((char)*p);
            break;
        }
        p++;
    }

    putchar('"');
}

static void json_sep(bool *first)
{
    if (*first) {
        *first = false;
        return;
    }
    printf(",\n");
}

static int render_attack(sqlite3_stmt *stmt, output_format_t format)
{
    int rc;
    bool first = true;

    if (format == FORMAT_TABLE) {
        printf("%-4s %-20s %-15s %-15s %-6s %-6s %-8s %s\n",
               "ID", "TIMESTAMP", "SRC_IP", "DST_IP", "TYPE", "LEVEL", "PROTOCOL", "DETAILS");
    } else {
        printf("[\n");
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *timestamp = sqlite3_column_text(stmt, 1);
        const unsigned char *src_ip = sqlite3_column_text(stmt, 2);
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 3);
        int event_type = sqlite3_column_int(stmt, 4);
        int threat_level = sqlite3_column_int(stmt, 5);
        const unsigned char *protocol = sqlite3_column_text(stmt, 6);
        const unsigned char *details = sqlite3_column_text(stmt, 7);

        if (format == FORMAT_TABLE) {
            printf("%-4d %-20.20s %-15.15s %-15.15s %-6.6s %-6d %-8.8s %.90s\n",
                   id, nz(timestamp), nz(src_ip), nz(dst_ip), event_name(event_type),
                   threat_level, nz(protocol), nz(details));
        } else {
            json_sep(&first);
            printf("  {\"id\":%d,", id);
            printf("\"timestamp\":"); json_escape(timestamp); printf(",");
            printf("\"src_ip\":"); json_escape(src_ip); printf(",");
            printf("\"dst_ip\":"); json_escape(dst_ip); printf(",");
            printf("\"event_type\":%d,", event_type);
            printf("\"event_name\":"); json_escape((const unsigned char *)event_name(event_type)); printf(",");
            printf("\"threat_level\":%d,", threat_level);
            printf("\"protocol\":"); json_escape(protocol); printf(",");
            printf("\"details\":"); json_escape(details);
            printf("}");
        }
    }

    if (format == FORMAT_JSON)
        printf("\n]\n");

    return rc == SQLITE_DONE ? 0 : -1;
}

static int render_sniffer(sqlite3_stmt *stmt, output_format_t format)
{
    int rc;
    bool first = true;

    if (format == FORMAT_TABLE) {
        printf("%-4s %-17s %-15s %-7s %-20s %-20s %-6s %-15s\n",
               "ID", "MAC", "IP", "IFIDX", "FIRST_SEEN", "LAST_SEEN", "RESP", "PROBE_IP");
    } else {
        printf("[\n");
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *mac = sqlite3_column_text(stmt, 1);
        const unsigned char *ip = sqlite3_column_text(stmt, 2);
        int ifindex = sqlite3_column_int(stmt, 3);
        const unsigned char *first_seen = sqlite3_column_text(stmt, 4);
        const unsigned char *last_seen = sqlite3_column_text(stmt, 5);
        int response_count = sqlite3_column_int(stmt, 6);
        const unsigned char *probe_ip = sqlite3_column_text(stmt, 7);

        if (format == FORMAT_TABLE) {
            printf("%-4d %-17.17s %-15.15s %-7d %-20.20s %-20.20s %-6d %-15.15s\n",
                   id, nz(mac), nz(ip), ifindex,
                   nz(first_seen), nz(last_seen), response_count, nz(probe_ip));
        } else {
            json_sep(&first);
            printf("  {\"id\":%d,", id);
            printf("\"mac\":"); json_escape(mac); printf(",");
            printf("\"ip\":"); json_escape(ip); printf(",");
            printf("\"ifindex\":%d,", ifindex);
            printf("\"first_seen\":"); json_escape(first_seen); printf(",");
            printf("\"last_seen\":"); json_escape(last_seen); printf(",");
            printf("\"response_count\":%d,", response_count);
            printf("\"probe_ip\":"); json_escape(probe_ip);
            printf("}");
        }
    }

    if (format == FORMAT_JSON)
        printf("\n]\n");

    return rc == SQLITE_DONE ? 0 : -1;
}

static int render_background(sqlite3_stmt *stmt, output_format_t format)
{
    int rc;
    bool first = true;

    if (format == FORMAT_TABLE) {
        printf("%-4s %-20s %-20s %-8s %-8s %-8s %-8s %s\n",
               "ID", "PERIOD_START", "PERIOD_END", "PROTO", "PACKETS", "BYTES", "UNIQUE", "SAMPLE");
    } else {
        printf("[\n");
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *period_start = sqlite3_column_text(stmt, 1);
        const unsigned char *period_end = sqlite3_column_text(stmt, 2);
        const unsigned char *protocol = sqlite3_column_text(stmt, 3);
        int packet_count = sqlite3_column_int(stmt, 4);
        int byte_count = sqlite3_column_int(stmt, 5);
        int unique_sources = sqlite3_column_int(stmt, 6);
        const unsigned char *sample_data = sqlite3_column_text(stmt, 7);

        if (format == FORMAT_TABLE) {
            printf("%-4d %-20.20s %-20.20s %-8.8s %-8d %-8d %-8d %.90s\n",
                   id, nz(period_start), nz(period_end), nz(protocol),
                   packet_count, byte_count, unique_sources, nz(sample_data));
        } else {
            json_sep(&first);
            printf("  {\"id\":%d,", id);
            printf("\"period_start\":"); json_escape(period_start); printf(",");
            printf("\"period_end\":"); json_escape(period_end); printf(",");
            printf("\"protocol\":"); json_escape(protocol); printf(",");
            printf("\"packet_count\":%d,", packet_count);
            printf("\"byte_count\":%d,", byte_count);
            printf("\"unique_sources\":%d,", unique_sources);
            printf("\"sample_data\":"); json_escape(sample_data);
            printf("}");
        }
    }

    if (format == FORMAT_JSON)
        printf("\n]\n");

    return rc == SQLITE_DONE ? 0 : -1;
}

static int render_audit(sqlite3_stmt *stmt, output_format_t format)
{
    int rc;
    bool first = true;

    if (format == FORMAT_TABLE) {
        printf("%-4s %-20s %-16s %-16s %-16s %-10s %s\n",
               "ID", "TIMESTAMP", "ACTION", "ACTOR", "TARGET", "RESULT", "DETAILS");
    } else {
        printf("[\n");
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *timestamp = sqlite3_column_text(stmt, 1);
        const unsigned char *action = sqlite3_column_text(stmt, 2);
        const unsigned char *actor = sqlite3_column_text(stmt, 3);
        const unsigned char *target = sqlite3_column_text(stmt, 4);
        const unsigned char *details = sqlite3_column_text(stmt, 5);
        const unsigned char *result = sqlite3_column_text(stmt, 6);

        if (format == FORMAT_TABLE) {
            printf("%-4d %-20.20s %-16.16s %-16.16s %-16.16s %-10.10s %.90s\n",
                   id, nz(timestamp), nz(action), nz(actor), nz(target), nz(result), nz(details));
        } else {
            json_sep(&first);
            printf("  {\"id\":%d,", id);
            printf("\"timestamp\":"); json_escape(timestamp); printf(",");
            printf("\"action\":"); json_escape(action); printf(",");
            printf("\"actor\":"); json_escape(actor); printf(",");
            printf("\"target\":"); json_escape(target); printf(",");
            printf("\"details\":"); json_escape(details); printf(",");
            printf("\"result\":"); json_escape(result);
            printf("}");
        }
    }

    if (format == FORMAT_JSON)
        printf("\n]\n");

    return rc == SQLITE_DONE ? 0 : -1;
}

static int prep_attack(sqlite3 *db, const cli_opts_t *opts, sqlite3_stmt **stmt)
{
    const char *sql;
    int idx = 1;

    if (opts->since && opts->limit > 0)
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log WHERE timestamp >= ? ORDER BY id DESC LIMIT ?";
    else if (opts->since)
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log WHERE timestamp >= ? ORDER BY id DESC";
    else if (opts->limit > 0)
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log ORDER BY id DESC LIMIT ?";
    else
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log ORDER BY id DESC";

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        return -1;
    if (opts->since)
        sqlite3_bind_text(*stmt, idx++, opts->since, -1, SQLITE_STATIC);
    if (opts->limit > 0)
        sqlite3_bind_int(*stmt, idx++, opts->limit);
    return 0;
}

static int prep_sniffer(sqlite3 *db, const cli_opts_t *opts, sqlite3_stmt **stmt)
{
    const char *sql;

    if (opts->limit > 0)
        sql = "SELECT id,mac,ip,ifindex,first_seen,last_seen,response_count,probe_ip FROM sniffer_log ORDER BY id DESC LIMIT ?";
    else
        sql = "SELECT id,mac,ip,ifindex,first_seen,last_seen,response_count,probe_ip FROM sniffer_log ORDER BY id DESC";

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        return -1;
    if (opts->limit > 0)
        sqlite3_bind_int(*stmt, 1, opts->limit);
    return 0;
}

static int prep_background(sqlite3 *db, const cli_opts_t *opts, sqlite3_stmt **stmt)
{
    const char *sql;
    int idx = 1;

    if (opts->proto && opts->limit > 0)
        sql = "SELECT id,period_start,period_end,protocol,packet_count,byte_count,unique_sources,sample_data FROM bg_capture WHERE lower(protocol)=lower(?) ORDER BY id DESC LIMIT ?";
    else if (opts->proto)
        sql = "SELECT id,period_start,period_end,protocol,packet_count,byte_count,unique_sources,sample_data FROM bg_capture WHERE lower(protocol)=lower(?) ORDER BY id DESC";
    else if (opts->limit > 0)
        sql = "SELECT id,period_start,period_end,protocol,packet_count,byte_count,unique_sources,sample_data FROM bg_capture ORDER BY id DESC LIMIT ?";
    else
        sql = "SELECT id,period_start,period_end,protocol,packet_count,byte_count,unique_sources,sample_data FROM bg_capture ORDER BY id DESC";

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        return -1;
    if (opts->proto)
        sqlite3_bind_text(*stmt, idx++, opts->proto, -1, SQLITE_STATIC);
    if (opts->limit > 0)
        sqlite3_bind_int(*stmt, idx++, opts->limit);
    return 0;
}

static int prep_audit(sqlite3 *db, const cli_opts_t *opts, sqlite3_stmt **stmt)
{
    const char *sql;
    int idx = 1;

    if (opts->since && opts->limit > 0)
        sql = "SELECT id,timestamp,action,actor,target,details,result FROM audit_log WHERE timestamp >= ? ORDER BY id DESC LIMIT ?";
    else if (opts->since)
        sql = "SELECT id,timestamp,action,actor,target,details,result FROM audit_log WHERE timestamp >= ? ORDER BY id DESC";
    else if (opts->limit > 0)
        sql = "SELECT id,timestamp,action,actor,target,details,result FROM audit_log ORDER BY id DESC LIMIT ?";
    else
        sql = "SELECT id,timestamp,action,actor,target,details,result FROM audit_log ORDER BY id DESC";

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        return -1;
    if (opts->since)
        sqlite3_bind_text(*stmt, idx++, opts->since, -1, SQLITE_STATIC);
    if (opts->limit > 0)
        sqlite3_bind_int(*stmt, idx++, opts->limit);
    return 0;
}

static int prep_threat(sqlite3 *db, const cli_opts_t *opts, sqlite3_stmt **stmt)
{
    const char *sql;
    int idx = 1;

    if (opts->limit > 0)
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log WHERE threat_level >= ? ORDER BY id DESC LIMIT ?";
    else
        sql = "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details FROM attack_log WHERE threat_level >= ? ORDER BY id DESC";

    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(*stmt, idx++, opts->threat_min);
    if (opts->limit > 0)
        sqlite3_bind_int(*stmt, idx++, opts->limit);
    return 0;
}

static int run_query(sqlite3 *db,
                     int (*prep)(sqlite3 *, const cli_opts_t *, sqlite3_stmt **),
                     int (*render)(sqlite3_stmt *, output_format_t),
                     const cli_opts_t *opts)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (prep(db, opts, &stmt) < 0) {
        fprintf(stderr, "jzlog: prepare failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = render(stmt, opts->format);
    sqlite3_finalize(stmt);

    if (rc < 0)
        fprintf(stderr, "jzlog: query failed\n");
    return rc;
}

static void stop_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        g_running = 0;
}

static int install_tail_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;
    return 0;
}

static int tail_start_id(sqlite3 *db, int *id)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(id),0) FROM attack_log", -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        *id = sqlite3_column_int(stmt, 0);
    else
        *id = 0;

    sqlite3_finalize(stmt);
    return 0;
}

static int run_tail_once(sqlite3 *db, const cli_opts_t *opts)
{
    return run_query(db, prep_attack, render_attack, opts);
}

static int run_tail_follow(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int last_id = 0;

    if (install_tail_signals() < 0)
        return -1;

    if (tail_start_id(db, &last_id) < 0)
        return -1;

    printf("%-4s %-20s %-15s %-15s %-6s %-6s %-8s %s\n",
           "ID", "TIMESTAMP", "SRC_IP", "DST_IP", "TYPE", "LEVEL", "PROTOCOL", "DETAILS");

    while (g_running) {
        rc = sqlite3_prepare_v2(db,
                                "SELECT id,timestamp,src_ip,dst_ip,event_type,threat_level,protocol,details "
                                "FROM attack_log WHERE id > ? ORDER BY id ASC",
                                -1, &stmt, NULL);
        if (rc != SQLITE_OK)
            return -1;

        sqlite3_bind_int(stmt, 1, last_id);

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char *timestamp = sqlite3_column_text(stmt, 1);
            const unsigned char *src_ip = sqlite3_column_text(stmt, 2);
            const unsigned char *dst_ip = sqlite3_column_text(stmt, 3);
            int event_type = sqlite3_column_int(stmt, 4);
            int threat_level = sqlite3_column_int(stmt, 5);
            const unsigned char *protocol = sqlite3_column_text(stmt, 6);
            const unsigned char *details = sqlite3_column_text(stmt, 7);

            printf("%-4d %-20.20s %-15.15s %-15.15s %-6.6s %-6d %-8.8s %.90s\n",
                   id, nz(timestamp), nz(src_ip), nz(dst_ip),
                   event_name(event_type), threat_level, nz(protocol), nz(details));

            if (id > last_id)
                last_id = id;
        }

        sqlite3_finalize(stmt);
        stmt = NULL;

        if (rc != SQLITE_DONE)
            return -1;

        sleep(1);
    }

    return 0;
}

static int run_command(cmd_t cmd, const cli_opts_t *opts)
{
    jz_db_t db_ctx;
    int rc;

    if (db_open_readonly(&db_ctx, opts->db_path) < 0)
        return -1;

    switch (cmd) {
    case CMD_ATTACK:
        rc = run_query(db_ctx.db, prep_attack, render_attack, opts);
        break;
    case CMD_SNIFFER:
        rc = run_query(db_ctx.db, prep_sniffer, render_sniffer, opts);
        break;
    case CMD_BACKGROUND:
        rc = run_query(db_ctx.db, prep_background, render_background, opts);
        break;
    case CMD_AUDIT:
        rc = run_query(db_ctx.db, prep_audit, render_audit, opts);
        break;
    case CMD_THREAT:
        rc = run_query(db_ctx.db, prep_threat, render_attack, opts);
        break;
    case CMD_TAIL:
        if (opts->follow)
            rc = run_tail_follow(db_ctx.db);
        else
            rc = run_tail_once(db_ctx.db, opts);
        break;
    default:
        rc = -1;
        break;
    }

    jz_db_close(&db_ctx);
    return rc;
}

int main(int argc, char **argv)
{
    int cmd_idx;
    int sub_argc;
    char **sub_argv;
    cli_opts_t opts;
    cmd_t cmd;

    opts_init(&opts);

    if (argc < 2) {
        usage(argv[0]);
        return EX_USAGE;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return EX_OK;
    }

    if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("jzlog version %s\n", JZLOG_VERSION);
        return EX_OK;
    }

    cmd_idx = find_command_index(argc, argv);
    if (cmd_idx < 0) {
        fprintf(stderr, "jzlog: missing command\n");
        usage(argv[0]);
        return EX_USAGE;
    }

    if (parse_global_opts(argc, argv, cmd_idx, &opts) < 0) {
        fprintf(stderr, "jzlog: invalid global options\n");
        usage(argv[0]);
        return EX_USAGE;
    }

    cmd = parse_command_name(argv[cmd_idx]);

    sub_argc = argc - cmd_idx + 1;
    sub_argv = &argv[cmd_idx - 1];
    if (parse_subcommand_opts(cmd, sub_argc, sub_argv, &opts) < 0) {
        fprintf(stderr, "jzlog: invalid command options\n");
        usage(argv[0]);
        return EX_USAGE;
    }

    if (run_command(cmd, &opts) < 0)
        return EX_ERR;

    return EX_OK;
}
