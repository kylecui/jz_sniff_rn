/* SPDX-License-Identifier: MIT */
/*
 * log.c - Logging implementation for jz_sniff_rn daemons.
 *
 * Dual output: syslog (LOG_DAEMON facility) + optional stderr.
 * Thread-safe via syslog (which is thread-safe) and flockfile on stderr.
 */

#define _GNU_SOURCE

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>

/* ── Global State ─────────────────────────────────────────────── */

static struct {
    jz_log_level_t level;
    bool           use_stderr;
    bool           initialized;
    char           ident[64];
} g_log = {
    .level      = JZ_LOG_INFO,
    .use_stderr = true,
    .initialized = false,
};

/* Map jz levels to syslog priorities */
static const int syslog_prio[] = {
    [JZ_LOG_DEBUG] = LOG_DEBUG,
    [JZ_LOG_INFO]  = LOG_INFO,
    [JZ_LOG_WARN]  = LOG_WARNING,
    [JZ_LOG_ERROR] = LOG_ERR,
    [JZ_LOG_FATAL] = LOG_CRIT,
};

static const char *level_names[] = {
    [JZ_LOG_DEBUG] = "DEBUG",
    [JZ_LOG_INFO]  = "INFO",
    [JZ_LOG_WARN]  = "WARN",
    [JZ_LOG_ERROR] = "ERROR",
    [JZ_LOG_FATAL] = "FATAL",
    [JZ_LOG_NONE]  = "NONE",
};

static const char *level_colors[] = {
    [JZ_LOG_DEBUG] = "\033[36m",   /* cyan */
    [JZ_LOG_INFO]  = "\033[32m",   /* green */
    [JZ_LOG_WARN]  = "\033[33m",   /* yellow */
    [JZ_LOG_ERROR] = "\033[31m",   /* red */
    [JZ_LOG_FATAL] = "\033[35m",   /* magenta */
};

#define COLOR_RESET "\033[0m"

/* ── Public API ───────────────────────────────────────────────── */

void jz_log_init(const char *ident, jz_log_level_t level, bool use_stderr)
{
    if (g_log.initialized)
        closelog();

    snprintf(g_log.ident, sizeof(g_log.ident), "%s", ident ? ident : "jz");
    g_log.level = level;
    g_log.use_stderr = use_stderr;
    g_log.initialized = true;

    openlog(g_log.ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void jz_log_set_level(jz_log_level_t level)
{
    g_log.level = level;
}

jz_log_level_t jz_log_get_level(void)
{
    return g_log.level;
}

void jz_log_set_stderr(bool enable)
{
    g_log.use_stderr = enable;
}

jz_log_level_t jz_log_level_from_str(const char *str)
{
    if (!str)
        return JZ_LOG_INFO;

    if (strcasecmp(str, "debug") == 0) return JZ_LOG_DEBUG;
    if (strcasecmp(str, "info") == 0)  return JZ_LOG_INFO;
    if (strcasecmp(str, "warn") == 0)  return JZ_LOG_WARN;
    if (strcasecmp(str, "warning") == 0) return JZ_LOG_WARN;
    if (strcasecmp(str, "error") == 0) return JZ_LOG_ERROR;
    if (strcasecmp(str, "fatal") == 0) return JZ_LOG_FATAL;
    if (strcasecmp(str, "none") == 0)  return JZ_LOG_NONE;

    return JZ_LOG_INFO;
}

const char *jz_log_level_str(jz_log_level_t level)
{
    if (level >= JZ_LOG_DEBUG && level <= JZ_LOG_NONE)
        return level_names[level];
    return "UNKNOWN";
}

void jz_log_write(jz_log_level_t level, const char *file, int line,
                  const char *fmt, ...)
{
    if (level < g_log.level)
        return;
    if (level > JZ_LOG_FATAL)
        return;

    va_list ap;

    /* Write to syslog */
    if (g_log.initialized) {
        va_start(ap, fmt);
        vsyslog(syslog_prio[level], fmt, ap);
        va_end(ap);
    }

    /* Write to stderr */
    if (g_log.use_stderr) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm;
        localtime_r(&ts.tv_sec, &tm);

        /* Strip path from filename */
        const char *basename = strrchr(file, '/');
        basename = basename ? basename + 1 : file;

        flockfile(stderr);

        fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03ld %s%-5s%s %s:%d: ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                ts.tv_nsec / 1000000,
                level_colors[level], level_names[level], COLOR_RESET,
                basename, line);

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);

        fputc('\n', stderr);
        fflush(stderr);

        funlockfile(stderr);
    }
}

void jz_log_close(void)
{
    if (g_log.initialized) {
        closelog();
        g_log.initialized = false;
    }
}
