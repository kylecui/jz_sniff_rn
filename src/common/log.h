/* SPDX-License-Identifier: MIT */
/*
 * log.h - Logging framework for jz_sniff_rn daemons.
 *
 * Provides dual-output logging to syslog and stderr with configurable
 * severity levels. Each daemon opens its own syslog identity via jz_log_init().
 *
 * Usage:
 *   jz_log_init("sniffd", JZ_LOG_INFO, true);  // syslog + stderr
 *   jz_log_info("Started on interface %s", ifname);
 *   jz_log_close();
 */

#ifndef JZ_LOG_H
#define JZ_LOG_H

#include <stdbool.h>

/* ── Log Levels ── */
typedef enum {
    JZ_LOG_DEBUG   = 0,
    JZ_LOG_INFO    = 1,
    JZ_LOG_WARN    = 2,
    JZ_LOG_ERROR   = 3,
    JZ_LOG_FATAL   = 4,
    JZ_LOG_NONE    = 5   /* Suppress all output */
} jz_log_level_t;

/* Initialize logging subsystem.
 * ident:      syslog identity (e.g. "sniffd", "configd")
 * level:      minimum level to output
 * use_stderr: also write to stderr (useful before daemonizing)
 */
void jz_log_init(const char *ident, jz_log_level_t level, bool use_stderr);

/* Change runtime log level. */
void jz_log_set_level(jz_log_level_t level);

/* Get current log level. */
jz_log_level_t jz_log_get_level(void);

/* Enable/disable stderr output (e.g. disable after daemonizing). */
void jz_log_set_stderr(bool enable);

/* Parse log level from string ("debug", "info", "warn", "error", "fatal").
 * Returns JZ_LOG_INFO on unrecognized input. */
jz_log_level_t jz_log_level_from_str(const char *str);

/* Convert log level to string. */
const char *jz_log_level_str(jz_log_level_t level);

/* Core logging function (use macros below instead). */
void jz_log_write(jz_log_level_t level, const char *file, int line,
                  const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* Close logging (closes syslog). */
void jz_log_close(void);

/* ── Convenience Macros ── */
#define jz_log_debug(fmt, ...) \
    jz_log_write(JZ_LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define jz_log_info(fmt, ...) \
    jz_log_write(JZ_LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define jz_log_warn(fmt, ...) \
    jz_log_write(JZ_LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define jz_log_error(fmt, ...) \
    jz_log_write(JZ_LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define jz_log_fatal(fmt, ...) \
    jz_log_write(JZ_LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* JZ_LOG_H */
