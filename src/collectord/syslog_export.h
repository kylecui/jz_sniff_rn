/* SPDX-License-Identifier: MIT */
/* syslog_export.h — rsyslog export for collectord. */

#ifndef JZ_SYSLOG_EXPORT_H
#define JZ_SYSLOG_EXPORT_H

#include <stdbool.h>

/* Initialize syslog connection.
 * facility: "local0" through "local7" (default "local0").
 * Returns 0 on success, -1 on invalid facility. */
int jz_syslog_init(const char *facility);

/* Send a pre-formatted log string via syslog(LOG_INFO, ...).
 * msg must be a complete formatted string (V1 KV or any text).
 * Returns 0 on success. */
int jz_syslog_send(const char *msg);

/* Close syslog connection. */
void jz_syslog_close(void);

/* Check if syslog export is initialized. */
bool jz_syslog_is_open(void);

#endif /* JZ_SYSLOG_EXPORT_H */
