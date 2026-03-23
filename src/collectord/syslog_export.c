/* SPDX-License-Identifier: MIT */
/* syslog_export.c — rsyslog export wrapper. */

#include "syslog_export.h"
#include "../common/log.h"

#include <syslog.h>
#include <string.h>
#include <stdbool.h>

static bool g_open = false;

int jz_syslog_init(const char *facility)
{
    static const struct {
        const char *name;
        int facility;
    } facility_map[] = {
        { "local0", LOG_LOCAL0 },
        { "local1", LOG_LOCAL1 },
        { "local2", LOG_LOCAL2 },
        { "local3", LOG_LOCAL3 },
        { "local4", LOG_LOCAL4 },
        { "local5", LOG_LOCAL5 },
        { "local6", LOG_LOCAL6 },
        { "local7", LOG_LOCAL7 },
    };

    const char *facility_name = facility ? facility : "local0";
    int facility_val = -1;

    for (size_t i = 0; i < sizeof(facility_map) / sizeof(facility_map[0]); i++) {
        if (strcmp(facility_name, facility_map[i].name) == 0) {
            facility_val = facility_map[i].facility;
            break;
        }
    }

    if (facility_val < 0) {
        jz_log_error("syslog_export: invalid facility=%s", facility_name);
        return -1;
    }

    if (g_open)
        closelog();

    openlog("jz_sniff", LOG_NDELAY | LOG_PID, facility_val);
    g_open = true;

    jz_log_info("syslog_export: opened facility=%s", facility_name);
    return 0;
}

int jz_syslog_send(const char *msg)
{
    if (!g_open)
        return -1;

    syslog(LOG_INFO, "%s", msg);
    return 0;
}

void jz_syslog_close(void)
{
    if (g_open) {
        closelog();
        g_open = false;
    }
}

bool jz_syslog_is_open(void)
{
    return g_open;
}
