/* SPDX-License-Identifier: MIT */
/*
 * config.c - Event-based YAML parser, merge, validation and serialization.
 *
 * This implementation uses libyaml's event API (yaml_parser_parse loop) to
 * parse jz_sniff_rn configuration files into fixed-size C structs.
 */

#include "config.h"

#include <yaml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <ctype.h>

typedef struct jz_strbuf {
    char   *data;
    size_t  len;
    size_t  cap;
} jz_strbuf_t;

static void add_error(jz_config_errors_t *e, int line, const char *field, const char *fmt, ...)
{
    va_list ap;
    jz_config_error_t *dst;

    if (!e)
        return;

    if (e->count >= JZ_CONFIG_MAX_ERRORS)
        return;

    dst = &e->errors[e->count++];
    memset(dst, 0, sizeof(*dst));
    dst->line = line;

    if (field)
        snprintf(dst->field, sizeof(dst->field), "%s", field);

    va_start(ap, fmt);
    vsnprintf(dst->message, sizeof(dst->message), fmt, ap);
    va_end(ap);
}

static int next_event(yaml_parser_t *parser, yaml_event_t *ev,
                      jz_config_errors_t *errors, const char *field)
{
    if (!yaml_parser_parse(parser, ev)) {
        int line = (int)parser->problem_mark.line + 1;
        add_error(errors, line, field ? field : "yaml", "%s",
                  parser->problem ? parser->problem : "yaml parse error");
        return -1;
    }

    return 0;
}

static int scalar_to_int(const yaml_event_t *ev, int *out)
{
    char *end = NULL;
    long v;

    if (ev->type != YAML_SCALAR_EVENT)
        return -1;

    v = strtol((const char *)ev->data.scalar.value, &end, 10);
    if (!end || *end != '\0')
        return -1;

    *out = (int)v;
    return 0;
}

static bool str_eq_ci(const char *a, const char *b)
{
    size_t i;

    if (!a || !b)
        return false;

    for (i = 0; a[i] && b[i]; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    }

    return a[i] == '\0' && b[i] == '\0';
}

static int scalar_to_bool(const yaml_event_t *ev, bool *out)
{
    const char *s;

    if (ev->type != YAML_SCALAR_EVENT)
        return -1;

    s = (const char *)ev->data.scalar.value;
    if (str_eq_ci(s, "true") || !strcmp(s, "1") || str_eq_ci(s, "yes")) {
        *out = true;
        return 0;
    }
    if (str_eq_ci(s, "false") || !strcmp(s, "0") || str_eq_ci(s, "no")) {
        *out = false;
        return 0;
    }

    return -1;
}

static void copy_scalar(char *dst, size_t dst_sz, const yaml_event_t *ev)
{
    if (!dst || dst_sz == 0)
        return;

    if (!ev || ev->type != YAML_SCALAR_EVENT) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_sz, "%s", (const char *)ev->data.scalar.value);
}

static int event_line(const yaml_event_t *ev)
{
    return (int)ev->start_mark.line + 1;
}

static int skip_node(yaml_parser_t *parser, yaml_event_t *start,
                     jz_config_errors_t *errors)
{
    int depth = 0;

    if (start->type == YAML_MAPPING_START_EVENT || start->type == YAML_SEQUENCE_START_EVENT)
        depth = 1;

    yaml_event_delete(start);

    while (depth > 0) {
        yaml_event_t ev;

        if (next_event(parser, &ev, errors, "yaml") != 0)
            return -1;

        if (ev.type == YAML_MAPPING_START_EVENT || ev.type == YAML_SEQUENCE_START_EVENT)
            depth++;
        else if (ev.type == YAML_MAPPING_END_EVENT || ev.type == YAML_SEQUENCE_END_EVENT)
            depth--;

        yaml_event_delete(&ev);
    }

    return 0;
}

static int parse_module_common_map(yaml_parser_t *parser, yaml_event_t *start,
                                   jz_config_module_t *module,
                                   jz_config_errors_t *errors,
                                   const char *field)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), field, "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;

        if (next_event(parser, &key_ev, errors, field) != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), field, "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, field) != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "enabled")) {
            if (scalar_to_bool(&val_ev, &module->enabled) != 0)
                add_error(errors, event_line(&val_ev), field, "enabled must be bool");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "stage")) {
            if (scalar_to_int(&val_ev, &module->stage) != 0)
                add_error(errors, event_line(&val_ev), field, "stage must be int");
            yaml_event_delete(&val_ev);
        } else {
            add_error(errors, event_line(&key_ev), field, "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }

        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_interfaces(yaml_parser_t *parser, yaml_event_t *start,
                            jz_config_t *cfg, jz_config_errors_t *errors)
{
    if (start->type != YAML_SEQUENCE_START_EVENT) {
        add_error(errors, event_line(start), "system.interfaces", "expected sequence");
        return skip_node(parser, start, errors);
    }
    yaml_event_delete(start);
    cfg->system.interface_count = 0;
    for (;;) {
        yaml_event_t item_ev;
        if (next_event(parser, &item_ev, errors, "system.interfaces") != 0)
            return -1;
        if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
            yaml_event_delete(&item_ev);
            break;
        }
        if (item_ev.type != YAML_MAPPING_START_EVENT) {
            add_error(errors, event_line(&item_ev), "system.interfaces", "entries must be mappings");
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        if (cfg->system.interface_count >= JZ_CONFIG_MAX_INTERFACES) {
            add_error(errors, event_line(&item_ev), "system.interfaces", "too many entries (max %d)",
                      JZ_CONFIG_MAX_INTERFACES);
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        yaml_event_delete(&item_ev);
        for (;;) {
            yaml_event_t k2, v2;
            const char *k;
            jz_config_interface_t *iface = &cfg->system.interfaces[cfg->system.interface_count];
            if (next_event(parser, &k2, errors, "system.interfaces") != 0)
                return -1;
            if (k2.type == YAML_MAPPING_END_EVENT) {
                yaml_event_delete(&k2);
                cfg->system.interface_count++;
                break;
            }
            if (k2.type != YAML_SCALAR_EVENT) {
                add_error(errors, event_line(&k2), "system.interfaces", "expected scalar key");
                yaml_event_delete(&k2);
                return -1;
            }
            k = (const char *)k2.data.scalar.value;
            if (next_event(parser, &v2, errors, "system.interfaces") != 0) {
                yaml_event_delete(&k2);
                return -1;
            }
            if (!strcmp(k, "name")) {
                copy_scalar(iface->name, sizeof(iface->name), &v2);
                yaml_event_delete(&v2);
            } else if (!strcmp(k, "role")) {
                copy_scalar(iface->role, sizeof(iface->role), &v2);
                yaml_event_delete(&v2);
            } else if (!strcmp(k, "subnet")) {
                copy_scalar(iface->subnet, sizeof(iface->subnet), &v2);
                yaml_event_delete(&v2);
            } else {
                add_error(errors, event_line(&k2), "system.interfaces", "unknown key '%s'", k);
                if (skip_node(parser, &v2, errors) != 0) {
                    yaml_event_delete(&k2);
                    return -1;
                }
            }
            yaml_event_delete(&k2);
        }
    }
    return 0;
}

static int parse_frozen_ips(yaml_parser_t *parser, yaml_event_t *start,
                            jz_config_t *cfg, jz_config_errors_t *errors)
{
    if (start->type != YAML_SEQUENCE_START_EVENT) {
        add_error(errors, event_line(start), "guards.frozen_ips", "expected sequence");
        return skip_node(parser, start, errors);
    }
    yaml_event_delete(start);
    cfg->guards.frozen_ip_count = 0;
    for (;;) {
        yaml_event_t item_ev;
        if (next_event(parser, &item_ev, errors, "guards.frozen_ips") != 0)
            return -1;
        if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
            yaml_event_delete(&item_ev);
            break;
        }
        if (item_ev.type != YAML_MAPPING_START_EVENT) {
            add_error(errors, event_line(&item_ev), "guards.frozen_ips", "entries must be mappings");
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        if (cfg->guards.frozen_ip_count >= JZ_CONFIG_MAX_FROZEN_IPS) {
            add_error(errors, event_line(&item_ev), "guards.frozen_ips", "too many entries (max %d)",
                      JZ_CONFIG_MAX_FROZEN_IPS);
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        yaml_event_delete(&item_ev);
        for (;;) {
            yaml_event_t k2, v2;
            const char *k;
            jz_config_frozen_ip_t *f = &cfg->guards.frozen_ips[cfg->guards.frozen_ip_count];
            if (next_event(parser, &k2, errors, "guards.frozen_ips") != 0)
                return -1;
            if (k2.type == YAML_MAPPING_END_EVENT) {
                yaml_event_delete(&k2);
                cfg->guards.frozen_ip_count++;
                break;
            }
            if (k2.type != YAML_SCALAR_EVENT) {
                add_error(errors, event_line(&k2), "guards.frozen_ips", "expected scalar key");
                yaml_event_delete(&k2);
                return -1;
            }
            k = (const char *)k2.data.scalar.value;
            if (next_event(parser, &v2, errors, "guards.frozen_ips") != 0) {
                yaml_event_delete(&k2);
                return -1;
            }
            if (!strcmp(k, "ip")) {
                copy_scalar(f->ip, sizeof(f->ip), &v2);
                yaml_event_delete(&v2);
            } else if (!strcmp(k, "reason")) {
                copy_scalar(f->reason, sizeof(f->reason), &v2);
                yaml_event_delete(&v2);
            } else {
                add_error(errors, event_line(&k2), "guards.frozen_ips", "unknown key '%s'", k);
                if (skip_node(parser, &v2, errors) != 0) {
                    yaml_event_delete(&k2);
                    return -1;
                }
            }
            yaml_event_delete(&k2);
        }
    }
    return 0;
}

static int parse_system(yaml_parser_t *parser, yaml_event_t *start,
                        jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "system", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;

        if (next_event(parser, &key_ev, errors, "system") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "system", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "system") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "device_id")) {
            if (val_ev.type != YAML_SCALAR_EVENT)
                add_error(errors, event_line(&val_ev), "system.device_id", "must be string");
            else
                copy_scalar(cfg->system.device_id, sizeof(cfg->system.device_id), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "log_level")) {
            if (val_ev.type != YAML_SCALAR_EVENT)
                add_error(errors, event_line(&val_ev), "system.log_level", "must be string");
            else
                copy_scalar(cfg->system.log_level, sizeof(cfg->system.log_level), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "data_dir")) {
            if (val_ev.type != YAML_SCALAR_EVENT)
                add_error(errors, event_line(&val_ev), "system.data_dir", "must be string");
            else
                copy_scalar(cfg->system.data_dir, sizeof(cfg->system.data_dir), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "run_dir")) {
            if (val_ev.type != YAML_SCALAR_EVENT)
                add_error(errors, event_line(&val_ev), "system.run_dir", "must be string");
            else
                copy_scalar(cfg->system.run_dir, sizeof(cfg->system.run_dir), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "mode")) {
            if (val_ev.type != YAML_SCALAR_EVENT)
                add_error(errors, event_line(&val_ev), "system.mode", "must be string");
            else
                copy_scalar(cfg->system.mode, sizeof(cfg->system.mode), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "interfaces")) {
            if (parse_interfaces(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else {
            add_error(errors, event_line(&key_ev), "system", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }

        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_bg_protocols(yaml_parser_t *parser, yaml_event_t *start,
                              jz_config_bg_protocols_t *p, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "modules.bg_collector.protocols", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        bool v;

        if (next_event(parser, &key_ev, errors, "modules.bg_collector.protocols") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "modules.bg_collector.protocols", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "modules.bg_collector.protocols") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (scalar_to_bool(&val_ev, &v) != 0) {
            add_error(errors, event_line(&val_ev), "modules.bg_collector.protocols", "'%s' must be bool", key);
            yaml_event_delete(&val_ev);
            yaml_event_delete(&key_ev);
            continue;
        }

        if (!strcmp(key, "arp"))
            p->arp = v;
        else if (!strcmp(key, "dhcp"))
            p->dhcp = v;
        else if (!strcmp(key, "mdns"))
            p->mdns = v;
        else if (!strcmp(key, "ssdp"))
            p->ssdp = v;
        else if (!strcmp(key, "lldp"))
            p->lldp = v;
        else if (!strcmp(key, "cdp"))
            p->cdp = v;
        else if (!strcmp(key, "stp"))
            p->stp = v;
        else if (!strcmp(key, "igmp"))
            p->igmp = v;
        else
            add_error(errors, event_line(&key_ev), "modules.bg_collector.protocols", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_modules(yaml_parser_t *parser, yaml_event_t *start,
                         jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "modules", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;

        if (next_event(parser, &key_ev, errors, "modules") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "modules", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "modules") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "guard_classifier")) {
            if (parse_module_common_map(parser, &val_ev, &cfg->modules.guard_classifier, errors,
                                        "modules.guard_classifier") != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "arp_honeypot")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.arp_honeypot", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.arp_honeypot") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.arp_honeypot", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.arp_honeypot") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.arp_honeypot.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.arp_honeypot.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.arp_honeypot.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.arp_honeypot.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "rate_limit_pps")) {
                        if (scalar_to_int(&v2, &cfg->modules.arp_honeypot.rate_limit_pps) != 0)
                            add_error(errors, event_line(&v2), "modules.arp_honeypot.rate_limit_pps", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "log_all")) {
                        if (scalar_to_bool(&v2, &cfg->modules.arp_honeypot.log_all) != 0)
                            add_error(errors, event_line(&v2), "modules.arp_honeypot.log_all", "must be bool");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "modules.arp_honeypot", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "icmp_honeypot")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.icmp_honeypot", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.icmp_honeypot") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.icmp_honeypot", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.icmp_honeypot") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.icmp_honeypot.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.icmp_honeypot.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.icmp_honeypot.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.icmp_honeypot.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "ttl")) {
                        if (scalar_to_int(&v2, &cfg->modules.icmp_honeypot.ttl) != 0)
                            add_error(errors, event_line(&v2), "modules.icmp_honeypot.ttl", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "rate_limit_pps")) {
                        if (scalar_to_int(&v2, &cfg->modules.icmp_honeypot.rate_limit_pps) != 0)
                            add_error(errors, event_line(&v2), "modules.icmp_honeypot.rate_limit_pps", "must be int");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "modules.icmp_honeypot", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "sniffer_detect")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.sniffer_detect", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.sniffer_detect") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.sniffer_detect", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.sniffer_detect") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.sniffer_detect.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.sniffer_detect.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.sniffer_detect.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.sniffer_detect.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "probe_interval_sec")) {
                        if (scalar_to_int(&v2, &cfg->modules.sniffer_detect.probe_interval_sec) != 0)
                            add_error(errors, event_line(&v2), "modules.sniffer_detect.probe_interval_sec", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "probe_count")) {
                        if (scalar_to_int(&v2, &cfg->modules.sniffer_detect.probe_count) != 0)
                            add_error(errors, event_line(&v2), "modules.sniffer_detect.probe_count", "must be int");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "modules.sniffer_detect", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "traffic_weaver")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.traffic_weaver", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.traffic_weaver") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.traffic_weaver", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.traffic_weaver") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.traffic_weaver.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.traffic_weaver.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.traffic_weaver.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.traffic_weaver.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "default_action")) {
                        if (v2.type != YAML_SCALAR_EVENT)
                            add_error(errors, event_line(&v2), "modules.traffic_weaver.default_action", "must be string");
                        else
                            copy_scalar(cfg->modules.traffic_weaver.default_action,
                                        sizeof(cfg->modules.traffic_weaver.default_action), &v2);
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "modules.traffic_weaver", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "bg_collector")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.bg_collector", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.bg_collector") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.bg_collector", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.bg_collector") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.bg_collector.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.bg_collector.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.bg_collector.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.bg_collector.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "sample_rate")) {
                        if (scalar_to_int(&v2, &cfg->modules.bg_collector.sample_rate) != 0)
                            add_error(errors, event_line(&v2), "modules.bg_collector.sample_rate", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "protocols")) {
                        if (parse_bg_protocols(parser, &v2, &cfg->modules.bg_collector.protocols, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    } else {
                        add_error(errors, event_line(&k2), "modules.bg_collector", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "threat_detect")) {
            if (parse_module_common_map(parser, &val_ev, &cfg->modules.threat_detect, errors,
                                        "modules.threat_detect") != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "forensics")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "modules.forensics", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "modules.forensics") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "modules.forensics", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "modules.forensics") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }

                    if (!strcmp(k, "enabled")) {
                        if (scalar_to_bool(&v2, &cfg->modules.forensics.common.enabled) != 0)
                            add_error(errors, event_line(&v2), "modules.forensics.enabled", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "stage")) {
                        if (scalar_to_int(&v2, &cfg->modules.forensics.common.stage) != 0)
                            add_error(errors, event_line(&v2), "modules.forensics.stage", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "max_payload_bytes")) {
                        if (scalar_to_int(&v2, &cfg->modules.forensics.max_payload_bytes) != 0)
                            add_error(errors, event_line(&v2), "modules.forensics.max_payload_bytes", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "sample_rate")) {
                        if (scalar_to_int(&v2, &cfg->modules.forensics.sample_rate) != 0)
                            add_error(errors, event_line(&v2), "modules.forensics.sample_rate", "must be int");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "modules.forensics", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }

                    yaml_event_delete(&k2);
                }
            }
        } else {
            add_error(errors, event_line(&key_ev), "modules", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }

        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_guards(yaml_parser_t *parser, yaml_event_t *start,
                        jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "guards", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;

        if (next_event(parser, &key_ev, errors, "guards") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "guards", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "guards") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "static")) {
            if (val_ev.type != YAML_SEQUENCE_START_EVENT) {
                add_error(errors, event_line(&val_ev), "guards.static", "expected sequence");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                yaml_event_delete(&key_ev);
                continue;
            }
            yaml_event_delete(&val_ev);
            cfg->guards.static_count = 0;
            for (;;) {
                yaml_event_t item_ev;
                if (next_event(parser, &item_ev, errors, "guards.static") != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
                    yaml_event_delete(&item_ev);
                    break;
                }
                if (item_ev.type != YAML_MAPPING_START_EVENT) {
                    add_error(errors, event_line(&item_ev), "guards.static", "entries must be mappings");
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                if (cfg->guards.static_count >= JZ_CONFIG_MAX_STATIC_GUARDS) {
                    add_error(errors, event_line(&item_ev), "guards.static", "too many entries (max %d)",
                              JZ_CONFIG_MAX_STATIC_GUARDS);
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                yaml_event_delete(&item_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    jz_config_guard_static_t *g = &cfg->guards.static_entries[cfg->guards.static_count];
                    if (next_event(parser, &k2, errors, "guards.static") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        cfg->guards.static_count++;
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "guards.static", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "guards.static") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (!strcmp(k, "ip")) {
                        copy_scalar(g->ip, sizeof(g->ip), &v2);
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "mac")) {
                        copy_scalar(g->mac, sizeof(g->mac), &v2);
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "vlan")) {
                        if (scalar_to_int(&v2, &g->vlan) != 0)
                            add_error(errors, event_line(&v2), "guards.static[].vlan", "must be int");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "guards.static", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }
                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "dynamic")) {
            if (val_ev.type != YAML_MAPPING_START_EVENT) {
                add_error(errors, event_line(&val_ev), "guards.dynamic", "expected mapping");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    if (next_event(parser, &k2, errors, "guards.dynamic") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        break;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "guards.dynamic") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (!strcmp(k, "auto_discover")) {
                        if (scalar_to_bool(&v2, &cfg->guards.dynamic.auto_discover) != 0)
                            add_error(errors, event_line(&v2), "guards.dynamic.auto_discover", "must be bool");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "max_entries")) {
                        if (scalar_to_int(&v2, &cfg->guards.dynamic.max_entries) != 0)
                            add_error(errors, event_line(&v2), "guards.dynamic.max_entries", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "ttl_hours")) {
                        if (scalar_to_int(&v2, &cfg->guards.dynamic.ttl_hours) != 0)
                            add_error(errors, event_line(&v2), "guards.dynamic.ttl_hours", "must be int");
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "max_ratio")) {
                        if (scalar_to_int(&v2, &cfg->guards.max_ratio) != 0)
                            add_error(errors, event_line(&v2), "guards.dynamic.max_ratio", "must be int");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "guards.dynamic", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }
                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "whitelist")) {
            if (val_ev.type != YAML_SEQUENCE_START_EVENT) {
                add_error(errors, event_line(&val_ev), "guards.whitelist", "expected sequence");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                yaml_event_delete(&key_ev);
                continue;
            }
            yaml_event_delete(&val_ev);
            cfg->guards.whitelist_count = 0;
            for (;;) {
                yaml_event_t item_ev;
                if (next_event(parser, &item_ev, errors, "guards.whitelist") != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
                    yaml_event_delete(&item_ev);
                    break;
                }
                if (item_ev.type != YAML_MAPPING_START_EVENT) {
                    add_error(errors, event_line(&item_ev), "guards.whitelist", "entries must be mappings");
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                if (cfg->guards.whitelist_count >= JZ_CONFIG_MAX_WHITELIST) {
                    add_error(errors, event_line(&item_ev), "guards.whitelist", "too many entries (max %d)",
                              JZ_CONFIG_MAX_WHITELIST);
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                yaml_event_delete(&item_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    jz_config_whitelist_t *w = &cfg->guards.whitelist[cfg->guards.whitelist_count];
                    if (next_event(parser, &k2, errors, "guards.whitelist") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        cfg->guards.whitelist_count++;
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "guards.whitelist", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "guards.whitelist") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (!strcmp(k, "ip")) {
                        copy_scalar(w->ip, sizeof(w->ip), &v2);
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "mac")) {
                        copy_scalar(w->mac, sizeof(w->mac), &v2);
                        yaml_event_delete(&v2);
                    } else if (!strcmp(k, "match_mac")) {
                        if (scalar_to_bool(&v2, &w->match_mac) != 0)
                            add_error(errors, event_line(&v2), "guards.whitelist[].match_mac", "must be bool");
                        yaml_event_delete(&v2);
                    } else {
                        add_error(errors, event_line(&k2), "guards.whitelist", "unknown key '%s'", k);
                        if (skip_node(parser, &v2, errors) != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                    }
                    yaml_event_delete(&k2);
                }
            }
        } else if (!strcmp(key, "frozen_ips")) {
            if (parse_frozen_ips(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "max_ratio")) {
            if (val_ev.type != YAML_SCALAR_EVENT ||
                scalar_to_int(&val_ev, &cfg->guards.max_ratio) != 0)
                add_error(errors, event_line(&val_ev), "guards.max_ratio", "must be int");
            yaml_event_delete(&val_ev);
        } else {
            add_error(errors, event_line(&key_ev), "guards", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }

        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_fake_mac_pool(yaml_parser_t *parser, yaml_event_t *start,
                               jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "fake_mac_pool", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "fake_mac_pool") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "threats", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "fake_mac_pool") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "prefix")) {
            copy_scalar(cfg->fake_mac_pool.prefix, sizeof(cfg->fake_mac_pool.prefix), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "count")) {
            if (scalar_to_int(&val_ev, &cfg->fake_mac_pool.count) != 0)
                add_error(errors, event_line(&val_ev), "fake_mac_pool.count", "must be int");
            yaml_event_delete(&val_ev);
        } else {
            add_error(errors, event_line(&key_ev), "fake_mac_pool", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_policies(yaml_parser_t *parser, yaml_event_t *start,
                          jz_config_t *cfg, jz_config_errors_t *errors)
{
    if (start->type != YAML_SEQUENCE_START_EVENT) {
        add_error(errors, event_line(start), "policies", "expected sequence");
        return skip_node(parser, start, errors);
    }

    cfg->policy_count = 0;
    yaml_event_delete(start);

    for (;;) {
        yaml_event_t item_ev;
        if (next_event(parser, &item_ev, errors, "policies") != 0)
            return -1;
        if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
            yaml_event_delete(&item_ev);
            break;
        }
        if (item_ev.type != YAML_MAPPING_START_EVENT) {
            add_error(errors, event_line(&item_ev), "policies", "entry must be mapping");
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        if (cfg->policy_count >= JZ_CONFIG_MAX_POLICIES) {
            add_error(errors, event_line(&item_ev), "policies", "too many entries (max %d)",
                      JZ_CONFIG_MAX_POLICIES);
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        yaml_event_delete(&item_ev);
        for (;;) {
            yaml_event_t k2, v2;
            const char *k;
            jz_config_policy_t *p = &cfg->policies[cfg->policy_count];
            if (next_event(parser, &k2, errors, "policies") != 0)
                return -1;
            if (k2.type == YAML_MAPPING_END_EVENT) {
                yaml_event_delete(&k2);
                cfg->policy_count++;
                break;
            }
            if (k2.type != YAML_SCALAR_EVENT) {
                add_error(errors, event_line(&k2), "policies", "expected scalar key");
                yaml_event_delete(&k2);
                return -1;
            }
            k = (const char *)k2.data.scalar.value;
            if (next_event(parser, &v2, errors, "policies") != 0) {
                yaml_event_delete(&k2);
                return -1;
            }
            if (!strcmp(k, "src_ip"))
                copy_scalar(p->src_ip, sizeof(p->src_ip), &v2);
            else if (!strcmp(k, "dst_ip"))
                copy_scalar(p->dst_ip, sizeof(p->dst_ip), &v2);
            else if (!strcmp(k, "src_port") && scalar_to_int(&v2, &p->src_port) != 0)
                add_error(errors, event_line(&v2), "policies[].src_port", "must be int");
            else if (!strcmp(k, "dst_port") && scalar_to_int(&v2, &p->dst_port) != 0)
                add_error(errors, event_line(&v2), "policies[].dst_port", "must be int");
            else if (!strcmp(k, "proto"))
                copy_scalar(p->proto, sizeof(p->proto), &v2);
            else if (!strcmp(k, "action"))
                copy_scalar(p->action, sizeof(p->action), &v2);
            else if (!strcmp(k, "redirect_port") && scalar_to_int(&v2, &p->redirect_port) != 0)
                add_error(errors, event_line(&v2), "policies[].redirect_port", "must be int");
            else if (!strcmp(k, "mirror_port") && scalar_to_int(&v2, &p->mirror_port) != 0)
                add_error(errors, event_line(&v2), "policies[].mirror_port", "must be int");
            else if (strcmp(k, "src_ip") && strcmp(k, "dst_ip") && strcmp(k, "src_port") &&
                     strcmp(k, "dst_port") && strcmp(k, "proto") && strcmp(k, "action") &&
                     strcmp(k, "redirect_port") && strcmp(k, "mirror_port"))
                add_error(errors, event_line(&k2), "policies", "unknown key '%s'", k);

            yaml_event_delete(&v2);
            yaml_event_delete(&k2);
        }
    }

    return 0;
}

static int parse_threats(yaml_parser_t *parser, yaml_event_t *start,
                         jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "threats", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "threats") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "collector", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "threats") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "blacklist_file")) {
            copy_scalar(cfg->threats.blacklist_file, sizeof(cfg->threats.blacklist_file), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "patterns")) {
            if (val_ev.type != YAML_SEQUENCE_START_EVENT) {
                add_error(errors, event_line(&val_ev), "threats.patterns", "expected sequence");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                yaml_event_delete(&key_ev);
                continue;
            }
            cfg->threats.pattern_count = 0;
            yaml_event_delete(&val_ev);
            for (;;) {
                yaml_event_t item_ev;
                if (next_event(parser, &item_ev, errors, "threats.patterns") != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
                    yaml_event_delete(&item_ev);
                    break;
                }
                if (item_ev.type != YAML_MAPPING_START_EVENT) {
                    add_error(errors, event_line(&item_ev), "threats.patterns", "entry must be mapping");
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                if (cfg->threats.pattern_count >= JZ_CONFIG_MAX_THREAT_PATTERNS) {
                    add_error(errors, event_line(&item_ev), "threats.patterns", "too many entries (max %d)",
                              JZ_CONFIG_MAX_THREAT_PATTERNS);
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                yaml_event_delete(&item_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    jz_config_threat_pattern_t *p = &cfg->threats.patterns[cfg->threats.pattern_count];
                    if (next_event(parser, &k2, errors, "threats.patterns") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        cfg->threats.pattern_count++;
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "threats.patterns", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "threats.patterns") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (!strcmp(k, "id"))
                        copy_scalar(p->id, sizeof(p->id), &v2);
                    else if (!strcmp(k, "dst_port") && scalar_to_int(&v2, &p->dst_port) != 0)
                        add_error(errors, event_line(&v2), "threats.patterns[].dst_port", "must be int");
                    else if (!strcmp(k, "proto"))
                        copy_scalar(p->proto, sizeof(p->proto), &v2);
                    else if (!strcmp(k, "threat_level"))
                        copy_scalar(p->threat_level, sizeof(p->threat_level), &v2);
                    else if (!strcmp(k, "action"))
                        copy_scalar(p->action, sizeof(p->action), &v2);
                    else if (!strcmp(k, "description"))
                        copy_scalar(p->description, sizeof(p->description), &v2);
                    else
                        add_error(errors, event_line(&k2), "threats.patterns", "unknown key '%s'", k);

                    yaml_event_delete(&v2);
                    yaml_event_delete(&k2);
                }
            }
        } else {
            add_error(errors, event_line(&key_ev), "threats", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_collector(yaml_parser_t *parser, yaml_event_t *start,
                           jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "collector", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "collector") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "uploader", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "collector") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "db_path"))
            copy_scalar(cfg->collector.db_path, sizeof(cfg->collector.db_path), &val_ev);
        else if (!strcmp(key, "max_db_size_mb") && scalar_to_int(&val_ev, &cfg->collector.max_db_size_mb) != 0)
            add_error(errors, event_line(&val_ev), "collector.max_db_size_mb", "must be int");
        else if (!strcmp(key, "dedup_window_sec") && scalar_to_int(&val_ev, &cfg->collector.dedup_window_sec) != 0)
            add_error(errors, event_line(&val_ev), "collector.dedup_window_sec", "must be int");
        else if (!strcmp(key, "rate_limit_eps") && scalar_to_int(&val_ev, &cfg->collector.rate_limit_eps) != 0)
            add_error(errors, event_line(&val_ev), "collector.rate_limit_eps", "must be int");
        else if (strcmp(key, "db_path") && strcmp(key, "max_db_size_mb") &&
                 strcmp(key, "dedup_window_sec") && strcmp(key, "rate_limit_eps"))
            add_error(errors, event_line(&key_ev), "collector", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_discovery(yaml_parser_t *parser, yaml_event_t *start,
                           jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "discovery", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "discovery") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "discovery", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "discovery") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "aggressive_mode") && scalar_to_bool(&val_ev, &cfg->discovery.aggressive_mode) != 0)
            add_error(errors, event_line(&val_ev), "discovery.aggressive_mode", "must be bool");
        else if (!strcmp(key, "dhcp_probe_interval_sec") && scalar_to_int(&val_ev, &cfg->discovery.dhcp_probe_interval_sec) != 0)
            add_error(errors, event_line(&val_ev), "discovery.dhcp_probe_interval_sec", "must be int");
        else if (strcmp(key, "aggressive_mode") && strcmp(key, "dhcp_probe_interval_sec"))
            add_error(errors, event_line(&key_ev), "discovery", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_policy_auto(yaml_parser_t *parser, yaml_event_t *start,
                             jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "policy_auto", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "policy_auto") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "policy_auto", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "policy_auto") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "enabled")) {
            if (scalar_to_bool(&val_ev, &cfg->policy_auto.enabled) != 0)
                add_error(errors, event_line(&val_ev), "policy_auto.enabled", "must be bool");
        } else if (!strcmp(key, "threshold") && scalar_to_int(&val_ev, &cfg->policy_auto.threshold) != 0)
            add_error(errors, event_line(&val_ev), "policy_auto.threshold", "must be int");
        else if (!strcmp(key, "window_sec") && scalar_to_int(&val_ev, &cfg->policy_auto.window_sec) != 0)
            add_error(errors, event_line(&val_ev), "policy_auto.window_sec", "must be int");
        else if (!strcmp(key, "ttl_sec") && scalar_to_int(&val_ev, &cfg->policy_auto.ttl_sec) != 0)
            add_error(errors, event_line(&val_ev), "policy_auto.ttl_sec", "must be int");
        else if (!strcmp(key, "max_auto_policies") && scalar_to_int(&val_ev, &cfg->policy_auto.max_auto_policies) != 0)
            add_error(errors, event_line(&val_ev), "policy_auto.max_auto_policies", "must be int");
        else if (!strcmp(key, "default_action"))
            copy_scalar(cfg->policy_auto.default_action, sizeof(cfg->policy_auto.default_action), &val_ev);
        else if (!strcmp(key, "escalation")) {
            if (scalar_to_bool(&val_ev, &cfg->policy_auto.escalation) != 0)
                add_error(errors, event_line(&val_ev), "policy_auto.escalation", "must be bool");
        } else if (strcmp(key, "enabled") && strcmp(key, "threshold") &&
                 strcmp(key, "window_sec") && strcmp(key, "ttl_sec") &&
                 strcmp(key, "max_auto_policies") && strcmp(key, "default_action") &&
                 strcmp(key, "escalation"))
            add_error(errors, event_line(&key_ev), "policy_auto", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_uploader(yaml_parser_t *parser, yaml_event_t *start,
                          jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "uploader", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "uploader") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "api", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "uploader") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "enabled") && scalar_to_bool(&val_ev, &cfg->uploader.enabled) != 0)
            add_error(errors, event_line(&val_ev), "uploader.enabled", "must be bool");
        else if (!strcmp(key, "platform_url"))
            copy_scalar(cfg->uploader.platform_url, sizeof(cfg->uploader.platform_url), &val_ev);
        else if (!strcmp(key, "interval_sec") && scalar_to_int(&val_ev, &cfg->uploader.interval_sec) != 0)
            add_error(errors, event_line(&val_ev), "uploader.interval_sec", "must be int");
        else if (!strcmp(key, "batch_size") && scalar_to_int(&val_ev, &cfg->uploader.batch_size) != 0)
            add_error(errors, event_line(&val_ev), "uploader.batch_size", "must be int");
        else if (!strcmp(key, "tls_cert"))
            copy_scalar(cfg->uploader.tls_cert, sizeof(cfg->uploader.tls_cert), &val_ev);
        else if (!strcmp(key, "tls_key"))
            copy_scalar(cfg->uploader.tls_key, sizeof(cfg->uploader.tls_key), &val_ev);
        else if (!strcmp(key, "compress") && scalar_to_bool(&val_ev, &cfg->uploader.compress) != 0)
            add_error(errors, event_line(&val_ev), "uploader.compress", "must be bool");
        else if (strcmp(key, "enabled") && strcmp(key, "platform_url") && strcmp(key, "interval_sec") &&
                 strcmp(key, "batch_size") && strcmp(key, "tls_cert") && strcmp(key, "tls_key") &&
                 strcmp(key, "compress"))
            add_error(errors, event_line(&key_ev), "uploader", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_log_syslog(yaml_parser_t *parser, yaml_event_t *start,
                            jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "log.syslog", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "log.syslog") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "log.syslog", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "log.syslog") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "enabled") && scalar_to_bool(&val_ev, &cfg->log.syslog.enabled) != 0)
            add_error(errors, event_line(&val_ev), "log.syslog.enabled", "must be bool");
        else if (!strcmp(key, "format"))
            copy_scalar(cfg->log.syslog.format, sizeof(cfg->log.syslog.format), &val_ev);
        else if (!strcmp(key, "facility"))
            copy_scalar(cfg->log.syslog.facility, sizeof(cfg->log.syslog.facility), &val_ev);
        else if (strcmp(key, "enabled") && strcmp(key, "format") && strcmp(key, "facility"))
            add_error(errors, event_line(&key_ev), "log.syslog", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_log_mqtt(yaml_parser_t *parser, yaml_event_t *start,
                          jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "log.mqtt", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "log.mqtt") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "log.mqtt", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "log.mqtt") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "enabled") && scalar_to_bool(&val_ev, &cfg->log.mqtt.enabled) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.enabled", "must be bool");
        else if (!strcmp(key, "format"))
            copy_scalar(cfg->log.mqtt.format, sizeof(cfg->log.mqtt.format), &val_ev);
        else if (!strcmp(key, "broker"))
            copy_scalar(cfg->log.mqtt.broker, sizeof(cfg->log.mqtt.broker), &val_ev);
        else if (!strcmp(key, "tls") && scalar_to_bool(&val_ev, &cfg->log.mqtt.tls) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.tls", "must be bool");
        else if (!strcmp(key, "tls_ca"))
            copy_scalar(cfg->log.mqtt.tls_ca, sizeof(cfg->log.mqtt.tls_ca), &val_ev);
        else if (!strcmp(key, "client_id"))
            copy_scalar(cfg->log.mqtt.client_id, sizeof(cfg->log.mqtt.client_id), &val_ev);
        else if (!strcmp(key, "topic_prefix"))
            copy_scalar(cfg->log.mqtt.topic_prefix, sizeof(cfg->log.mqtt.topic_prefix), &val_ev);
        else if (!strcmp(key, "qos") && scalar_to_int(&val_ev, &cfg->log.mqtt.qos) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.qos", "must be int");
        else if (!strcmp(key, "keepalive_sec") && scalar_to_int(&val_ev, &cfg->log.mqtt.keepalive_sec) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.keepalive_sec", "must be int");
        else if (!strcmp(key, "heartbeat_interval_sec") && scalar_to_int(&val_ev, &cfg->log.mqtt.heartbeat_interval_sec) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.heartbeat_interval_sec", "must be int");
        else if (!strcmp(key, "heartbeat_max_devices") && scalar_to_int(&val_ev, &cfg->log.mqtt.heartbeat_max_devices) != 0)
            add_error(errors, event_line(&val_ev), "log.mqtt.heartbeat_max_devices", "must be int");
        else if (strcmp(key, "enabled") && strcmp(key, "format") && strcmp(key, "broker") &&
                 strcmp(key, "tls") && strcmp(key, "tls_ca") && strcmp(key, "client_id") &&
                 strcmp(key, "topic_prefix") && strcmp(key, "qos") && strcmp(key, "keepalive_sec") &&
                 strcmp(key, "heartbeat_interval_sec") && strcmp(key, "heartbeat_max_devices"))
            add_error(errors, event_line(&key_ev), "log.mqtt", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_log_https(yaml_parser_t *parser, yaml_event_t *start,
                           jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "log.https", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "log.https") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "log.https", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "log.https") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "enabled") && scalar_to_bool(&val_ev, &cfg->log.https.enabled) != 0)
            add_error(errors, event_line(&val_ev), "log.https.enabled", "must be bool");
        else if (!strcmp(key, "url"))
            copy_scalar(cfg->log.https.url, sizeof(cfg->log.https.url), &val_ev);
        else if (!strcmp(key, "tls_cert"))
            copy_scalar(cfg->log.https.tls_cert, sizeof(cfg->log.https.tls_cert), &val_ev);
        else if (!strcmp(key, "tls_key"))
            copy_scalar(cfg->log.https.tls_key, sizeof(cfg->log.https.tls_key), &val_ev);
        else if (!strcmp(key, "interval_sec") && scalar_to_int(&val_ev, &cfg->log.https.interval_sec) != 0)
            add_error(errors, event_line(&val_ev), "log.https.interval_sec", "must be int");
        else if (!strcmp(key, "batch_size") && scalar_to_int(&val_ev, &cfg->log.https.batch_size) != 0)
            add_error(errors, event_line(&val_ev), "log.https.batch_size", "must be int");
        else if (!strcmp(key, "compress") && scalar_to_bool(&val_ev, &cfg->log.https.compress) != 0)
            add_error(errors, event_line(&val_ev), "log.https.compress", "must be bool");
        else if (strcmp(key, "enabled") && strcmp(key, "url") && strcmp(key, "tls_cert") &&
                 strcmp(key, "tls_key") && strcmp(key, "interval_sec") && strcmp(key, "batch_size") &&
                 strcmp(key, "compress"))
            add_error(errors, event_line(&key_ev), "log.https", "unknown key '%s'", key);

        yaml_event_delete(&val_ev);
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_log(yaml_parser_t *parser, yaml_event_t *start,
                     jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "log", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "log") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "log", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "log") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "format")) {
            copy_scalar(cfg->log.format, sizeof(cfg->log.format), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "heartbeat_interval_sec") &&
                   scalar_to_int(&val_ev, &cfg->log.heartbeat_interval_sec) != 0) {
            add_error(errors, event_line(&val_ev), "log.heartbeat_interval_sec", "must be int");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "heartbeat_interval_sec")) {
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "syslog")) {
            if (parse_log_syslog(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "mqtt")) {
            if (parse_log_mqtt(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "https")) {
            if (parse_log_https(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else {
            add_error(errors, event_line(&key_ev), "log", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_arp_spoof(yaml_parser_t *parser, yaml_event_t *start,
                           jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "arp_spoof", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "arp_spoof") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "arp_spoof", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "arp_spoof") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "enabled")) {
            if (scalar_to_bool(&val_ev, &cfg->arp_spoof.enabled) != 0)
                add_error(errors, event_line(&val_ev), "arp_spoof.enabled", "must be bool");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "interval_sec")) {
            if (scalar_to_int(&val_ev, &cfg->arp_spoof.interval_sec) != 0)
                add_error(errors, event_line(&val_ev), "arp_spoof.interval_sec", "must be int");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "targets")) {
            if (val_ev.type != YAML_SEQUENCE_START_EVENT) {
                add_error(errors, event_line(&val_ev), "arp_spoof.targets", "expected sequence");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
            } else {
                yaml_event_delete(&val_ev);
                cfg->arp_spoof.target_count = 0;
                for (;;) {
                    yaml_event_t item_ev;
                    if (next_event(parser, &item_ev, errors, "arp_spoof.targets") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
                        yaml_event_delete(&item_ev);
                        break;
                    }
                    if (item_ev.type != YAML_MAPPING_START_EVENT) {
                        add_error(errors, event_line(&item_ev), "arp_spoof.targets", "entries must be mappings");
                        if (skip_node(parser, &item_ev, errors) != 0) {
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                        continue;
                    }
                    if (cfg->arp_spoof.target_count >= JZ_CONFIG_MAX_ARP_SPOOF_TARGETS) {
                        add_error(errors, event_line(&item_ev), "arp_spoof.targets",
                                  "too many entries (max %d)", JZ_CONFIG_MAX_ARP_SPOOF_TARGETS);
                        if (skip_node(parser, &item_ev, errors) != 0) {
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                        continue;
                    }
                    yaml_event_delete(&item_ev);
                    for (;;) {
                        yaml_event_t k2, v2;
                        const char *k;
                        jz_config_arp_spoof_target_t *t =
                            &cfg->arp_spoof.targets[cfg->arp_spoof.target_count];
                        if (next_event(parser, &k2, errors, "arp_spoof.targets") != 0) {
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                        if (k2.type == YAML_MAPPING_END_EVENT) {
                            yaml_event_delete(&k2);
                            cfg->arp_spoof.target_count++;
                            break;
                        }
                        if (k2.type != YAML_SCALAR_EVENT) {
                            add_error(errors, event_line(&k2), "arp_spoof.targets", "expected scalar key");
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                        k = (const char *)k2.data.scalar.value;
                        if (next_event(parser, &v2, errors, "arp_spoof.targets") != 0) {
                            yaml_event_delete(&k2);
                            yaml_event_delete(&key_ev);
                            return -1;
                        }
                        if (!strcmp(k, "target_ip"))
                            copy_scalar(t->target_ip, sizeof(t->target_ip), &v2);
                        else if (!strcmp(k, "gateway_ip"))
                            copy_scalar(t->gateway_ip, sizeof(t->gateway_ip), &v2);
                        else
                            add_error(errors, event_line(&k2), "arp_spoof.targets", "unknown key '%s'", k);
                        yaml_event_delete(&v2);
                        yaml_event_delete(&k2);
                    }
                }
            }
        } else {
            add_error(errors, event_line(&key_ev), "arp_spoof", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_vlans(yaml_parser_t *parser, yaml_event_t *start,
                       jz_config_t *cfg, jz_config_errors_t *errors)
{
    if (start->type != YAML_SEQUENCE_START_EVENT) {
        add_error(errors, event_line(start), "vlans", "expected sequence");
        return skip_node(parser, start, errors);
    }
    yaml_event_delete(start);
    cfg->vlan_count = 0;
    for (;;) {
        yaml_event_t item_ev;
        if (next_event(parser, &item_ev, errors, "vlans") != 0)
            return -1;
        if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
            yaml_event_delete(&item_ev);
            break;
        }
        if (item_ev.type != YAML_MAPPING_START_EVENT) {
            add_error(errors, event_line(&item_ev), "vlans", "entries must be mappings");
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        if (cfg->vlan_count >= JZ_CONFIG_MAX_VLANS) {
            add_error(errors, event_line(&item_ev), "vlans", "too many entries (max %d)",
                      JZ_CONFIG_MAX_VLANS);
            if (skip_node(parser, &item_ev, errors) != 0)
                return -1;
            continue;
        }

        yaml_event_delete(&item_ev);
        for (;;) {
            yaml_event_t k2, v2;
            const char *k;
            jz_config_vlan_t *v = &cfg->vlans[cfg->vlan_count];
            if (next_event(parser, &k2, errors, "vlans") != 0)
                return -1;
            if (k2.type == YAML_MAPPING_END_EVENT) {
                yaml_event_delete(&k2);
                cfg->vlan_count++;
                break;
            }
            if (k2.type != YAML_SCALAR_EVENT) {
                add_error(errors, event_line(&k2), "vlans", "expected scalar key");
                yaml_event_delete(&k2);
                return -1;
            }
            k = (const char *)k2.data.scalar.value;
            if (next_event(parser, &v2, errors, "vlans") != 0) {
                yaml_event_delete(&k2);
                return -1;
            }
            if (!strcmp(k, "id")) {
                if (scalar_to_int(&v2, &v->id) != 0)
                    add_error(errors, event_line(&v2), "vlans[].id", "must be int");
            } else if (!strcmp(k, "name")) {
                copy_scalar(v->name, sizeof(v->name), &v2);
            } else if (!strcmp(k, "subnet")) {
                copy_scalar(v->subnet, sizeof(v->subnet), &v2);
            } else {
                add_error(errors, event_line(&k2), "vlans", "unknown key '%s'", k);
            }
            yaml_event_delete(&v2);
            yaml_event_delete(&k2);
        }
    }
    return 0;
}

static int parse_api(yaml_parser_t *parser, yaml_event_t *start,
                     jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "api", "expected mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);
    for (;;) {
        yaml_event_t val_ev;
        const char *key;
        if (next_event(parser, &key_ev, errors, "api") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, "api") != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }
        if (!strcmp(key, "enabled")) {
            if (scalar_to_bool(&val_ev, &cfg->api.enabled) != 0)
                add_error(errors, event_line(&val_ev), "api.enabled", "must be bool");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "listen")) {
            copy_scalar(cfg->api.listen, sizeof(cfg->api.listen), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "tls_cert")) {
            copy_scalar(cfg->api.tls_cert, sizeof(cfg->api.tls_cert), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "tls_key")) {
            copy_scalar(cfg->api.tls_key, sizeof(cfg->api.tls_key), &val_ev);
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "auth_tokens")) {
            if (val_ev.type != YAML_SEQUENCE_START_EVENT) {
                add_error(errors, event_line(&val_ev), "api.auth_tokens", "expected sequence");
                if (skip_node(parser, &val_ev, errors) != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                yaml_event_delete(&key_ev);
                continue;
            }
            cfg->api.auth_token_count = 0;
            yaml_event_delete(&val_ev);
            for (;;) {
                yaml_event_t item_ev;
                if (next_event(parser, &item_ev, errors, "api.auth_tokens") != 0) {
                    yaml_event_delete(&key_ev);
                    return -1;
                }
                if (item_ev.type == YAML_SEQUENCE_END_EVENT) {
                    yaml_event_delete(&item_ev);
                    break;
                }
                if (item_ev.type != YAML_MAPPING_START_EVENT) {
                    add_error(errors, event_line(&item_ev), "api.auth_tokens", "entry must be mapping");
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                if (cfg->api.auth_token_count >= JZ_CONFIG_MAX_AUTH_TOKENS) {
                    add_error(errors, event_line(&item_ev), "api.auth_tokens", "too many entries (max %d)",
                              JZ_CONFIG_MAX_AUTH_TOKENS);
                    if (skip_node(parser, &item_ev, errors) != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    continue;
                }

                yaml_event_delete(&item_ev);
                for (;;) {
                    yaml_event_t k2, v2;
                    const char *k;
                    jz_config_auth_token_t *t = &cfg->api.auth_tokens[cfg->api.auth_token_count];
                    if (next_event(parser, &k2, errors, "api.auth_tokens") != 0) {
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (k2.type == YAML_MAPPING_END_EVENT) {
                        yaml_event_delete(&k2);
                        cfg->api.auth_token_count++;
                        break;
                    }
                    if (k2.type != YAML_SCALAR_EVENT) {
                        add_error(errors, event_line(&k2), "api.auth_tokens", "expected scalar key");
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    k = (const char *)k2.data.scalar.value;
                    if (next_event(parser, &v2, errors, "api.auth_tokens") != 0) {
                        yaml_event_delete(&k2);
                        yaml_event_delete(&key_ev);
                        return -1;
                    }
                    if (!strcmp(k, "token"))
                        copy_scalar(t->token, sizeof(t->token), &v2);
                    else if (!strcmp(k, "role"))
                        copy_scalar(t->role, sizeof(t->role), &v2);
                    else
                        add_error(errors, event_line(&k2), "api.auth_tokens", "unknown key '%s'", k);

                    yaml_event_delete(&v2);
                    yaml_event_delete(&k2);
                }
            }
        } else {
            add_error(errors, event_line(&key_ev), "api", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }
        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_root_mapping(yaml_parser_t *parser, yaml_event_t *start,
                              jz_config_t *cfg, jz_config_errors_t *errors)
{
    yaml_event_t key_ev;

    if (start->type != YAML_MAPPING_START_EVENT) {
        add_error(errors, event_line(start), "root", "expected top-level mapping");
        return skip_node(parser, start, errors);
    }

    yaml_event_delete(start);

    for (;;) {
        yaml_event_t val_ev;
        const char *key;

        if (next_event(parser, &key_ev, errors, "root") != 0)
            return -1;
        if (key_ev.type == YAML_MAPPING_END_EVENT) {
            yaml_event_delete(&key_ev);
            break;
        }
        if (key_ev.type != YAML_SCALAR_EVENT) {
            add_error(errors, event_line(&key_ev), "root", "expected scalar key");
            yaml_event_delete(&key_ev);
            return -1;
        }

        key = (const char *)key_ev.data.scalar.value;
        if (next_event(parser, &val_ev, errors, key) != 0) {
            yaml_event_delete(&key_ev);
            return -1;
        }

        if (!strcmp(key, "version")) {
            if (scalar_to_int(&val_ev, &cfg->version) != 0)
                add_error(errors, event_line(&val_ev), "version", "must be int");
            yaml_event_delete(&val_ev);
        } else if (!strcmp(key, "system")) {
            if (parse_system(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "modules")) {
            if (parse_modules(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "guards")) {
            if (parse_guards(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "fake_mac_pool")) {
            if (parse_fake_mac_pool(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "policies")) {
            if (parse_policies(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "policy_auto")) {
            if (parse_policy_auto(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "threats")) {
            if (parse_threats(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "collector")) {
            if (parse_collector(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "uploader")) {
            if (parse_uploader(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "log")) {
            if (parse_log(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "api")) {
            if (parse_api(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "arp_spoof")) {
            if (parse_arp_spoof(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "discovery")) {
            if (parse_discovery(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else if (!strcmp(key, "vlans")) {
            if (parse_vlans(parser, &val_ev, cfg, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        } else {
            add_error(errors, event_line(&key_ev), "root", "unknown key '%s'", key);
            if (skip_node(parser, &val_ev, errors) != 0) {
                yaml_event_delete(&key_ev);
                return -1;
            }
        }

        yaml_event_delete(&key_ev);
    }

    return 0;
}

static int parse_file_into_cfg(jz_config_t *cfg, const char *path, jz_config_errors_t *errors)
{
    FILE *fp;
    yaml_parser_t parser;
    yaml_event_t ev;
    int rc = -1;

    fp = fopen(path, "rb");
    if (!fp) {
        add_error(errors, 0, "file", "cannot open '%s'", path);
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        add_error(errors, 0, "yaml", "failed to initialize yaml parser");
        fclose(fp);
        return -1;
    }

    yaml_parser_set_input_file(&parser, fp);

    if (next_event(&parser, &ev, errors, "yaml") != 0)
        goto out;
    if (ev.type != YAML_STREAM_START_EVENT) {
        add_error(errors, event_line(&ev), "yaml", "missing stream start");
        yaml_event_delete(&ev);
        goto out;
    }
    yaml_event_delete(&ev);

    if (next_event(&parser, &ev, errors, "yaml") != 0)
        goto out;
    if (ev.type != YAML_DOCUMENT_START_EVENT) {
        add_error(errors, event_line(&ev), "yaml", "missing document start");
        yaml_event_delete(&ev);
        goto out;
    }
    yaml_event_delete(&ev);

    if (next_event(&parser, &ev, errors, "root") != 0)
        goto out;
    if (parse_root_mapping(&parser, &ev, cfg, errors) != 0)
        goto out;

    if (next_event(&parser, &ev, errors, "yaml") != 0)
        goto out;
    if (ev.type != YAML_DOCUMENT_END_EVENT) {
        add_error(errors, event_line(&ev), "yaml", "missing document end");
        yaml_event_delete(&ev);
        goto out;
    }
    yaml_event_delete(&ev);

    if (next_event(&parser, &ev, errors, "yaml") != 0)
        goto out;
    if (ev.type != YAML_STREAM_END_EVENT) {
        add_error(errors, event_line(&ev), "yaml", "missing stream end");
        yaml_event_delete(&ev);
        goto out;
    }
    yaml_event_delete(&ev);

    rc = 0;

out:
    yaml_parser_delete(&parser);
    fclose(fp);
    return rc;
}

static bool is_valid_ipv4(const char *s)
{
    struct in_addr addr;
    return s && s[0] != '\0' && inet_pton(AF_INET, s, &addr) == 1;
}

static bool is_valid_mac(const char *s)
{
    int i;

    if (!s)
        return false;
    if (strlen(s) != 17)
        return false;

    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (s[i] != ':')
                return false;
        } else if (!isxdigit((unsigned char)s[i])) {
            return false;
        }
    }

    return true;
}

static bool is_valid_cidr(const char *s)
{
    char buf[64];
    char *slash;
    struct in_addr addr;
    long prefix;
    char *end;

    if (!s || s[0] == '\0')
        return false;

    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (!slash)
        return false;

    *slash = '\0';
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return false;

    prefix = strtol(slash + 1, &end, 10);
    if (!end || *end != '\0' || prefix < 0 || prefix > 32)
        return false;

    return true;
}

static bool is_valid_stage(int stage)
{
    return stage == JZ_STAGE_GUARD_CLASSIFIER ||
           stage == JZ_STAGE_ARP_HONEYPOT ||
           stage == JZ_STAGE_ICMP_HONEYPOT ||
           stage == JZ_STAGE_SNIFFER_DETECT ||
           stage == JZ_STAGE_TRAFFIC_WEAVER ||
           stage == JZ_STAGE_BG_COLLECTOR ||
           stage == JZ_STAGE_THREAT_DETECT ||
           stage == JZ_STAGE_FORENSICS;
}

static bool in_set(const char *s, const char *const *set)
{
    int i;
    if (!s)
        return false;
    for (i = 0; set[i]; i++) {
        if (!strcmp(s, set[i]))
            return true;
    }
    return false;
}

int jz_config_validate(const jz_config_t *cfg, jz_config_errors_t *errors)
{
    static const char *const log_levels[] = {"debug", "info", "warn", "error", NULL};
    static const char *const actions[] = {"pass", "drop", "redirect", "mirror", "redirect_mirror", NULL};
    static const char *const threat_actions[] = {"log_only", "log_drop", "log_redirect", NULL};
    static const char *const threat_levels[] = {"low", "medium", "high", "critical", NULL};
    static const char *const protos[] = {"tcp", "udp", "icmp", "any", NULL};
    static const char *const iface_roles[] = {"monitor", "manage", "mirror", NULL};
    static const char *const deploy_modes[] = {"bypass", "inline", NULL};
    int i;
    int start_count = errors ? errors->count : 0;

    if (!cfg) {
        add_error(errors, 0, "config", "config pointer is NULL");
        return -1;
    }

    if (cfg->version <= 0)
        add_error(errors, 0, "version", "must be > 0");

    if (cfg->system.device_id[0] == '\0')
        add_error(errors, 0, "system.device_id", "must not be empty");
    if (cfg->system.data_dir[0] == '\0')
        add_error(errors, 0, "system.data_dir", "must not be empty");
    if (cfg->system.run_dir[0] == '\0')
        add_error(errors, 0, "system.run_dir", "must not be empty");
    if (!in_set(cfg->system.log_level, log_levels))
        add_error(errors, 0, "system.log_level", "must be debug/info/warn/error");
    if (cfg->system.mode[0] != '\0' && !in_set(cfg->system.mode, deploy_modes))
        add_error(errors, 0, "system.mode", "must be bypass/inline");

    for (i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface = &cfg->system.interfaces[i];
        if (iface->name[0] == '\0')
            add_error(errors, 0, "system.interfaces[].name", "must not be empty");
        if (!in_set(iface->role, iface_roles))
            add_error(errors, 0, "system.interfaces[].role", "must be monitor/manage/mirror");
        if (iface->subnet[0] != '\0' && !is_valid_cidr(iface->subnet))
            add_error(errors, 0, "system.interfaces[].subnet", "invalid CIDR '%s'", iface->subnet);
    }

    if (!is_valid_stage(cfg->modules.guard_classifier.stage))
        add_error(errors, 0, "modules.guard_classifier.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.arp_honeypot.common.stage))
        add_error(errors, 0, "modules.arp_honeypot.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.icmp_honeypot.common.stage))
        add_error(errors, 0, "modules.icmp_honeypot.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.sniffer_detect.common.stage))
        add_error(errors, 0, "modules.sniffer_detect.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.traffic_weaver.common.stage))
        add_error(errors, 0, "modules.traffic_weaver.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.bg_collector.common.stage))
        add_error(errors, 0, "modules.bg_collector.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.threat_detect.stage))
        add_error(errors, 0, "modules.threat_detect.stage", "invalid stage");
    if (!is_valid_stage(cfg->modules.forensics.common.stage))
        add_error(errors, 0, "modules.forensics.stage", "invalid stage");

    if (!in_set(cfg->modules.traffic_weaver.default_action, actions))
        add_error(errors, 0, "modules.traffic_weaver.default_action", "invalid action");

    if (cfg->guards.static_count < 0)
        add_error(errors, 0, "guards.static_count", "must be non-negative");
    if (cfg->guards.whitelist_count < 0)
        add_error(errors, 0, "guards.whitelist_count", "must be non-negative");
    if (cfg->guards.frozen_ip_count < 0)
        add_error(errors, 0, "guards.frozen_ip_count", "must be non-negative");
    if (cfg->guards.max_ratio < 0 || cfg->guards.max_ratio > 100)
        add_error(errors, 0, "guards.max_ratio", "must be 0-100");
    if (cfg->policy_count < 0)
        add_error(errors, 0, "policy_count", "must be non-negative");
    if (cfg->threats.pattern_count < 0)
        add_error(errors, 0, "threats.pattern_count", "must be non-negative");
    if (cfg->api.auth_token_count < 0)
        add_error(errors, 0, "api.auth_token_count", "must be non-negative");

    for (i = 0; i < cfg->guards.static_count && i < JZ_CONFIG_MAX_STATIC_GUARDS; i++) {
        if (!is_valid_ipv4(cfg->guards.static_entries[i].ip))
            add_error(errors, 0, "guards.static[].ip", "invalid IPv4 '%s'", cfg->guards.static_entries[i].ip);
        if (cfg->guards.static_entries[i].mac[0] && !is_valid_mac(cfg->guards.static_entries[i].mac))
            add_error(errors, 0, "guards.static[].mac", "invalid MAC '%s'", cfg->guards.static_entries[i].mac);
        if (cfg->guards.static_entries[i].vlan < 0)
            add_error(errors, 0, "guards.static[].vlan", "must be >= 0");
    }

    for (i = 0; i < cfg->guards.whitelist_count && i < JZ_CONFIG_MAX_WHITELIST; i++) {
        if (!is_valid_ipv4(cfg->guards.whitelist[i].ip))
            add_error(errors, 0, "guards.whitelist[].ip", "invalid IPv4 '%s'", cfg->guards.whitelist[i].ip);
        if (!is_valid_mac(cfg->guards.whitelist[i].mac))
            add_error(errors, 0, "guards.whitelist[].mac", "invalid MAC '%s'", cfg->guards.whitelist[i].mac);
    }

    for (i = 0; i < cfg->guards.frozen_ip_count && i < JZ_CONFIG_MAX_FROZEN_IPS; i++) {
        if (!is_valid_ipv4(cfg->guards.frozen_ips[i].ip))
            add_error(errors, 0, "guards.frozen_ips[].ip", "invalid IPv4 '%s'", cfg->guards.frozen_ips[i].ip);
    }

    for (i = 0; i < cfg->policy_count && i < JZ_CONFIG_MAX_POLICIES; i++) {
        const jz_config_policy_t *p = &cfg->policies[i];
        if (!is_valid_ipv4(p->src_ip))
            add_error(errors, 0, "policies[].src_ip", "invalid IPv4 '%s'", p->src_ip);
        if (!is_valid_ipv4(p->dst_ip))
            add_error(errors, 0, "policies[].dst_ip", "invalid IPv4 '%s'", p->dst_ip);
        if (p->src_port < 0 || p->src_port > 65535)
            add_error(errors, 0, "policies[].src_port", "must be 0-65535");
        if (p->dst_port < 0 || p->dst_port > 65535)
            add_error(errors, 0, "policies[].dst_port", "must be 0-65535");
        if (p->redirect_port < 0 || p->redirect_port > 65535)
            add_error(errors, 0, "policies[].redirect_port", "must be 0-65535");
        if (p->mirror_port < 0 || p->mirror_port > 65535)
            add_error(errors, 0, "policies[].mirror_port", "must be 0-65535");
        if (!in_set(p->proto, protos))
            add_error(errors, 0, "policies[].proto", "must be tcp/udp/icmp/any");
        if (!in_set(p->action, actions))
            add_error(errors, 0, "policies[].action", "invalid action");
        if (!strcmp(p->action, "redirect") && p->redirect_port <= 0)
            add_error(errors, 0, "policies[].redirect_port", "must be > 0 when action=redirect");
        if ((!strcmp(p->action, "mirror") || !strcmp(p->action, "redirect_mirror")) && p->mirror_port <= 0)
            add_error(errors, 0, "policies[].mirror_port", "must be > 0 for mirror actions");
    }

    for (i = 0; i < cfg->threats.pattern_count && i < JZ_CONFIG_MAX_THREAT_PATTERNS; i++) {
        const jz_config_threat_pattern_t *p = &cfg->threats.patterns[i];
        if (p->id[0] == '\0')
            add_error(errors, 0, "threats.patterns[].id", "must not be empty");
        if (p->dst_port < 0 || p->dst_port > 65535)
            add_error(errors, 0, "threats.patterns[].dst_port", "must be 0-65535");
        if (!in_set(p->proto, protos))
            add_error(errors, 0, "threats.patterns[].proto", "must be tcp/udp/icmp/any");
        if (!in_set(p->threat_level, threat_levels))
            add_error(errors, 0, "threats.patterns[].threat_level", "invalid threat level");
        if (!in_set(p->action, threat_actions))
            add_error(errors, 0, "threats.patterns[].action", "must be log_only/log_drop/log_redirect");
    }

    for (i = 0; i < cfg->api.auth_token_count && i < JZ_CONFIG_MAX_AUTH_TOKENS; i++) {
        if (cfg->api.auth_tokens[i].token[0] == '\0')
            add_error(errors, 0, "api.auth_tokens[].token", "must not be empty");
        if (cfg->api.auth_tokens[i].role[0] == '\0')
            add_error(errors, 0, "api.auth_tokens[].role", "must not be empty");
    }

    if (cfg->arp_spoof.interval_sec < 1)
        add_error(errors, 0, "arp_spoof.interval_sec", "must be >= 1");
    if (cfg->arp_spoof.target_count < 0)
        add_error(errors, 0, "arp_spoof.target_count", "must be non-negative");
    for (i = 0; i < cfg->arp_spoof.target_count && i < JZ_CONFIG_MAX_ARP_SPOOF_TARGETS; i++) {
        if (!is_valid_ipv4(cfg->arp_spoof.targets[i].target_ip))
            add_error(errors, 0, "arp_spoof.targets[].target_ip", "invalid IPv4 '%s'",
                      cfg->arp_spoof.targets[i].target_ip);
        if (!is_valid_ipv4(cfg->arp_spoof.targets[i].gateway_ip))
            add_error(errors, 0, "arp_spoof.targets[].gateway_ip", "invalid IPv4 '%s'",
                      cfg->arp_spoof.targets[i].gateway_ip);
    }

    if (cfg->discovery.dhcp_probe_interval_sec < 10)
        add_error(errors, 0, "discovery.dhcp_probe_interval_sec", "must be >= 10");

    if (cfg->vlan_count < 0)
        add_error(errors, 0, "vlan_count", "must be non-negative");
    for (i = 0; i < cfg->vlan_count && i < JZ_CONFIG_MAX_VLANS; i++) {
        const jz_config_vlan_t *vl = &cfg->vlans[i];
        if (vl->id < 1 || vl->id > 4094)
            add_error(errors, 0, "vlans[].id", "must be 1-4094, got %d", vl->id);
        if (vl->subnet[0] != '\0' && !is_valid_cidr(vl->subnet))
            add_error(errors, 0, "vlans[].subnet", "invalid CIDR '%s'", vl->subnet);
        {
            int j;
            for (j = 0; j < i; j++) {
                if (cfg->vlans[j].id == vl->id)
                    add_error(errors, 0, "vlans[].id", "duplicate VLAN ID %d", vl->id);
            }
        }
    }

    return (errors && errors->count > start_count) ? -1 : 0;
}

void jz_config_defaults(jz_config_t *cfg)
{
    if (!cfg)
        return;

    memset(cfg, 0, sizeof(*cfg));

    cfg->version = 1;

    snprintf(cfg->system.device_id, sizeof(cfg->system.device_id), "jz-sniff-001");
    snprintf(cfg->system.log_level, sizeof(cfg->system.log_level), "info");
    snprintf(cfg->system.data_dir, sizeof(cfg->system.data_dir), "/var/lib/jz");
    snprintf(cfg->system.run_dir, sizeof(cfg->system.run_dir), "/var/run/jz");
    snprintf(cfg->system.mode, sizeof(cfg->system.mode), "bypass");

    cfg->modules.guard_classifier.enabled = true;
    cfg->modules.guard_classifier.stage = JZ_STAGE_GUARD_CLASSIFIER;

    cfg->modules.arp_honeypot.common.enabled = true;
    cfg->modules.arp_honeypot.common.stage = JZ_STAGE_ARP_HONEYPOT;
    cfg->modules.arp_honeypot.rate_limit_pps = 100;
    cfg->modules.arp_honeypot.log_all = false;

    cfg->modules.icmp_honeypot.common.enabled = true;
    cfg->modules.icmp_honeypot.common.stage = JZ_STAGE_ICMP_HONEYPOT;
    cfg->modules.icmp_honeypot.ttl = 64;
    cfg->modules.icmp_honeypot.rate_limit_pps = 100;

    cfg->modules.sniffer_detect.common.enabled = true;
    cfg->modules.sniffer_detect.common.stage = JZ_STAGE_SNIFFER_DETECT;
    cfg->modules.sniffer_detect.probe_interval_sec = 30;
    cfg->modules.sniffer_detect.probe_count = 5;

    cfg->modules.traffic_weaver.common.enabled = true;
    cfg->modules.traffic_weaver.common.stage = JZ_STAGE_TRAFFIC_WEAVER;
    snprintf(cfg->modules.traffic_weaver.default_action,
             sizeof(cfg->modules.traffic_weaver.default_action), "pass");

    cfg->modules.bg_collector.common.enabled = true;
    cfg->modules.bg_collector.common.stage = JZ_STAGE_BG_COLLECTOR;
    cfg->modules.bg_collector.sample_rate = 1;
    cfg->modules.bg_collector.protocols.arp = true;
    cfg->modules.bg_collector.protocols.dhcp = true;
    cfg->modules.bg_collector.protocols.mdns = true;
    cfg->modules.bg_collector.protocols.ssdp = true;
    cfg->modules.bg_collector.protocols.lldp = true;
    cfg->modules.bg_collector.protocols.cdp = true;
    cfg->modules.bg_collector.protocols.stp = true;
    cfg->modules.bg_collector.protocols.igmp = true;

    cfg->modules.threat_detect.enabled = true;
    cfg->modules.threat_detect.stage = JZ_STAGE_THREAT_DETECT;

    cfg->modules.forensics.common.enabled = true;
    cfg->modules.forensics.common.stage = JZ_STAGE_FORENSICS;
    cfg->modules.forensics.max_payload_bytes = 256;
    cfg->modules.forensics.sample_rate = 0;

    cfg->guards.dynamic.auto_discover = false;
    cfg->guards.dynamic.max_entries = 16384;
    cfg->guards.dynamic.ttl_hours = 24;
    cfg->guards.max_ratio = 30;

    snprintf(cfg->fake_mac_pool.prefix, sizeof(cfg->fake_mac_pool.prefix), "aa:bb:cc");
    cfg->fake_mac_pool.count = 64;

    snprintf(cfg->threats.blacklist_file, sizeof(cfg->threats.blacklist_file), "/etc/jz/blacklist.txt");

    cfg->policy_auto.enabled = true;
    cfg->policy_auto.threshold = 5;
    cfg->policy_auto.window_sec = 300;
    cfg->policy_auto.ttl_sec = 3600;
    cfg->policy_auto.max_auto_policies = 256;
    snprintf(cfg->policy_auto.default_action, sizeof(cfg->policy_auto.default_action), "redirect");
    cfg->policy_auto.escalation = true;

    snprintf(cfg->collector.db_path, sizeof(cfg->collector.db_path), "/var/lib/jz/jz.db");
    cfg->collector.max_db_size_mb = 512;
    cfg->collector.dedup_window_sec = 10;
    cfg->collector.rate_limit_eps = 1000;

    cfg->uploader.enabled = false;
    cfg->uploader.interval_sec = 60;
    cfg->uploader.batch_size = 1000;
    cfg->uploader.compress = true;

    snprintf(cfg->log.format, sizeof(cfg->log.format), "v2");
    cfg->log.heartbeat_interval_sec = 1800;

    cfg->log.syslog.enabled = false;
    snprintf(cfg->log.syslog.format, sizeof(cfg->log.syslog.format), "v1");
    snprintf(cfg->log.syslog.facility, sizeof(cfg->log.syslog.facility), "local0");

    cfg->log.mqtt.enabled = false;
    snprintf(cfg->log.mqtt.format, sizeof(cfg->log.mqtt.format), "v2");
    cfg->log.mqtt.tls = false;
    cfg->log.mqtt.qos = 1;
    cfg->log.mqtt.keepalive_sec = 60;
    cfg->log.mqtt.heartbeat_interval_sec = 300;
    cfg->log.mqtt.heartbeat_max_devices = 200;

    cfg->log.https.enabled = false;
    cfg->log.https.interval_sec = 60;
    cfg->log.https.batch_size = 1000;
    cfg->log.https.compress = true;

    cfg->api.enabled = true;
    snprintf(cfg->api.listen, sizeof(cfg->api.listen), "0.0.0.0:8443");

    cfg->arp_spoof.enabled = false;
    cfg->arp_spoof.interval_sec = 5;
    cfg->arp_spoof.target_count = 0;

    cfg->discovery.aggressive_mode = false;
    cfg->discovery.dhcp_probe_interval_sec = 120;

    cfg->vlan_count = 0;
}

void jz_config_free(jz_config_t *cfg)
{
    if (!cfg)
        return;
}

int jz_config_load(jz_config_t *cfg, const char *path, jz_config_errors_t *errors)
{
    int rc;

    if (!cfg || !path)
        return -1;

    if (errors)
        errors->count = 0;

    jz_config_defaults(cfg);

    rc = parse_file_into_cfg(cfg, path, errors);
    if (rc != 0)
        return -1;

    return jz_config_validate(cfg, errors);
}

int jz_config_load_merged(jz_config_t *cfg, const char *base_path,
                          const char *overlay_path, jz_config_errors_t *errors)
{
    int rc;

    if (!cfg || !base_path || !overlay_path)
        return -1;

    if (errors)
        errors->count = 0;

    jz_config_defaults(cfg);

    rc = parse_file_into_cfg(cfg, base_path, errors);
    if (rc != 0)
        return -1;

    rc = parse_file_into_cfg(cfg, overlay_path, errors);
    if (rc != 0)
        return -1;

    return jz_config_validate(cfg, errors);
}

static int sb_init(jz_strbuf_t *sb)
{
    sb->cap = 8192;
    sb->len = 0;
    sb->data = (char *)malloc(sb->cap);
    if (!sb->data)
        return -1;
    sb->data[0] = '\0';
    return 0;
}

static int sb_ensure(jz_strbuf_t *sb, size_t extra)
{
    size_t needed = sb->len + extra + 1;
    size_t new_cap;
    char *new_data;

    if (needed <= sb->cap)
        return 0;

    new_cap = sb->cap;
    while (new_cap < needed)
        new_cap *= 2;

    new_data = (char *)realloc(sb->data, new_cap);
    if (!new_data)
        return -1;

    sb->data = new_data;
    sb->cap = new_cap;
    return 0;
}

static int sb_appendf(jz_strbuf_t *sb, const char *fmt, ...)
{
    va_list ap;
    va_list cp;
    int need;

    va_start(ap, fmt);
    va_copy(cp, ap);
    need = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (need < 0) {
        va_end(ap);
        return -1;
    }

    if (sb_ensure(sb, (size_t)need) != 0) {
        va_end(ap);
        return -1;
    }

    vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    sb->len += (size_t)need;
    return 0;
}

char *jz_config_serialize(const jz_config_t *cfg)
{
    jz_strbuf_t sb;
    int i;

    if (!cfg)
        return NULL;

    if (sb_init(&sb) != 0)
        return NULL;

    if (sb_appendf(&sb,
                   "version: %d\n"
                   "system:\n"
                   "  device_id: %s\n"
                   "  log_level: %s\n"
                   "  mode: %s\n"
                   "  data_dir: %s\n"
                   "  run_dir: %s\n"
                   "  interfaces:\n",
                   cfg->version,
                   cfg->system.device_id,
                   cfg->system.log_level,
                   cfg->system.mode[0] ? cfg->system.mode : "bypass",
                   cfg->system.data_dir,
                   cfg->system.run_dir) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->system.interface_count; i++) {
        if (sb_appendf(&sb, "    - { name: %s, role: %s, subnet: %s }\n",
                       cfg->system.interfaces[i].name,
                       cfg->system.interfaces[i].role,
                       cfg->system.interfaces[i].subnet) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "modules:\n"
                   "  guard_classifier: { enabled: %s, stage: %d }\n"
                   "  arp_honeypot: { enabled: %s, stage: %d, rate_limit_pps: %d, log_all: %s }\n"
                   "  icmp_honeypot: { enabled: %s, stage: %d, ttl: %d, rate_limit_pps: %d }\n"
                   "  sniffer_detect: { enabled: %s, stage: %d, probe_interval_sec: %d, probe_count: %d }\n"
                   "  traffic_weaver: { enabled: %s, stage: %d, default_action: %s }\n"
                   "  bg_collector:\n"
                   "    enabled: %s\n"
                   "    stage: %d\n"
                   "    sample_rate: %d\n"
                   "    protocols: { arp: %s, dhcp: %s, mdns: %s, ssdp: %s, lldp: %s, cdp: %s, stp: %s, igmp: %s }\n"
                   "  threat_detect: { enabled: %s, stage: %d }\n"
                   "  forensics: { enabled: %s, stage: %d, max_payload_bytes: %d, sample_rate: %d }\n"
                   "guards:\n"
                   "  static:\n",
                   cfg->modules.guard_classifier.enabled ? "true" : "false",
                   cfg->modules.guard_classifier.stage,
                   cfg->modules.arp_honeypot.common.enabled ? "true" : "false",
                   cfg->modules.arp_honeypot.common.stage,
                   cfg->modules.arp_honeypot.rate_limit_pps,
                   cfg->modules.arp_honeypot.log_all ? "true" : "false",
                   cfg->modules.icmp_honeypot.common.enabled ? "true" : "false",
                   cfg->modules.icmp_honeypot.common.stage,
                   cfg->modules.icmp_honeypot.ttl,
                   cfg->modules.icmp_honeypot.rate_limit_pps,
                   cfg->modules.sniffer_detect.common.enabled ? "true" : "false",
                   cfg->modules.sniffer_detect.common.stage,
                   cfg->modules.sniffer_detect.probe_interval_sec,
                   cfg->modules.sniffer_detect.probe_count,
                   cfg->modules.traffic_weaver.common.enabled ? "true" : "false",
                   cfg->modules.traffic_weaver.common.stage,
                   cfg->modules.traffic_weaver.default_action,
                   cfg->modules.bg_collector.common.enabled ? "true" : "false",
                   cfg->modules.bg_collector.common.stage,
                   cfg->modules.bg_collector.sample_rate,
                   cfg->modules.bg_collector.protocols.arp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.dhcp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.mdns ? "true" : "false",
                   cfg->modules.bg_collector.protocols.ssdp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.lldp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.cdp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.stp ? "true" : "false",
                   cfg->modules.bg_collector.protocols.igmp ? "true" : "false",
                   cfg->modules.threat_detect.enabled ? "true" : "false",
                   cfg->modules.threat_detect.stage,
                   cfg->modules.forensics.common.enabled ? "true" : "false",
                   cfg->modules.forensics.common.stage,
                   cfg->modules.forensics.max_payload_bytes,
                   cfg->modules.forensics.sample_rate) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->guards.static_count; i++) {
        if (sb_appendf(&sb, "    - { ip: %s, mac: %s, vlan: %d }\n",
                       cfg->guards.static_entries[i].ip,
                       cfg->guards.static_entries[i].mac,
                       cfg->guards.static_entries[i].vlan) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "  dynamic: { auto_discover: %s, max_entries: %d, ttl_hours: %d, max_ratio: %d }\n"
                   "  whitelist:\n",
                   cfg->guards.dynamic.auto_discover ? "true" : "false",
                   cfg->guards.dynamic.max_entries,
                   cfg->guards.dynamic.ttl_hours,
                   cfg->guards.max_ratio) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->guards.whitelist_count; i++) {
        if (sb_appendf(&sb, "    - { ip: %s, mac: %s, match_mac: %s }\n",
                       cfg->guards.whitelist[i].ip,
                       cfg->guards.whitelist[i].mac,
                       cfg->guards.whitelist[i].match_mac ? "true" : "false") != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb, "  frozen_ips:\n") != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->guards.frozen_ip_count; i++) {
        if (sb_appendf(&sb, "    - { ip: %s, reason: %s }\n",
                       cfg->guards.frozen_ips[i].ip,
                       cfg->guards.frozen_ips[i].reason) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "fake_mac_pool: { prefix: %s, count: %d }\n"
                   "policies:\n",
                   cfg->fake_mac_pool.prefix,
                   cfg->fake_mac_pool.count) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->policy_count; i++) {
        const jz_config_policy_t *p = &cfg->policies[i];
        if (sb_appendf(&sb,
                       "  - { src_ip: %s, dst_ip: %s, src_port: %d, dst_port: %d, proto: %s, action: %s, redirect_port: %d, mirror_port: %d }\n",
                       p->src_ip, p->dst_ip, p->src_port, p->dst_port,
                       p->proto, p->action, p->redirect_port, p->mirror_port) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "threats:\n"
                   "  blacklist_file: %s\n"
                   "  patterns:\n",
                   cfg->threats.blacklist_file) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->threats.pattern_count; i++) {
        const jz_config_threat_pattern_t *p = &cfg->threats.patterns[i];
        if (sb_appendf(&sb,
                       "    - { id: %s, dst_port: %d, proto: %s, threat_level: %s, action: %s, description: %s }\n",
                       p->id, p->dst_port, p->proto, p->threat_level, p->action, p->description) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "collector: { db_path: %s, max_db_size_mb: %d, dedup_window_sec: %d, rate_limit_eps: %d }\n"
                   "uploader: { enabled: %s, platform_url: %s, interval_sec: %d, batch_size: %d, tls_cert: %s, tls_key: %s, compress: %s }\n"
                   "log:\n"
                   "  format: %s\n"
                   "  heartbeat_interval_sec: %d\n"
                   "  syslog:\n"
                   "    enabled: %s\n"
                   "    format: %s\n"
                   "    facility: %s\n"
                   "  mqtt:\n"
                   "    enabled: %s\n"
                   "    format: %s\n"
                   "    broker: %s\n"
                   "    tls: %s\n"
                   "    tls_ca: %s\n"
                   "    client_id: %s\n"
                   "    topic_prefix: %s\n"
                   "    qos: %d\n"
                   "    keepalive_sec: %d\n"
                   "    heartbeat_interval_sec: %d\n"
                   "    heartbeat_max_devices: %d\n"
                   "  https:\n"
                   "    enabled: %s\n"
                   "    url: %s\n"
                   "    tls_cert: %s\n"
                   "    tls_key: %s\n"
                   "    interval_sec: %d\n"
                   "    batch_size: %d\n"
                   "    compress: %s\n"
                   "api:\n"
                   "  enabled: %s\n"
                   "  listen: %s\n"
                   "  tls_cert: %s\n"
                   "  tls_key: %s\n"
                   "  auth_tokens:\n",
                   cfg->collector.db_path,
                   cfg->collector.max_db_size_mb,
                   cfg->collector.dedup_window_sec,
                   cfg->collector.rate_limit_eps,
                   cfg->uploader.enabled ? "true" : "false",
                   cfg->uploader.platform_url,
                   cfg->uploader.interval_sec,
                   cfg->uploader.batch_size,
                   cfg->uploader.tls_cert,
                   cfg->uploader.tls_key,
                   cfg->uploader.compress ? "true" : "false",
                   cfg->log.format,
                   cfg->log.heartbeat_interval_sec,
                   cfg->log.syslog.enabled ? "true" : "false",
                   cfg->log.syslog.format,
                   cfg->log.syslog.facility,
                   cfg->log.mqtt.enabled ? "true" : "false",
                   cfg->log.mqtt.format,
                   cfg->log.mqtt.broker,
                   cfg->log.mqtt.tls ? "true" : "false",
                   cfg->log.mqtt.tls_ca,
                   cfg->log.mqtt.client_id,
                   cfg->log.mqtt.topic_prefix,
                   cfg->log.mqtt.qos,
                   cfg->log.mqtt.keepalive_sec,
                   cfg->log.mqtt.heartbeat_interval_sec,
                   cfg->log.mqtt.heartbeat_max_devices,
                   cfg->log.https.enabled ? "true" : "false",
                   cfg->log.https.url,
                   cfg->log.https.tls_cert,
                   cfg->log.https.tls_key,
                   cfg->log.https.interval_sec,
                   cfg->log.https.batch_size,
                   cfg->log.https.compress ? "true" : "false",
                   cfg->api.enabled ? "true" : "false",
                   cfg->api.listen,
                   cfg->api.tls_cert,
                   cfg->api.tls_key) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->api.auth_token_count; i++) {
        if (sb_appendf(&sb, "    - { token: %s, role: %s }\n",
                       cfg->api.auth_tokens[i].token,
                       cfg->api.auth_tokens[i].role) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "arp_spoof:\n"
                   "  enabled: %s\n"
                   "  interval_sec: %d\n"
                   "  targets:\n",
                   cfg->arp_spoof.enabled ? "true" : "false",
                   cfg->arp_spoof.interval_sec) != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->arp_spoof.target_count; i++) {
        if (sb_appendf(&sb, "    - { target_ip: %s, gateway_ip: %s }\n",
                       cfg->arp_spoof.targets[i].target_ip,
                       cfg->arp_spoof.targets[i].gateway_ip) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    if (sb_appendf(&sb,
                   "discovery:\n"
                   "  aggressive_mode: %s\n"
                   "  dhcp_probe_interval_sec: %d\n",
                   cfg->discovery.aggressive_mode ? "true" : "false",
                   cfg->discovery.dhcp_probe_interval_sec) != 0) {
        free(sb.data);
        return NULL;
    }

    if (sb_appendf(&sb, "vlans:\n") != 0) {
        free(sb.data);
        return NULL;
    }

    for (i = 0; i < cfg->vlan_count; i++) {
        if (sb_appendf(&sb, "  - { id: %d, name: %s, subnet: %s }\n",
                       cfg->vlans[i].id,
                       cfg->vlans[i].name,
                       cfg->vlans[i].subnet) != 0) {
            free(sb.data);
            return NULL;
        }
    }

    return sb.data;
}
