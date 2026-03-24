/* SPDX-License-Identifier: MIT */
/*
 * config.h - YAML configuration structures and APIs for jz_sniff_rn.
 *
 * This module defines the in-memory schema for base.yaml/profile overlays,
 * validation error reporting, and loader/serializer entry points.
 */

#ifndef JZ_CONFIG_H
#define JZ_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define JZ_CONFIG_STR_SHORT                64
#define JZ_CONFIG_STR_MEDIUM               128
#define JZ_CONFIG_STR_LONG                 256

#define JZ_CONFIG_MAX_STATIC_GUARDS        256
#define JZ_CONFIG_MAX_WHITELIST            256
#define JZ_CONFIG_MAX_POLICIES             512
#define JZ_CONFIG_MAX_THREAT_PATTERNS      512
#define JZ_CONFIG_MAX_AUTH_TOKENS          16
#define JZ_CONFIG_MAX_INTERFACES           8
#define JZ_CONFIG_MAX_FROZEN_IPS           256
#define JZ_CONFIG_MAX_ARP_SPOOF_TARGETS   32

#define JZ_CONFIG_MAX_ERRORS               64

/* Valid stage IDs in the BPF processing pipeline.
 * MUST match bpf/include/jz_common.h — stages 21-28 sit between
 * rSwitch VLAN(20) and ACL(30). */
#define JZ_STAGE_GUARD_CLASSIFIER         21
#define JZ_STAGE_ARP_HONEYPOT             22
#define JZ_STAGE_ICMP_HONEYPOT            23
#define JZ_STAGE_SNIFFER_DETECT           24
#define JZ_STAGE_TRAFFIC_WEAVER           25
#define JZ_STAGE_BG_COLLECTOR             26
#define JZ_STAGE_THREAT_DETECT            27
#define JZ_STAGE_FORENSICS                28

typedef struct jz_config_error {
    int  line;                                   /* YAML source line (0 if unknown) */
    char field[JZ_CONFIG_STR_MEDIUM];            /* Field path, e.g. guards.static[0].ip */
    char message[JZ_CONFIG_STR_LONG];            /* Human-readable error text */
} jz_config_error_t;

typedef struct jz_config_errors {
    jz_config_error_t errors[JZ_CONFIG_MAX_ERRORS];
    int count;
} jz_config_errors_t;

typedef struct jz_config_interface {
    char name[JZ_CONFIG_STR_SHORT];          /* e.g. "eth0", "ens33" */
    char role[JZ_CONFIG_STR_SHORT];          /* "monitor", "manage", "mirror" */
    char subnet[JZ_CONFIG_STR_SHORT];        /* e.g. "10.0.1.0/24" */
} jz_config_interface_t;

typedef struct jz_config_system {
    char device_id[JZ_CONFIG_STR_SHORT];
    char log_level[JZ_CONFIG_STR_SHORT];
    char data_dir[JZ_CONFIG_STR_LONG];
    char run_dir[JZ_CONFIG_STR_LONG];
    char mode[JZ_CONFIG_STR_SHORT];              /* "bypass" (default) or "inline" */

    jz_config_interface_t interfaces[JZ_CONFIG_MAX_INTERFACES];
    int interface_count;
} jz_config_system_t;

typedef struct jz_config_module {
    bool enabled;
    int  stage;
} jz_config_module_t;

typedef struct jz_config_bg_protocols {
    bool arp;
    bool dhcp;
    bool mdns;
    bool ssdp;
    bool lldp;
    bool cdp;
    bool stp;
    bool igmp;
} jz_config_bg_protocols_t;

typedef struct jz_config_modules {
    jz_config_module_t guard_classifier;

    struct {
        jz_config_module_t common;
        int  rate_limit_pps;
        bool log_all;
    } arp_honeypot;

    struct {
        jz_config_module_t common;
        int ttl;
        int rate_limit_pps;
    } icmp_honeypot;

    struct {
        jz_config_module_t common;
        int probe_interval_sec;
        int probe_count;
    } sniffer_detect;

    struct {
        jz_config_module_t common;
        char default_action[JZ_CONFIG_STR_SHORT];
    } traffic_weaver;

    struct {
        jz_config_module_t common;
        int sample_rate;
        jz_config_bg_protocols_t protocols;
    } bg_collector;

    jz_config_module_t threat_detect;

    struct {
        jz_config_module_t common;
        int max_payload_bytes;
        int sample_rate;
    } forensics;
} jz_config_modules_t;

typedef struct jz_config_guard_static {
    char ip[JZ_CONFIG_STR_SHORT];
    char mac[JZ_CONFIG_STR_SHORT];
    int  vlan;
} jz_config_guard_static_t;

typedef struct jz_config_guard_dynamic {
    bool auto_discover;
    int  max_entries;
    int  ttl_hours;
} jz_config_guard_dynamic_t;

typedef struct jz_config_whitelist {
    char ip[JZ_CONFIG_STR_SHORT];
    char mac[JZ_CONFIG_STR_SHORT];
    bool match_mac;
} jz_config_whitelist_t;

typedef struct jz_config_frozen_ip {
    char ip[JZ_CONFIG_STR_SHORT];
    char reason[JZ_CONFIG_STR_MEDIUM];
} jz_config_frozen_ip_t;

typedef struct jz_config_guards {
    jz_config_guard_static_t static_entries[JZ_CONFIG_MAX_STATIC_GUARDS];
    int static_count;

    jz_config_guard_dynamic_t dynamic;

    jz_config_whitelist_t whitelist[JZ_CONFIG_MAX_WHITELIST];
    int whitelist_count;

    jz_config_frozen_ip_t frozen_ips[JZ_CONFIG_MAX_FROZEN_IPS];
    int frozen_ip_count;

    int max_ratio;   /* max % of subnet IPs to use as dynamic guards (0-100) */
} jz_config_guards_t;

typedef struct jz_config_mac_pool {
    char prefix[JZ_CONFIG_STR_SHORT];
    int  count;
} jz_config_mac_pool_t;

typedef struct jz_config_policy {
    char src_ip[JZ_CONFIG_STR_SHORT];
    char dst_ip[JZ_CONFIG_STR_SHORT];
    int  src_port;
    int  dst_port;
    char proto[JZ_CONFIG_STR_SHORT];
    char action[JZ_CONFIG_STR_SHORT];
    int  redirect_port;
    int  mirror_port;
} jz_config_policy_t;

typedef struct jz_config_policy_auto {
    bool enabled;
    int  threshold;
    int  window_sec;
    int  ttl_sec;
    int  max_auto_policies;
    char default_action[JZ_CONFIG_STR_SHORT];
    bool escalation;
} jz_config_policy_auto_t;

typedef struct jz_config_threat_pattern {
    char id[JZ_CONFIG_STR_SHORT];
    int  dst_port;
    char proto[JZ_CONFIG_STR_SHORT];
    char threat_level[JZ_CONFIG_STR_SHORT];
    char action[JZ_CONFIG_STR_SHORT];
    char description[JZ_CONFIG_STR_LONG];
} jz_config_threat_pattern_t;

typedef struct jz_config_threats {
    char blacklist_file[JZ_CONFIG_STR_LONG];
    jz_config_threat_pattern_t patterns[JZ_CONFIG_MAX_THREAT_PATTERNS];
    int pattern_count;
} jz_config_threats_t;

typedef struct jz_config_collector {
    char db_path[JZ_CONFIG_STR_LONG];
    int  max_db_size_mb;
    int  dedup_window_sec;
    int  rate_limit_eps;
} jz_config_collector_t;

typedef struct jz_config_uploader {
    bool enabled;
    char platform_url[JZ_CONFIG_STR_LONG];
    int  interval_sec;
    int  batch_size;
    char tls_cert[JZ_CONFIG_STR_LONG];
    char tls_key[JZ_CONFIG_STR_LONG];
    bool compress;
} jz_config_uploader_t;

typedef struct jz_config_auth_token {
    char token[JZ_CONFIG_STR_LONG];
    char role[JZ_CONFIG_STR_SHORT];
} jz_config_auth_token_t;

typedef struct jz_config_api {
    bool enabled;
    char listen[JZ_CONFIG_STR_SHORT];
    char tls_cert[JZ_CONFIG_STR_LONG];
    char tls_key[JZ_CONFIG_STR_LONG];
    jz_config_auth_token_t auth_tokens[JZ_CONFIG_MAX_AUTH_TOKENS];
    int auth_token_count;
} jz_config_api_t;

typedef struct jz_config_log_syslog {
    bool enabled;
    char format[JZ_CONFIG_STR_SHORT];      /* "v1" or "v2" */
    char facility[JZ_CONFIG_STR_SHORT];    /* "local0" through "local7" */
} jz_config_log_syslog_t;

typedef struct jz_config_log_mqtt {
    bool enabled;
    char format[JZ_CONFIG_STR_SHORT];      /* "v1" or "v2" */
    char broker[JZ_CONFIG_STR_LONG];       /* "tcp://broker:1883" */
    bool tls;
    char tls_ca[JZ_CONFIG_STR_LONG];
    char client_id[JZ_CONFIG_STR_MEDIUM];
    char topic_prefix[JZ_CONFIG_STR_MEDIUM];
    int  qos;                               /* 0, 1, or 2 */
    int  keepalive_sec;
    int  heartbeat_interval_sec;
    int  heartbeat_max_devices;
} jz_config_log_mqtt_t;

typedef struct jz_config_log_https {
    bool enabled;
    char url[JZ_CONFIG_STR_LONG];
    char tls_cert[JZ_CONFIG_STR_LONG];
    char tls_key[JZ_CONFIG_STR_LONG];
    int  interval_sec;
    int  batch_size;
    bool compress;
} jz_config_log_https_t;

typedef struct jz_config_log {
    char format[JZ_CONFIG_STR_SHORT];      /* global default: "v2" */
    int  heartbeat_interval_sec;            /* 1800 for V1 syslog heartbeat */
    jz_config_log_syslog_t syslog;
    jz_config_log_mqtt_t mqtt;
    jz_config_log_https_t https;
} jz_config_log_t;

typedef struct jz_config_arp_spoof_target {
    char target_ip[JZ_CONFIG_STR_SHORT];    /* IP of the host whose traffic we intercept */
    char gateway_ip[JZ_CONFIG_STR_SHORT];   /* IP of the gateway we impersonate */
} jz_config_arp_spoof_target_t;

typedef struct jz_config_arp_spoof {
    bool enabled;
    int  interval_sec;                      /* GARP send interval (default 5) */
    jz_config_arp_spoof_target_t targets[JZ_CONFIG_MAX_ARP_SPOOF_TARGETS];
    int  target_count;
} jz_config_arp_spoof_t;

typedef struct jz_config {
    int version;
    jz_config_system_t system;
    jz_config_modules_t modules;
    jz_config_guards_t guards;
    jz_config_mac_pool_t fake_mac_pool;
    jz_config_policy_t policies[JZ_CONFIG_MAX_POLICIES];
    int policy_count;
    jz_config_policy_auto_t policy_auto;
    jz_config_threats_t threats;
    jz_config_collector_t collector;
    jz_config_uploader_t uploader;
    jz_config_log_t log;
    jz_config_api_t api;
    jz_config_arp_spoof_t arp_spoof;
} jz_config_t;

/* Load config from YAML file. Returns 0 on success, -1 on error.
 * Errors are written to errors if non-NULL. */
int jz_config_load(jz_config_t *cfg, const char *path, jz_config_errors_t *errors);

/* Load config with profile inheritance: base <- overlay.
 * Base is loaded first, then overlay merges on top. */
int jz_config_load_merged(jz_config_t *cfg,
                          const char *base_path,
                          const char *overlay_path,
                          jz_config_errors_t *errors);

/* Validate a loaded config. Returns 0 if valid, -1 if errors found.
 * Errors are appended to errors. */
int jz_config_validate(const jz_config_t *cfg, jz_config_errors_t *errors);

/* Free any dynamically allocated resources in config. */
void jz_config_free(jz_config_t *cfg);

/* Initialize config to sensible defaults (matching base.yaml defaults). */
void jz_config_defaults(jz_config_t *cfg);

/* Serialize config to YAML string. Caller must free() returned string.
 * Returns NULL on error. */
char *jz_config_serialize(const jz_config_t *cfg);

#endif /* JZ_CONFIG_H */
