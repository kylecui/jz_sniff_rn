/* SPDX-License-Identifier: MIT */
/*
 * api.h - REST API module for sniffd.
 *
 * Exposes HTTPS management endpoints for status, guard operations,
 * log queries, statistics, and configuration management.
 */

#ifndef JZ_API_H
#define JZ_API_H

#include <stdbool.h>

#ifndef JZ_CONFIG_H
typedef struct jz_config jz_config_t;
#endif

#ifndef JZ_DB_H
typedef struct jz_db jz_db_t;
#endif

#ifndef JZ_BPF_LOADER_H
typedef struct jz_bpf_loader jz_bpf_loader_t;
#endif

#ifndef JZ_GUARD_MGR_H
typedef struct jz_guard_mgr jz_guard_mgr_t;
#endif

#ifndef JZ_DISCOVERY_H
typedef struct jz_discovery jz_discovery_t;
#endif

#ifndef JZ_GUARD_AUTO_H
typedef struct jz_guard_auto jz_guard_auto_t;
#endif

#ifndef JZ_POLICY_MGR_H
typedef struct jz_policy_mgr jz_policy_mgr_t;
#endif

typedef enum {
    JZ_API_ROLE_VIEWER = 0,
    JZ_API_ROLE_OPERATOR = 1,
    JZ_API_ROLE_ADMIN = 2
} jz_api_role_t;

typedef struct jz_api {
    void *mgr;
    bool enabled;
    int port;

    char tls_cert[256];
    char tls_key[256];
    char tls_ca[256];
    char auth_token[256];

    void *tls_cert_pem;
    void *tls_key_pem;
    void *tls_ca_pem;

    jz_bpf_loader_t *loader;
    jz_guard_mgr_t *guard_mgr;
    jz_discovery_t *discovery;
    jz_guard_auto_t *guard_auto;
    jz_policy_mgr_t *policy_mgr;
    jz_config_t *config;
    jz_db_t *db;
} jz_api_t;

int jz_api_init(jz_api_t *api, int port,
                const char *tls_cert, const char *tls_key,
                const char *tls_ca, const char *auth_token);

void jz_api_destroy(jz_api_t *api);

void jz_api_poll(jz_api_t *api, int timeout_ms);

#endif /* JZ_API_H */
