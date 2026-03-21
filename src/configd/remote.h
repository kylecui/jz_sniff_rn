#ifndef JZ_REMOTE_H
#define JZ_REMOTE_H

#include <stdbool.h>
#include <stdint.h>

#ifndef JZ_CONFIG_H
typedef struct jz_config jz_config_t;
#endif

#ifndef JZ_DB_H
typedef struct jz_db jz_db_t;
#endif


typedef struct jz_remote jz_remote_t;


typedef int (*jz_remote_config_cb)(const char *json_body, int json_len,
                                   int version, void *user_data);


struct jz_remote {
    void              *mgr;
    bool               enabled;
    int               *config_version_ptr;
    int                config_version;

    char               listen_addr[64];
    char               tls_cert[256];
    char               tls_key[256];
    char               tls_ca[256];

    jz_remote_config_cb config_cb;
    void              *cb_data;

    void              *tls_cert_pem;
    void              *tls_key_pem;
    void              *tls_ca_pem;
};


int  jz_remote_init(jz_remote_t *remote, const char *listen_addr,
                    const char *tls_cert, const char *tls_key, const char *tls_ca);


void jz_remote_shutdown(jz_remote_t *remote);


void jz_remote_poll(jz_remote_t *remote, int timeout_ms);


int  jz_remote_set_callback(jz_remote_t *remote, jz_remote_config_cb cb, void *data);

#endif
