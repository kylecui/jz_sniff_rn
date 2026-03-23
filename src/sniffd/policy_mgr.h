#ifndef JZ_POLICY_MGR_H
#define JZ_POLICY_MGR_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define JZ_POLICY_MGR_MAX_POLICIES        512
#define JZ_POLICY_MGR_EXPIRY_CHECK_SEC    30

typedef struct jz_policy_entry_user {
    uint32_t id;
    char name[64];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t action;
    uint8_t redirect_port;
    uint8_t mirror_port;
    bool is_auto;
    bool enabled;
    uint64_t created_at;
    uint32_t ttl_sec;
} jz_policy_entry_user_t;

typedef struct jz_policy_mgr {
    int flow_policy_map_fd;
    jz_policy_entry_user_t entries[JZ_POLICY_MGR_MAX_POLICIES];
    int count;
    uint32_t next_id;
    uint64_t last_expiry_check_ns;
    bool initialized;
} jz_policy_mgr_t;

int jz_policy_mgr_init(jz_policy_mgr_t *pm, const jz_config_t *cfg);
void jz_policy_mgr_destroy(jz_policy_mgr_t *pm);
int jz_policy_mgr_tick(jz_policy_mgr_t *pm);

int jz_policy_mgr_add(jz_policy_mgr_t *pm, const jz_policy_entry_user_t *entry);
int jz_policy_mgr_remove(jz_policy_mgr_t *pm, uint32_t id);
int jz_policy_mgr_update(jz_policy_mgr_t *pm, uint32_t id, const jz_policy_entry_user_t *entry);
const jz_policy_entry_user_t *jz_policy_mgr_find(const jz_policy_mgr_t *pm, uint32_t id);
int jz_policy_mgr_list_json(const jz_policy_mgr_t *pm, char *buf, size_t buf_size);
int jz_policy_mgr_load_config(jz_policy_mgr_t *pm, const jz_config_t *cfg);
void jz_policy_mgr_update_config(jz_policy_mgr_t *pm, const jz_config_t *cfg);

#endif
