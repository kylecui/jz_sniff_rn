/* mac_pool.c - Fake MAC pool management implementation for jz_sniff_rn */

#include "mac_pool.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void fill_random_tail(uint8_t tail[3], int urandom_fd)
{
    ssize_t nread;

    if (urandom_fd >= 0) {
        nread = read(urandom_fd, tail, 3);
        if (nread == 3)
            return;
    }

    tail[0] = (uint8_t)(rand() & 0xff);
    tail[1] = (uint8_t)(rand() & 0xff);
    tail[2] = (uint8_t)(rand() & 0xff);
}

int jz_mac_pool_init(struct jz_mac_pool *pool, const struct jz_mac_pool_config *config)
{
    uint32_t i;
    int urandom_fd;

    if (!pool || !config)
        return -EINVAL;

    if (config->pool_size == 0 || config->pool_size > JZ_MAC_POOL_MAX_SIZE) {
        fprintf(stderr, "jz_mac_pool: invalid pool size %u\n", config->pool_size);
        return -EINVAL;
    }

    memset(pool, 0, sizeof(*pool));
    pool->entries = calloc(config->pool_size, sizeof(*pool->entries));
    if (!pool->entries) {
        fprintf(stderr, "jz_mac_pool: calloc failed: %s\n", strerror(errno));
        return -errno;
    }

    memcpy(pool->oui, config->oui, sizeof(pool->oui));
    pool->size = config->pool_size;
    pool->next_alloc = 0;
    pool->map_fd = -1;

    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
        srand((unsigned int)(time(NULL) + getpid()));

    for (i = 0; i < pool->size; i++) {
        uint8_t tail[3];

        fill_random_tail(tail, urandom_fd);

        pool->entries[i].mac[0] = pool->oui[0];
        pool->entries[i].mac[1] = pool->oui[1];
        pool->entries[i].mac[2] = pool->oui[2];
        pool->entries[i].mac[3] = tail[0];
        pool->entries[i].mac[4] = tail[1];
        pool->entries[i].mac[5] = tail[2];
        pool->entries[i].in_use = 1;
        pool->entries[i].assigned_ip = 0;
    }

    if (urandom_fd >= 0)
        close(urandom_fd);

    return 0;
}

void jz_mac_pool_destroy(struct jz_mac_pool *pool)
{
    if (!pool)
        return;

    free(pool->entries);

    if (pool->map_fd >= 0)
        close(pool->map_fd);

    memset(pool, 0, sizeof(*pool));
    pool->map_fd = -1;
}

const uint8_t *jz_mac_pool_alloc(struct jz_mac_pool *pool, uint32_t guard_ip)
{
    uint32_t i;

    if (!pool || !pool->entries || pool->size == 0 || guard_ip == 0)
        return NULL;

    for (i = 0; i < pool->size; i++) {
        if (pool->entries[i].assigned_ip == guard_ip)
            return pool->entries[i].mac;
    }

    for (i = 0; i < pool->size; i++) {
        uint32_t idx = (pool->next_alloc + i) % pool->size;

        if (pool->entries[idx].assigned_ip == 0) {
            pool->entries[idx].assigned_ip = guard_ip;
            pool->next_alloc = (idx + 1) % pool->size;
            return pool->entries[idx].mac;
        }
    }

    fprintf(stderr, "jz_mac_pool: no free MAC entries for guard IP %u\n", guard_ip);
    return NULL;
}

int jz_mac_pool_release(struct jz_mac_pool *pool, uint32_t guard_ip)
{
    uint32_t i;

    if (!pool || !pool->entries || guard_ip == 0)
        return -EINVAL;

    for (i = 0; i < pool->size; i++) {
        if (pool->entries[i].assigned_ip == guard_ip) {
            pool->entries[i].assigned_ip = 0;
            return 0;
        }
    }

    return -ENOENT;
}

int jz_mac_pool_sync_bpf_fd(struct jz_mac_pool *pool, int map_fd)
{
    uint32_t idx;

    if (!pool || !pool->entries || pool->size == 0)
        return -EINVAL;

    if (map_fd < 0)
        return -EBADF;

    for (idx = 0; idx < JZ_MAC_POOL_MAX_SIZE; idx++) {
        struct jz_mac_pool_entry value;

        if (idx < pool->size)
            value = pool->entries[idx];
        else
            memset(&value, 0, sizeof(value));

        if (bpf_map_update_elem(map_fd, &idx, &value, BPF_ANY) != 0) {
            int err = errno;
            fprintf(stderr, "jz_mac_pool: bpf_map_update_elem failed at %u: %s\n",
                    idx, strerror(err));
            return -err;
        }
    }

    return 0;
}

int jz_mac_pool_sync_bpf(struct jz_mac_pool *pool)
{
    int fd;
    int ret;

    if (!pool)
        return -EINVAL;

    fd = bpf_obj_get(JZ_MAC_POOL_PIN_PATH);
    if (fd < 0) {
        int err = errno;
        fprintf(stderr, "jz_mac_pool: bpf_obj_get(%s) failed: %s\n",
                JZ_MAC_POOL_PIN_PATH, strerror(err));
        return -err;
    }

    if (pool->map_fd >= 0 && pool->map_fd != fd)
        close(pool->map_fd);

    pool->map_fd = fd;
    ret = jz_mac_pool_sync_bpf_fd(pool, pool->map_fd);

    if (ret != 0) {
        close(pool->map_fd);
        pool->map_fd = -1;
    }

    return ret;
}
