/* mac_pool.h - Fake MAC pool management for jz_sniff_rn */

#ifndef JZ_MAC_POOL_H
#define JZ_MAC_POOL_H

#include <stdint.h>
#include <stdbool.h>

#define JZ_MAC_POOL_DEFAULT_OUI     "\xaa\xbb\xcc"
#define JZ_MAC_POOL_DEFAULT_SIZE    64
#define JZ_MAC_POOL_MAX_SIZE        256
#define JZ_MAC_POOL_PIN_PATH        "/sys/fs/bpf/jz/jz_fake_mac_pool"

struct jz_mac_pool_config {
    uint8_t  oui[3];          /* OUI prefix for generated MACs */
    uint32_t pool_size;       /* number of MACs to generate (max 256) */
};

struct jz_mac_pool_entry {
    uint8_t  mac[6];
    uint8_t  in_use;
    uint8_t  _pad;
    uint32_t assigned_ip;     /* guard IP this MAC is assigned to */
};

struct jz_mac_pool {
    struct jz_mac_pool_entry *entries;
    uint32_t size;
    uint32_t next_alloc;      /* round-robin index */
    uint8_t  oui[3];
    int      map_fd;          /* BPF map file descriptor */
};

/* Initialize pool with config. Returns 0 on success, -errno on error. */
int jz_mac_pool_init(struct jz_mac_pool *pool, const struct jz_mac_pool_config *config);

/* Destroy pool and free resources (does NOT unpin the BPF map). */
void jz_mac_pool_destroy(struct jz_mac_pool *pool);

/* Allocate a MAC for a guard IP. If the IP already has a MAC assigned,
 * returns the same one. Otherwise assigns the next available MAC.
 * Returns pointer to the 6-byte MAC, or NULL on error. */
const uint8_t *jz_mac_pool_alloc(struct jz_mac_pool *pool, uint32_t guard_ip);

/* Release a MAC assignment for a guard IP. */
int jz_mac_pool_release(struct jz_mac_pool *pool, uint32_t guard_ip);

/* Populate the BPF map with current pool state.
 * Opens the pinned map at JZ_MAC_POOL_PIN_PATH.
 * Returns 0 on success, -errno on error. */
int jz_mac_pool_sync_bpf(struct jz_mac_pool *pool);

/* Populate via an already-open map FD. */
int jz_mac_pool_sync_bpf_fd(struct jz_mac_pool *pool, int map_fd);

#endif /* JZ_MAC_POOL_H */
