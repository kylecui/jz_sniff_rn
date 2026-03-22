/* test_pipeline.c -- BPF pipeline integration test
 *
 * End-to-end tests for the jz_sniff_rn BPF pipeline using
 * bpf_prog_test_run to chain guard_classifier -> arp_honeypot -> icmp_honeypot
 * via rs_progs tail-call array.
 *
 * Requirements:
 *   - Root privileges (CAP_BPF)
 *   - Compiled BPF objects in build/bpf/
 *   - Kernel 5.8+ with BTF support
 *   - Clean /sys/fs/bpf/jz_integ_test/ (created/destroyed by test)
 *
 * Build:
 *   make test-integration   (runs with sudo)
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * uapi.h / map_defs.h contain __uint()/SEC() BPF map definitions that
 * don't compile in userspace. We manually replicate the structs we need.
 */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

#define RS_ONLYKEY 0

struct rs_layers {
    uint16_t eth_proto;
    uint16_t vlan_ids[2];
    uint8_t  vlan_depth;
    uint8_t  ip_proto;
    uint8_t  pad[2];
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t l2_offset;
    uint16_t l3_offset;
    uint16_t l4_offset;
    uint16_t payload_offset;
    uint32_t payload_len;
};

struct rs_ctx {
    uint32_t ifindex;
    uint32_t timestamp;
    uint8_t  parsed;
    uint8_t  modified;
    uint8_t  pad[2];
    struct rs_layers layers;
    uint16_t ingress_vlan;
    uint16_t egress_vlan;
    uint8_t  prio;
    uint8_t  dscp;
    uint8_t  ecn;
    uint8_t  traffic_class;
    uint32_t egress_ifindex;
    uint8_t  action;
    uint8_t  mirror;
    uint16_t mirror_port;
    uint32_t error;
    uint32_t drop_reason;
    uint32_t next_prog_id;
    uint32_t call_depth;
    uint32_t reserved[4];
};

/* ── BPF object paths ── */
#define BPF_OBJ_DIR        "build/bpf"
#define GC_OBJ_PATH        BPF_OBJ_DIR "/jz_guard_classifier.bpf.o"
#define ARP_OBJ_PATH       BPF_OBJ_DIR "/jz_arp_honeypot.bpf.o"
#define ICMP_OBJ_PATH      BPF_OBJ_DIR "/jz_icmp_honeypot.bpf.o"

/* ── Test constants ── */
#define TEST_GUARDED_IP     0x0A000132  /* 10.0.1.50 (network byte order set below) */
#define TEST_SRC_IP         0x0A00010A  /* 10.0.1.10 */
#define TEST_UNGUARDED_IP   0x0A000199  /* 10.0.1.153 */
#define TEST_IFINDEX        2

static const uint8_t TEST_SRC_MAC[6]  = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t TEST_FAKE_MAC[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
static const uint8_t BCAST_MAC[6]     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ── Packet structures ── */

struct test_arp_packet {
    struct ethhdr eth;
    struct {
        uint16_t ar_hrd;
        uint16_t ar_pro;
        uint8_t  ar_hln;
        uint8_t  ar_pln;
        uint16_t ar_op;
        uint8_t  ar_sha[6];
        uint32_t ar_sip;
        uint8_t  ar_tha[6];
        uint32_t ar_tip;
    } __attribute__((packed)) arp;
} __attribute__((packed));

struct test_icmp_packet {
    struct ethhdr eth;
    struct iphdr  ip;
    struct {
        uint8_t  type;
        uint8_t  code;
        uint16_t checksum;
        uint16_t id;
        uint16_t sequence;
    } __attribute__((packed)) icmp;
    uint8_t payload[56];
} __attribute__((packed));

/* ── Global test state ── */

struct test_state {
    struct bpf_object *obj_gc;
    struct bpf_object *obj_arp;
    struct bpf_object *obj_icmp;

    int gc_prog_fd;
    int arp_prog_fd;
    int icmp_prog_fd;

    int rs_ctx_map_fd;
    int rs_progs_fd;
    int rs_event_bus_fd;
    int jz_static_guards_fd;
    int jz_dynamic_guards_fd;
    int jz_whitelist_fd;
    int jz_guard_result_map_fd;

    int jz_arp_config_fd;
    int jz_fake_mac_pool_fd;

    int jz_icmp_config_fd;

    int ncpus;
};

/* ── Helpers ── */

static uint16_t ip_checksum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; i++)
        sum += p[i];
    if (len & 1)
        sum += ((const uint8_t *)data)[len - 1];
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void build_arp_request(struct test_arp_packet *pkt,
                              uint32_t src_ip_he,
                              uint32_t target_ip_he)
{
    memset(pkt, 0, sizeof(*pkt));

    memcpy(pkt->eth.h_source, TEST_SRC_MAC, 6);
    memcpy(pkt->eth.h_dest, BCAST_MAC, 6);
    pkt->eth.h_proto = htons(ETH_P_ARP);

    pkt->arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt->arp.ar_pro = htons(ETH_P_IP);
    pkt->arp.ar_hln = 6;
    pkt->arp.ar_pln = 4;
    pkt->arp.ar_op  = htons(ARPOP_REQUEST);
    memcpy(pkt->arp.ar_sha, TEST_SRC_MAC, 6);
    pkt->arp.ar_sip = htonl(src_ip_he);
    memset(pkt->arp.ar_tha, 0, 6);
    pkt->arp.ar_tip = htonl(target_ip_he);
}

static void build_icmp_echo_request(struct test_icmp_packet *pkt,
                                    uint32_t src_ip_he,
                                    uint32_t dst_ip_he)
{
    memset(pkt, 0, sizeof(*pkt));

    memcpy(pkt->eth.h_source, TEST_SRC_MAC, 6);
    memcpy(pkt->eth.h_dest, BCAST_MAC, 6);
    pkt->eth.h_proto = htons(ETH_P_IP);

    pkt->ip.version  = 4;
    pkt->ip.ihl      = 5;
    pkt->ip.tot_len  = htons(sizeof(struct iphdr) + 8 + sizeof(pkt->payload));
    pkt->ip.ttl      = 64;
    pkt->ip.protocol = IPPROTO_ICMP;
    pkt->ip.saddr    = htonl(src_ip_he);
    pkt->ip.daddr    = htonl(dst_ip_he);
    pkt->ip.check    = ip_checksum(&pkt->ip, sizeof(pkt->ip));

    pkt->icmp.type     = 8;  /* echo request */
    pkt->icmp.code     = 0;
    pkt->icmp.id       = htons(0x1234);
    pkt->icmp.sequence = htons(1);

    /* Fill payload with pattern */
    for (int i = 0; i < (int)sizeof(pkt->payload); i++)
        pkt->payload[i] = (uint8_t)(i & 0xFF);

    /* ICMP checksum over type/code/checksum/id/sequence + payload */
    pkt->icmp.checksum = 0;
    pkt->icmp.checksum = ip_checksum(&pkt->icmp, 8 + sizeof(pkt->payload));
}

/* Set up rs_ctx_map[0] on CPU 0 with parsed packet metadata */
static int setup_rs_ctx(struct test_state *st,
                        uint16_t eth_proto_ne,
                        uint32_t saddr_ne,
                        uint32_t daddr_ne,
                        uint8_t  ip_proto,
                        uint16_t l3_offset)
{
    struct rs_ctx *ctx_vals = calloc(st->ncpus, sizeof(struct rs_ctx));
    if (!ctx_vals)
        return -ENOMEM;

    ctx_vals[0].ifindex           = TEST_IFINDEX;
    ctx_vals[0].parsed            = 1;
    ctx_vals[0].layers.eth_proto  = eth_proto_ne;
    ctx_vals[0].layers.saddr      = saddr_ne;
    ctx_vals[0].layers.daddr      = daddr_ne;
    ctx_vals[0].layers.ip_proto   = ip_proto;
    ctx_vals[0].layers.l2_offset  = 0;
    ctx_vals[0].layers.l3_offset  = l3_offset;
    ctx_vals[0].layers.l4_offset  = l3_offset + sizeof(struct iphdr);
    ctx_vals[0].next_prog_id      = 0;
    ctx_vals[0].call_depth        = 0;

    uint32_t key = 0;
    int err = bpf_map_update_elem(st->rs_ctx_map_fd, &key, ctx_vals, BPF_ANY);
    free(ctx_vals);
    return err;
}

/* Read guard result from CPU 0 */
static int read_guard_result(struct test_state *st, struct jz_guard_result *out)
{
    struct jz_guard_result *vals = calloc(st->ncpus, sizeof(struct jz_guard_result));
    if (!vals)
        return -ENOMEM;

    uint32_t key = 0;
    int err = bpf_map_lookup_elem(st->jz_guard_result_map_fd, &key, vals);
    if (!err)
        memcpy(out, &vals[0], sizeof(*out));
    free(vals);
    return err;
}

/* Add a static guard entry */
static int add_static_guard(struct test_state *st, uint32_t ip_he,
                            const uint8_t *fake_mac)
{
    uint32_t key = htonl(ip_he);
    struct jz_guard_entry entry = {
        .ip_addr    = key,
        .guard_type = JZ_GUARD_STATIC,
        .enabled    = 1,
        .hit_count  = 0,
    };
    if (fake_mac)
        memcpy(entry.fake_mac, fake_mac, 6);
    return bpf_map_update_elem(st->jz_static_guards_fd, &key, &entry, BPF_ANY);
}

/* Add a dynamic guard entry */
static int add_dynamic_guard(struct test_state *st, uint32_t ip_he,
                             const uint8_t *fake_mac)
{
    uint32_t key = htonl(ip_he);
    struct jz_guard_entry entry = {
        .ip_addr    = key,
        .guard_type = JZ_GUARD_DYNAMIC,
        .enabled    = 1,
        .hit_count  = 0,
    };
    if (fake_mac)
        memcpy(entry.fake_mac, fake_mac, 6);
    return bpf_map_update_elem(st->jz_dynamic_guards_fd, &key, &entry, BPF_ANY);
}

/* Add whitelist entry */
static int add_whitelist(struct test_state *st, uint32_t ip_he)
{
    uint32_t key = htonl(ip_he);
    struct jz_whitelist_entry entry = {
        .ip_addr   = key,
        .enabled   = 1,
        .match_mac = 0,
    };
    return bpf_map_update_elem(st->jz_whitelist_fd, &key, &entry, BPF_ANY);
}

/* Set ARP config */
static int set_arp_config(struct test_state *st, uint8_t enabled,
                          uint16_t rate_limit_pps)
{
    uint32_t key = 0;
    struct jz_arp_config cfg = {
        .enabled        = enabled,
        .log_all        = 1,
        .rate_limit_pps = rate_limit_pps,
    };
    return bpf_map_update_elem(st->jz_arp_config_fd, &key, &cfg, BPF_ANY);
}

/* Set ICMP config */
static int set_icmp_config(struct test_state *st, uint8_t enabled,
                           uint8_t ttl, uint16_t rate_limit_pps)
{
    uint32_t key = 0;
    struct jz_icmp_config cfg = {
        .enabled        = enabled,
        .ttl            = ttl,
        .rate_limit_pps = rate_limit_pps,
    };
    return bpf_map_update_elem(st->jz_icmp_config_fd, &key, &cfg, BPF_ANY);
}

/* Set fake MAC pool entry */
static int set_fake_mac(struct test_state *st, uint32_t idx,
                        const uint8_t *mac)
{
    struct jz_fake_mac entry = { .in_use = 1 };
    memcpy(entry.mac, mac, 6);
    return bpf_map_update_elem(st->jz_fake_mac_pool_fd, &idx, &entry, BPF_ANY);
}

/* Run guard_classifier via bpf_prog_test_run */
static int run_prog(int prog_fd, void *pkt, uint32_t pkt_size,
                    void *out_buf, uint32_t *out_size, uint32_t *retval)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in      = pkt,
        .data_size_in = pkt_size,
        .data_out     = out_buf,
        .data_size_out = out_buf ? *out_size : 0,
        .cpu          = 0,
        .repeat       = 1,
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (!err) {
        *retval = opts.retval;
        if (out_size)
            *out_size = opts.data_size_out;
    }
    return err;
}

/* Clear all guard/whitelist maps between tests */
static void clear_maps(struct test_state *st)
{
    uint32_t key, next_key;

    while (bpf_map_get_next_key(st->jz_static_guards_fd, NULL, &key) == 0)
        bpf_map_delete_elem(st->jz_static_guards_fd, &key);

    while (bpf_map_get_next_key(st->jz_dynamic_guards_fd, NULL, &key) == 0)
        bpf_map_delete_elem(st->jz_dynamic_guards_fd, &key);

    while (bpf_map_get_next_key(st->jz_whitelist_fd, NULL, &key) == 0)
        bpf_map_delete_elem(st->jz_whitelist_fd, &key);

    struct jz_guard_result *zero = calloc(st->ncpus, sizeof(struct jz_guard_result));
    if (zero) {
        key = 0;
        bpf_map_update_elem(st->jz_guard_result_map_fd, &key, zero, BPF_ANY);
        free(zero);
    }

    struct jz_rate_state *rate_zero = calloc(st->ncpus, sizeof(struct jz_rate_state));
    if (rate_zero) {
        key = 0;
        int arp_rate_fd = bpf_object__find_map_fd_by_name(st->obj_arp, "jz_arp_rate");
        if (arp_rate_fd >= 0)
            bpf_map_update_elem(arp_rate_fd, &key, rate_zero, BPF_ANY);
        int icmp_rate_fd = bpf_object__find_map_fd_by_name(st->obj_icmp, "jz_icmp_rate");
        if (icmp_rate_fd >= 0)
            bpf_map_update_elem(icmp_rate_fd, &key, rate_zero, BPF_ANY);
        free(rate_zero);
    }

    (void)next_key;
}

/* ── Group Setup / Teardown ── */

static int find_map_fd(struct bpf_object *obj, const char *name)
{
    int fd = bpf_object__find_map_fd_by_name(obj, name);
    if (fd < 0)
        fprintf(stderr, "WARN: map '%s' not found (fd=%d)\n", name, fd);
    return fd;
}

static int group_setup(void **state)
{
    struct test_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;

    st->ncpus = libbpf_num_possible_cpus();
    if (st->ncpus <= 0) {
        fprintf(stderr, "ERROR: libbpf_num_possible_cpus() = %d\n", st->ncpus);
        free(st);
        return -1;
    }

    /*
     * Load each BPF object separately.  Maps that appear in multiple objects
     * (rSwitch shared maps + jz_guard_result_map) are wired to share the
     * same kernel map instance via bpf_map__reuse_fd() between open & load.
     */

    /* ── 1. Open & load guard_classifier (primary — owns all shared maps) ── */
    st->obj_gc = bpf_object__open(GC_OBJ_PATH);
    if (!st->obj_gc) {
        fprintf(stderr, "ERROR: open %s: %s\n", GC_OBJ_PATH, strerror(errno));
        goto fail;
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, st->obj_gc)
        bpf_map__set_pin_path(map, NULL);

    int err = bpf_object__load(st->obj_gc);
    if (err) {
        fprintf(stderr, "ERROR: load %s: %s\n", GC_OBJ_PATH, strerror(-err));
        goto fail;
    }

    /* ── 2. Open arp_honeypot, reuse shared maps from GC, then load ── */
    st->obj_arp = bpf_object__open(ARP_OBJ_PATH);
    if (!st->obj_arp) {
        fprintf(stderr, "ERROR: open %s: %s\n", ARP_OBJ_PATH, strerror(errno));
        goto fail;
    }

    bpf_object__for_each_map(map, st->obj_arp) {
        bpf_map__set_pin_path(map, NULL);
        const char *name = bpf_map__name(map);
        int gc_fd = bpf_object__find_map_fd_by_name(st->obj_gc, name);
        if (gc_fd >= 0) {
            err = bpf_map__reuse_fd(map, gc_fd);
            if (err)
                fprintf(stderr, "WARN: reuse_fd(%s) for ARP: %s\n", name, strerror(-err));
        }
    }

    err = bpf_object__load(st->obj_arp);
    if (err) {
        fprintf(stderr, "ERROR: load %s: %s\n", ARP_OBJ_PATH, strerror(-err));
        goto fail;
    }

    /* ── 3. Open icmp_honeypot, reuse shared maps from GC, then load ── */
    st->obj_icmp = bpf_object__open(ICMP_OBJ_PATH);
    if (!st->obj_icmp) {
        fprintf(stderr, "ERROR: open %s: %s\n", ICMP_OBJ_PATH, strerror(errno));
        goto fail;
    }

    bpf_object__for_each_map(map, st->obj_icmp) {
        bpf_map__set_pin_path(map, NULL);
        const char *name = bpf_map__name(map);
        int gc_fd = bpf_object__find_map_fd_by_name(st->obj_gc, name);
        if (gc_fd >= 0) {
            err = bpf_map__reuse_fd(map, gc_fd);
            if (err)
                fprintf(stderr, "WARN: reuse_fd(%s) for ICMP: %s\n", name, strerror(-err));
        }
    }

    err = bpf_object__load(st->obj_icmp);
    if (err) {
        fprintf(stderr, "ERROR: load %s: %s\n", ICMP_OBJ_PATH, strerror(-err));
        goto fail;
    }

    /* ── Get program FDs ── */
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(st->obj_gc, "jz_guard_classifier_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: prog jz_guard_classifier_prog not found\n");
        goto fail;
    }
    st->gc_prog_fd = bpf_program__fd(prog);

    prog = bpf_object__find_program_by_name(st->obj_arp, "jz_arp_honeypot_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: prog jz_arp_honeypot_prog not found\n");
        goto fail;
    }
    st->arp_prog_fd = bpf_program__fd(prog);

    prog = bpf_object__find_program_by_name(st->obj_icmp, "jz_icmp_honeypot_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: prog jz_icmp_honeypot_prog not found\n");
        goto fail;
    }
    st->icmp_prog_fd = bpf_program__fd(prog);

    /* ── Collect map FDs (from owning objects) ── */
    st->rs_ctx_map_fd         = find_map_fd(st->obj_gc, "rs_ctx_map");
    st->rs_progs_fd           = find_map_fd(st->obj_gc, "rs_progs");
    st->rs_event_bus_fd       = find_map_fd(st->obj_gc, "rs_event_bus");
    st->jz_static_guards_fd  = find_map_fd(st->obj_gc, "jz_static_guards");
    st->jz_dynamic_guards_fd = find_map_fd(st->obj_gc, "jz_dynamic_guards");
    st->jz_whitelist_fd       = find_map_fd(st->obj_gc, "jz_whitelist");
    st->jz_guard_result_map_fd = find_map_fd(st->obj_gc, "jz_guard_result_map");
    st->jz_arp_config_fd     = find_map_fd(st->obj_arp, "jz_arp_config");
    st->jz_fake_mac_pool_fd  = find_map_fd(st->obj_arp, "jz_fake_mac_pool");
    st->jz_icmp_config_fd    = find_map_fd(st->obj_icmp, "jz_icmp_config");

    if (st->rs_ctx_map_fd < 0 || st->rs_progs_fd < 0 ||
        st->jz_static_guards_fd < 0 || st->jz_guard_result_map_fd < 0 ||
        st->jz_arp_config_fd < 0 || st->jz_icmp_config_fd < 0) {
        fprintf(stderr, "ERROR: critical map FDs missing\n");
        goto fail;
    }

    /* ── Set up rs_progs tail-call chain ── */
    /*
     * guard_classifier is called directly via bpf_prog_test_run (not from rs_progs).
     * RS_TAIL_CALL_NEXT increments next_prog_id THEN tail-calls rs_progs[next_prog_id].
     * Starting with next_prog_id=0:
     *   guard_classifier does RS_TAIL_CALL_NEXT -> next_prog_id becomes 1 -> calls rs_progs[1]
     *   arp_honeypot does RS_TAIL_CALL_NEXT -> next_prog_id becomes 2 -> calls rs_progs[2]
     *   icmp_honeypot does RS_TAIL_CALL_NEXT -> next_prog_id becomes 3 -> no slot 3, falls through
     */
    uint32_t slot;

    slot = 1;
    err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->arp_prog_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: rs_progs[1]=arp: %s\n", strerror(-err));
        goto fail;
    }

    slot = 2;
    err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->icmp_prog_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "ERROR: rs_progs[2]=icmp: %s\n", strerror(-err));
        goto fail;
    }

    set_arp_config(st, 1, 0);
    set_icmp_config(st, 1, 64, 0);
    set_fake_mac(st, 0, TEST_FAKE_MAC);

    fprintf(stderr, "=== Pipeline loaded: GC -> ARP(slot 1) -> ICMP(slot 2) ===\n");
    fprintf(stderr, "    CPUs: %d\n", st->ncpus);

    *state = st;
    return 0;

fail:
    if (st->obj_icmp) bpf_object__close(st->obj_icmp);
    if (st->obj_arp) bpf_object__close(st->obj_arp);
    if (st->obj_gc) bpf_object__close(st->obj_gc);
    free(st);
    return -1;
}

static int group_teardown(void **state)
{
    struct test_state *st = *state;
    if (!st) return 0;

    if (st->obj_icmp) bpf_object__close(st->obj_icmp);
    if (st->obj_arp) bpf_object__close(st->obj_arp);
    if (st->obj_gc) bpf_object__close(st->obj_gc);

    free(st);
    *state = NULL;
    return 0;
}

/* Per-test setup: clear maps to known state */
static int test_setup(void **state)
{
    struct test_state *st = *state;
    clear_maps(st);

    /* Re-set default configs each test */
    set_arp_config(st, 1, 0);
    set_icmp_config(st, 1, 64, 0);
    set_fake_mac(st, 0, TEST_FAKE_MAC);

    return 0;
}

static int test_teardown(void **state)
{
    (void)state;
    return 0;
}

/* ═══════════════════════════════════════════════
 * TESTS
 * ═══════════════════════════════════════════════ */

/* 1. ARP request for guarded IP -> XDP_TX (ARP reply) */
static void test_arp_guard_reply(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);
}

/* 2. ARP request for non-guarded IP -> XDP_PASS */
static void test_arp_non_guard_passthrough(void **state)
{
    struct test_state *st = *state;

    /* No guard entry for TEST_UNGUARDED_IP */
    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_UNGUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_PASS);
}

/* 3. ICMP echo request for guarded IP -> XDP_TX (ICMP reply) */
static void test_icmp_guard_reply(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 IPPROTO_ICMP,
                 sizeof(struct ethhdr));

    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);
}

/* 4. ICMP echo for non-guarded IP -> XDP_PASS */
static void test_icmp_non_guard_passthrough(void **state)
{
    struct test_state *st = *state;

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_UNGUARDED_IP),
                 IPPROTO_ICMP,
                 sizeof(struct ethhdr));

    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_PASS);
}

/* 5. Whitelist bypass: ARP for guarded IP from whitelisted source -> XDP_PASS */
static void test_whitelist_bypass(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);
    add_whitelist(st, TEST_SRC_IP);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);

    assert_int_equal(retval, XDP_PASS);

    struct jz_guard_result result;
    int rerr = read_guard_result(st, &result);
    assert_int_equal(rerr, 0);
    assert_int_equal(result.guard_type, JZ_GUARD_NONE);
    assert_true(result.flags & JZ_FLAG_WHITELIST_BYPASS);
}

/* 6. TCP SYN for guarded IP -> XDP_PASS (no TCP honeypot) */
static void test_tcp_guard_passthrough(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 IPPROTO_TCP,
                 sizeof(struct ethhdr));

    /* Build a minimal TCP-ish IP packet (enough to pass guard_classifier) */
    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);
    /* Override protocol to TCP */
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.check = 0;
    pkt.ip.check = ip_checksum(&pkt.ip, sizeof(pkt.ip));

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);

    /* Guard matched TCP, but no TCP honeypot -> arp/icmp both skip -> XDP_PASS */
    assert_int_equal(retval, XDP_PASS);

    /* Verify guard result has proto=3 (TCP) */
    struct jz_guard_result result;
    read_guard_result(st, &result);
    assert_int_equal(result.guard_type, JZ_GUARD_STATIC);
    assert_int_equal(result.proto, 3);  /* TCP */
}

/* 7. Dynamic guard entry -> ARP -> XDP_TX */
static void test_dynamic_guard_reply(void **state)
{
    struct test_state *st = *state;

    add_dynamic_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);

    /* Verify guard result shows DYNAMIC */
    struct jz_guard_result result;
    read_guard_result(st, &result);
    assert_int_equal(result.guard_type, JZ_GUARD_DYNAMIC);
}

/* 8. Guard hit counter increments */
static void test_guard_hit_counter(void **state)
{
    struct test_state *st = *state;

    uint32_t key = htonl(TEST_GUARDED_IP);
    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    /* Verify initial hit_count = 0 */
    struct jz_guard_entry entry;
    int lerr = bpf_map_lookup_elem(st->jz_static_guards_fd, &key, &entry);
    assert_int_equal(lerr, 0);
    assert_int_equal(entry.hit_count, 0);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);

    /* Read back guard entry — hit_count should be >= 1 */
    lerr = bpf_map_lookup_elem(st->jz_static_guards_fd, &key, &entry);
    assert_int_equal(lerr, 0);
    assert_true(entry.hit_count >= 1);
}

/* 9. ARP reply packet is valid */
static void test_arp_reply_packet_valid(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);

    /* Verify output packet is a valid ARP reply */
    assert_true(out_size >= sizeof(struct test_arp_packet));

    struct test_arp_packet *reply = (struct test_arp_packet *)out;

    /* Ethernet: dest = original source, source = fake MAC */
    assert_memory_equal(reply->eth.h_dest, TEST_SRC_MAC, 6);
    assert_memory_equal(reply->eth.h_source, TEST_FAKE_MAC, 6);
    assert_int_equal(reply->eth.h_proto, htons(ETH_P_ARP));

    /* ARP: opcode = reply (2) */
    assert_int_equal(reply->arp.ar_op, htons(ARPOP_REPLY));

    /* ARP: sender = fake MAC + guarded IP */
    assert_memory_equal(reply->arp.ar_sha, TEST_FAKE_MAC, 6);
    assert_int_equal(reply->arp.ar_sip, htonl(TEST_GUARDED_IP));

    /* ARP: target = original requester */
    assert_memory_equal(reply->arp.ar_tha, TEST_SRC_MAC, 6);
    assert_int_equal(reply->arp.ar_tip, htonl(TEST_SRC_IP));
}

/* 10. ICMP reply packet is valid */
static void test_icmp_reply_packet_valid(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 IPPROTO_ICMP,
                 sizeof(struct ethhdr));

    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);

    assert_true(out_size >= sizeof(struct test_icmp_packet));

    struct test_icmp_packet *reply = (struct test_icmp_packet *)out;

    /* Ethernet: dest = original src, source = fake MAC */
    assert_memory_equal(reply->eth.h_dest, TEST_SRC_MAC, 6);
    assert_memory_equal(reply->eth.h_source, TEST_FAKE_MAC, 6);

    /* IP: src/dst swapped, TTL = configured (64) */
    assert_int_equal(reply->ip.saddr, htonl(TEST_GUARDED_IP));
    assert_int_equal(reply->ip.daddr, htonl(TEST_SRC_IP));
    assert_int_equal(reply->ip.ttl, 64);
    assert_int_equal(reply->ip.protocol, IPPROTO_ICMP);

    /* ICMP: type = 0 (echo reply), code = 0 */
    assert_int_equal(reply->icmp.type, 0);
    assert_int_equal(reply->icmp.code, 0);

    /* ID and sequence should be preserved */
    assert_int_equal(reply->icmp.id, htons(0x1234));
    assert_int_equal(reply->icmp.sequence, htons(1));
}

/* 11. Guard classifier stores correct result for ARP */
static void test_guard_result_arp(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);

    struct jz_guard_result result;
    int rerr = read_guard_result(st, &result);
    assert_int_equal(rerr, 0);
    assert_int_equal(result.guard_type, JZ_GUARD_STATIC);
    assert_int_equal(result.proto, 1);  /* ARP */
    assert_true(result.flags & JZ_FLAG_ARP_REQUEST);
    assert_int_equal(result.guarded_ip, htonl(TEST_GUARDED_IP));
    assert_memory_equal(result.fake_mac, TEST_FAKE_MAC, 6);
}

/* 12. Static guard takes priority over dynamic */
static void test_static_over_dynamic_priority(void **state)
{
    struct test_state *st = *state;

    /* Add both static and dynamic entries for same IP */
    static const uint8_t static_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
    static const uint8_t dynamic_mac[6] = {0x02, 0xDD, 0xEE, 0xFF, 0x00, 0x02};

    add_static_guard(st, TEST_GUARDED_IP, static_mac);
    add_dynamic_guard(st, TEST_GUARDED_IP, dynamic_mac);

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(retval, XDP_TX);

    /* Verify result is STATIC, not DYNAMIC */
    struct jz_guard_result result;
    read_guard_result(st, &result);
    assert_int_equal(result.guard_type, JZ_GUARD_STATIC);
    assert_memory_equal(result.fake_mac, static_mac, 6);
}

/* 13. ARP disabled -> passthrough even for guarded IP */
static void test_arp_disabled_passthrough(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);
    set_arp_config(st, 0, 0);  /* disabled */

    setup_rs_ctx(st,
                 htons(ETH_P_ARP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 0,
                 sizeof(struct ethhdr));

    struct test_arp_packet pkt;
    build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);

    /* Guard matched, but ARP module disabled -> passthrough to ICMP -> ICMP skips ARP -> XDP_PASS */
    assert_int_equal(retval, XDP_PASS);
}

/* 14. ICMP disabled -> passthrough */
static void test_icmp_disabled_passthrough(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);
    set_icmp_config(st, 0, 64, 0);  /* disabled */

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 IPPROTO_ICMP,
                 sizeof(struct ethhdr));

    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_PASS);
}

/* 15. ICMP TTL spoofing: verify configurable TTL in reply */
static void test_icmp_ttl_spoofing(void **state)
{
    struct test_state *st = *state;

    add_static_guard(st, TEST_GUARDED_IP, TEST_FAKE_MAC);
    set_icmp_config(st, 1, 128, 0);  /* TTL=128 (Windows fingerprint) */

    setup_rs_ctx(st,
                 htons(ETH_P_IP),
                 htonl(TEST_SRC_IP),
                 htonl(TEST_GUARDED_IP),
                 IPPROTO_ICMP,
                 sizeof(struct ethhdr));

    struct test_icmp_packet pkt;
    build_icmp_echo_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);

    uint8_t out[256];
    uint32_t out_size = sizeof(out);
    uint32_t retval = 0;

    int err = run_prog(st->gc_prog_fd, &pkt, sizeof(pkt), out, &out_size, &retval);
    assert_int_equal(err, 0);
    assert_int_equal(retval, XDP_TX);

    struct test_icmp_packet *reply = (struct test_icmp_packet *)out;
    assert_int_equal(reply->ip.ttl, 128);  /* Windows-like TTL */
}

/* ── Main ── */

int main(void)
{
    /* Root check */
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: integration tests require root (CAP_BPF)\n");
        fprintf(stderr, "Run with: sudo make test-integration\n");
        return 77;  /* skip exit code */
    }

    /* BPF object check */
    if (access(GC_OBJ_PATH, F_OK) != 0) {
        fprintf(stderr, "ERROR: %s not found -- run 'make bpf' first\n",
                GC_OBJ_PATH);
        return 77;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_arp_guard_reply,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_arp_non_guard_passthrough,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_icmp_guard_reply,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_icmp_non_guard_passthrough,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_whitelist_bypass,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_tcp_guard_passthrough,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_dynamic_guard_reply,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_guard_hit_counter,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_arp_reply_packet_valid,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_icmp_reply_packet_valid,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_guard_result_arp,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_static_over_dynamic_priority,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_arp_disabled_passthrough,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_icmp_disabled_passthrough,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_icmp_ttl_spoofing,
                                        test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
