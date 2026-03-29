/* test_perf.c -- BPF module performance benchmarks
 *
 * Measures packets-per-second (PPS) and nanoseconds-per-packet (ns/pkt) for
 * each jz_sniff_rn BPF module individually and the full pipeline chain.
 *
 * Uses bpf_prog_test_run_opts with repeat=N to run each BPF program in
 * kernel context without actual network traffic — ideal for benchmarking.
 *
 * Requirements:
 *   - Root privileges (CAP_BPF)
 *   - Compiled BPF objects in build/bpf/
 *   - Kernel 5.8+ with BTF support
 *   - libbpf 1.7+
 *
 * Build:
 *   make test-perf   (runs with sudo)
 *
 * Output format (parseable):
 *   MODULE | PACKET_TYPE | REPEAT | TOTAL_NS | NS_PKT | MPPS | ACTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * uapi.h / map_defs.h contain BPF-only macros. Replicate needed structs.
 */
#include "jz_common.h"
#include "jz_maps.h"
#include "jz_events.h"

/* ── Configuration ── */

#define WARMUP_REPEAT     100
#define BENCH_REPEAT      100000   /* 100K iterations per benchmark */
#define BENCH_REPEAT_PIPE 50000    /* 50K for full pipeline (heavier) */

/* ── BPF Object Paths ── */

#define BPF_OBJ_DIR        "build/bpf"
#define GC_OBJ_PATH        BPF_OBJ_DIR "/jz_guard_classifier.bpf.o"
#define ARP_OBJ_PATH       BPF_OBJ_DIR "/jz_arp_honeypot.bpf.o"
#define ICMP_OBJ_PATH      BPF_OBJ_DIR "/jz_icmp_honeypot.bpf.o"
#define SD_OBJ_PATH        BPF_OBJ_DIR "/jz_sniffer_detect.bpf.o"
#define TW_OBJ_PATH        BPF_OBJ_DIR "/jz_traffic_weaver.bpf.o"

/* ── Test Constants ── */

#define TEST_GUARDED_IP     0x0A000132  /* 10.0.1.50 */
#define TEST_SRC_IP         0x0A00010A  /* 10.0.1.10 */
#define TEST_UNGUARDED_IP   0x0A000199  /* 10.0.1.153 */
#define TEST_IFINDEX        2

static const uint8_t TEST_SRC_MAC[6]  = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t TEST_FAKE_MAC[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
static const uint8_t BCAST_MAC[6]     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define RS_ONLYKEY 0

/* ── rs_ctx (same as integration test) ── */

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
    uint32_t reserved[16];
};

/* ── Packet Structures ── */

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

struct test_tcp_packet {
    struct ethhdr eth;
    struct iphdr  ip;
    struct tcphdr tcp;
    uint8_t       payload[32];
} __attribute__((packed));

struct test_udp_packet {
    struct ethhdr eth;
    struct iphdr  ip;
    struct udphdr udp;
    uint8_t       payload[32];
} __attribute__((packed));

/* ── Global State ── */

struct perf_state {
    struct bpf_object *obj_gc;
    struct bpf_object *obj_arp;
    struct bpf_object *obj_icmp;
    struct bpf_object *obj_sd;
    struct bpf_object *obj_tw;

    int gc_prog_fd;
    int arp_prog_fd;
    int icmp_prog_fd;
    int sd_prog_fd;
    int tw_prog_fd;

    /* Shared maps from GC */
    int rs_ctx_map_fd;
    int rs_progs_fd;
    int rs_event_bus_fd;
    int jz_static_guards_fd;
    int jz_dynamic_guards_fd;
    int jz_whitelist_fd;
    int jz_guard_result_map_fd;

    /* Module-specific maps */
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
                              uint32_t src_ip_he, uint32_t target_ip_he)
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

static void build_icmp_echo(struct test_icmp_packet *pkt,
                            uint32_t src_ip_he, uint32_t dst_ip_he)
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

    pkt->icmp.type     = 8;
    pkt->icmp.code     = 0;
    pkt->icmp.id       = htons(0x1234);
    pkt->icmp.sequence = htons(1);
    for (int i = 0; i < (int)sizeof(pkt->payload); i++)
        pkt->payload[i] = (uint8_t)(i & 0xFF);
    pkt->icmp.checksum = 0;
    pkt->icmp.checksum = ip_checksum(&pkt->icmp, 8 + sizeof(pkt->payload));
}

static void build_tcp_syn(struct test_tcp_packet *pkt,
                          uint32_t src_ip_he, uint32_t dst_ip_he,
                          uint16_t sport, uint16_t dport)
{
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->eth.h_source, TEST_SRC_MAC, 6);
    memcpy(pkt->eth.h_dest, BCAST_MAC, 6);
    pkt->eth.h_proto = htons(ETH_P_IP);

    pkt->ip.version  = 4;
    pkt->ip.ihl      = 5;
    pkt->ip.tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(pkt->payload));
    pkt->ip.ttl      = 64;
    pkt->ip.protocol = IPPROTO_TCP;
    pkt->ip.saddr    = htonl(src_ip_he);
    pkt->ip.daddr    = htonl(dst_ip_he);
    pkt->ip.check    = ip_checksum(&pkt->ip, sizeof(pkt->ip));

    pkt->tcp.source  = htons(sport);
    pkt->tcp.dest    = htons(dport);
    pkt->tcp.seq     = htonl(1000);
    pkt->tcp.doff    = 5;
    pkt->tcp.syn     = 1;
    pkt->tcp.window  = htons(65535);
}

static void build_udp_packet(struct test_udp_packet *pkt,
                             uint32_t src_ip_he, uint32_t dst_ip_he,
                             uint16_t sport, uint16_t dport)
{
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->eth.h_source, TEST_SRC_MAC, 6);
    memcpy(pkt->eth.h_dest, BCAST_MAC, 6);
    pkt->eth.h_proto = htons(ETH_P_IP);

    pkt->ip.version  = 4;
    pkt->ip.ihl      = 5;
    pkt->ip.tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(pkt->payload));
    pkt->ip.ttl      = 64;
    pkt->ip.protocol = IPPROTO_UDP;
    pkt->ip.saddr    = htonl(src_ip_he);
    pkt->ip.daddr    = htonl(dst_ip_he);
    pkt->ip.check    = ip_checksum(&pkt->ip, sizeof(pkt->ip));

    pkt->udp.source = htons(sport);
    pkt->udp.dest   = htons(dport);
    pkt->udp.len    = htons(sizeof(struct udphdr) + sizeof(pkt->payload));
}

/* Set up rs_ctx_map[0] on CPU 0 */
static int setup_rs_ctx(struct perf_state *st,
                        uint16_t eth_proto_ne,
                        uint32_t saddr_ne, uint32_t daddr_ne,
                        uint8_t ip_proto, uint16_t l3_offset,
                        uint16_t sport, uint16_t dport)
{
    struct rs_ctx *ctx_vals = calloc(st->ncpus, sizeof(struct rs_ctx));
    if (!ctx_vals) return -ENOMEM;

    ctx_vals[0].ifindex           = TEST_IFINDEX;
    ctx_vals[0].parsed            = 1;
    ctx_vals[0].layers.eth_proto  = eth_proto_ne;
    ctx_vals[0].layers.saddr      = saddr_ne;
    ctx_vals[0].layers.daddr      = daddr_ne;
    ctx_vals[0].layers.ip_proto   = ip_proto;
    ctx_vals[0].layers.l2_offset  = 0;
    ctx_vals[0].layers.l3_offset  = l3_offset;
    ctx_vals[0].layers.l4_offset  = l3_offset + sizeof(struct iphdr);
    ctx_vals[0].layers.sport      = sport;
    ctx_vals[0].layers.dport      = dport;
    ctx_vals[0].next_prog_id      = 0;
    ctx_vals[0].call_depth        = 0;

    uint32_t key = 0;
    int err = bpf_map_update_elem(st->rs_ctx_map_fd, &key, ctx_vals, BPF_ANY);
    free(ctx_vals);
    return err;
}

/* Reset guard result between benchmarks */
static void clear_guard_result(struct perf_state *st)
{
    struct jz_guard_result *zero = calloc(st->ncpus, sizeof(struct jz_guard_result));
    if (zero) {
        uint32_t key = 0;
        bpf_map_update_elem(st->jz_guard_result_map_fd, &key, zero, BPF_ANY);
        free(zero);
    }
}

/* ── Benchmark Runner ── */

struct bench_result {
    char        module[32];
    char        pkt_type[32];
    uint32_t    repeat;
    uint64_t    total_ns;
    double      ns_per_pkt;
    double      mpps;
    uint32_t    xdp_action;
};

static const char *xdp_action_str(uint32_t action)
{
    switch (action) {
    case 0: return "ABORTED";
    case 1: return "DROP";
    case 2: return "PASS";
    case 3: return "TX";
    case 4: return "REDIRECT";
    default: return "UNKNOWN";
    }
}

/*
 * run_bench — Run a BPF program with bpf_prog_test_run_opts.
 *
 * We do a warmup pass (WARMUP_REPEAT iterations), then a timed bench pass
 * (repeat iterations). Timing uses CLOCK_MONOTONIC around the kernel call.
 * The kernel's opts.duration reports total ns for all repeats.
 */
static int run_bench(int prog_fd, void *pkt, uint32_t pkt_size,
                     uint32_t repeat, struct bench_result *res)
{
    uint8_t out[512];

    /* Warmup */
    LIBBPF_OPTS(bpf_test_run_opts, warmup_opts,
        .data_in       = pkt,
        .data_size_in  = pkt_size,
        .data_out      = out,
        .data_size_out = sizeof(out),
        .cpu           = 0,
        .repeat        = WARMUP_REPEAT,
    );
    int err = bpf_prog_test_run_opts(prog_fd, &warmup_opts);
    if (err) {
        fprintf(stderr, "  warmup failed: %s\n", strerror(-err));
        return err;
    }

    /* Timed run */
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in       = pkt,
        .data_size_in  = pkt_size,
        .data_out      = out,
        .data_size_out = sizeof(out),
        .cpu           = 0,
        .repeat        = repeat,
    );

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    err = bpf_prog_test_run_opts(prog_fd, &opts);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (err) {
        fprintf(stderr, "  bench failed: %s\n", strerror(-err));
        return err;
    }

    uint64_t wall_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                     + (uint64_t)(t1.tv_nsec - t0.tv_nsec);

    res->repeat     = repeat;
    res->total_ns   = wall_ns;
    res->ns_per_pkt = (double)wall_ns / (double)repeat;
    res->mpps       = 1000.0 / res->ns_per_pkt;
    res->xdp_action = opts.retval;

    return 0;
}

/* ── Results Table ── */

#define MAX_RESULTS 64
static struct bench_result results[MAX_RESULTS];
static int nresults = 0;

static void record(const char *module, const char *pkt_type, struct bench_result *r)
{
    snprintf(r->module, sizeof(r->module), "%s", module);
    snprintf(r->pkt_type, sizeof(r->pkt_type), "%s", pkt_type);
    if (nresults < MAX_RESULTS)
        results[nresults++] = *r;
}

static void print_results(void)
{
    printf("\n");
    printf("╔══════════════════════════╦═══════════════╦════════╦══════════════╦══════════╦════════╦══════════╗\n");
    printf("║ MODULE                   ║ PACKET TYPE   ║ REPEAT ║ TOTAL (ms)   ║ NS/PKT   ║ MPPS   ║ ACTION   ║\n");
    printf("╠══════════════════════════╬═══════════════╬════════╬══════════════╬══════════╬════════╬══════════╣\n");

    for (int i = 0; i < nresults; i++) {
        struct bench_result *r = &results[i];
        printf("║ %-24s ║ %-13s ║ %6u ║ %10.3f   ║ %8.1f ║ %6.3f ║ %-8s ║\n",
               r->module, r->pkt_type, r->repeat,
               (double)r->total_ns / 1e6,
               r->ns_per_pkt, r->mpps,
               xdp_action_str(r->xdp_action));
    }

    printf("╚══════════════════════════╩═══════════════╩════════╩══════════════╩══════════╩════════╩══════════╝\n");
    printf("\n");

    /* Also emit machine-parseable CSV */
    printf("# CSV: module,pkt_type,repeat,total_ns,ns_pkt,mpps,action\n");
    for (int i = 0; i < nresults; i++) {
        struct bench_result *r = &results[i];
        printf("%s,%s,%u,%lu,%.1f,%.3f,%s\n",
               r->module, r->pkt_type, r->repeat,
               r->total_ns, r->ns_per_pkt, r->mpps,
               xdp_action_str(r->xdp_action));
    }
}

/* ── BPF Object Loading ── */

static int find_map_fd(struct bpf_object *obj, const char *name)
{
    int fd = bpf_object__find_map_fd_by_name(obj, name);
    if (fd < 0)
        fprintf(stderr, "WARN: map '%s' not found (fd=%d)\n", name, fd);
    return fd;
}

static struct bpf_object *open_and_load(const char *path,
                                        struct bpf_object *share_from)
{
    struct bpf_object *obj = bpf_object__open(path);
    if (!obj) {
        fprintf(stderr, "ERROR: open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        bpf_map__set_pin_path(map, NULL);
        if (share_from) {
            const char *name = bpf_map__name(map);
            int src_fd = bpf_object__find_map_fd_by_name(share_from, name);
            if (src_fd >= 0) {
                int err = bpf_map__reuse_fd(map, src_fd);
                if (err)
                    fprintf(stderr, "WARN: reuse_fd(%s): %s\n", name, strerror(-err));
            }
        }
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: load %s: %s\n", path, strerror(-err));
        bpf_object__close(obj);
        return NULL;
    }

    return obj;
}

static int find_prog_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
    if (!prog) {
        fprintf(stderr, "ERROR: program '%s' not found\n", name);
        return -1;
    }
    return bpf_program__fd(prog);
}

/* ── Setup / Teardown ── */

static int perf_setup(struct perf_state *st)
{
    memset(st, 0, sizeof(*st));
    st->ncpus = libbpf_num_possible_cpus();
    if (st->ncpus <= 0) {
        fprintf(stderr, "ERROR: libbpf_num_possible_cpus() = %d\n", st->ncpus);
        return -1;
    }

    fprintf(stderr, "[setup] Loading BPF objects (ncpus=%d)...\n", st->ncpus);

    /* 1. Guard classifier (owns all shared maps) */
    st->obj_gc = open_and_load(GC_OBJ_PATH, NULL);
    if (!st->obj_gc) return -1;

    /* 2. ARP honeypot (reuse GC maps) */
    st->obj_arp = open_and_load(ARP_OBJ_PATH, st->obj_gc);
    if (!st->obj_arp) return -1;

    /* 3. ICMP honeypot (reuse GC maps) */
    st->obj_icmp = open_and_load(ICMP_OBJ_PATH, st->obj_gc);
    if (!st->obj_icmp) return -1;

    /* 4. Sniffer detect (reuse GC maps) */
    st->obj_sd = open_and_load(SD_OBJ_PATH, st->obj_gc);
    if (!st->obj_sd) return -1;

    /* 5. Traffic weaver (reuse GC maps) */
    st->obj_tw = open_and_load(TW_OBJ_PATH, st->obj_gc);
    if (!st->obj_tw) return -1;

    /* Get program FDs */
    st->gc_prog_fd   = find_prog_fd(st->obj_gc,   "jz_guard_classifier_prog");
    st->arp_prog_fd  = find_prog_fd(st->obj_arp,  "jz_arp_honeypot_prog");
    st->icmp_prog_fd = find_prog_fd(st->obj_icmp, "jz_icmp_honeypot_prog");
    st->sd_prog_fd   = find_prog_fd(st->obj_sd,   "jz_sniffer_detect_prog");
    st->tw_prog_fd   = find_prog_fd(st->obj_tw,   "jz_traffic_weaver_prog");

    if (st->gc_prog_fd < 0 || st->arp_prog_fd < 0 || st->icmp_prog_fd < 0 ||
        st->sd_prog_fd < 0 || st->tw_prog_fd < 0) {
        fprintf(stderr, "ERROR: missing program FDs\n");
        return -1;
    }

    /* Collect map FDs */
    st->rs_ctx_map_fd          = find_map_fd(st->obj_gc, "rs_ctx_map");
    st->rs_progs_fd            = find_map_fd(st->obj_gc, "rs_progs");
    st->rs_event_bus_fd        = find_map_fd(st->obj_gc, "rs_event_bus");
    st->jz_static_guards_fd   = find_map_fd(st->obj_gc, "jz_static_guards");
    st->jz_dynamic_guards_fd  = find_map_fd(st->obj_gc, "jz_dynamic_guards");
    st->jz_whitelist_fd        = find_map_fd(st->obj_gc, "jz_whitelist");
    st->jz_guard_result_map_fd = find_map_fd(st->obj_gc, "jz_guard_result_map");
    st->jz_arp_config_fd      = find_map_fd(st->obj_arp, "jz_arp_config");
    st->jz_fake_mac_pool_fd   = find_map_fd(st->obj_arp, "jz_fake_mac_pool");
    st->jz_icmp_config_fd     = find_map_fd(st->obj_icmp, "jz_icmp_config");

    if (st->rs_ctx_map_fd < 0 || st->rs_progs_fd < 0 ||
        st->jz_static_guards_fd < 0 || st->jz_guard_result_map_fd < 0) {
        fprintf(stderr, "ERROR: critical map FDs missing\n");
        return -1;
    }

    /* Set up rs_progs tail-call chain for pipeline tests:
     * GC(entry) -> slot[1]=ARP -> slot[2]=ICMP -> slot[3]=SD -> slot[4]=TW */
    uint32_t slot;
    int err;

    slot = 1; err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->arp_prog_fd, BPF_ANY);
    if (err) { fprintf(stderr, "ERROR: rs_progs[1]=arp: %s\n", strerror(-err)); return -1; }

    slot = 2; err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->icmp_prog_fd, BPF_ANY);
    if (err) { fprintf(stderr, "ERROR: rs_progs[2]=icmp: %s\n", strerror(-err)); return -1; }

    slot = 3; err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->sd_prog_fd, BPF_ANY);
    if (err) { fprintf(stderr, "ERROR: rs_progs[3]=sd: %s\n", strerror(-err)); return -1; }

    slot = 4; err = bpf_map_update_elem(st->rs_progs_fd, &slot, &st->tw_prog_fd, BPF_ANY);
    if (err) { fprintf(stderr, "ERROR: rs_progs[4]=tw: %s\n", strerror(-err)); return -1; }

    /* Configure modules */
    {
        uint32_t key = 0;
        struct jz_arp_config arp_cfg = { .enabled = 1, .log_all = 0, .rate_limit_pps = 0 };
        bpf_map_update_elem(st->jz_arp_config_fd, &key, &arp_cfg, BPF_ANY);

        struct jz_icmp_config icmp_cfg = { .enabled = 1, .ttl = 64, .rate_limit_pps = 0 };
        bpf_map_update_elem(st->jz_icmp_config_fd, &key, &icmp_cfg, BPF_ANY);

        struct jz_fake_mac fm = { .in_use = 1 };
        memcpy(fm.mac, TEST_FAKE_MAC, 6);
        bpf_map_update_elem(st->jz_fake_mac_pool_fd, &key, &fm, BPF_ANY);
    }

    /* Add a guard entry for benchmark */
    {
        struct jz_guard_key gkey = {
            .ip_addr = htonl(TEST_GUARDED_IP),
            .ifindex = TEST_IFINDEX,
        };
        struct jz_guard_entry entry = {
            .ip_addr    = gkey.ip_addr,
            .guard_type = JZ_GUARD_STATIC,
            .enabled    = 1,
        };
        memcpy(entry.fake_mac, TEST_FAKE_MAC, 6);
        bpf_map_update_elem(st->jz_static_guards_fd, &gkey, &entry, BPF_ANY);
    }

    fprintf(stderr, "[setup] Pipeline loaded: GC -> ARP(1) -> ICMP(2) -> SD(3) -> TW(4)\n");
    return 0;
}

static void perf_teardown(struct perf_state *st)
{
    if (st->obj_tw)   bpf_object__close(st->obj_tw);
    if (st->obj_sd)   bpf_object__close(st->obj_sd);
    if (st->obj_icmp) bpf_object__close(st->obj_icmp);
    if (st->obj_arp)  bpf_object__close(st->obj_arp);
    if (st->obj_gc)   bpf_object__close(st->obj_gc);
}

/* ── Individual Module Benchmarks ── */

/*
 * Bench 1: guard_classifier ONLY (no tail-call chain)
 * We temporarily clear rs_progs so GC falls through without chaining.
 */
static void bench_gc_only(struct perf_state *st)
{
    fprintf(stderr, "\n[bench] guard_classifier (isolated)\n");

    struct bench_result r;

    /* ARP packet -> guarded IP (guard match path) */
    {
        struct test_arp_packet pkt;
        build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), 0, sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
            record("guard_classifier", "ARP(guarded)", &r);
    }

    /* ARP packet -> unguarded IP (fast miss path) */
    {
        struct test_arp_packet pkt;
        build_arp_request(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), 0, sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
            record("guard_classifier", "ARP(miss)", &r);
    }

    /* ICMP packet -> guarded IP */
    {
        struct test_icmp_packet pkt;
        build_icmp_echo(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), IPPROTO_ICMP,
                     sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
            record("guard_classifier", "ICMP(guarded)", &r);
    }

    /* TCP SYN -> guarded IP */
    {
        struct test_tcp_packet pkt;
        build_tcp_syn(&pkt, TEST_SRC_IP, TEST_GUARDED_IP, 12345, 80);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), IPPROTO_TCP,
                     sizeof(struct ethhdr), htons(12345), htons(80));
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
            record("guard_classifier", "TCP(guarded)", &r);
    }

    /* TCP SYN -> unguarded IP (fast miss) */
    {
        struct test_tcp_packet pkt;
        build_tcp_syn(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP, 12345, 80);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), IPPROTO_TCP,
                     sizeof(struct ethhdr), htons(12345), htons(80));
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
            record("guard_classifier", "TCP(miss)", &r);
    }
}

/*
 * Bench 2: Full pipeline (GC -> ARP -> ICMP -> SD -> TW)
 * Entry point is GC; tail calls chain through all modules.
 */
static void bench_pipeline(struct perf_state *st)
{
    fprintf(stderr, "\n[bench] Full pipeline (GC->ARP->ICMP->SD->TW)\n");
    struct bench_result r;

    /* ARP for guarded IP (GC matches, ARP replies with XDP_TX) */
    {
        struct test_arp_packet pkt;
        build_arp_request(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), 0, sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "ARP(guarded)", &r);
    }

    /* ARP for unguarded IP (GC miss -> ARP skip -> ICMP skip -> SD skip -> TW skip -> PASS) */
    {
        struct test_arp_packet pkt;
        build_arp_request(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), 0, sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "ARP(miss)", &r);
    }

    /* ICMP for guarded IP (GC matches, ARP skips ICMP, ICMP replies with XDP_TX) */
    {
        struct test_icmp_packet pkt;
        build_icmp_echo(&pkt, TEST_SRC_IP, TEST_GUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), IPPROTO_ICMP,
                     sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "ICMP(guarded)", &r);
    }

    /* ICMP for unguarded IP (all pass through) */
    {
        struct test_icmp_packet pkt;
        build_icmp_echo(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), IPPROTO_ICMP,
                     sizeof(struct ethhdr), 0, 0);
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "ICMP(miss)", &r);
    }

    /* TCP SYN for guarded IP (GC matches, no TCP honeypot -> all pass through) */
    {
        struct test_tcp_packet pkt;
        build_tcp_syn(&pkt, TEST_SRC_IP, TEST_GUARDED_IP, 12345, 80);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_GUARDED_IP), IPPROTO_TCP,
                     sizeof(struct ethhdr), htons(12345), htons(80));
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "TCP(guarded)", &r);
    }

    /* TCP SYN for unguarded IP (pure passthrough) */
    {
        struct test_tcp_packet pkt;
        build_tcp_syn(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP, 12345, 80);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), IPPROTO_TCP,
                     sizeof(struct ethhdr), htons(12345), htons(80));
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "TCP(miss)", &r);
    }

    /* UDP for unguarded IP (pure passthrough — baseline) */
    {
        struct test_udp_packet pkt;
        build_udp_packet(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP, 5000, 53);
        setup_rs_ctx(st, htons(ETH_P_IP), htonl(TEST_SRC_IP),
                     htonl(TEST_UNGUARDED_IP), IPPROTO_UDP,
                     sizeof(struct ethhdr), htons(5000), htons(53));
        clear_guard_result(st);
        if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT_PIPE, &r) == 0)
            record("pipeline", "UDP(miss)", &r);
    }
}

/*
 * Bench 3: Scalability — measure GC lookup latency with different guard table sizes
 */
static void bench_scalability(struct perf_state *st)
{
    fprintf(stderr, "\n[bench] Guard table scalability\n");

    /* Clear existing guard entries */
    struct jz_guard_key key = {0};
    while (bpf_map_get_next_key(st->jz_static_guards_fd, NULL, &key) == 0)
        bpf_map_delete_elem(st->jz_static_guards_fd, &key);

    int sizes[] = {1, 10, 100, 1000};
    struct bench_result r;

    for (int s = 0; s < 4; s++) {
        int target_size = sizes[s];

        /* Clear and repopulate */
        while (bpf_map_get_next_key(st->jz_static_guards_fd, NULL, &key) == 0)
            bpf_map_delete_elem(st->jz_static_guards_fd, &key);

        for (int i = 0; i < target_size; i++) {
            uint32_t ip_he = 0x0A000100 + i;  /* 10.0.1.0 + i */
            uint32_t ip_ne = htonl(ip_he);
            struct jz_guard_key gkey = {
                .ip_addr = ip_ne,
                .ifindex = TEST_IFINDEX,
            };
            struct jz_guard_entry entry = {
                .ip_addr    = ip_ne,
                .guard_type = JZ_GUARD_STATIC,
                .enabled    = 1,
            };
            memcpy(entry.fake_mac, TEST_FAKE_MAC, 6);
            bpf_map_update_elem(st->jz_static_guards_fd, &gkey, &entry, BPF_ANY);
        }

        /* Benchmark a HIT (last entry in table) */
        {
            uint32_t hit_ip = 0x0A000100 + (target_size - 1);
            struct test_arp_packet pkt;
            build_arp_request(&pkt, TEST_SRC_IP, hit_ip);
            setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                         htonl(hit_ip), 0, sizeof(struct ethhdr), 0, 0);
            clear_guard_result(st);

            char label[32];
            snprintf(label, sizeof(label), "HIT(n=%d)", target_size);
            if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
                record("gc_scalability", label, &r);
        }

        /* Benchmark a MISS */
        {
            struct test_arp_packet pkt;
            build_arp_request(&pkt, TEST_SRC_IP, TEST_UNGUARDED_IP);
            setup_rs_ctx(st, htons(ETH_P_ARP), htonl(TEST_SRC_IP),
                         htonl(TEST_UNGUARDED_IP), 0, sizeof(struct ethhdr), 0, 0);
            clear_guard_result(st);

            char label[32];
            snprintf(label, sizeof(label), "MISS(n=%d)", target_size);
            if (run_bench(st->gc_prog_fd, &pkt, sizeof(pkt), BENCH_REPEAT, &r) == 0)
                record("gc_scalability", label, &r);
        }
    }

    /* Restore single guard entry */
    while (bpf_map_get_next_key(st->jz_static_guards_fd, NULL, &key) == 0)
        bpf_map_delete_elem(st->jz_static_guards_fd, &key);
    {
        struct jz_guard_key gkey = {
            .ip_addr = htonl(TEST_GUARDED_IP),
            .ifindex = TEST_IFINDEX,
        };
        struct jz_guard_entry entry = {
            .ip_addr    = gkey.ip_addr,
            .guard_type = JZ_GUARD_STATIC,
            .enabled    = 1,
        };
        memcpy(entry.fake_mac, TEST_FAKE_MAC, 6);
        bpf_map_update_elem(st->jz_static_guards_fd, &gkey, &entry, BPF_ANY);
    }
}

/* ── Main ── */

int main(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: performance tests require root (CAP_BPF)\n");
        fprintf(stderr, "Run with: sudo make test-perf\n");
        return 77;
    }

    if (access(GC_OBJ_PATH, F_OK) != 0) {
        fprintf(stderr, "ERROR: %s not found -- run 'make bpf' first\n", GC_OBJ_PATH);
        return 77;
    }

    printf("jz_sniff_rn Performance Benchmark\n");
    printf("==================================\n");
    printf("Warmup: %d iterations\n", WARMUP_REPEAT);
    printf("Bench:  %d iterations (single module), %d (pipeline)\n",
           BENCH_REPEAT, BENCH_REPEAT_PIPE);
    printf("\n");

    struct perf_state st;
    if (perf_setup(&st) != 0) {
        fprintf(stderr, "FATAL: setup failed\n");
        perf_teardown(&st);
        return 1;
    }

    /* Run all benchmark suites */
    bench_gc_only(&st);
    bench_pipeline(&st);
    bench_scalability(&st);

    /* Print consolidated results */
    print_results();

    perf_teardown(&st);

    printf("\nBenchmark complete. %d tests recorded.\n", nresults);
    return 0;
}
