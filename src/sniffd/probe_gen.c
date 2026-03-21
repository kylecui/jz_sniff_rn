/* SPDX-License-Identifier: MIT */
/*
 * probe_gen.c - ARP probe generator implementation for sniffd.
 *
 * Periodically emits ARP probes to non-existent subnet IPs and stores
 * pending probe targets in jz_probe_targets for sniffer correlation.
 */

#include "probe_gen.h"
#include "log.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>

/* ── Constants ─────────────────────────────────────────────────── */

#define BPF_PIN_PROBE_TARGETS "/sys/fs/bpf/jz/jz_probe_targets"

/* ── Types ─────────────────────────────────────────────────────── */

struct arp_pkt {
    struct ethhdr eth;
    struct {
        __be16 ar_hrd;
        __be16 ar_pro;
        uint8_t ar_hln;
        uint8_t ar_pln;
        __be16 ar_op;
        uint8_t ar_sha[6];
        uint32_t ar_sip;
        uint8_t ar_tha[6];
        uint32_t ar_tip;
    } __attribute__((packed)) arp;
};

struct jz_probe_target {
    uint32_t probe_ip;
    uint64_t probe_sent_ns;
    uint32_t probe_ifindex;
    uint8_t  status;
    uint8_t  _pad[3];
};

static const jz_config_t *g_cfg;

/* ── Helpers ───────────────────────────────────────────────────── */

/* Return monotonic timestamp in nanoseconds. */
static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;

    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

/* Arm timerfd using current interval. */
static int arm_timerfd(jz_probe_gen_t *pg)
{
    struct itimerspec its;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = pg->interval_sec;
    its.it_interval.tv_sec = pg->interval_sec;
    if (timerfd_settime(pg->timerfd, 0, &its, NULL) < 0) {
        jz_log_error("timerfd_settime failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Return true if candidate IP is configured guard/whitelist target. */
static bool is_reserved_ip(uint32_t ip)
{
    int i;

    if (!g_cfg)
        return false;

    for (i = 0; i < g_cfg->guards.static_count; i++) {
        struct in_addr addr;

        if (inet_pton(AF_INET, g_cfg->guards.static_entries[i].ip, &addr) == 1 &&
            addr.s_addr == ip) {
            return true;
        }
    }

    for (i = 0; i < g_cfg->guards.whitelist_count; i++) {
        struct in_addr addr;

        if (inet_pton(AF_INET, g_cfg->guards.whitelist[i].ip, &addr) == 1 &&
            addr.s_addr == ip) {
            return true;
        }
    }

    return false;
}

/* Return true if candidate is already active. */
static bool is_active_target(const jz_probe_gen_t *pg, uint32_t ip)
{
    int i;

    for (i = 0; i < JZ_PROBE_MAX_TARGETS; i++) {
        if (pg->targets[i].active && pg->targets[i].ip == ip)
            return true;
    }

    return false;
}

/* Pick random likely non-existent host IP from high subnet range. */
static uint32_t pick_nonexistent_ip(const jz_probe_gen_t *pg)
{
    uint32_t local_h = ntohl(pg->local_ip);
    uint32_t mask_h = ntohl(pg->netmask);
    uint32_t base_h = local_h & mask_h;
    uint32_t bcast_h = base_h | ~mask_h;
    uint32_t span;
    int attempt;

    if (bcast_h <= base_h + 3)
        return htonl(local_h ^ 1u);

    span = bcast_h - base_h - 2u;
    for (attempt = 0; attempt < 16; attempt++) {
        uint32_t offset = ((uint32_t)rand() % span) + 2u;
        uint32_t candidate = htonl(bcast_h - offset);

        if (candidate == pg->local_ip)
            continue;
        if (is_reserved_ip(candidate))
            continue;
        if (is_active_target(pg, candidate))
            continue;
        return candidate;
    }

    return htonl(bcast_h - 2u);
}

/* Craft and send one ARP probe packet. */
static int send_arp_probe(const jz_probe_gen_t *pg, uint32_t probe_ip)
{
    struct arp_pkt pkt;
    struct sockaddr_ll sa;

    memset(&pkt, 0, sizeof(pkt));
    memset(&sa, 0, sizeof(sa));

    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, pg->local_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = ETH_ALEN;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt.arp.ar_sha, pg->local_mac, ETH_ALEN);
    pkt.arp.ar_sip = pg->local_ip;
    memset(pkt.arp.ar_tha, 0x00, ETH_ALEN);
    pkt.arp.ar_tip = probe_ip;

    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = pg->ifindex;
    sa.sll_halen = ETH_ALEN;
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(pg->raw_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_error("sendto failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* Expire stale targets and remove from map. */
static void expire_targets(jz_probe_gen_t *pg)
{
    uint64_t now = monotonic_ns();
    uint64_t expire_ns = (uint64_t)JZ_PROBE_EXPIRY_SEC * 1000000000ull;
    int i;

    for (i = 0; i < JZ_PROBE_MAX_TARGETS; i++) {
        uint32_t key;

        if (!pg->targets[i].active)
            continue;
        if (pg->targets[i].sent_ns + expire_ns >= now)
            continue;

        key = pg->targets[i].ip;
        if (pg->bpf_map_fd >= 0 &&
            bpf_map_delete_elem(pg->bpf_map_fd, &key) < 0 && errno != ENOENT) {
            jz_log_warn("bpf_map_delete_elem failed: %s", strerror(errno));
        }

        pg->targets[i].active = false;
        pg->targets[i].ip = 0;
        pg->targets[i].sent_ns = 0;
        if (pg->target_count > 0)
            pg->target_count--;
    }
}

/* Sync active targets to jz_probe_targets map. */
static void sync_to_bpf_map(jz_probe_gen_t *pg)
{
    int i;

    if (pg->bpf_map_fd < 0)
        return;

    for (i = 0; i < JZ_PROBE_MAX_TARGETS; i++) {
        struct jz_probe_target value;
        uint32_t key;

        if (!pg->targets[i].active)
            continue;

        memset(&value, 0, sizeof(value));
        key = pg->targets[i].ip;
        value.probe_ip = pg->targets[i].ip;
        value.probe_sent_ns = pg->targets[i].sent_ns;
        value.probe_ifindex = (uint32_t)pg->ifindex;
        value.status = 0;

        if (bpf_map_update_elem(pg->bpf_map_fd, &key, &value, BPF_ANY) < 0)
            jz_log_warn("bpf_map_update_elem failed: %s", strerror(errno));
    }
}

/* ── Public API ───────────────────────────────────────────────── */

int jz_probe_gen_init(jz_probe_gen_t *pg, const jz_config_t *cfg, int ifindex)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    char ifname[IF_NAMESIZE];

    if (!pg || !cfg || ifindex <= 0)
        return -1;

    memset(pg, 0, sizeof(*pg));
    pg->timerfd = -1;
    pg->raw_sock = -1;
    pg->bpf_map_fd = -1;
    pg->ifindex = ifindex;
    pg->interval_sec = cfg->modules.sniffer_detect.probe_interval_sec;
    pg->probe_count = cfg->modules.sniffer_detect.probe_count;
    if (pg->interval_sec <= 0)
        pg->interval_sec = JZ_PROBE_DEFAULT_INTERVAL_SEC;
    if (pg->probe_count <= 0)
        pg->probe_count = JZ_PROBE_DEFAULT_COUNT;

    pg->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (pg->timerfd < 0) {
        jz_log_error("timerfd_create failed: %s", strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }
    if (arm_timerfd(pg) < 0) {
        jz_probe_gen_destroy(pg);
        return -1;
    }

    pg->raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (pg->raw_sock < 0) {
        jz_log_error("socket(AF_PACKET) failed: %s", strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }

    if (!if_indextoname((unsigned int)ifindex, ifname)) {
        jz_log_error("if_indextoname(%d) failed: %s", ifindex, strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(pg->raw_sock, SIOCGIFHWADDR, &ifr) < 0) {
        jz_log_error("ioctl(SIOCGIFHWADDR) failed: %s", strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }
    memcpy(pg->local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(pg->raw_sock, SIOCGIFADDR, &ifr) < 0) {
        jz_log_error("ioctl(SIOCGIFADDR) failed: %s", strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    pg->local_ip = sin->sin_addr.s_addr;

    if (ioctl(pg->raw_sock, SIOCGIFNETMASK, &ifr) < 0) {
        jz_log_error("ioctl(SIOCGIFNETMASK) failed: %s", strerror(errno));
        jz_probe_gen_destroy(pg);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    pg->netmask = sin->sin_addr.s_addr;

    pg->bpf_map_fd = bpf_obj_get(BPF_PIN_PROBE_TARGETS);
    if (pg->bpf_map_fd < 0)
        jz_log_warn("Cannot open %s: %s", BPF_PIN_PROBE_TARGETS, strerror(errno));

    srand((unsigned int)(time(NULL) ^ (time_t)getpid() ^ (time_t)ifindex));
    g_cfg = cfg;
    pg->initialized = true;

    jz_log_info("Probe generator initialized: interval=%ds, count=%d, ifindex=%d",
                pg->interval_sec, pg->probe_count, pg->ifindex);
    return 0;
}

int jz_probe_gen_tick(jz_probe_gen_t *pg)
{
    uint64_t expirations;
    int sent = 0;
    bool warned_full = false;
    int i;

    if (!pg || !pg->initialized)
        return -1;

    if (read(pg->timerfd, &expirations, sizeof(expirations)) < 0 && errno != EAGAIN) {
        jz_log_error("timerfd read failed: %s", strerror(errno));
        return -1;
    }

    expire_targets(pg);

    for (i = 0; i < pg->probe_count; i++) {
        uint32_t probe_ip = pick_nonexistent_ip(pg);
        int slot;

        for (slot = 0; slot < JZ_PROBE_MAX_TARGETS; slot++) {
            if (!pg->targets[slot].active)
                break;
        }
        if (slot >= JZ_PROBE_MAX_TARGETS) {
            if (!warned_full) {
                jz_log_warn("Probe target table full, skipping probes");
                warned_full = true;
            }
            continue;
        }
        if (send_arp_probe(pg, probe_ip) < 0)
            continue;

        pg->targets[slot].ip = probe_ip;
        pg->targets[slot].sent_ns = monotonic_ns();
        pg->targets[slot].active = true;
        pg->target_count++;
        sent++;
    }

    sync_to_bpf_map(pg);
    jz_log_debug("Sent %d ARP probes, %d active targets", sent, pg->target_count);
    return 0;
}

void jz_probe_gen_update_config(jz_probe_gen_t *pg, const jz_config_t *cfg)
{
    int old_interval;

    if (!pg || !cfg || !pg->initialized)
        return;

    old_interval = pg->interval_sec;
    pg->interval_sec = cfg->modules.sniffer_detect.probe_interval_sec;
    pg->probe_count = cfg->modules.sniffer_detect.probe_count;
    if (pg->interval_sec <= 0)
        pg->interval_sec = JZ_PROBE_DEFAULT_INTERVAL_SEC;
    if (pg->probe_count <= 0)
        pg->probe_count = JZ_PROBE_DEFAULT_COUNT;
    if (pg->timerfd >= 0 && old_interval != pg->interval_sec)
        (void)arm_timerfd(pg);

    g_cfg = cfg;
    jz_log_info("Probe config updated: interval=%ds, count=%d",
                pg->interval_sec, pg->probe_count);
}

void jz_probe_gen_destroy(jz_probe_gen_t *pg)
{
    if (!pg)
        return;

    if (pg->timerfd >= 0)
        close(pg->timerfd);
    if (pg->raw_sock >= 0)
        close(pg->raw_sock);
    if (pg->bpf_map_fd >= 0)
        close(pg->bpf_map_fd);

    memset(pg, 0, sizeof(*pg));
    g_cfg = NULL;
    jz_log_info("Probe generator destroyed");
}
