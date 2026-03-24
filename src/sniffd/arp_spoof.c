/* SPDX-License-Identifier: MIT */

#include "arp_spoof.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
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

struct arp_pkt {
    struct ethhdr eth;
    struct {
        __be16  ar_hrd;
        __be16  ar_pro;
        uint8_t ar_hln;
        uint8_t ar_pln;
        __be16  ar_op;
        uint8_t ar_sha[6];
        uint32_t ar_sip;
        uint8_t ar_tha[6];
        uint32_t ar_tip;
    } __attribute__((packed)) arp;
};

static int arm_timerfd(jz_arp_spoof_t *as)
{
    struct itimerspec its;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = as->interval_sec;
    its.it_interval.tv_sec = as->interval_sec;
    if (timerfd_settime(as->timerfd, 0, &its, NULL) < 0) {
        jz_log_error("arp_spoof: timerfd_settime failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int disarm_timerfd(jz_arp_spoof_t *as)
{
    struct itimerspec its;

    memset(&its, 0, sizeof(its));
    if (timerfd_settime(as->timerfd, 0, &its, NULL) < 0)
        return -1;
    return 0;
}

static int send_arp_reply(const jz_arp_spoof_t *as,
                          const uint8_t *dst_mac, uint32_t dst_ip,
                          const uint8_t *src_mac, uint32_t src_ip)
{
    struct arp_pkt pkt;
    struct sockaddr_ll sa;

    memset(&pkt, 0, sizeof(pkt));
    memset(&sa, 0, sizeof(sa));

    memcpy(pkt.eth.h_dest, dst_mac, ETH_ALEN);
    memcpy(pkt.eth.h_source, src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = ETH_ALEN;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op  = htons(ARPOP_REPLY);
    memcpy(pkt.arp.ar_sha, src_mac, ETH_ALEN);
    pkt.arp.ar_sip = src_ip;
    memcpy(pkt.arp.ar_tha, dst_mac, ETH_ALEN);
    pkt.arp.ar_tip = dst_ip;

    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = as->ifindex;
    sa.sll_halen    = ETH_ALEN;
    memcpy(sa.sll_addr, dst_mac, ETH_ALEN);

    if (sendto(as->raw_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_error("arp_spoof: sendto failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int resolve_mac_via_arp(const jz_arp_spoof_t *as, uint32_t ip, uint8_t *mac_out)
{
    struct arpreq req;
    struct sockaddr_in *sin;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;

    if (if_indextoname((unsigned int)as->ifindex, req.arp_dev) == NULL) {
        close(sock);
        return -1;
    }

    if (ioctl(sock, SIOCGARP, &req) < 0) {
        close(sock);
        return -1;
    }
    close(sock);

    if (!(req.arp_flags & ATF_COM))
        return -1;

    memcpy(mac_out, req.arp_ha.sa_data, 6);
    return 0;
}

static void send_poison_packets(jz_arp_spoof_t *as)
{
    int i;
    int sent = 0;

    for (i = 0; i < as->target_count; i++) {
        jz_arp_spoof_target_t *t = &as->targets[i];

        if (!t->resolved) {
            if (resolve_mac_via_arp(as, t->target_ip, t->target_mac) == 0 &&
                resolve_mac_via_arp(as, t->gateway_ip, t->gateway_mac) == 0) {
                t->resolved = true;
                jz_log_info("arp_spoof: resolved target %08x gw %08x",
                            ntohl(t->target_ip), ntohl(t->gateway_ip));
            } else {
                continue;
            }
        }

        /* Tell target: gateway is at our MAC */
        send_arp_reply(as, t->target_mac, t->target_ip,
                       as->local_mac, t->gateway_ip);

        /* Tell gateway: target is at our MAC */
        send_arp_reply(as, t->gateway_mac, t->gateway_ip,
                       as->local_mac, t->target_ip);
        sent++;
    }

    if (sent > 0)
        jz_log_debug("arp_spoof: sent poison to %d target pairs", sent);
}

static void send_restore_packets(jz_arp_spoof_t *as)
{
    int i;

    for (i = 0; i < as->target_count; i++) {
        jz_arp_spoof_target_t *t = &as->targets[i];
        if (!t->resolved)
            continue;

        /* Restore target: gateway is at gateway's real MAC */
        send_arp_reply(as, t->target_mac, t->target_ip,
                       t->gateway_mac, t->gateway_ip);

        /* Restore gateway: target is at target's real MAC */
        send_arp_reply(as, t->gateway_mac, t->gateway_ip,
                       t->target_mac, t->target_ip);
    }

    jz_log_info("arp_spoof: sent restore packets for %d targets", as->target_count);
}

static void load_targets_from_config(jz_arp_spoof_t *as, const jz_config_t *cfg)
{
    int i;
    int count = cfg->arp_spoof.target_count;

    if (count > JZ_ARP_SPOOF_MAX_TARGETS)
        count = JZ_ARP_SPOOF_MAX_TARGETS;

    as->target_count = 0;
    for (i = 0; i < count; i++) {
        struct in_addr tip, gip;

        if (inet_pton(AF_INET, cfg->arp_spoof.targets[i].target_ip, &tip) != 1)
            continue;
        if (inet_pton(AF_INET, cfg->arp_spoof.targets[i].gateway_ip, &gip) != 1)
            continue;

        as->targets[as->target_count].target_ip  = tip.s_addr;
        as->targets[as->target_count].gateway_ip = gip.s_addr;
        as->targets[as->target_count].resolved   = false;
        as->target_count++;
    }
}

int jz_arp_spoof_init(jz_arp_spoof_t *as, const jz_config_t *cfg, int ifindex)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    char ifname[IF_NAMESIZE];

    if (!as || !cfg || ifindex <= 0)
        return -1;

    memset(as, 0, sizeof(*as));
    as->timerfd  = -1;
    as->raw_sock = -1;
    as->ifindex  = ifindex;
    as->interval_sec = cfg->arp_spoof.interval_sec;
    as->enabled  = cfg->arp_spoof.enabled;
    if (as->interval_sec < 1)
        as->interval_sec = 5;

    as->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (as->timerfd < 0) {
        jz_log_error("arp_spoof: timerfd_create failed: %s", strerror(errno));
        jz_arp_spoof_destroy(as);
        return -1;
    }

    as->raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (as->raw_sock < 0) {
        jz_log_error("arp_spoof: socket(AF_PACKET) failed: %s", strerror(errno));
        jz_arp_spoof_destroy(as);
        return -1;
    }

    if (!if_indextoname((unsigned int)ifindex, ifname)) {
        jz_log_error("arp_spoof: if_indextoname(%d) failed: %s", ifindex, strerror(errno));
        jz_arp_spoof_destroy(as);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(as->raw_sock, SIOCGIFHWADDR, &ifr) < 0) {
        jz_log_error("arp_spoof: ioctl(SIOCGIFHWADDR) failed: %s", strerror(errno));
        jz_arp_spoof_destroy(as);
        return -1;
    }
    memcpy(as->local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(as->raw_sock, SIOCGIFADDR, &ifr) < 0) {
        jz_log_error("arp_spoof: ioctl(SIOCGIFADDR) failed: %s", strerror(errno));
        jz_arp_spoof_destroy(as);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    as->local_ip = sin->sin_addr.s_addr;

    load_targets_from_config(as, cfg);

    if (as->enabled && as->target_count > 0) {
        if (arm_timerfd(as) < 0) {
            jz_arp_spoof_destroy(as);
            return -1;
        }
    }

    as->initialized = true;
    jz_log_info("arp_spoof: initialized (enabled=%s, targets=%d, interval=%ds)",
                as->enabled ? "true" : "false", as->target_count, as->interval_sec);
    return 0;
}

int jz_arp_spoof_tick(jz_arp_spoof_t *as)
{
    uint64_t expirations = 0;
    ssize_t n;

    if (!as || !as->initialized || !as->enabled)
        return 0;

    n = read(as->timerfd, &expirations, sizeof(expirations));
    if (n < 0) {
        if (errno == EAGAIN)
            return 0;
        jz_log_error("arp_spoof: timerfd read failed: %s", strerror(errno));
        return -1;
    }
    if (expirations == 0)
        return 0;

    send_poison_packets(as);
    return 0;
}

void jz_arp_spoof_update_config(jz_arp_spoof_t *as, const jz_config_t *cfg)
{
    bool was_enabled;
    int old_interval;

    if (!as || !cfg || !as->initialized)
        return;

    was_enabled  = as->enabled;
    old_interval = as->interval_sec;

    as->enabled      = cfg->arp_spoof.enabled;
    as->interval_sec = cfg->arp_spoof.interval_sec;
    if (as->interval_sec < 1)
        as->interval_sec = 5;

    if (was_enabled && !as->enabled) {
        send_restore_packets(as);
        disarm_timerfd(as);
        jz_log_info("arp_spoof: stopped");
    }

    load_targets_from_config(as, cfg);

    if (as->enabled && as->target_count > 0) {
        if (!was_enabled || old_interval != as->interval_sec)
            arm_timerfd(as);
        jz_log_info("arp_spoof: config updated (targets=%d, interval=%ds)",
                    as->target_count, as->interval_sec);
    } else if (as->enabled && as->target_count == 0) {
        disarm_timerfd(as);
        jz_log_info("arp_spoof: enabled but no targets");
    }
}

int jz_arp_spoof_start(jz_arp_spoof_t *as)
{
    if (!as || !as->initialized)
        return -1;

    as->enabled = true;
    if (as->target_count > 0)
        return arm_timerfd(as);
    return 0;
}

int jz_arp_spoof_stop(jz_arp_spoof_t *as)
{
    if (!as || !as->initialized)
        return -1;

    if (as->enabled)
        send_restore_packets(as);

    as->enabled = false;
    return disarm_timerfd(as);
}

void jz_arp_spoof_destroy(jz_arp_spoof_t *as)
{
    if (!as)
        return;

    if (as->initialized && as->enabled)
        send_restore_packets(as);

    if (as->timerfd >= 0)
        close(as->timerfd);
    if (as->raw_sock >= 0)
        close(as->raw_sock);

    memset(as, 0, sizeof(*as));
    as->timerfd  = -1;
    as->raw_sock = -1;
    jz_log_info("arp_spoof: destroyed");
}
