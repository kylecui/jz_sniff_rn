/* SPDX-License-Identifier: MIT */

#include "discovery.h"
#include "guard_auto.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
#include <stdarg.h>
#include <fcntl.h>
#include <poll.h>

#define JZ_DISCOVERY_ARP_BATCH_SIZE   16

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

static uint64_t get_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static uint32_t mac_hash(const uint8_t mac[6])
{
    uint32_t h;
    int i;

    h = 2166136261U;
    for (i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619U;
    }
    return h % JZ_DISCOVERY_HASH_BUCKETS;
}

static bool is_zero_mac(const uint8_t mac[6])
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

static bool parse_subnet_cidr(const char *cidr, uint32_t *subnet, uint32_t *mask)
{
    struct in_addr addr;
    char ipbuf[64];
    char *slash;
    unsigned long prefix;
    uint32_t mask_h;

    if (!cidr || !subnet || !mask)
        return false;

    memset(ipbuf, 0, sizeof(ipbuf));
    snprintf(ipbuf, sizeof(ipbuf), "%s", cidr);
    slash = strchr(ipbuf, '/');
    if (!slash)
        return false;
    *slash = '\0';
    slash++;

    errno = 0;
    prefix = strtoul(slash, NULL, 10);
    if (errno != 0 || prefix > 32)
        return false;

    if (inet_pton(AF_INET, ipbuf, &addr) != 1)
        return false;

    if (prefix == 0)
        mask_h = 0;
    else
        mask_h = 0xFFFFFFFFU << (32U - (uint32_t)prefix);

    *mask = htonl(mask_h);
    *subnet = addr.s_addr & *mask;
    return true;
}

static const jz_config_interface_t *find_monitor_interface(const jz_config_t *cfg)
{
    int i;

    if (!cfg)
        return NULL;

    for (i = 0; i < cfg->system.interface_count; i++) {
        const jz_config_interface_t *iface = &cfg->system.interfaces[i];
        if (strcmp(iface->role, "monitor") == 0 && iface->name[0] != '\0')
            return iface;
    }

    return NULL;
}

static void set_scan_cursor_start(jz_discovery_t *disc)
{
    uint32_t subnet_h;
    uint32_t mask_h;
    uint32_t bcast_h;
    uint32_t start_h;

    if (!disc)
        return;

    subnet_h = ntohl(disc->scan_subnet);
    mask_h = ntohl(disc->scan_mask);
    bcast_h = subnet_h | ~mask_h;

    if (bcast_h <= subnet_h + 1U)
        start_h = subnet_h;
    else
        start_h = subnet_h + 1U;

    disc->scan_next_ip = htonl(start_h);
}

static uint32_t get_scan_end_ip(const jz_discovery_t *disc)
{
    uint32_t subnet_h;
    uint32_t mask_h;
    uint32_t bcast_h;

    subnet_h = ntohl(disc->scan_subnet);
    mask_h = ntohl(disc->scan_mask);
    bcast_h = subnet_h | ~mask_h;
    if (bcast_h <= subnet_h + 1U)
        return htonl(subnet_h);
    return htonl(bcast_h - 1U);
}

static int open_arp_socket(jz_discovery_t *disc, const jz_config_t *cfg)
{
    const jz_config_interface_t *iface;
    struct sockaddr_ll bind_addr;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    unsigned int ifindex;
    int sock;

    if (!disc || !cfg)
        return -1;

    iface = find_monitor_interface(cfg);
    if (!iface) {
        jz_log_warn("Discovery ARP init skipped: no monitor interface in config");
        return -1;
    }

    ifindex = if_nametoindex(iface->name);
    if (ifindex == 0) {
        jz_log_error("if_nametoindex(%s) failed: %s", iface->name, strerror(errno));
        return -1;
    }

    if (!parse_subnet_cidr(iface->subnet, &disc->scan_subnet, &disc->scan_mask)) {
        jz_log_error("Invalid monitor subnet CIDR: %s", iface->subnet);
        return -1;
    }

    sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ARP));
    if (sock < 0) {
        jz_log_error("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP) failed: %s", strerror(errno));
        return -1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex = (int)ifindex;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        jz_log_error("bind(AF_PACKET ifindex=%u) failed: %s", ifindex, strerror(errno));
        close(sock);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    {
        size_t ifname_len = strnlen(iface->name, IFNAMSIZ - 1);
        memcpy(ifr.ifr_name, iface->name, ifname_len);
        ifr.ifr_name[ifname_len] = '\0';
    }
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        jz_log_error("ioctl(SIOCGIFHWADDR) failed for %s: %s", iface->name, strerror(errno));
        close(sock);
        return -1;
    }
    memcpy(disc->arp_src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        jz_log_error("ioctl(SIOCGIFADDR) failed for %s: %s", iface->name, strerror(errno));
        close(sock);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    disc->arp_src_ip = sin->sin_addr.s_addr;

    disc->arp_sock = sock;
    disc->arp_ifindex = (int)ifindex;
    set_scan_cursor_start(disc);
    disc->last_arp_scan_ns = 0;
    return 0;
}

static int reopen_arp_socket_if_needed(jz_discovery_t *disc, const jz_config_t *cfg)
{
    const jz_config_interface_t *iface;
    uint32_t cfg_subnet;
    uint32_t cfg_mask;
    unsigned int cfg_ifindex;
    bool changed;

    if (!disc || !cfg)
        return -1;

    iface = find_monitor_interface(cfg);
    if (!iface)
        return 0;

    cfg_ifindex = if_nametoindex(iface->name);
    if (cfg_ifindex == 0)
        return 0;

    if (!parse_subnet_cidr(iface->subnet, &cfg_subnet, &cfg_mask))
        return 0;

    changed = (disc->arp_ifindex != (int)cfg_ifindex) ||
              (disc->scan_subnet != cfg_subnet) ||
              (disc->scan_mask != cfg_mask);
    if (!changed)
        return 0;

    if (disc->arp_sock >= 0)
        close(disc->arp_sock);
    disc->arp_sock = -1;
    disc->arp_ifindex = 0;
    disc->arp_src_ip = 0;
    memset(disc->arp_src_mac, 0, sizeof(disc->arp_src_mac));
    disc->scan_subnet = 0;
    disc->scan_mask = 0;
    disc->scan_next_ip = 0;

    if (open_arp_socket(disc, cfg) < 0) {
        jz_log_warn("Discovery ARP socket reinit failed; active scan disabled until next reload");
        return -1;
    }

    return 0;
}

static int send_arp_request(jz_discovery_t *disc, uint32_t target_ip)
{
    struct arp_pkt pkt;
    struct sockaddr_ll sa;

    if (!disc || disc->arp_sock < 0 || disc->arp_ifindex <= 0)
        return -1;

    memset(&pkt, 0, sizeof(pkt));
    memset(&sa, 0, sizeof(sa));

    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, disc->arp_src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = ETH_ALEN;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt.arp.ar_sha, disc->arp_src_mac, ETH_ALEN);
    pkt.arp.ar_sip = disc->arp_src_ip;
    memset(pkt.arp.ar_tha, 0x00, ETH_ALEN);
    pkt.arp.ar_tip = target_ip;

    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = disc->arp_ifindex;
    sa.sll_halen = ETH_ALEN;
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(disc->arp_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_warn("Discovery ARP sendto failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static bool extract_src_ip(uint8_t proto, const uint8_t *payload, uint32_t payload_len, uint32_t *src_ip)
{
    uint16_t ethertype;

    if (!payload || !src_ip || payload_len < 14)
        return false;

    if (proto == FP_PROTO_ARP) {
        if (payload_len < 32)
            return false;
        memcpy(src_ip, payload + 28, sizeof(*src_ip));
        return *src_ip != 0;
    }

    ethertype = ((uint16_t)payload[12] << 8) | payload[13];
    if (ethertype != ETH_P_IP || payload_len < 30)
        return false;

    memcpy(src_ip, payload + 26, sizeof(*src_ip));
    return *src_ip != 0;
}

static bool extract_arp_reply_sender(const uint8_t *payload, uint32_t payload_len,
                                     uint32_t *sender_ip, uint8_t sender_mac[6])
{
    uint16_t ethertype;
    uint16_t arp_op;

    if (!payload || payload_len < 42 || !sender_ip || !sender_mac)
        return false;

    ethertype = ((uint16_t)payload[12] << 8) | payload[13];
    if (ethertype != ETH_P_ARP)
        return false;

    arp_op = ((uint16_t)payload[20] << 8) | payload[21];
    if (arp_op != ARPOP_REPLY)
        return false;

    memcpy(sender_mac, payload + 22, 6);
    memcpy(sender_ip, payload + 28, sizeof(*sender_ip));
    return true;
}

static int buf_append(char *buf, size_t buf_size, int *off, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!buf || !off || !fmt || *off < 0)
        return -1;
    if ((size_t)(*off) >= buf_size)
        return -1;

    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - (size_t)(*off), fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size - (size_t)(*off)) {
        *off = (int)(buf_size - 1);
        return -1;
    }

    *off += n;
    return 0;
}

static int buf_append_json_escaped(char *buf, size_t buf_size, int *off, const char *src)
{
    const char *s;

    if (!src)
        src = "";

    for (s = src; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            if (buf_append(buf, buf_size, off, "\\%c", c) < 0)
                return -1;
        } else if (c < 0x20) {
            if (buf_append(buf, buf_size, off, "\\u%04x", (unsigned int)c) < 0)
                return -1;
        } else {
            if (buf_append(buf, buf_size, off, "%c", c) < 0)
                return -1;
        }
    }

    return 0;
}

int jz_discovery_init(jz_discovery_t *disc, const jz_config_t *cfg)
{
    int rc;

    if (!disc || !cfg)
        return -1;

    memset(disc, 0, sizeof(*disc));
    disc->arp_sock = -1;
    disc->max_devices = cfg->guards.dynamic.max_entries;
    if (disc->max_devices <= 0 || disc->max_devices > JZ_DISCOVERY_MAX_DEVICES)
        disc->max_devices = JZ_DISCOVERY_MAX_DEVICES;

    rc = fp_init();
    if (rc < 0) {
        jz_log_error("Fingerprint init failed");
        jz_discovery_destroy(disc);
        return -1;
    }

    disc->arp_interval_sec = JZ_DISCOVERY_ARP_INTERVAL;
    if (open_arp_socket(disc, cfg) < 0)
        jz_log_warn("Discovery active ARP scanning disabled at init");

    disc->initialized = true;
    return 0;
}

void jz_discovery_destroy(jz_discovery_t *disc)
{
    int i;

    if (!disc)
        return;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        jz_discovery_device_t *node = disc->buckets[i];
        while (node) {
            jz_discovery_device_t *next = node->next;
            free(node);
            node = next;
        }
    }

    if (disc->arp_sock > 0)
        close(disc->arp_sock);

    fp_destroy();
    memset(disc, 0, sizeof(*disc));
}

int jz_discovery_tick(jz_discovery_t *disc)
{
    uint64_t now_ns;
    uint64_t interval_ns;
    uint32_t scan_end;
    int i;

    if (!disc || !disc->initialized)
        return -1;
    if (disc->arp_sock < 0 || disc->arp_ifindex <= 0 || disc->scan_mask == 0)
        return 0;

    now_ns = get_monotonic_ns();
    interval_ns = (uint64_t)disc->arp_interval_sec * 1000000000ULL;
    if (disc->last_arp_scan_ns != 0 && now_ns > disc->last_arp_scan_ns &&
        (now_ns - disc->last_arp_scan_ns) < interval_ns)
        return 0;

    if (disc->scan_next_ip == 0)
        set_scan_cursor_start(disc);
    scan_end = get_scan_end_ip(disc);

    for (i = 0; i < JZ_DISCOVERY_ARP_BATCH_SIZE; i++) {
        uint32_t tip = disc->scan_next_ip;
        uint32_t tip_h;
        uint32_t end_h;
        uint32_t start_h;

        if (send_arp_request(disc, tip) < 0)
            break;

        tip_h = ntohl(tip);
        end_h = ntohl(scan_end);
        start_h = ntohl(disc->scan_subnet);
        if (end_h > start_h)
            start_h += 1U;

        if (tip_h >= end_h)
            disc->scan_next_ip = htonl(start_h);
        else
            disc->scan_next_ip = htonl(tip_h + 1U);
    }

    disc->last_arp_scan_ns = now_ns;
    return 0;
}

int jz_discovery_recv_arp(jz_discovery_t *disc)
{
    uint8_t buf[128];
    ssize_t n;
    int count;

    if (!disc || !disc->initialized || disc->arp_sock < 0)
        return 0;

    /*
     * Drain all pending ARP frames from the raw socket (non-blocking).
     * The socket is AF_PACKET bound to ETH_P_ARP, so every frame here
     * is an ARP packet including the ethernet header.
     * Cap at 64 per call to avoid starving the main loop.
     */
    count = 0;
    while (count < 64) {
        n = recv(disc->arp_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            jz_log_warn("discovery recv_arp error: %s", strerror(errno));
            break;
        }
        if (n < 42)   /* minimum ARP frame: 14 eth + 28 arp */
            continue;

        /* Feed the raw frame — discovery_feed_event extracts src_mac at
         * offset 6 and, for FP_PROTO_ARP, sender IP at offset 28. */
        jz_discovery_feed_event(disc, FP_PROTO_ARP, buf, (uint32_t)n, 0);
        count++;
    }

    return count;
}

jz_discovery_device_t *jz_discovery_lookup(jz_discovery_t *disc, const uint8_t mac[6])
{
    uint32_t bucket;
    jz_discovery_device_t *node;

    if (!disc || !mac)
        return NULL;

    bucket = mac_hash(mac);
    node = disc->buckets[bucket];
    while (node) {
        if (memcmp(node->profile.mac, mac, 6) == 0)
            return node;
        node = node->next;
    }
    return NULL;
}

int jz_discovery_feed_event(jz_discovery_t *disc, uint8_t proto,
                            const uint8_t *payload, uint32_t payload_len,
                            uint16_t vlan_id)
{
    uint8_t src_mac[6];
    uint32_t src_ip;
    jz_discovery_device_t *device;
    uint32_t now_sec;

    if (!disc || !disc->initialized || !payload || payload_len < 12)
        return -1;

    memcpy(src_mac, payload + 6, sizeof(src_mac));
    if (is_zero_mac(src_mac))
        return -1;

    device = jz_discovery_lookup(disc, src_mac);
    if (!device) {
        uint32_t bucket;

        if (disc->device_count >= disc->max_devices) {
            jz_log_warn("Discovery table full (%d), dropping new device", disc->max_devices);
            return 0;
        }

        device = calloc(1, sizeof(*device));
        if (!device)
            return -1;

        memcpy(device->profile.mac, src_mac, sizeof(src_mac));
        bucket = mac_hash(src_mac);
        device->next = disc->buckets[bucket];
        disc->buckets[bucket] = device;
        disc->device_count++;
    }

    now_sec = (uint32_t)time(NULL);
    if (device->profile.first_seen == 0)
        device->profile.first_seen = now_sec;
    device->profile.last_seen = now_sec;

    if (vlan_id != 0)
        device->profile.vlan = vlan_id;

    src_ip = 0;
    if (extract_src_ip(proto, payload, payload_len, &src_ip) && device->profile.ip == 0)
        device->profile.ip = src_ip;

    if (fp_update_profile(&device->profile, proto, payload, payload_len) < 0)
        return 0;

    if (proto == FP_PROTO_ARP && disc->guard_auto) {
        uint32_t arp_sender_ip;
        uint8_t arp_sender_mac[6];

        if (extract_arp_reply_sender(payload, payload_len,
                                     &arp_sender_ip, arp_sender_mac))
            (void)jz_guard_auto_check_conflict(disc->guard_auto,
                                               arp_sender_ip,
                                               arp_sender_mac);
    }

    return 0;
}

int jz_discovery_list_json(const jz_discovery_t *disc, char *buf, size_t buf_size)
{
    int off;
    int i;
    int written;
    bool first;
    int total;

    if (!disc || !buf || buf_size == 0)
        return -1;

    off = 0;
    first = true;
    total = 0;

    if (buf_append(buf, buf_size, &off, "{\"devices\":[") < 0)
        return -1;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        const jz_discovery_device_t *node = disc->buckets[i];
        while (node) {
            const device_profile_t *p = &node->profile;
            char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";
            char macbuf[18];

            if (p->ip != 0) {
                struct in_addr addr;
                addr.s_addr = p->ip;
                if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                    snprintf(ipbuf, sizeof(ipbuf), "0.0.0.0");
            }

            written = snprintf(macbuf, sizeof(macbuf),
                               "%02x:%02x:%02x:%02x:%02x:%02x",
                               p->mac[0], p->mac[1], p->mac[2],
                               p->mac[3], p->mac[4], p->mac[5]);
            if (written < 0 || (size_t)written >= sizeof(macbuf))
                return -1;

            if (!first) {
                if (buf_append(buf, buf_size, &off, ",") < 0)
                    return -1;
            }
            first = false;

            if (buf_append(buf, buf_size, &off,
                           "{\"mac\":\"%s\",\"ip\":\"%s\",\"vendor\":\"",
                           macbuf, ipbuf) < 0)
                return -1;
            if (buf_append_json_escaped(buf, buf_size, &off, p->vendor) < 0)
                return -1;
            if (buf_append(buf, buf_size, &off, "\",\"os_class\":\"") < 0)
                return -1;
            if (buf_append_json_escaped(buf, buf_size, &off, p->os_class) < 0)
                return -1;
            if (buf_append(buf, buf_size, &off, "\",\"device_class\":\"") < 0)
                return -1;
            if (buf_append_json_escaped(buf, buf_size, &off, p->device_class) < 0)
                return -1;
            if (buf_append(buf, buf_size, &off, "\",\"hostname\":\"") < 0)
                return -1;
            if (buf_append_json_escaped(buf, buf_size, &off, p->hostname) < 0)
                return -1;
            if (buf_append(buf, buf_size, &off,
                           "\",\"confidence\":%u,\"signals\":%u,\"first_seen\":%u,\"last_seen\":%u,\"vlan\":%u}",
                           p->confidence, p->signals, p->first_seen, p->last_seen, p->vlan) < 0)
                return -1;

            total++;
            node = node->next;
        }
    }

    if (buf_append(buf, buf_size, &off, "],\"total\":%d}", total) < 0)
        return -1;
    return off;
}

void jz_discovery_update_config(jz_discovery_t *disc, const jz_config_t *cfg)
{
    int new_max;

    if (!disc || !cfg || !disc->initialized)
        return;

    new_max = cfg->guards.dynamic.max_entries;
    if (new_max <= 0 || new_max > JZ_DISCOVERY_MAX_DEVICES)
        new_max = JZ_DISCOVERY_MAX_DEVICES;
    disc->max_devices = new_max;
    disc->arp_interval_sec = JZ_DISCOVERY_ARP_INTERVAL;

    (void)reopen_arp_socket_if_needed(disc, cfg);
}
