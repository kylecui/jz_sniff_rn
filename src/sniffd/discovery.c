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
#include <netinet/ip.h>
#include <netinet/udp.h>
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

static uint32_t device_hash(const uint8_t mac[6], uint32_t ifindex)
{
    uint32_t hash = 2166136261U;

    for (int i = 0; i < 6; i++) {
        hash ^= mac[i];
        hash *= 16777619U;
    }
    hash ^= ifindex;
    hash *= 16777619U;
    return hash % JZ_DISCOVERY_HASH_BUCKETS;
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

static void set_scan_cursor_start(jz_discovery_iface_t *iface)
{
    uint32_t subnet_h;
    uint32_t mask_h;
    uint32_t bcast_h;
    uint32_t start_h;

    if (!iface)
        return;

    subnet_h = ntohl(iface->scan_subnet);
    mask_h = ntohl(iface->scan_mask);
    bcast_h = subnet_h | ~mask_h;

    if (bcast_h <= subnet_h + 1U)
        start_h = subnet_h;
    else
        start_h = subnet_h + 1U;

    iface->scan_next_ip = htonl(start_h);
}

static uint32_t get_scan_end_ip(const jz_discovery_iface_t *iface)
{
    uint32_t subnet_h;
    uint32_t mask_h;
    uint32_t bcast_h;

    subnet_h = ntohl(iface->scan_subnet);
    mask_h = ntohl(iface->scan_mask);
    bcast_h = subnet_h | ~mask_h;
    if (bcast_h <= subnet_h + 1U)
        return htonl(subnet_h);
    return htonl(bcast_h - 1U);
}

static bool get_interface_mac(const char *ifname, uint8_t mac[6])
{
    struct ifreq ifr;
    int sock;

    if (!ifname || !mac)
        return false;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(sock);
    return true;
}

static bool get_interface_ip(const char *ifname, uint32_t *ip)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock;

    if (!ifname || !ip)
        return false;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = sin->sin_addr.s_addr;
    close(sock);
    return true;
}

static bool get_interface_netmask(const char *ifname, uint32_t *mask)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    int sock;

    if (!ifname || !mask)
        return false;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        close(sock);
        return false;
    }

    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    *mask = sin->sin_addr.s_addr;
    close(sock);
    return true;
}

static int find_monitor_interfaces(jz_discovery_t *disc, const jz_config_t *cfg)
{
    int i;

    if (!disc || !cfg)
        return 0;

    disc->iface_count = 0;

    for (i = 0; i < cfg->system.interface_count; i++) {
        const jz_config_interface_t *iface = &cfg->system.interfaces[i];
        jz_discovery_iface_t *dst;
        unsigned int ifindex;

        if (strcmp(iface->role, "monitor") != 0 || iface->name[0] == '\0')
            continue;
        if (disc->iface_count >= JZ_DISCOVERY_MAX_IFACES) {
            jz_log_warn("Discovery monitor interface limit reached (%d)",
                        JZ_DISCOVERY_MAX_IFACES);
            break;
        }

        ifindex = if_nametoindex(iface->name);
        if (ifindex == 0) {
            jz_log_warn("Discovery skip monitor iface %s: if_nametoindex failed (%s)",
                        iface->name, strerror(errno));
            continue;
        }

        dst = &disc->ifaces[disc->iface_count];
        memset(dst, 0, sizeof(*dst));
        dst->arp_sock = -1;
        dst->dhcp_sock = -1;
        dst->ifindex = (int)ifindex;

        if (!get_interface_ip(iface->name, &dst->src_ip)) {
            jz_log_warn("Discovery skip monitor iface %s: cannot read IPv4", iface->name);
            continue;
        }
        if (!get_interface_mac(iface->name, dst->src_mac)) {
            jz_log_warn("Discovery skip monitor iface %s: cannot read MAC", iface->name);
            continue;
        }
        if (!parse_subnet_cidr(iface->subnet, &dst->scan_subnet, &dst->scan_mask)) {
            /* Config subnet missing/invalid (e.g. DHCP interface with empty
             * subnet).  Fall back to the live kernel netmask so that
             * discovery still works once the interface has an IP. */
            uint32_t live_mask;
            if (!get_interface_netmask(iface->name, &live_mask) || live_mask == 0) {
                jz_log_warn("Discovery skip monitor iface %s: no subnet in config"
                            " and cannot read live netmask", iface->name);
                continue;
            }
            dst->scan_mask = live_mask;
            dst->scan_subnet = dst->src_ip & live_mask;
            jz_log_info("Discovery iface %s: using live netmask (no config subnet)",
                        iface->name);
        }

        set_scan_cursor_start(dst);

        if (iface->guard_warmup_mode >= 0)
            dst->warmup_mode = iface->guard_warmup_mode;
        else
            dst->warmup_mode = cfg->guards.dynamic.warmup_mode;

        disc->iface_count++;
    }

    return disc->iface_count;
}

static void close_iface_sockets(jz_discovery_iface_t *iface)
{
    if (!iface)
        return;

    if (iface->arp_sock >= 0) {
        close(iface->arp_sock);
        iface->arp_sock = -1;
    }
    if (iface->dhcp_sock >= 0) {
        close(iface->dhcp_sock);
        iface->dhcp_sock = -1;
    }
}

static void close_all_iface_sockets(jz_discovery_t *disc)
{
    int i;

    if (!disc)
        return;

    for (i = 0; i < disc->iface_count; i++)
        close_iface_sockets(&disc->ifaces[i]);
}

static int open_arp_socket(jz_discovery_iface_t *iface)
{
    struct sockaddr_ll bind_addr;
    int sock;

    if (!iface || iface->ifindex <= 0)
        return -1;

    sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ARP));
    if (sock < 0) {
        jz_log_error("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP) failed: %s", strerror(errno));
        return -1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex = iface->ifindex;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        jz_log_error("bind(AF_PACKET ifindex=%d) failed: %s", iface->ifindex, strerror(errno));
        close(sock);
        return -1;
    }

    iface->arp_sock = sock;
    return 0;
}

#define JZ_DHCP_BOOTP_MIN_LEN   300
#define JZ_DHCP_MAGIC_COOKIE    0x63825363

struct dhcp_discover_pkt {
    struct ethhdr eth;
    struct {
        uint8_t  ihl_ver;
        uint8_t  tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    } __attribute__((packed)) ip;
    struct {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    } __attribute__((packed)) udp;
    uint8_t bootp[JZ_DHCP_BOOTP_MIN_LEN];
} __attribute__((packed));

static uint16_t ip_checksum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)p;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static int open_dhcp_socket(jz_discovery_iface_t *iface)
{
    struct sockaddr_ll bind_addr;
    int sock;

    if (!iface || iface->ifindex <= 0)
        return -1;

    sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP));
    if (sock < 0) {
        jz_log_error("DHCP probe: socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_IP);
    bind_addr.sll_ifindex = iface->ifindex;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        jz_log_error("DHCP probe: bind failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    iface->dhcp_sock = sock;
    return 0;
}

static int send_dhcp_discover(jz_discovery_iface_t *iface)
{
    struct dhcp_discover_pkt pkt;
    struct sockaddr_ll sa;
    uint16_t udp_len;
    uint16_t ip_total;
    uint32_t xid;

    if (!iface || iface->dhcp_sock < 0 || iface->ifindex <= 0)
        return -1;

    xid = (uint32_t)get_monotonic_ns();

    memset(&pkt, 0, sizeof(pkt));

    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, iface->src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_IP);

    udp_len = (uint16_t)(sizeof(pkt.udp) + sizeof(pkt.bootp));
    ip_total = (uint16_t)(20 + udp_len);

    pkt.ip.ihl_ver = 0x45;
    pkt.ip.ttl = 128;
    pkt.ip.protocol = IPPROTO_UDP;
    pkt.ip.tot_len = htons(ip_total);
    pkt.ip.id = htons((uint16_t)(xid & 0xFFFF));
    pkt.ip.saddr = 0;
    pkt.ip.daddr = 0xFFFFFFFF;
    pkt.ip.check = ip_checksum(&pkt.ip, 20);

    pkt.udp.source = htons(68);
    pkt.udp.dest = htons(67);
    pkt.udp.len = htons(udp_len);

    pkt.bootp[0] = 1;
    pkt.bootp[1] = 1;
    pkt.bootp[2] = 6;
    memcpy(pkt.bootp + 4, &xid, 4);
    pkt.bootp[10] = 0x80;  /* BROADCAST flag — forces server to reply via
                               broadcast so bg_collector can capture it */
    memcpy(pkt.bootp + 28, iface->src_mac, ETH_ALEN);

    pkt.bootp[236] = 0x63;
    pkt.bootp[237] = 0x82;
    pkt.bootp[238] = 0x53;
    pkt.bootp[239] = 0x63;

    pkt.bootp[240] = 53;
    pkt.bootp[241] = 1;
    pkt.bootp[242] = 1;

    pkt.bootp[243] = 55;
    pkt.bootp[244] = 4;
    pkt.bootp[245] = 1;
    pkt.bootp[246] = 3;
    pkt.bootp[247] = 6;
    pkt.bootp[248] = 15;

    pkt.bootp[249] = 255;

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = iface->ifindex;
    sa.sll_halen = ETH_ALEN;
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(iface->dhcp_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_warn("DHCP probe sendto failed: %s", strerror(errno));
        return -1;
    }

    jz_log_debug("DHCP DISCOVER sent (xid=%08x)", xid);
    return 0;
}

static int send_arp_request(jz_discovery_iface_t *iface, uint32_t target_ip)
{
    struct arp_pkt pkt;
    struct sockaddr_ll sa;

    if (!iface || iface->arp_sock < 0 || iface->ifindex <= 0)
        return -1;

    memset(&pkt, 0, sizeof(pkt));
    memset(&sa, 0, sizeof(sa));

    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, iface->src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = ETH_ALEN;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt.arp.ar_sha, iface->src_mac, ETH_ALEN);
    pkt.arp.ar_sip = iface->src_ip;
    memset(pkt.arp.ar_tha, 0x00, ETH_ALEN);
    pkt.arp.ar_tip = target_ip;

    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = iface->ifindex;
    sa.sll_halen = ETH_ALEN;
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(iface->arp_sock, &pkt, sizeof(pkt), 0,
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
    int i;
    int rc;

    if (!disc || !cfg)
        return -1;

    memset(disc, 0, sizeof(*disc));
    for (i = 0; i < JZ_DISCOVERY_MAX_IFACES; i++) {
        disc->ifaces[i].arp_sock = -1;
        disc->ifaces[i].dhcp_sock = -1;
    }
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
    disc->iface_count = find_monitor_interfaces(disc, cfg);
    if (disc->iface_count <= 0) {
        jz_log_warn("Discovery ARP init skipped: no usable monitor interfaces");
    } else {
        for (i = 0; i < disc->iface_count; i++) {
            jz_discovery_iface_t *iface = &disc->ifaces[i];
            if (open_arp_socket(iface) < 0)
                jz_log_warn("Discovery ARP socket open failed on ifindex=%d", iface->ifindex);
        }
    }
    disc->last_arp_scan_ns = 0;

    disc->aggressive_mode = cfg->discovery.aggressive_mode;
    disc->dhcp_probe_interval_sec = cfg->discovery.dhcp_probe_interval_sec;
    if (disc->dhcp_probe_interval_sec < 10)
        disc->dhcp_probe_interval_sec = 120;
    if (disc->aggressive_mode) {
        for (i = 0; i < disc->iface_count; i++) {
            jz_discovery_iface_t *iface = &disc->ifaces[i];
            if (open_dhcp_socket(iface) < 0)
                jz_log_warn("DHCP probe socket open failed on ifindex=%d", iface->ifindex);
        }
    }

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

    close_all_iface_sockets(disc);

    fp_destroy();
    memset(disc, 0, sizeof(*disc));
}

int jz_discovery_tick(jz_discovery_t *disc)
{
    uint64_t now_ns;
    uint64_t interval_ns;
    int i;

    if (!disc || !disc->initialized)
        return -1;

    now_ns = get_monotonic_ns();

    if (disc->aggressive_mode) {
        uint64_t dhcp_interval_ns = (uint64_t)disc->dhcp_probe_interval_sec * 1000000000ULL;
        if (disc->last_dhcp_probe_ns == 0 ||
            (now_ns > disc->last_dhcp_probe_ns &&
             (now_ns - disc->last_dhcp_probe_ns) >= dhcp_interval_ns)) {
            for (i = 0; i < disc->iface_count; i++) {
                if (disc->ifaces[i].dhcp_sock >= 0)
                    (void)send_dhcp_discover(&disc->ifaces[i]);
            }
            disc->last_dhcp_probe_ns = now_ns;
        }
    }

    interval_ns = (uint64_t)disc->arp_interval_sec * 1000000000ULL;
    if (disc->last_arp_scan_ns != 0 && now_ns > disc->last_arp_scan_ns &&
        (now_ns - disc->last_arp_scan_ns) < interval_ns)
        return 0;

    for (i = 0; i < disc->iface_count; i++) {
        jz_discovery_iface_t *iface = &disc->ifaces[i];
        uint32_t scan_end;
        int batch_size;
        int j;
        uint64_t iface_interval_ns;

        if (iface->arp_sock < 0 || iface->ifindex <= 0 || iface->scan_mask == 0)
            continue;

        if (!iface->first_pass_done && iface->warmup_mode == JZ_WARMUP_BURST) {
            batch_size = iface->scan_mask == 0 ? JZ_DISCOVERY_ARP_BATCH_SIZE
                : (int)(~ntohl(iface->scan_mask)) + 1;
            if (batch_size > 4096)
                batch_size = 4096;
        } else if (!iface->first_pass_done && iface->warmup_mode == JZ_WARMUP_FAST) {
            iface_interval_ns = (uint64_t)JZ_DISCOVERY_ARP_FAST_INTERVAL * 1000000000ULL;
            if (iface->last_scan_ns != 0 && now_ns > iface->last_scan_ns &&
                (now_ns - iface->last_scan_ns) < iface_interval_ns)
                continue;
            batch_size = JZ_DISCOVERY_ARP_BATCH_SIZE;
        } else {
            batch_size = JZ_DISCOVERY_ARP_BATCH_SIZE;
        }

        if (iface->scan_next_ip == 0)
            set_scan_cursor_start(iface);
        scan_end = get_scan_end_ip(iface);

        for (j = 0; j < batch_size; j++) {
            uint32_t tip = iface->scan_next_ip;
            uint32_t tip_h;
            uint32_t end_h;
            uint32_t start_h;

            if (send_arp_request(iface, tip) < 0)
                break;

            tip_h = ntohl(tip);
            end_h = ntohl(scan_end);
            start_h = ntohl(iface->scan_subnet);
            if (end_h > start_h)
                start_h += 1U;

            if (tip_h >= end_h) {
                iface->scan_next_ip = htonl(start_h);
                iface->scan_pass_count++;
                if (!iface->first_pass_done) {
                    iface->first_pass_done = true;
                    jz_log_info("discovery ifindex=%d: first scan pass complete "
                                "(mode=%d, passes=%d)",
                                iface->ifindex, iface->warmup_mode,
                                iface->scan_pass_count);
                }
                break;
            } else {
                iface->scan_next_ip = htonl(tip_h + 1U);
            }
        }

        iface->last_scan_ns = now_ns;
    }

    disc->last_arp_scan_ns = now_ns;
    return 0;
}

int jz_discovery_recv_arp(jz_discovery_t *disc)
{
    int i;
    int total;

    if (!disc || !disc->initialized)
        return 0;

    total = 0;
    for (i = 0; i < disc->iface_count; i++) {
        jz_discovery_iface_t *iface = &disc->ifaces[i];
        uint8_t buf[128];
        ssize_t n;
        int count;

        if (iface->arp_sock < 0)
            continue;

        count = 0;
        while (count < 64) {
            n = recv(iface->arp_sock, buf, sizeof(buf), MSG_DONTWAIT);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                if (errno == EINTR)
                    continue;
                jz_log_warn("discovery recv_arp(ifindex=%d) error: %s",
                            iface->ifindex, strerror(errno));
                break;
            }
            if (n < 42)
                continue;

            jz_discovery_feed_event(disc, FP_PROTO_ARP, buf, (uint32_t)n, 0,
                                    (uint32_t)iface->ifindex);
            count++;
            total++;
        }
    }

    return total;
}

jz_discovery_device_t *jz_discovery_lookup(jz_discovery_t *disc,
                                           const uint8_t mac[6],
                                           uint32_t ifindex)
{
    uint32_t bucket;
    jz_discovery_device_t *node;

    if (!disc || !mac)
        return NULL;

    bucket = device_hash(mac, ifindex);
    node = disc->buckets[bucket];
    while (node) {
        if (memcmp(node->profile.mac, mac, 6) == 0 && node->ifindex == ifindex)
            return node;
        node = node->next;
    }
    return NULL;
}

jz_discovery_device_t *jz_discovery_lookup_by_ip(jz_discovery_t *disc,
                                                  uint32_t ip,
                                                  uint32_t ifindex)
{
    int i;
    jz_discovery_device_t *node;

    if (!disc || ip == 0)
        return NULL;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        node = disc->buckets[i];
        while (node) {
            if (node->profile.ip == ip && (ifindex == 0 || node->ifindex == ifindex))
                return node;
            node = node->next;
        }
    }
    return NULL;
}

int jz_discovery_find_dhcp_servers(const jz_discovery_t *disc,
                                    jz_discovery_device_t **out, int max_out)
{
    int i;
    int count = 0;
    jz_discovery_device_t *node;

    if (!disc || !out || max_out <= 0)
        return 0;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        node = disc->buckets[i];
        while (node) {
            if (node->profile.signals & FP_SIG_DHCP_SERVER) {
                out[count++] = node;
                if (count >= max_out)
                    return count;
            }
            node = node->next;
        }
    }
    return count;
}

int jz_discovery_feed_event(jz_discovery_t *disc, uint8_t proto,
                            const uint8_t *payload, uint32_t payload_len,
                            uint16_t vlan_id, uint32_t ifindex)
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

    device = jz_discovery_lookup(disc, src_mac, ifindex);
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
        device->ifindex = ifindex;
        bucket = device_hash(src_mac, ifindex);
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

    if (src_ip != 0 && disc->guard_auto)
        (void)jz_guard_auto_evict_ip(disc->guard_auto, src_ip, ifindex);

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
            char ifname[IF_NAMESIZE];

            memset(ifname, 0, sizeof(ifname));
            if (!if_indextoname(node->ifindex, ifname))
                snprintf(ifname, sizeof(ifname), "ifindex-%u", node->ifindex);

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
                           "{\"mac\":\"%s\",\"ip\":\"%s\",\"ifindex\":%u,\"interface\":\"",
                           macbuf, ipbuf, node->ifindex) < 0)
                return -1;
            if (buf_append_json_escaped(buf, buf_size, &off, ifname) < 0)
                return -1;
            if (buf_append(buf, buf_size, &off, "\",\"vendor\":\"") < 0)
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

int jz_discovery_list_vlans(const jz_discovery_t *disc, char *buf, size_t buf_size)
{
    struct vlan_entry {
        uint16_t id;
        uint32_t ifindex;
        int      device_count;
        uint32_t last_seen;
    };

    struct vlan_entry seen[128];
    int nseen = 0;
    int off = 0;
    int i, j;
    bool first;

    if (!disc || !buf || buf_size == 0)
        return -1;

    for (i = 0; i < JZ_DISCOVERY_HASH_BUCKETS; i++) {
        const jz_discovery_device_t *node = disc->buckets[i];
        while (node) {
            uint16_t vid = node->profile.vlan;
            if (vid > 0) {
                int found = -1;
                for (j = 0; j < nseen; j++) {
                    if (seen[j].id == vid && seen[j].ifindex == node->ifindex) {
                        found = j;
                        break;
                    }
                }
                if (found >= 0) {
                    seen[found].device_count++;
                    if (node->profile.last_seen > seen[found].last_seen)
                        seen[found].last_seen = node->profile.last_seen;
                } else if (nseen < 128) {
                    seen[nseen].id = vid;
                    seen[nseen].ifindex = node->ifindex;
                    seen[nseen].device_count = 1;
                    seen[nseen].last_seen = node->profile.last_seen;
                    nseen++;
                }
            }
            node = node->next;
        }
    }

    for (i = 1; i < nseen; i++) {
        struct vlan_entry tmp = seen[i];
        j = i - 1;
        while (j >= 0 &&
               (seen[j].id > tmp.id ||
                (seen[j].id == tmp.id && seen[j].ifindex > tmp.ifindex))) {
            seen[j + 1] = seen[j];
            j--;
        }
        seen[j + 1] = tmp;
    }

    if (buf_append(buf, buf_size, &off, "{\"vlans\":[") < 0)
        return -1;

    first = true;
    for (i = 0; i < nseen; i++) {
        if (!first) {
            if (buf_append(buf, buf_size, &off, ",") < 0)
                return -1;
        }
        first = false;
        if (buf_append(buf, buf_size, &off,
                       "{\"id\":%u,\"ifindex\":%u,\"device_count\":%d,\"last_seen\":%u}",
                       (unsigned)seen[i].id,
                       (unsigned)seen[i].ifindex,
                       seen[i].device_count,
                       (unsigned)seen[i].last_seen) < 0)
            return -1;
    }

    if (buf_append(buf, buf_size, &off, "],\"total\":%d}", nseen) < 0)
        return -1;
    return off;
}

const jz_discovery_iface_t *jz_discovery_iface_by_ifindex(const jz_discovery_t *disc,
                                                           uint32_t ifindex)
{
    int i;

    if (!disc)
        return NULL;

    for (i = 0; i < disc->iface_count; i++) {
        if ((uint32_t)disc->ifaces[i].ifindex == ifindex)
            return &disc->ifaces[i];
    }

    return NULL;
}

void jz_discovery_update_config(jz_discovery_t *disc, const jz_config_t *cfg)
{
    int new_max;
    int i;

    if (!disc || !cfg || !disc->initialized)
        return;

    new_max = cfg->guards.dynamic.max_entries;
    if (new_max <= 0 || new_max > JZ_DISCOVERY_MAX_DEVICES)
        new_max = JZ_DISCOVERY_MAX_DEVICES;
    disc->max_devices = new_max;
    disc->arp_interval_sec = JZ_DISCOVERY_ARP_INTERVAL;

    disc->aggressive_mode = cfg->discovery.aggressive_mode;
    disc->dhcp_probe_interval_sec = cfg->discovery.dhcp_probe_interval_sec;
    if (disc->dhcp_probe_interval_sec < 10)
        disc->dhcp_probe_interval_sec = 120;

    close_all_iface_sockets(disc);
    for (i = 0; i < JZ_DISCOVERY_MAX_IFACES; i++) {
        disc->ifaces[i].arp_sock = -1;
        disc->ifaces[i].dhcp_sock = -1;
    }

    disc->iface_count = find_monitor_interfaces(disc, cfg);
    for (i = 0; i < disc->iface_count; i++) {
        jz_discovery_iface_t *iface = &disc->ifaces[i];
        if (open_arp_socket(iface) < 0)
            jz_log_warn("Discovery ARP socket open failed on config update ifindex=%d",
                        iface->ifindex);
        if (disc->aggressive_mode) {
            if (open_dhcp_socket(iface) < 0)
                jz_log_warn("DHCP probe socket open failed on config update ifindex=%d",
                            iface->ifindex);
        }
    }

    disc->last_dhcp_probe_ns = 0;
    disc->last_arp_scan_ns = 0;
}
