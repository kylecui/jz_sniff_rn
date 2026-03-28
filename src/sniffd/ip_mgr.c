/* SPDX-License-Identifier: MIT */

#include "ip_mgr.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ifaddrs.h>

/* ── Timing constants ───────────────────────────────────────────── */

#define NS_PER_SEC              1000000000ULL
#define DHCP_DISCOVER_TIMEOUT   (3 * NS_PER_SEC)
#define DHCP_REQUEST_TIMEOUT    (3 * NS_PER_SEC)
#define DHCP_MAX_RETRIES        5
#define DHCP_RECV_BUF_SIZE      1500

/* ── BOOTP / DHCP constants ─────────────────────────────────────── */

#define BOOTP_OP_REQUEST        1
#define BOOTP_OP_REPLY          2
#define BOOTP_HTYPE_ETHER       1
#define BOOTP_HLEN_ETHER        6

#define DHCP_MAGIC_COOKIE       0x63825363

/* DHCP message types (option 53) */
#define DHCP_DISCOVER           1
#define DHCP_OFFER              2
#define DHCP_REQUEST            3
#define DHCP_ACK                5
#define DHCP_NAK                6

/* DHCP option codes */
#define DHCP_OPT_SUBNET_MASK    1
#define DHCP_OPT_ROUTER         3
#define DHCP_OPT_DNS            6
#define DHCP_OPT_LEASE_TIME     51
#define DHCP_OPT_MSG_TYPE       53
#define DHCP_OPT_SERVER_ID      54
#define DHCP_OPT_PARAM_REQ      55
#define DHCP_OPT_END            255

/* BOOTP field offsets within bootp[] payload */
#define BOOTP_OFF_OP            0
#define BOOTP_OFF_HTYPE         1
#define BOOTP_OFF_HLEN          2
#define BOOTP_OFF_XID           4
#define BOOTP_OFF_FLAGS         10
#define BOOTP_OFF_YIADDR        16
#define BOOTP_OFF_SIADDR        20
#define BOOTP_OFF_CHADDR        28
#define BOOTP_OFF_MAGIC         236
#define BOOTP_OFF_OPTIONS       240
#define BOOTP_MIN_LEN           300

/* ── Packet structures ──────────────────────────────────────────── */

struct dhcp_pkt {
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
    uint8_t bootp[BOOTP_MIN_LEN];
} __attribute__((packed));

/* ── Helpers ────────────────────────────────────────────────────── */

static uint64_t get_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

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

static bool get_iface_mac(const char *ifname, uint8_t mac[6])
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;
    memset(&ifr, 0, sizeof(ifr));
    size_t nlen = strlen(ifname);
    if (nlen >= IFNAMSIZ)
        nlen = IFNAMSIZ - 1;
    memcpy(ifr.ifr_name, ifname, nlen);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

static int get_iface_index(const char *ifname)
{
    unsigned int idx = if_nametoindex(ifname);
    return idx > 0 ? (int)idx : -1;
}

/* ── Netlink helpers ────────────────────────────────────────────── */

static int netlink_open(void)
{
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) {
        jz_log_error("ip_mgr: netlink socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid    = (uint32_t)getpid(),
    };
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_error("ip_mgr: netlink bind: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

struct nl_req {
    struct nlmsghdr  nlh;
    struct ifaddrmsg ifa;
    char             buf[256];
};

static int netlink_addr_op(int nl_sock, int ifindex, uint32_t ip,
                           uint8_t prefix_len, uint16_t nl_type)
{
    struct nl_req req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type  = nl_type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (nl_type == RTM_NEWADDR)
        req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
    req.nlh.nlmsg_seq   = 1;

    req.ifa.ifa_family    = AF_INET;
    req.ifa.ifa_prefixlen = prefix_len;
    req.ifa.ifa_index     = (unsigned int)ifindex;
    req.ifa.ifa_scope     = RT_SCOPE_UNIVERSE;

    /* IFA_LOCAL attribute */
    struct rtattr *rta = (struct rtattr *)
        (((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &ip, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;

    /* IFA_ADDRESS attribute */
    rta = (struct rtattr *)
        (((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &ip, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    if (sendto(nl_sock, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        jz_log_error("ip_mgr: netlink sendto: %s", strerror(errno));
        return -1;
    }

    /* Read ACK */
    char ack_buf[4096];
    ssize_t n = recv(nl_sock, ack_buf, sizeof(ack_buf), 0);
    if (n < 0) {
        jz_log_error("ip_mgr: netlink recv: %s", strerror(errno));
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)ack_buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0) {
            jz_log_error("ip_mgr: netlink %s failed: %s",
                         nl_type == RTM_NEWADDR ? "NEWADDR" : "DELADDR",
                         strerror(-err->error));
            return -1;
        }
    }
    return 0;
}

static int apply_ip(int nl_sock, jz_ip_iface_t *iface,
                    uint32_t ip, uint8_t prefix_len)
{
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    jz_log_info("ip_mgr: applying %s/%d to %s (ifindex %d)",
                ip_str, prefix_len, iface->name, iface->ifindex);

    if (netlink_addr_op(nl_sock, iface->ifindex, ip,
                        prefix_len, RTM_NEWADDR) < 0)
        return -1;

    iface->ip         = ip;
    iface->prefix_len = prefix_len;
    iface->ip_applied = true;

    /* Derive mask from prefix */
    if (prefix_len > 0 && prefix_len <= 32)
        iface->mask = htonl(0xFFFFFFFFU << (32 - prefix_len));
    else
        iface->mask = 0;

    jz_log_info("ip_mgr: %s now has %s/%d", iface->name, ip_str, prefix_len);
    return 0;
}

static void remove_ip(int nl_sock, jz_ip_iface_t *iface)
{
    if (!iface->ip_applied || iface->ip == 0)
        return;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iface->ip, ip_str, sizeof(ip_str));
    jz_log_info("ip_mgr: removing %s/%d from %s",
                ip_str, iface->prefix_len, iface->name);

    netlink_addr_op(nl_sock, iface->ifindex, iface->ip,
                    iface->prefix_len, RTM_DELADDR);
    iface->ip         = 0;
    iface->mask       = 0;
    iface->prefix_len = 0;
    iface->ip_applied = false;
}

/* ── resolv.conf ────────────────────────────────────────────────── */

static void write_resolv_conf(const jz_ip_mgr_t *mgr)
{
    char dns_list[JZ_IP_MGR_MAX_IFACES * 2][INET_ADDRSTRLEN];
    int dns_count = 0;

    for (int i = 0; i < mgr->iface_count; i++) {
        const jz_ip_iface_t *iface = &mgr->ifaces[i];
        if (!iface->active || !iface->ip_applied)
            continue;
        if (iface->dns1 && dns_count < JZ_IP_MGR_MAX_IFACES * 2) {
            inet_ntop(AF_INET, &iface->dns1,
                      dns_list[dns_count], INET_ADDRSTRLEN);
            dns_count++;
        }
        if (iface->dns2 && dns_count < JZ_IP_MGR_MAX_IFACES * 2) {
            inet_ntop(AF_INET, &iface->dns2,
                      dns_list[dns_count], INET_ADDRSTRLEN);
            dns_count++;
        }
    }

    if (dns_count == 0)
        return;

    FILE *fp = fopen("/etc/resolv.conf", "w");
    if (!fp) {
        jz_log_warn("ip_mgr: cannot write /etc/resolv.conf: %s",
                     strerror(errno));
        return;
    }
    fprintf(fp, "# Generated by jz ip_mgr\n");
    for (int i = 0; i < dns_count; i++)
        fprintf(fp, "nameserver %s\n", dns_list[i]);
    fclose(fp);
    jz_log_info("ip_mgr: wrote /etc/resolv.conf with %d nameservers", dns_count);
}

/* ── DHCP raw socket ────────────────────────────────────────────── */

static int open_dhcp_sock(jz_ip_iface_t *iface)
{
    int sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP));
    if (sock < 0) {
        jz_log_error("ip_mgr: DHCP socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_ll sa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = iface->ifindex,
    };
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_error("ip_mgr: DHCP bind: %s", strerror(errno));
        close(sock);
        return -1;
    }

    iface->dhcp_sock = sock;
    return 0;
}

/* ── DHCP send ──────────────────────────────────────────────────── */

static int send_dhcp_discover(jz_ip_iface_t *iface)
{
    struct dhcp_pkt pkt;
    uint16_t udp_len, ip_total;

    iface->dhcp_xid = (uint32_t)get_mono_ns();

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, iface->mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_IP);

    udp_len  = (uint16_t)(sizeof(pkt.udp) + sizeof(pkt.bootp));
    ip_total = (uint16_t)(20 + udp_len);

    pkt.ip.ihl_ver  = 0x45;
    pkt.ip.ttl      = 128;
    pkt.ip.protocol = 17; /* UDP */
    pkt.ip.tot_len  = htons(ip_total);
    pkt.ip.id       = htons((uint16_t)(iface->dhcp_xid & 0xFFFF));
    pkt.ip.saddr    = 0;
    pkt.ip.daddr    = 0xFFFFFFFF;
    pkt.ip.check    = ip_checksum(&pkt.ip, 20);

    pkt.udp.source = htons(68);
    pkt.udp.dest   = htons(67);
    pkt.udp.len    = htons(udp_len);

    /* BOOTP header */
    pkt.bootp[BOOTP_OFF_OP]    = BOOTP_OP_REQUEST;
    pkt.bootp[BOOTP_OFF_HTYPE] = BOOTP_HTYPE_ETHER;
    pkt.bootp[BOOTP_OFF_HLEN]  = BOOTP_HLEN_ETHER;
    memcpy(pkt.bootp + BOOTP_OFF_XID, &iface->dhcp_xid, 4);
    pkt.bootp[BOOTP_OFF_FLAGS] = 0x80; /* broadcast flag */
    memcpy(pkt.bootp + BOOTP_OFF_CHADDR, iface->mac, 6);

    /* Magic cookie */
    pkt.bootp[BOOTP_OFF_MAGIC]     = 0x63;
    pkt.bootp[BOOTP_OFF_MAGIC + 1] = 0x82;
    pkt.bootp[BOOTP_OFF_MAGIC + 2] = 0x53;
    pkt.bootp[BOOTP_OFF_MAGIC + 3] = 0x63;

    /* Option 53: DHCP Discover */
    pkt.bootp[BOOTP_OFF_OPTIONS]     = DHCP_OPT_MSG_TYPE;
    pkt.bootp[BOOTP_OFF_OPTIONS + 1] = 1;
    pkt.bootp[BOOTP_OFF_OPTIONS + 2] = DHCP_DISCOVER;

    /* Option 55: Parameter Request List */
    pkt.bootp[BOOTP_OFF_OPTIONS + 3] = DHCP_OPT_PARAM_REQ;
    pkt.bootp[BOOTP_OFF_OPTIONS + 4] = 4;
    pkt.bootp[BOOTP_OFF_OPTIONS + 5] = DHCP_OPT_SUBNET_MASK;
    pkt.bootp[BOOTP_OFF_OPTIONS + 6] = DHCP_OPT_ROUTER;
    pkt.bootp[BOOTP_OFF_OPTIONS + 7] = DHCP_OPT_DNS;
    pkt.bootp[BOOTP_OFF_OPTIONS + 8] = 15; /* domain name */

    pkt.bootp[BOOTP_OFF_OPTIONS + 9] = DHCP_OPT_END;

    struct sockaddr_ll sa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = iface->ifindex,
        .sll_halen    = ETH_ALEN,
    };
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(iface->dhcp_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_warn("ip_mgr: DISCOVER sendto failed on %s: %s",
                     iface->name, strerror(errno));
        return -1;
    }

    iface->dhcp_last_send_ns = get_mono_ns();
    jz_log_debug("ip_mgr: DISCOVER sent on %s (xid=%08x)",
                 iface->name, iface->dhcp_xid);
    return 0;
}

static int send_dhcp_request(jz_ip_iface_t *iface, bool broadcast)
{
    struct dhcp_pkt pkt;
    uint16_t udp_len, ip_total;
    int opt_off;

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, iface->mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_IP);

    udp_len  = (uint16_t)(sizeof(pkt.udp) + sizeof(pkt.bootp));
    ip_total = (uint16_t)(20 + udp_len);

    pkt.ip.ihl_ver  = 0x45;
    pkt.ip.ttl      = 128;
    pkt.ip.protocol = 17;
    pkt.ip.tot_len  = htons(ip_total);
    pkt.ip.id       = htons((uint16_t)(iface->dhcp_xid & 0xFFFF));

    if (broadcast) {
        pkt.ip.saddr = 0;
        pkt.ip.daddr = 0xFFFFFFFF;
    } else {
        pkt.ip.saddr = iface->ip;
        pkt.ip.daddr = iface->dhcp_server_ip;
    }
    pkt.ip.check = ip_checksum(&pkt.ip, 20);

    pkt.udp.source = htons(68);
    pkt.udp.dest   = htons(67);
    pkt.udp.len    = htons(udp_len);

    pkt.bootp[BOOTP_OFF_OP]    = BOOTP_OP_REQUEST;
    pkt.bootp[BOOTP_OFF_HTYPE] = BOOTP_HTYPE_ETHER;
    pkt.bootp[BOOTP_OFF_HLEN]  = BOOTP_HLEN_ETHER;
    memcpy(pkt.bootp + BOOTP_OFF_XID, &iface->dhcp_xid, 4);
    pkt.bootp[BOOTP_OFF_FLAGS] = 0x80;

    /* ciaddr = our current IP if renewing */
    if (!broadcast && iface->ip)
        memcpy(pkt.bootp + 12, &iface->ip, 4);

    memcpy(pkt.bootp + BOOTP_OFF_CHADDR, iface->mac, 6);

    pkt.bootp[BOOTP_OFF_MAGIC]     = 0x63;
    pkt.bootp[BOOTP_OFF_MAGIC + 1] = 0x82;
    pkt.bootp[BOOTP_OFF_MAGIC + 2] = 0x53;
    pkt.bootp[BOOTP_OFF_MAGIC + 3] = 0x63;

    opt_off = BOOTP_OFF_OPTIONS;

    /* Option 53: DHCP Request */
    pkt.bootp[opt_off++] = DHCP_OPT_MSG_TYPE;
    pkt.bootp[opt_off++] = 1;
    pkt.bootp[opt_off++] = DHCP_REQUEST;

    /* Option 54: Server Identifier (only in SELECTING/REQUESTING) */
    if (broadcast && iface->dhcp_server_ip) {
        pkt.bootp[opt_off++] = DHCP_OPT_SERVER_ID;
        pkt.bootp[opt_off++] = 4;
        memcpy(pkt.bootp + opt_off, &iface->dhcp_server_ip, 4);
        opt_off += 4;
    }

    /* Option 50: Requested IP (only in SELECTING/REQUESTING) */
    if (broadcast && iface->dhcp_offered_ip) {
        pkt.bootp[opt_off++] = 50;
        pkt.bootp[opt_off++] = 4;
        memcpy(pkt.bootp + opt_off, &iface->dhcp_offered_ip, 4);
        opt_off += 4;
    }

    /* Option 55: Parameter Request List */
    pkt.bootp[opt_off++] = DHCP_OPT_PARAM_REQ;
    pkt.bootp[opt_off++] = 4;
    pkt.bootp[opt_off++] = DHCP_OPT_SUBNET_MASK;
    pkt.bootp[opt_off++] = DHCP_OPT_ROUTER;
    pkt.bootp[opt_off++] = DHCP_OPT_DNS;
    pkt.bootp[opt_off++] = 15;

    pkt.bootp[opt_off] = DHCP_OPT_END;

    struct sockaddr_ll sa = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = iface->ifindex,
        .sll_halen    = ETH_ALEN,
    };
    memset(sa.sll_addr, 0xff, ETH_ALEN);

    if (sendto(iface->dhcp_sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        jz_log_warn("ip_mgr: REQUEST sendto failed on %s: %s",
                     iface->name, strerror(errno));
        return -1;
    }

    iface->dhcp_last_send_ns = get_mono_ns();
    jz_log_debug("ip_mgr: REQUEST sent on %s (xid=%08x, broadcast=%d)",
                 iface->name, iface->dhcp_xid, broadcast);
    return 0;
}

/* ── DHCP receive & parse ───────────────────────────────────────── */

struct dhcp_parsed {
    uint8_t  msg_type;
    uint32_t yiaddr;
    uint32_t server_ip;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t dns1;
    uint32_t dns2;
    uint32_t lease_time;
    uint32_t xid;
};

static bool parse_dhcp_reply(const uint8_t *buf, ssize_t len,
                             const uint8_t mac[6], struct dhcp_parsed *out)
{
    memset(out, 0, sizeof(*out));

    /* Minimum: ETH(14) + IP(20) + UDP(8) + BOOTP_MIN(300) = 342 */
    if (len < 342)
        return false;

    /* Check ETH type = IP */
    const struct ethhdr *eth = (const struct ethhdr *)buf;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    const uint8_t *ip_hdr = buf + sizeof(struct ethhdr);
    uint8_t ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    if (ip_hdr[9] != 17) /* not UDP */
        return false;

    const uint8_t *udp_hdr = ip_hdr + ip_hdr_len;
    uint16_t src_port = ntohs(*(const uint16_t *)udp_hdr);
    uint16_t dst_port = ntohs(*(const uint16_t *)(udp_hdr + 2));
    if (src_port != 67 || dst_port != 68)
        return false;

    const uint8_t *bootp = udp_hdr + 8;
    ssize_t bootp_len = len - (ssize_t)(bootp - buf);
    if (bootp_len < BOOTP_MIN_LEN)
        return false;

    if (bootp[BOOTP_OFF_OP] != BOOTP_OP_REPLY)
        return false;

    /* Verify MAC matches */
    if (memcmp(bootp + BOOTP_OFF_CHADDR, mac, 6) != 0)
        return false;

    /* Extract xid */
    memcpy(&out->xid, bootp + BOOTP_OFF_XID, 4);

    /* yiaddr (offered IP) */
    memcpy(&out->yiaddr, bootp + BOOTP_OFF_YIADDR, 4);

    /* siaddr (server IP, fallback) */
    memcpy(&out->server_ip, bootp + BOOTP_OFF_SIADDR, 4);

    /* Verify magic cookie */
    if (bootp[BOOTP_OFF_MAGIC] != 0x63 || bootp[BOOTP_OFF_MAGIC + 1] != 0x82 ||
        bootp[BOOTP_OFF_MAGIC + 2] != 0x53 || bootp[BOOTP_OFF_MAGIC + 3] != 0x63)
        return false;

    /* Parse DHCP options */
    int off = BOOTP_OFF_OPTIONS;
    while (off < bootp_len - 1) {
        uint8_t opt_code = bootp[off++];
        if (opt_code == DHCP_OPT_END)
            break;
        if (opt_code == 0) /* padding */
            continue;
        if (off >= bootp_len)
            break;
        uint8_t opt_len = bootp[off++];
        if (off + opt_len > bootp_len)
            break;

        switch (opt_code) {
        case DHCP_OPT_MSG_TYPE:
            if (opt_len >= 1)
                out->msg_type = bootp[off];
            break;
        case DHCP_OPT_SUBNET_MASK:
            if (opt_len >= 4)
                memcpy(&out->subnet_mask, bootp + off, 4);
            break;
        case DHCP_OPT_ROUTER:
            if (opt_len >= 4)
                memcpy(&out->router, bootp + off, 4);
            break;
        case DHCP_OPT_DNS:
            if (opt_len >= 4)
                memcpy(&out->dns1, bootp + off, 4);
            if (opt_len >= 8)
                memcpy(&out->dns2, bootp + off + 4, 4);
            break;
        case DHCP_OPT_LEASE_TIME:
            if (opt_len >= 4) {
                uint32_t lt;
                memcpy(&lt, bootp + off, 4);
                out->lease_time = ntohl(lt);
            }
            break;
        case DHCP_OPT_SERVER_ID:
            if (opt_len >= 4)
                memcpy(&out->server_ip, bootp + off, 4);
            break;
        }
        off += opt_len;
    }

    return out->msg_type != 0;
}

static void dhcp_recv(jz_ip_iface_t *iface)
{
    uint8_t buf[DHCP_RECV_BUF_SIZE];

    for (int attempts = 0; attempts < 10; attempts++) {
        ssize_t n = recv(iface->dhcp_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0)
            return;

        struct dhcp_parsed reply;
        if (!parse_dhcp_reply(buf, n, iface->mac, &reply))
            continue;

        if (reply.xid != iface->dhcp_xid)
            continue;

        char offered_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &reply.yiaddr, offered_str, sizeof(offered_str));

        if (reply.msg_type == DHCP_OFFER &&
            iface->dhcp_state == JZ_DHCP_SELECTING) {
            jz_log_info("ip_mgr: OFFER %s from server on %s",
                        offered_str, iface->name);
            iface->dhcp_offered_ip   = reply.yiaddr;
            iface->dhcp_offered_mask = reply.subnet_mask;
            iface->dhcp_offered_gw   = reply.router;
            iface->dhcp_offered_dns1 = reply.dns1;
            iface->dhcp_offered_dns2 = reply.dns2;
            iface->dhcp_server_ip    = reply.server_ip;
            iface->dhcp_lease_time   = reply.lease_time;
            iface->dhcp_state        = JZ_DHCP_REQUESTING;
            iface->dhcp_retries      = 0;
            send_dhcp_request(iface, true);
            return;
        }

        if (reply.msg_type == DHCP_ACK &&
            (iface->dhcp_state == JZ_DHCP_REQUESTING ||
             iface->dhcp_state == JZ_DHCP_RENEWING ||
             iface->dhcp_state == JZ_DHCP_REBINDING)) {
            jz_log_info("ip_mgr: ACK %s on %s (lease %us)",
                        offered_str, iface->name, reply.lease_time);

            iface->dhcp_offered_ip   = reply.yiaddr;
            if (reply.subnet_mask)
                iface->dhcp_offered_mask = reply.subnet_mask;
            if (reply.router)
                iface->dhcp_offered_gw = reply.router;
            if (reply.dns1)
                iface->dhcp_offered_dns1 = reply.dns1;
            if (reply.dns2)
                iface->dhcp_offered_dns2 = reply.dns2;
            if (reply.lease_time)
                iface->dhcp_lease_time = reply.lease_time;
            if (reply.server_ip)
                iface->dhcp_server_ip = reply.server_ip;

            iface->dhcp_lease_start_ns = get_mono_ns();
            iface->dhcp_state = JZ_DHCP_BOUND;
            iface->dhcp_retries = 0;

            /* Derive prefix from mask */
            uint8_t prefix = 24;
            if (iface->dhcp_offered_mask) {
                uint32_t m = ntohl(iface->dhcp_offered_mask);
                prefix = 0;
                while (m & 0x80000000) {
                    prefix++;
                    m <<= 1;
                }
            }

            iface->dns1    = iface->dhcp_offered_dns1;
            iface->dns2    = iface->dhcp_offered_dns2;
            iface->gateway = iface->dhcp_offered_gw;

            /* IP will be applied in tick() to keep flow clean */
            return;
        }

        if (reply.msg_type == DHCP_NAK) {
            jz_log_warn("ip_mgr: NAK on %s, restarting DHCP",
                        iface->name);
            iface->dhcp_state   = JZ_DHCP_INIT;
            iface->dhcp_retries = 0;
            return;
        }
    }
}

/* ── DHCP state machine tick ────────────────────────────────────── */

static void dhcp_tick(jz_ip_mgr_t *mgr, jz_ip_iface_t *iface)
{
    uint64_t now;
    uint64_t elapsed;

    /* Always try to receive */
    if (iface->dhcp_sock >= 0)
        dhcp_recv(iface);

    now = get_mono_ns();

    switch (iface->dhcp_state) {
    case JZ_DHCP_INIT:
        if (iface->dhcp_sock < 0) {
            if (open_dhcp_sock(iface) < 0)
                return;
        }
        send_dhcp_discover(iface);
        iface->dhcp_state   = JZ_DHCP_SELECTING;
        iface->dhcp_retries = 0;
        break;

    case JZ_DHCP_SELECTING:
        elapsed = now - iface->dhcp_last_send_ns;
        if (elapsed > DHCP_DISCOVER_TIMEOUT) {
            iface->dhcp_retries++;
            if (iface->dhcp_retries >= DHCP_MAX_RETRIES) {
                jz_log_warn("ip_mgr: DISCOVER timeout on %s after %d retries",
                            iface->name, DHCP_MAX_RETRIES);
                iface->dhcp_state   = JZ_DHCP_INIT;
                iface->dhcp_retries = 0;
                /* Back off: close and reopen socket next cycle */
                close(iface->dhcp_sock);
                iface->dhcp_sock = -1;
            } else {
                send_dhcp_discover(iface);
            }
        }
        break;

    case JZ_DHCP_REQUESTING:
        elapsed = now - iface->dhcp_last_send_ns;
        if (elapsed > DHCP_REQUEST_TIMEOUT) {
            iface->dhcp_retries++;
            if (iface->dhcp_retries >= DHCP_MAX_RETRIES) {
                jz_log_warn("ip_mgr: REQUEST timeout on %s, restarting",
                            iface->name);
                iface->dhcp_state   = JZ_DHCP_INIT;
                iface->dhcp_retries = 0;
            } else {
                send_dhcp_request(iface, true);
            }
        }
        break;

    case JZ_DHCP_BOUND: {
        /* Apply IP if not yet applied */
        if (!iface->ip_applied || iface->ip != iface->dhcp_offered_ip) {
            uint8_t prefix = 24;
            if (iface->dhcp_offered_mask) {
                uint32_t m = ntohl(iface->dhcp_offered_mask);
                prefix = 0;
                while (m & 0x80000000) {
                    prefix++;
                    m <<= 1;
                }
            }
            if (apply_ip(mgr->nl_sock, iface,
                         iface->dhcp_offered_ip, prefix) == 0) {
                mgr->new_ip_applied = true;
                write_resolv_conf(mgr);
            }
        }

        if (iface->dhcp_lease_time == 0)
            break;

        uint64_t lease_ns  = (uint64_t)iface->dhcp_lease_time * NS_PER_SEC;
        uint64_t since     = now - iface->dhcp_lease_start_ns;

        /* T1 = 50% of lease: start unicast renewal */
        if (since > lease_ns / 2 && since <= lease_ns * 7 / 8) {
            jz_log_info("ip_mgr: T1 renewal on %s", iface->name);
            iface->dhcp_state   = JZ_DHCP_RENEWING;
            iface->dhcp_retries = 0;
            send_dhcp_request(iface, false);
        }
        /* T2 = 87.5% of lease: broadcast rebind */
        else if (since > lease_ns * 7 / 8 && since <= lease_ns) {
            jz_log_info("ip_mgr: T2 rebind on %s", iface->name);
            iface->dhcp_state   = JZ_DHCP_REBINDING;
            iface->dhcp_retries = 0;
            send_dhcp_request(iface, true);
        }
        /* Lease expired: keep IP but warn (user decision) */
        else if (since > lease_ns) {
            jz_log_warn("ip_mgr: DHCP lease EXPIRED on %s — keeping IP",
                        iface->name);
            iface->dhcp_lease_start_ns = now;
        }
        break;
    }

    case JZ_DHCP_RENEWING:
        elapsed = now - iface->dhcp_last_send_ns;
        if (elapsed > DHCP_REQUEST_TIMEOUT) {
            iface->dhcp_retries++;
            if (iface->dhcp_retries >= DHCP_MAX_RETRIES) {
                jz_log_warn("ip_mgr: renew failed on %s, trying rebind",
                            iface->name);
                iface->dhcp_state   = JZ_DHCP_REBINDING;
                iface->dhcp_retries = 0;
                send_dhcp_request(iface, true);
            } else {
                send_dhcp_request(iface, false);
            }
        }
        break;

    case JZ_DHCP_REBINDING:
        elapsed = now - iface->dhcp_last_send_ns;
        if (elapsed > DHCP_REQUEST_TIMEOUT) {
            iface->dhcp_retries++;
            if (iface->dhcp_retries >= DHCP_MAX_RETRIES) {
                jz_log_warn("ip_mgr: rebind failed on %s — keeping IP",
                            iface->name);
                /* Stay BOUND with current IP, re-attempt later */
                iface->dhcp_state          = JZ_DHCP_BOUND;
                iface->dhcp_lease_start_ns = now;
                iface->dhcp_retries        = 0;
            } else {
                send_dhcp_request(iface, true);
            }
        }
        break;
    }
}

/* ── Config parsing helpers ─────────────────────────────────────── */

static bool parse_static_addr(const char *addr_str, uint32_t *ip_out,
                              uint8_t *prefix_out)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", addr_str);

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int prefix = atoi(slash + 1);
        if (prefix < 1 || prefix > 32)
            return false;
        *prefix_out = (uint8_t)prefix;
    } else {
        *prefix_out = 24;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return false;

    *ip_out = a.s_addr;
    return true;
}

static void setup_iface_from_config(jz_ip_iface_t *iface,
                                    const jz_config_interface_t *cfg_iface)
{
    memset(iface, 0, sizeof(*iface));
    iface->dhcp_sock = -1;

    snprintf(iface->name, sizeof(iface->name), "%s", cfg_iface->name);
    iface->ifindex = get_iface_index(cfg_iface->name);
    if (iface->ifindex < 0) {
        jz_log_warn("ip_mgr: interface %s not found", cfg_iface->name);
        return;
    }

    if (!get_iface_mac(cfg_iface->name, iface->mac)) {
        jz_log_warn("ip_mgr: cannot get MAC for %s", cfg_iface->name);
        return;
    }

    if (cfg_iface->address[0] == '\0' || strcmp(cfg_iface->address, "none") == 0) {
        iface->mode = JZ_IP_MODE_NONE;
        return;
    }

    if (strcmp(cfg_iface->address, "dhcp") == 0) {
        iface->mode   = JZ_IP_MODE_DHCP;
        iface->active = true;
        return;
    }

    /* Static IP: "10.0.1.50/24" */
    uint32_t sip;
    uint8_t  sprefix;
    if (parse_static_addr(cfg_iface->address, &sip, &sprefix)) {
        iface->mode          = JZ_IP_MODE_STATIC;
        iface->static_ip     = sip;
        iface->static_prefix = sprefix;
        if (sprefix > 0 && sprefix <= 32)
            iface->static_mask = htonl(0xFFFFFFFFU << (32 - sprefix));
        iface->active = true;

        /* Parse optional gateway/dns from config */
        struct in_addr tmp;
        if (cfg_iface->gateway[0] && inet_pton(AF_INET, cfg_iface->gateway, &tmp) == 1)
            iface->static_gw = tmp.s_addr;
        if (cfg_iface->dns1[0] && inet_pton(AF_INET, cfg_iface->dns1, &tmp) == 1)
            iface->static_dns1 = tmp.s_addr;
        if (cfg_iface->dns2[0] && inet_pton(AF_INET, cfg_iface->dns2, &tmp) == 1)
            iface->static_dns2 = tmp.s_addr;
    } else {
        jz_log_warn("ip_mgr: invalid address '%s' for %s",
                     cfg_iface->address, cfg_iface->name);
        iface->mode = JZ_IP_MODE_NONE;
    }
}

/* ── Existing IP detection ──────────────────────────────────────── */

static bool parse_subnet(const char *subnet_str, uint32_t *net_out, uint32_t *mask_out)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", subnet_str);

    char *slash = strchr(buf, '/');
    if (!slash)
        return false;

    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 1 || prefix > 32)
        return false;

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return false;

    *net_out  = a.s_addr;
    *mask_out = htonl(0xFFFFFFFFU << (32 - prefix));
    return true;
}

static bool check_existing_ip(jz_ip_iface_t *iface, uint32_t subnet, uint32_t mask)
{
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) < 0)
        return false;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, iface->name) != 0)
            continue;

        uint32_t addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        if ((addr & mask) == (subnet & mask)) {
            uint8_t prefix = 0;
            uint32_t m_host = ntohl(mask);
            while (m_host & 0x80000000) { prefix++; m_host <<= 1; }

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            jz_log_info("ip_mgr: %s already has %s/%d, adopting",
                        iface->name, ip_str, prefix);

            iface->ip         = addr;
            iface->prefix_len = prefix;
            iface->mask       = mask;
            iface->ip_applied = true;
            iface->os_ip_adopted = true;
            freeifaddrs(ifap);
            return true;
        }
    }
    freeifaddrs(ifap);
    return false;
}

/* ── Public API ─────────────────────────────────────────────────── */

int jz_ip_mgr_init(jz_ip_mgr_t *mgr, const jz_config_t *cfg)
{
    memset(mgr, 0, sizeof(*mgr));
    mgr->nl_sock = -1;

    mgr->nl_sock = netlink_open();
    if (mgr->nl_sock < 0)
        return -1;

    int count = 0;
    for (int i = 0; i < cfg->system.interface_count && i < JZ_IP_MGR_MAX_IFACES; i++) {
        const jz_config_interface_t *ci = &cfg->system.interfaces[i];
        if (strcmp(ci->role, "monitor") != 0)
            continue;
        if (ci->address[0] == '\0')
            continue;

        jz_ip_iface_t *iface = &mgr->ifaces[count];
        setup_iface_from_config(iface, ci);

        if (iface->active) {
            uint32_t subnet_net, subnet_mask;
            if (parse_subnet(ci->subnet, &subnet_net, &subnet_mask) &&
                check_existing_ip(iface, subnet_net, subnet_mask)) {
                mgr->new_ip_applied = true;
            } else if (iface->mode == JZ_IP_MODE_STATIC) {
                if (apply_ip(mgr->nl_sock, iface,
                             iface->static_ip, iface->static_prefix) == 0) {
                    mgr->new_ip_applied = true;
                    iface->dns1    = iface->static_dns1;
                    iface->dns2    = iface->static_dns2;
                    iface->gateway = iface->static_gw;
                }
            }
            jz_log_info("ip_mgr: managing %s (mode=%s, ifindex=%d, adopted=%s)",
                        iface->name,
                        iface->mode == JZ_IP_MODE_DHCP ? "dhcp" : "static",
                        iface->ifindex,
                        iface->os_ip_adopted ? "yes" : "no");
            count++;
        }
    }

    mgr->iface_count = count;
    mgr->initialized = true;

    if (count > 0)
        write_resolv_conf(mgr);

    jz_log_info("ip_mgr: initialized, managing %d interface(s)", count);
    return 0;
}

void jz_ip_mgr_tick(jz_ip_mgr_t *mgr)
{
    if (!mgr->initialized)
        return;

    for (int i = 0; i < mgr->iface_count; i++) {
        jz_ip_iface_t *iface = &mgr->ifaces[i];
        if (!iface->active)
            continue;

        if (iface->mode == JZ_IP_MODE_DHCP && !iface->os_ip_adopted) {
            dhcp_tick(mgr, iface);
        }
        /* Static IPs are applied once in init/update_config; no tick needed */
    }
}

void jz_ip_mgr_update_config(jz_ip_mgr_t *mgr, const jz_config_t *cfg)
{
    if (!mgr->initialized)
        return;

    for (int i = 0; i < mgr->iface_count; i++) {
        jz_ip_iface_t *iface = &mgr->ifaces[i];
        if (iface->ip_applied && !iface->os_ip_adopted)
            remove_ip(mgr->nl_sock, iface);
        if (iface->dhcp_sock >= 0) {
            close(iface->dhcp_sock);
            iface->dhcp_sock = -1;
        }
    }

    /* Rebuild interface list from new config */
    int count = 0;
    for (int i = 0; i < cfg->system.interface_count && i < JZ_IP_MGR_MAX_IFACES; i++) {
        const jz_config_interface_t *ci = &cfg->system.interfaces[i];
        if (strcmp(ci->role, "monitor") != 0)
            continue;
        if (ci->address[0] == '\0')
            continue;

        jz_ip_iface_t *iface = &mgr->ifaces[count];
        setup_iface_from_config(iface, ci);

        if (iface->active) {
            uint32_t subnet_net, subnet_mask;
            if (parse_subnet(ci->subnet, &subnet_net, &subnet_mask) &&
                check_existing_ip(iface, subnet_net, subnet_mask)) {
                mgr->new_ip_applied = true;
            } else if (iface->mode == JZ_IP_MODE_STATIC) {
                if (apply_ip(mgr->nl_sock, iface,
                             iface->static_ip, iface->static_prefix) == 0) {
                    mgr->new_ip_applied = true;
                    iface->dns1    = iface->static_dns1;
                    iface->dns2    = iface->static_dns2;
                    iface->gateway = iface->static_gw;
                }
            }
            count++;
        }
    }

    mgr->iface_count = count;

    if (count > 0)
        write_resolv_conf(mgr);

    jz_log_info("ip_mgr: config updated, managing %d interface(s)", count);
}

void jz_ip_mgr_destroy(jz_ip_mgr_t *mgr)
{
    if (!mgr->initialized)
        return;

    for (int i = 0; i < mgr->iface_count; i++) {
        jz_ip_iface_t *iface = &mgr->ifaces[i];
        if (iface->ip_applied && !iface->os_ip_adopted)
            remove_ip(mgr->nl_sock, iface);
        if (iface->dhcp_sock >= 0)
            close(iface->dhcp_sock);
    }

    if (mgr->nl_sock >= 0)
        close(mgr->nl_sock);

    mgr->initialized = false;
    jz_log_info("ip_mgr: destroyed");
}
