/* SPDX-License-Identifier: MIT */
/*
 * ip_mgr.h - Monitor interface IP address management.
 *
 * Applies IP addresses to monitor interfaces based on YAML config:
 *   address: dhcp   → inline DHCP client (non-blocking state machine)
 *   address: x.x.x.x/N → static IP via netlink RTM_NEWADDR
 *
 * Must init BEFORE discovery so get_interface_ip() succeeds.
 */

#ifndef JZ_IP_MGR_H
#define JZ_IP_MGR_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define JZ_IP_MGR_MAX_IFACES    JZ_CONFIG_MAX_INTERFACES

/* DHCP client state machine states */
enum jz_dhcp_state {
    JZ_DHCP_INIT       = 0,  /* no IP, need to send DISCOVER */
    JZ_DHCP_SELECTING  = 1,  /* DISCOVER sent, waiting for OFFER */
    JZ_DHCP_REQUESTING = 2,  /* REQUEST sent, waiting for ACK */
    JZ_DHCP_BOUND      = 3,  /* IP acquired and applied */
    JZ_DHCP_RENEWING   = 4,  /* T1 expired, unicast REQUEST to server */
    JZ_DHCP_REBINDING  = 5,  /* T2 expired, broadcast REQUEST */
};

/* IP address mode (derived from config address field) */
enum jz_ip_mode {
    JZ_IP_MODE_NONE   = 0,   /* no address configured */
    JZ_IP_MODE_DHCP   = 1,   /* address: dhcp */
    JZ_IP_MODE_STATIC = 2,   /* address: x.x.x.x/N */
};

/* Per-interface IP management state */
typedef struct jz_ip_iface {
    char        name[64];           /* interface name (e.g. "ens37") */
    int         ifindex;            /* interface index */
    uint8_t     mac[6];             /* interface MAC address */
    enum jz_ip_mode mode;           /* DHCP or static */

    /* Applied IP state */
    uint32_t    ip;                 /* current IP (network order) */
    uint32_t    mask;               /* subnet mask (network order) */
    uint32_t    gateway;            /* gateway IP (network order) */
    uint32_t    dns1;               /* primary DNS (network order) */
    uint32_t    dns2;               /* secondary DNS (network order) */
    uint8_t     prefix_len;         /* CIDR prefix length */
    bool        ip_applied;         /* IP has been applied to OS */

    /* DHCP client state */
    enum jz_dhcp_state dhcp_state;
    int         dhcp_sock;          /* AF_PACKET raw socket for DHCP */
    uint32_t    dhcp_xid;           /* transaction ID */
    uint32_t    dhcp_server_ip;     /* DHCP server IP */
    uint32_t    dhcp_offered_ip;    /* IP from OFFER */
    uint32_t    dhcp_offered_mask;  /* mask from OFFER */
    uint32_t    dhcp_offered_gw;    /* gateway from OFFER */
    uint32_t    dhcp_offered_dns1;  /* DNS from OFFER */
    uint32_t    dhcp_offered_dns2;  /* DNS from OFFER */
    uint32_t    dhcp_lease_time;    /* lease duration in seconds */
    uint64_t    dhcp_last_send_ns;  /* last packet send time (monotonic ns) */
    uint64_t    dhcp_lease_start_ns;/* when lease was acquired */
    int         dhcp_retries;       /* retry counter for current state */

    /* Static IP config (parsed from address field) */
    uint32_t    static_ip;          /* configured static IP */
    uint32_t    static_mask;        /* configured static mask */
    uint32_t    static_gw;          /* configured gateway */
    uint32_t    static_dns1;        /* configured DNS */
    uint32_t    static_dns2;        /* configured DNS */
    uint8_t     static_prefix;      /* configured prefix length */

    bool        active;             /* interface is managed by ip_mgr */
    bool        os_ip_adopted;      /* true = adopted pre-existing OS IP, don't remove on destroy */
} jz_ip_iface_t;

typedef struct jz_ip_mgr {
    jz_ip_iface_t   ifaces[JZ_IP_MGR_MAX_IFACES];
    int              iface_count;
    int              nl_sock;       /* netlink socket for IP management */
    bool             initialized;
    bool             new_ip_applied; /* set when a new IP is applied, cleared by caller */
} jz_ip_mgr_t;

int  jz_ip_mgr_init(jz_ip_mgr_t *mgr, const jz_config_t *cfg);
void jz_ip_mgr_tick(jz_ip_mgr_t *mgr);
void jz_ip_mgr_update_config(jz_ip_mgr_t *mgr, const jz_config_t *cfg);
void jz_ip_mgr_destroy(jz_ip_mgr_t *mgr);

#endif /* JZ_IP_MGR_H */
