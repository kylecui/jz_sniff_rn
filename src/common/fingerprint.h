/* SPDX-License-Identifier: MIT */

#ifndef JZ_FINGERPRINT_H
#define JZ_FINGERPRINT_H

#include <stdint.h>

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
    uint16_t vlan;
    char     vendor[32];
    char     os_class[24];
    char     device_class[24];
    char     device_model[48];
    char     hostname[48];
    uint8_t  confidence;
    uint8_t  signals;
    uint32_t first_seen;
    uint32_t last_seen;
} device_profile_t;

#define FP_SIG_OUI        0x01
#define FP_SIG_DHCP       0x02
#define FP_SIG_MDNS       0x04
#define FP_SIG_SSDP       0x08
#define FP_SIG_LLDP       0x10
#define FP_SIG_CDP        0x20

#define FP_SCORE_OUI          15
#define FP_SCORE_DHCP_OPT55   35
#define FP_SCORE_DHCP_OPT60   20
#define FP_SCORE_MDNS         25
#define FP_SCORE_SSDP         25
#define FP_SCORE_LLDP         30
#define FP_SCORE_LLDP_MED     50

typedef enum {
    FP_PROTO_ARP  = 1,
    FP_PROTO_DHCP = 2,
    FP_PROTO_MDNS = 3,
    FP_PROTO_SSDP = 4,
    FP_PROTO_LLDP = 5,
    FP_PROTO_CDP  = 6,
} fp_proto_t;

int fp_init(void);
void fp_destroy(void);
int fp_update_profile(device_profile_t *profile,
                      uint8_t proto,
                      const uint8_t *payload,
                      uint32_t payload_len);
uint8_t fp_get_confidence(const device_profile_t *profile);
const char *fp_lookup_oui(const uint8_t mac[6]);

#endif /* JZ_FINGERPRINT_H */
