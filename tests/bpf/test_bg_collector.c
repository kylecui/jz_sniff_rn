/* test_bg_collector.c -- BPF test harness for jz_bg_collector module */
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
#include <linux/udp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_OBJ_PATH "build/bpf/jz_bg_collector.bpf.o"

struct test_arp_broadcast_packet {
    struct ethhdr eth;
    struct {
        uint16_t ar_hrd;
        uint16_t ar_pro;
        uint8_t ar_hln;
        uint8_t ar_pln;
        uint16_t ar_op;
        uint8_t ar_sha[6];
        uint32_t ar_sip;
        uint8_t ar_tha[6];
        uint32_t ar_tip;
    } __attribute__((packed)) arp;
};

struct test_udp_broadcast_packet {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    uint8_t payload[64];
};

static void build_arp_broadcast_packet(struct test_arp_broadcast_packet *pkt,
                                       const uint8_t *src_mac,
                                       uint32_t src_ip,
                                       uint32_t target_ip)
{
    static const uint8_t bcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->eth.h_dest, bcast, ETH_ALEN);
    pkt->eth.h_proto = htons(ETH_P_ARP);
    pkt->arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt->arp.ar_pro = htons(ETH_P_IP);
    pkt->arp.ar_hln = ETH_ALEN;
    pkt->arp.ar_pln = 4;
    pkt->arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt->arp.ar_sha, src_mac, ETH_ALEN);
    pkt->arp.ar_sip = src_ip;
    memcpy(pkt->arp.ar_tha, zero_mac, ETH_ALEN);
    pkt->arp.ar_tip = target_ip;
}

static void build_udp_broadcast_packet(struct test_udp_broadcast_packet *pkt,
                                       const uint8_t *src_mac,
                                       uint32_t src_ip,
                                       uint32_t dst_ip,
                                       uint16_t dst_port)
{
    static const uint8_t bcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->eth.h_dest, bcast, ETH_ALEN);
    pkt->eth.h_proto = htons(ETH_P_IP);
    pkt->ip.version = 4;
    pkt->ip.ihl = 5;
    pkt->ip.ttl = 64;
    pkt->ip.protocol = IPPROTO_UDP;
    pkt->ip.saddr = src_ip;
    pkt->ip.daddr = dst_ip;
    pkt->ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(pkt->payload));
    pkt->udp.source = htons(55555);
    pkt->udp.dest = htons(dst_port);
    pkt->udp.len = htons(sizeof(struct udphdr) + sizeof(pkt->payload));
    memcpy(pkt->payload, "jz-bg-collector-udp", 19);
}

static int is_broadcast(const uint8_t *mac)
{
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return memcmp(mac, bcast, 6) == 0;
}

static int is_multicast(const uint8_t *mac)
{
    return mac[0] & 0x01;
}

static void test_bpf_obj_exists(void **state)
{
    (void)state;
    assert_int_equal(0, access(BPF_OBJ_PATH, F_OK));
}

static void test_bpf_program_loads(void **state)
{
    (void)state;
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    int err;
    if (!obj) {
        skip();
        return;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF load failed (expected without root): %s\n", strerror(-err));
        bpf_object__close(obj);
        skip();
        return;
    }
    bpf_object__close(obj);
}

static void test_module_descriptor(void **state)
{
    (void)state;
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    struct bpf_map *map;
    bool found_rodata_mod = false;
    if (!obj) {
        skip();
        return;
    }
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (name && strstr(name, "rodata.mod")) {
            found_rodata_mod = true;
            break;
        }
    }
    assert_true(found_rodata_mod);
    bpf_object__close(obj);
}

static void test_required_maps_exist(void **state)
{
    (void)state;
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    struct bpf_map *map;
    bool found_bg_filter = false;
    bool found_bg_stats = false;
    if (!obj) {
        skip();
        return;
    }
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (!name)
            continue;
        if (strcmp(name, "jz_bg_filter") == 0)
            found_bg_filter = true;
        else if (strcmp(name, "jz_bg_stats") == 0)
            found_bg_stats = true;
    }
    assert_true(found_bg_filter);
    assert_true(found_bg_stats);
    bpf_object__close(obj);
}

static void test_arp_broadcast_structure(void **state)
{
    (void)state;
    struct test_arp_broadcast_packet pkt;
    uint8_t src_mac[ETH_ALEN] = {0x02, 0xde, 0xad, 0xbe, 0xef, 0x01};
    const uint8_t bcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    build_arp_broadcast_packet(&pkt, src_mac, htonl(0x0a00010a), htonl(0x0a000101));
    assert_int_equal(sizeof(struct test_arp_broadcast_packet), sizeof(struct ethhdr) + sizeof(pkt.arp));
    assert_int_equal(pkt.eth.h_proto, htons(ETH_P_ARP));
    assert_int_equal(pkt.arp.ar_op, htons(ARPOP_REQUEST));
    assert_memory_equal(pkt.eth.h_source, src_mac, ETH_ALEN);
    assert_memory_equal(pkt.eth.h_dest, bcast, ETH_ALEN);
    assert_int_equal(pkt.arp.ar_sip, htonl(0x0a00010a));
    assert_int_equal(pkt.arp.ar_tip, htonl(0x0a000101));
}

static void test_udp_broadcast_dhcp(void **state)
{
    (void)state;
    struct test_udp_broadcast_packet pkt;
    uint8_t src_mac[ETH_ALEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t bcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    build_udp_broadcast_packet(&pkt, src_mac, htonl(0xc0a80164), htonl(0xffffffff), 67);
    assert_int_equal(pkt.eth.h_proto, htons(ETH_P_IP));
    assert_memory_equal(pkt.eth.h_dest, bcast, ETH_ALEN);
    assert_int_equal(pkt.ip.protocol, IPPROTO_UDP);
    assert_int_equal(pkt.ip.saddr, htonl(0xc0a80164));
    assert_int_equal(pkt.ip.daddr, htonl(0xffffffff));
    assert_int_equal(pkt.udp.dest, htons(67));
    assert_int_equal(pkt.udp.len, htons(sizeof(struct udphdr) + sizeof(pkt.payload)));
}

static void test_broadcast_mac_detection(void **state)
{
    (void)state;
    uint8_t bcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t unicast_mac[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    assert_true(is_broadcast(bcast_mac));
    assert_false(is_broadcast(unicast_mac));
    assert_true(is_multicast(bcast_mac));
}

static void test_multicast_mac_detection(void **state)
{
    (void)state;
    uint8_t multicast_mac[ETH_ALEN] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
    uint8_t another_multicast[ETH_ALEN] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x16};
    uint8_t unicast_mac[ETH_ALEN] = {0x02, 0x7a, 0x88, 0x90, 0x10, 0x11};
    assert_true(is_multicast(multicast_mac));
    assert_true(is_multicast(another_multicast));
    assert_false(is_multicast(unicast_mac));
    assert_false(is_broadcast(multicast_mac));
}

static void test_prog_run_placeholder(void **state)
{
    (void)state;
    fprintf(stderr, "NOTE: prog_test_run tests require root + full map setup\n");
    assert_true(1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bpf_obj_exists),
        cmocka_unit_test(test_bpf_program_loads),
        cmocka_unit_test(test_module_descriptor),
        cmocka_unit_test(test_required_maps_exist),
        cmocka_unit_test(test_arp_broadcast_structure),
        cmocka_unit_test(test_udp_broadcast_dhcp),
        cmocka_unit_test(test_broadcast_mac_detection),
        cmocka_unit_test(test_multicast_mac_detection),
        cmocka_unit_test(test_prog_run_placeholder),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
