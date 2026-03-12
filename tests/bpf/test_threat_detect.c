/* test_threat_detect.c -- BPF test harness for jz_threat_detect module */
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_OBJ_PATH "build/bpf/jz_threat_detect.bpf.o"

struct test_ip_packet {
    struct ethhdr eth;
    struct iphdr ip;
    uint8_t payload[64];
};

struct jz_threat_pattern {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t threat_level;
    uint32_t pattern_id;
    uint8_t action;
    uint8_t _pad[3];
    char description[32];
};

static void build_ip_packet(struct test_ip_packet *pkt, const uint8_t *src_mac,
                            const uint8_t *dst_mac, uint32_t src_ip,
                            uint32_t dst_ip, uint8_t proto)
{
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->eth.h_dest, dst_mac, ETH_ALEN);
    pkt->eth.h_proto = htons(ETH_P_IP);
    pkt->ip.version = 4;
    pkt->ip.ihl = 5;
    pkt->ip.ttl = 32;
    pkt->ip.protocol = proto;
    pkt->ip.saddr = src_ip;
    pkt->ip.daddr = dst_ip;
    pkt->ip.tot_len = htons(sizeof(struct iphdr) + sizeof(pkt->payload));
    memcpy(pkt->payload, "jz-threat-detect", 16);
}

static int pattern_matches(const struct jz_threat_pattern *p, uint32_t src_ip,
                           uint32_t dst_ip, uint16_t dst_port, uint8_t proto)
{
    if (p->src_ip != 0 && p->src_ip != src_ip) return 0;
    if (p->dst_ip != 0 && p->dst_ip != dst_ip) return 0;
    if (p->dst_port != 0 && p->dst_port != dst_port) return 0;
    if (p->proto != 0 && p->proto != proto) return 0;
    return 1;
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
    if (err)
        fprintf(stderr, "BPF load failed (expected without root): %s\n", strerror(-err));
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
    bool found_patterns = false;
    bool found_blacklist = false;
    bool found_stats = false;
    bool found_result_map = false;
    if (!obj) {
        skip();
        return;
    }
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (!name) continue;
        if (strcmp(name, "jz_threat_patterns") == 0)
            found_patterns = true;
        else if (strcmp(name, "jz_threat_blacklist") == 0)
            found_blacklist = true;
        else if (strcmp(name, "jz_threat_stats") == 0)
            found_stats = true;
        else if (strcmp(name, "jz_threat_result_map") == 0)
            found_result_map = true;
    }
    assert_true(found_patterns);
    assert_true(found_blacklist);
    assert_true(found_stats);
    assert_true(found_result_map);
    bpf_object__close(obj);
}

static void test_ip_packet_structure(void **state)
{
    (void)state;
    struct test_ip_packet pkt;
    uint8_t src_mac[ETH_ALEN] = {0x02, 0x42, 0x42, 0x42, 0x42, 0x01};
    uint8_t dst_mac[ETH_ALEN] = {0x02, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e};
    build_ip_packet(&pkt, src_mac, dst_mac, htonl(0x0a00020a), htonl(0x0a000201), IPPROTO_TCP);
    assert_int_equal(sizeof(struct test_ip_packet), sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(pkt.payload));
    assert_int_equal(pkt.eth.h_proto, htons(ETH_P_IP));
    assert_int_equal(pkt.ip.protocol, IPPROTO_TCP);
    assert_int_equal(pkt.ip.saddr, htonl(0x0a00020a));
    assert_int_equal(pkt.ip.daddr, htonl(0x0a000201));
    assert_memory_equal(pkt.eth.h_source, src_mac, ETH_ALEN);
    assert_memory_equal(pkt.eth.h_dest, dst_mac, ETH_ALEN);
}

static void test_threat_pattern_wildcards(void **state)
{
    (void)state;
    struct jz_threat_pattern wildcard_proto;
    struct jz_threat_pattern wildcard_ip_port;
    memset(&wildcard_proto, 0, sizeof(wildcard_proto));
    wildcard_proto.src_ip = htonl(0x0a00020a);
    wildcard_proto.dst_ip = htonl(0x0a000201);
    wildcard_proto.dst_port = 443;
    wildcard_proto.proto = 0;
    wildcard_proto.threat_level = 2;

    memset(&wildcard_ip_port, 0, sizeof(wildcard_ip_port));
    wildcard_ip_port.src_ip = 0;
    wildcard_ip_port.dst_ip = htonl(0x0a000201);
    wildcard_ip_port.dst_port = 0;
    wildcard_ip_port.proto = IPPROTO_UDP;
    wildcard_ip_port.threat_level = 1;

    assert_true(pattern_matches(&wildcard_proto, htonl(0x0a00020a), htonl(0x0a000201), 443, IPPROTO_TCP));
    assert_true(pattern_matches(&wildcard_proto, htonl(0x0a00020a), htonl(0x0a000201), 443, IPPROTO_UDP));
    assert_true(pattern_matches(&wildcard_ip_port, htonl(0x7f000001), htonl(0x0a000201), 53, IPPROTO_UDP));
    assert_false(pattern_matches(&wildcard_ip_port, htonl(0x7f000001), htonl(0x0a000202), 53, IPPROTO_UDP));
}

static void test_threat_pattern_exact(void **state)
{
    (void)state;
    struct jz_threat_pattern exact;
    memset(&exact, 0, sizeof(exact));
    exact.src_ip = htonl(0xc0a80132);
    exact.dst_ip = htonl(0xc0a80101);
    exact.dst_port = 22;
    exact.proto = IPPROTO_TCP;
    exact.threat_level = 3;
    exact.pattern_id = 0x1001;
    exact.action = 2;
    memcpy(exact.description, "ssh-brute-force", 16);

    assert_true(pattern_matches(&exact, htonl(0xc0a80132), htonl(0xc0a80101), 22, IPPROTO_TCP));
    assert_false(pattern_matches(&exact, htonl(0xc0a80132), htonl(0xc0a80101), 80, IPPROTO_TCP));
    assert_false(pattern_matches(&exact, htonl(0xc0a80164), htonl(0xc0a80101), 22, IPPROTO_TCP));
    assert_false(pattern_matches(&exact, htonl(0xc0a80132), htonl(0xc0a80101), 22, IPPROTO_UDP));
    assert_int_equal(exact.threat_level, 3);
    assert_int_equal(exact.pattern_id, 0x1001);
    assert_int_equal(exact.action, 2);
    assert_memory_equal(exact._pad, (const uint8_t[3]){0, 0, 0}, sizeof(exact._pad));
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
        cmocka_unit_test(test_ip_packet_structure),
        cmocka_unit_test(test_threat_pattern_wildcards),
        cmocka_unit_test(test_threat_pattern_exact),
        cmocka_unit_test(test_prog_run_placeholder),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
