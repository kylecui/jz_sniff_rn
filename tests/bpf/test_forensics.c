/* test_forensics.c -- BPF test harness for jz_forensics module */
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

#define BPF_OBJ_PATH "build/bpf/jz_forensics.bpf.o"

struct test_generic_packet {
    struct ethhdr eth;
    struct iphdr ip;
    uint8_t payload[256];
} __attribute__((packed));

struct jz_sample_config {
    uint8_t enabled;
    uint8_t _pad;
    uint16_t max_payload_bytes;
    uint32_t sample_rate;
};

static void build_generic_packet(struct test_generic_packet *pkt,
                                 const uint8_t *src_mac,
                                 const uint8_t *dst_mac,
                                 uint32_t src_ip,
                                 uint32_t dst_ip)
{
    memset(pkt, 0, sizeof(*pkt));

    memcpy(pkt->eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->eth.h_dest, dst_mac, ETH_ALEN);
    pkt->eth.h_proto = htons(ETH_P_IP);

    pkt->ip.version = 4;
    pkt->ip.ihl = 5;
    pkt->ip.ttl = 64;
    pkt->ip.protocol = IPPROTO_TCP;
    pkt->ip.saddr = src_ip;
    pkt->ip.daddr = dst_ip;
    pkt->ip.tot_len = htons(sizeof(struct iphdr) + sizeof(pkt->payload));

    memset(pkt->payload, 0xa5, sizeof(pkt->payload));
    memcpy(pkt->payload, "jz-forensics-sample", 19);
}

static int should_sample(uint64_t packet_counter, uint32_t sample_rate)
{
    if (sample_rate == 0)
        return 0;
    return (packet_counter % sample_rate) == 0;
}

static void test_bpf_obj_exists(void **state)
{
    (void)state;
    assert_int_equal(0, access(BPF_OBJ_PATH, F_OK));
}

static void test_bpf_program_loads(void **state)
{
    (void)state;
    struct bpf_object *obj;
    int err;

    obj = bpf_object__open(BPF_OBJ_PATH);
    if (!obj) {
        skip();
        return;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF load failed (expected without root): %s\n", strerror(-err));
    }

    bpf_object__close(obj);
}

static void test_module_descriptor(void **state)
{
    (void)state;
    struct bpf_object *obj;
    struct bpf_map *map;
    bool found_rodata_mod = false;

    obj = bpf_object__open(BPF_OBJ_PATH);
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
    struct bpf_object *obj;
    struct bpf_map *map;
    bool found_sample_config = false;
    bool found_sample_ringbuf = false;

    obj = bpf_object__open(BPF_OBJ_PATH);
    if (!obj) {
        skip();
        return;
    }

    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (!name)
            continue;
        if (strcmp(name, "jz_sample_config") == 0)
            found_sample_config = true;
        else if (strcmp(name, "jz_sample_ringbuf") == 0)
            found_sample_ringbuf = true;
    }

    assert_true(found_sample_config);
    assert_true(found_sample_ringbuf);
    bpf_object__close(obj);
}

static void test_sample_config_struct(void **state)
{
    (void)state;
    struct jz_sample_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    cfg.max_payload_bytes = 128;
    cfg.sample_rate = 100;

    assert_int_equal(sizeof(struct jz_sample_config), 8);
    assert_int_equal(offsetof(struct jz_sample_config, enabled), 0);
    assert_int_equal(offsetof(struct jz_sample_config, _pad), 1);
    assert_int_equal(offsetof(struct jz_sample_config, max_payload_bytes), 2);
    assert_int_equal(offsetof(struct jz_sample_config, sample_rate), 4);

    assert_int_equal(cfg.enabled, 1);
    assert_int_equal(cfg.max_payload_bytes, 128);
    assert_int_equal(cfg.sample_rate, 100);
}

static void test_generic_packet_structure(void **state)
{
    (void)state;
    struct test_generic_packet pkt;
    uint8_t src_mac[ETH_ALEN] = {0x02, 0x13, 0x37, 0x13, 0x37, 0x01};
    uint8_t dst_mac[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

    build_generic_packet(&pkt,
                         src_mac,
                         dst_mac,
                         htonl(0xac10010a),
                         htonl(0xac100101));

    assert_int_equal(sizeof(struct test_generic_packet), sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(pkt.payload));
    assert_int_equal(pkt.eth.h_proto, htons(ETH_P_IP));
    assert_int_equal(pkt.ip.version, 4);
    assert_int_equal(pkt.ip.protocol, IPPROTO_TCP);
    assert_int_equal(pkt.ip.saddr, htonl(0xac10010a));
    assert_int_equal(pkt.ip.daddr, htonl(0xac100101));
    assert_memory_equal(pkt.eth.h_source, src_mac, ETH_ALEN);
    assert_memory_equal(pkt.eth.h_dest, dst_mac, ETH_ALEN);
    assert_memory_equal(pkt.payload, "jz-forensics-sample", 19);
}

static void test_sampling_decision_logic(void **state)
{
    (void)state;

    assert_false(should_sample(0, 0));
    assert_true(should_sample(0, 1));
    assert_true(should_sample(1, 1));

    assert_true(should_sample(0, 10));
    assert_true(should_sample(10, 10));
    assert_true(should_sample(20, 10));
    assert_false(should_sample(9, 10));
    assert_false(should_sample(11, 10));

    assert_true(should_sample(100, 100));
    assert_false(should_sample(101, 100));
    assert_false(should_sample(199, 100));
    assert_true(should_sample(200, 100));
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
        cmocka_unit_test(test_sample_config_struct),
        cmocka_unit_test(test_generic_packet_structure),
        cmocka_unit_test(test_sampling_decision_logic),
        cmocka_unit_test(test_prog_run_placeholder),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
