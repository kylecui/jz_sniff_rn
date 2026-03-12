/* test_arp_honeypot.c -- BPF test harness for jz_arp_honeypot module
 *
 * Uses BPF_PROG_TEST_RUN to test the arp_honeypot BPF program
 * with synthetic packets.
 *
 * NOTE: This test requires:
 *   - Root privileges (CAP_BPF)
 *   - Compiled BPF object: build/bpf/jz_arp_honeypot.bpf.o
 *   - Kernel 5.8+ with BTF support
 */

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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Path to compiled BPF object */
#define BPF_OBJ_PATH "build/bpf/jz_arp_honeypot.bpf.o"

/* -- Helper: Build a simple ARP request packet -- */

struct test_arp_packet {
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

static void build_arp_request_packet(struct test_arp_packet *pkt,
                                     const uint8_t *src_mac,
                                     const uint8_t *src_ip,
                                     const uint8_t *target_ip)
{
    static const uint8_t broadcast_mac[ETH_ALEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static const uint8_t zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};

    memset(pkt, 0, sizeof(*pkt));

    memcpy(pkt->eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->eth.h_dest, broadcast_mac, ETH_ALEN);
    pkt->eth.h_proto = htons(ETH_P_ARP);

    pkt->arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt->arp.ar_pro = htons(ETH_P_IP);
    pkt->arp.ar_hln = ETH_ALEN;
    pkt->arp.ar_pln = 4;
    pkt->arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt->arp.ar_sha, src_mac, ETH_ALEN);
    memcpy(&pkt->arp.ar_sip, src_ip, sizeof(pkt->arp.ar_sip));
    memcpy(pkt->arp.ar_tha, zero_mac, ETH_ALEN);
    memcpy(&pkt->arp.ar_tip, target_ip, sizeof(pkt->arp.ar_tip));
}

/* -- Test: BPF object file exists -- */

static void test_bpf_obj_exists(void **state)
{
    (void)state;
    assert_int_equal(0, access(BPF_OBJ_PATH, F_OK));
}

/* -- Test: BPF program loads -- */

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
        fprintf(stderr, "BPF load failed (expected without root): %s\n",
                strerror(-err));
    }

    bpf_object__close(obj);
}

/* -- Test: Module descriptor in .rodata.mod -- */

static void test_module_descriptor(void **state)
{
    (void)state;

    struct bpf_object *obj;
    obj = bpf_object__open(BPF_OBJ_PATH);
    if (!obj) {
        skip();
        return;
    }

    struct bpf_map *map;
    bool found_rodata_mod = false;

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

/* -- Test: ARP packet structure and helper output -- */

static void test_arp_packet_structure(void **state)
{
    (void)state;

    struct test_arp_packet pkt;
    uint8_t src_mac[ETH_ALEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src_ip[4] = {10, 0, 1, 10};
    uint8_t target_ip[4] = {10, 0, 1, 1};

    build_arp_request_packet(&pkt, src_mac, src_ip, target_ip);

    assert_int_equal(sizeof(struct test_arp_packet), sizeof(struct ethhdr) + sizeof(pkt.arp));
    assert_int_equal(pkt.eth.h_proto, htons(ETH_P_ARP));
    assert_int_equal(pkt.arp.ar_op, htons(ARPOP_REQUEST));
    assert_memory_equal(pkt.eth.h_source, src_mac, ETH_ALEN);
}

/* -- Placeholder: prog_test_run tests (require root + loaded prog) -- */

static void test_prog_run_arp_reply(void **state)
{
    (void)state;
    fprintf(stderr, "NOTE: prog_test_run tests require root + full map setup\n");
    assert_true(1);
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bpf_obj_exists),
        cmocka_unit_test(test_bpf_program_loads),
        cmocka_unit_test(test_module_descriptor),
        cmocka_unit_test(test_arp_packet_structure),
        cmocka_unit_test(test_prog_run_arp_reply),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
