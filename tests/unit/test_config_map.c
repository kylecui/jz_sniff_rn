/* SPDX-License-Identifier: MIT */
/* test_config_map.c -- Unit tests for config_map translation layer */

#include "test_helpers.h"
#include "config.h"
#include "config_map.h"

#include <arpa/inet.h>
#include <netinet/in.h>

/* -- Fixtures -- */

static jz_config_t test_cfg;
static jz_config_map_batch_t *test_batch;

static int setup(void **state)
{
    (void)state;
    test_batch = calloc(1, sizeof(*test_batch));
    assert_non_null(test_batch);

    jz_config_defaults(&test_cfg);
    test_cfg.threats.blacklist_file[0] = '\0';
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    free(test_batch);
    test_batch = NULL;
    return 0;
}

/* -- Helpers -- */

static uint32_t ip_to_u32(const char *ip)
{
    struct in_addr addr;
    assert_int_equal(1, inet_pton(AF_INET, ip, &addr));
    return addr.s_addr;
}

/* -- Test: Defaults translation -- */

static void test_config_to_maps_defaults(void **state)
{
    (void)state;

    assert_int_equal(0, jz_config_to_maps(&test_cfg, test_batch));

    assert_int_equal(0, test_batch->static_guards.count);
    assert_int_equal(0, test_batch->whitelist.count);
    assert_int_equal(0, test_batch->policies.count);
    assert_int_equal(0, test_batch->threat_patterns.count);

    assert_int_equal(1, test_batch->arp_config.enabled);
    assert_int_equal(100, test_batch->arp_config.rate_limit_pps);

    assert_int_equal(1, test_batch->icmp_config.enabled);
    assert_int_equal(64, test_batch->icmp_config.ttl);
    assert_int_equal(100, test_batch->icmp_config.rate_limit_pps);

    assert_int_equal(1, test_batch->sample_config.enabled);
    assert_int_equal(256, test_batch->sample_config.max_payload_bytes);
    assert_int_equal(0, test_batch->sample_config.sample_rate);

    assert_true(test_batch->bg_filters.count > 0);
    assert_int_equal(8, test_batch->bg_filters.count);
}

/* -- Test: Static guard translation -- */

static void test_config_to_maps_static_guards(void **state)
{
    uint32_t ip0;
    uint32_t ip1;

    (void)state;

    snprintf(test_cfg.guards.static_entries[0].ip,
             sizeof(test_cfg.guards.static_entries[0].ip),
             "10.0.1.50");
    snprintf(test_cfg.guards.static_entries[1].ip,
             sizeof(test_cfg.guards.static_entries[1].ip),
             "10.0.1.60");
    test_cfg.guards.static_entries[0].vlan = 0;
    test_cfg.guards.static_entries[1].vlan = 0;
    test_cfg.guards.static_count = 2;

    assert_int_equal(0, jz_config_to_maps(&test_cfg, test_batch));
    assert_int_equal(2, test_batch->static_guards.count);

    ip0 = ip_to_u32("10.0.1.50");
    ip1 = ip_to_u32("10.0.1.60");

    assert_int_equal(ip0, test_batch->static_guards.keys[0]);
    assert_int_equal(ip1, test_batch->static_guards.keys[1]);

    assert_int_equal(JZ_GUARD_STATIC, test_batch->static_guards.values[0].guard_type);
    assert_int_equal(JZ_GUARD_STATIC, test_batch->static_guards.values[1].guard_type);
    assert_int_equal(1, test_batch->static_guards.values[0].enabled);
    assert_int_equal(1, test_batch->static_guards.values[1].enabled);
}

/* -- Test: Whitelist translation -- */

static void test_config_to_maps_whitelist(void **state)
{
    uint32_t ip0;
    uint32_t ip1;

    (void)state;

    snprintf(test_cfg.guards.whitelist[0].ip,
             sizeof(test_cfg.guards.whitelist[0].ip),
             "10.0.1.10");
    snprintf(test_cfg.guards.whitelist[0].mac,
             sizeof(test_cfg.guards.whitelist[0].mac),
             "de:ad:be:ef:00:01");
    test_cfg.guards.whitelist[0].match_mac = true;

    snprintf(test_cfg.guards.whitelist[1].ip,
             sizeof(test_cfg.guards.whitelist[1].ip),
             "10.0.1.11");
    test_cfg.guards.whitelist[1].match_mac = false;
    test_cfg.guards.whitelist_count = 2;

    assert_int_equal(0, jz_config_to_maps(&test_cfg, test_batch));
    assert_int_equal(2, test_batch->whitelist.count);

    ip0 = ip_to_u32("10.0.1.10");
    ip1 = ip_to_u32("10.0.1.11");

    assert_int_equal(ip0, test_batch->whitelist.keys[0]);
    assert_int_equal(ip1, test_batch->whitelist.keys[1]);
    assert_int_equal(1, test_batch->whitelist.values[0].match_mac);
    assert_int_equal(0xde, test_batch->whitelist.values[0].mac[0]);
    assert_int_equal(0xad, test_batch->whitelist.values[0].mac[1]);
    assert_int_equal(0xbe, test_batch->whitelist.values[0].mac[2]);
    assert_int_equal(0xef, test_batch->whitelist.values[0].mac[3]);
    assert_int_equal(0x00, test_batch->whitelist.values[0].mac[4]);
    assert_int_equal(0x01, test_batch->whitelist.values[0].mac[5]);
    assert_int_equal(0, test_batch->whitelist.values[1].match_mac);
    assert_int_equal(1, test_batch->whitelist.values[0].enabled);
    assert_int_equal(1, test_batch->whitelist.values[1].enabled);
}

/* -- Test: Policy translation -- */

static void test_config_to_maps_policies(void **state)
{
    uint32_t src_ip;
    uint32_t dst_ip;

    (void)state;

    snprintf(test_cfg.policies[0].src_ip, sizeof(test_cfg.policies[0].src_ip), "10.0.1.0");
    snprintf(test_cfg.policies[0].dst_ip, sizeof(test_cfg.policies[0].dst_ip), "10.0.1.50");
    snprintf(test_cfg.policies[0].proto, sizeof(test_cfg.policies[0].proto), "tcp");
    snprintf(test_cfg.policies[0].action, sizeof(test_cfg.policies[0].action), "redirect");
    test_cfg.policies[0].dst_port = 22;
    test_cfg.policies[0].redirect_port = 8;
    test_cfg.policy_count = 1;

    assert_int_equal(0, jz_config_to_maps(&test_cfg, test_batch));
    assert_int_equal(1, test_batch->policies.count);

    src_ip = ip_to_u32("10.0.1.0");
    dst_ip = ip_to_u32("10.0.1.50");

    assert_int_equal(src_ip, test_batch->policies.keys[0].src_ip);
    assert_int_equal(dst_ip, test_batch->policies.keys[0].dst_ip);
    assert_int_equal(0, test_batch->policies.keys[0].src_port);
    assert_int_equal(22, test_batch->policies.keys[0].dst_port);
    assert_int_equal(IPPROTO_TCP, test_batch->policies.keys[0].proto);

    assert_int_equal(JZ_ACTION_REDIRECT, test_batch->policies.values[0].action);
    assert_int_equal(8, test_batch->policies.values[0].redirect_port);
}

/* -- Test: Threat pattern translation -- */

static void test_config_to_maps_threat_patterns(void **state)
{
    (void)state;

    snprintf(test_cfg.threats.patterns[0].id, sizeof(test_cfg.threats.patterns[0].id), "1");
    snprintf(test_cfg.threats.patterns[0].proto,
             sizeof(test_cfg.threats.patterns[0].proto),
             "tcp");
    snprintf(test_cfg.threats.patterns[0].threat_level,
             sizeof(test_cfg.threats.patterns[0].threat_level),
             "high");
    snprintf(test_cfg.threats.patterns[0].action,
             sizeof(test_cfg.threats.patterns[0].action),
             "log_drop");
    snprintf(test_cfg.threats.patterns[0].description,
             sizeof(test_cfg.threats.patterns[0].description),
             "SMB lateral movement");
    test_cfg.threats.patterns[0].dst_port = 445;
    test_cfg.threats.pattern_count = 1;

    assert_int_equal(0, jz_config_to_maps(&test_cfg, test_batch));
    assert_int_equal(1, test_batch->threat_patterns.count);
    assert_int_equal(1, test_batch->threat_patterns.keys[0]);
    assert_int_equal(445, test_batch->threat_patterns.values[0].dst_port);
    assert_int_equal(IPPROTO_TCP, test_batch->threat_patterns.values[0].proto);
    assert_int_equal(3, test_batch->threat_patterns.values[0].threat_level);
    assert_int_equal(1, test_batch->threat_patterns.values[0].action);
}

/* -- Test: MAC generation -- */

static void test_config_generate_macs(void **state)
{
    (void)state;

    assert_int_equal(0, jz_config_generate_macs("aa:bb:cc", 4, test_batch));
    assert_int_equal(4, test_batch->fake_macs.count);

    for (int i = 0; i < 4; i++) {
        assert_int_equal(0xaa, test_batch->fake_macs.entries[i].mac[0]);
        assert_int_equal(0xbb, test_batch->fake_macs.entries[i].mac[1]);
        assert_int_equal(0xcc, test_batch->fake_macs.entries[i].mac[2]);
        assert_int_equal(1, test_batch->fake_macs.entries[i].in_use);
    }
}

/* -- Test: Blacklist loading -- */

static void test_config_load_blacklist(void **state)
{
    uint32_t ip0;
    uint32_t ip1;
    uint32_t ip2;
    char *path;
    FILE *fp;

    (void)state;

    path = test_tmpfile("blacklist.txt");
    fp = fopen(path, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "192.168.1.10\n") > 0);
    assert_true(fprintf(fp, "10.0.1.200\n") > 0);
    assert_true(fprintf(fp, "172.16.0.55\n") > 0);
    fclose(fp);

    assert_int_equal(0, jz_config_load_blacklist(path, test_batch));
    assert_int_equal(3, test_batch->threat_blacklist.count);

    ip0 = ip_to_u32("192.168.1.10");
    ip1 = ip_to_u32("10.0.1.200");
    ip2 = ip_to_u32("172.16.0.55");

    assert_int_equal(ip0, test_batch->threat_blacklist.keys[0]);
    assert_int_equal(ip1, test_batch->threat_blacklist.keys[1]);
    assert_int_equal(ip2, test_batch->threat_blacklist.keys[2]);

    test_cleanup_file(path);
}

/* -- Test: NULL pointer safety -- */

static void test_config_map_null_safety(void **state)
{
    (void)state;

    assert_int_equal(-1, jz_config_to_maps(NULL, test_batch));
    assert_int_equal(-1, jz_config_to_maps(&test_cfg, NULL));

    assert_int_equal(-1, jz_config_generate_macs("aa:bb:cc", 4, NULL));
    assert_int_equal(-1, jz_config_generate_macs(NULL, 1, test_batch));

    assert_int_equal(-1, jz_config_load_blacklist(NULL, test_batch));
    assert_int_equal(-1, jz_config_load_blacklist("/tmp/none.txt", NULL));
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_config_to_maps_defaults, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_to_maps_static_guards, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_to_maps_whitelist, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_to_maps_policies, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_to_maps_threat_patterns, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_generate_macs, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_load_blacklist, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_map_null_safety, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
