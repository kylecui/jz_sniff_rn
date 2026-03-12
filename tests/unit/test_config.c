/* SPDX-License-Identifier: MIT */
/* test_config.c -- Unit tests for config.h / config.c */

#include "test_helpers.h"
#include "config.h"

/* -- Fixtures -- */

static jz_config_t test_cfg;
static jz_config_errors_t test_errors;
static char test_yaml_path[256];
static char test_overlay_path[256];

static int setup(void **state)
{
    (void)state;
    memset(&test_cfg, 0, sizeof(test_cfg));
    memset(&test_errors, 0, sizeof(test_errors));
    jz_config_defaults(&test_cfg);

    snprintf(test_yaml_path, sizeof(test_yaml_path), "%s", test_tmpfile("config_test.yaml"));
    snprintf(test_overlay_path, sizeof(test_overlay_path), "%s.overlay", test_yaml_path);
    test_cleanup_file(test_yaml_path);
    test_cleanup_file(test_overlay_path);
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    test_cleanup_file(test_yaml_path);
    test_cleanup_file(test_overlay_path);
    return 0;
}

static void set_valid_policy(jz_config_policy_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->src_ip, sizeof(p->src_ip), "10.0.1.1");
    snprintf(p->dst_ip, sizeof(p->dst_ip), "10.0.1.50");
    p->src_port = 12345;
    p->dst_port = 22;
    snprintf(p->proto, sizeof(p->proto), "tcp");
    snprintf(p->action, sizeof(p->action), "pass");
    p->redirect_port = 0;
    p->mirror_port = 0;
}

static void set_valid_threat(jz_config_threat_pattern_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->id, sizeof(p->id), "smb_scan");
    p->dst_port = 445;
    snprintf(p->proto, sizeof(p->proto), "tcp");
    snprintf(p->threat_level, sizeof(p->threat_level), "high");
    snprintf(p->action, sizeof(p->action), "log_only");
    snprintf(p->description, sizeof(p->description), "SMB probe");
}

/* -- Test: Defaults match base.yaml -- */

static void test_config_defaults_values(void **state)
{
    (void)state;

    assert_int_equal(1, test_cfg.version);
    assert_string_equal("jz-sniff-001", test_cfg.system.device_id);
    assert_string_equal("info", test_cfg.system.log_level);
    assert_string_equal("/var/lib/jz", test_cfg.system.data_dir);
    assert_string_equal("/var/run/jz", test_cfg.system.run_dir);

    assert_true(test_cfg.modules.guard_classifier.enabled);
    assert_int_equal(22, test_cfg.modules.guard_classifier.stage);
    assert_true(test_cfg.modules.arp_honeypot.common.enabled);
    assert_int_equal(23, test_cfg.modules.arp_honeypot.common.stage);
    assert_true(test_cfg.modules.icmp_honeypot.common.enabled);
    assert_int_equal(24, test_cfg.modules.icmp_honeypot.common.stage);
    assert_true(test_cfg.modules.sniffer_detect.common.enabled);
    assert_int_equal(25, test_cfg.modules.sniffer_detect.common.stage);
    assert_true(test_cfg.modules.traffic_weaver.common.enabled);
    assert_int_equal(35, test_cfg.modules.traffic_weaver.common.stage);
    assert_true(test_cfg.modules.bg_collector.common.enabled);
    assert_int_equal(40, test_cfg.modules.bg_collector.common.stage);
    assert_true(test_cfg.modules.threat_detect.enabled);
    assert_int_equal(50, test_cfg.modules.threat_detect.stage);
    assert_true(test_cfg.modules.forensics.common.enabled);
    assert_int_equal(55, test_cfg.modules.forensics.common.stage);

    assert_int_equal(100, test_cfg.modules.arp_honeypot.rate_limit_pps);
    assert_false(test_cfg.modules.arp_honeypot.log_all);
    assert_int_equal(64, test_cfg.modules.icmp_honeypot.ttl);
    assert_int_equal(100, test_cfg.modules.icmp_honeypot.rate_limit_pps);
    assert_int_equal(30, test_cfg.modules.sniffer_detect.probe_interval_sec);
    assert_int_equal(5, test_cfg.modules.sniffer_detect.probe_count);
    assert_string_equal("pass", test_cfg.modules.traffic_weaver.default_action);

    assert_int_equal(1, test_cfg.modules.bg_collector.sample_rate);
    assert_true(test_cfg.modules.bg_collector.protocols.arp);
    assert_true(test_cfg.modules.bg_collector.protocols.dhcp);
    assert_true(test_cfg.modules.bg_collector.protocols.mdns);
    assert_true(test_cfg.modules.bg_collector.protocols.ssdp);
    assert_true(test_cfg.modules.bg_collector.protocols.lldp);
    assert_true(test_cfg.modules.bg_collector.protocols.cdp);
    assert_true(test_cfg.modules.bg_collector.protocols.stp);
    assert_true(test_cfg.modules.bg_collector.protocols.igmp);

    assert_int_equal(256, test_cfg.modules.forensics.max_payload_bytes);
    assert_int_equal(0, test_cfg.modules.forensics.sample_rate);

    assert_false(test_cfg.guards.dynamic.auto_discover);
    assert_int_equal(16384, test_cfg.guards.dynamic.max_entries);
    assert_int_equal(24, test_cfg.guards.dynamic.ttl_hours);

    assert_string_equal("aa:bb:cc", test_cfg.fake_mac_pool.prefix);
    assert_int_equal(64, test_cfg.fake_mac_pool.count);

    assert_string_equal("/etc/jz/blacklist.txt", test_cfg.threats.blacklist_file);
    assert_string_equal("/var/lib/jz/jz.db", test_cfg.collector.db_path);
    assert_int_equal(512, test_cfg.collector.max_db_size_mb);
    assert_int_equal(10, test_cfg.collector.dedup_window_sec);
    assert_int_equal(1000, test_cfg.collector.rate_limit_eps);

    assert_false(test_cfg.uploader.enabled);
    assert_int_equal(60, test_cfg.uploader.interval_sec);
    assert_int_equal(1000, test_cfg.uploader.batch_size);
    assert_true(test_cfg.uploader.compress);

    assert_true(test_cfg.api.enabled);
    assert_string_equal("0.0.0.0:8443", test_cfg.api.listen);
}

/* -- Test: Validate -- */

static void test_config_validate_valid(void **state)
{
    (void)state;
    assert_int_equal(0, jz_config_validate(&test_cfg, &test_errors));
    assert_int_equal(0, test_errors.count);
}

static void test_config_validate_empty_device_id(void **state)
{
    (void)state;
    test_cfg.system.device_id[0] = '\0';
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_invalid_log_level(void **state)
{
    (void)state;
    snprintf(test_cfg.system.log_level, sizeof(test_cfg.system.log_level), "verbose");
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_invalid_stage(void **state)
{
    (void)state;
    test_cfg.modules.guard_classifier.stage = 999;
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_policy_invalid_action(void **state)
{
    (void)state;
    test_cfg.policy_count = 1;
    set_valid_policy(&test_cfg.policies[0]);
    snprintf(test_cfg.policies[0].action, sizeof(test_cfg.policies[0].action), "block");
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_policy_invalid_proto(void **state)
{
    (void)state;
    test_cfg.policy_count = 1;
    set_valid_policy(&test_cfg.policies[0]);
    snprintf(test_cfg.policies[0].proto, sizeof(test_cfg.policies[0].proto), "gre");
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_redirect_without_port(void **state)
{
    (void)state;
    test_cfg.policy_count = 1;
    set_valid_policy(&test_cfg.policies[0]);
    snprintf(test_cfg.policies[0].action, sizeof(test_cfg.policies[0].action), "redirect");
    test_cfg.policies[0].redirect_port = 0;
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_threat_invalid_action_drop(void **state)
{
    (void)state;
    test_cfg.threats.pattern_count = 1;
    set_valid_threat(&test_cfg.threats.patterns[0]);
    snprintf(test_cfg.threats.patterns[0].action, sizeof(test_cfg.threats.patterns[0].action), "drop");
    assert_int_equal(-1, jz_config_validate(&test_cfg, &test_errors));
    assert_true(test_errors.count > 0);
}

static void test_config_validate_threat_valid_action_log_drop(void **state)
{
    (void)state;
    test_cfg.threats.pattern_count = 1;
    set_valid_threat(&test_cfg.threats.patterns[0]);
    snprintf(test_cfg.threats.patterns[0].action, sizeof(test_cfg.threats.patterns[0].action), "log_drop");
    assert_int_equal(0, jz_config_validate(&test_cfg, &test_errors));
    assert_int_equal(0, test_errors.count);
}

/* -- Test: Load from YAML -- */

static void test_config_load_file(void **state)
{
    FILE *fp;
    int rc;
    (void)state;

    fp = fopen(test_yaml_path, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "version: 1\nsystem:\n  device_id: unit-001\n") > 0);
    fclose(fp);

    rc = jz_config_load(&test_cfg, test_yaml_path, &test_errors);
    assert_int_equal(0, rc);
    assert_string_equal("unit-001", test_cfg.system.device_id);
    assert_string_equal("info", test_cfg.system.log_level);
    assert_string_equal("/var/run/jz", test_cfg.system.run_dir);
}

/* -- Test: Load merged base + overlay -- */

static void test_config_load_merged(void **state)
{
    FILE *base_fp;
    FILE *overlay_fp;
    int rc;
    (void)state;

    base_fp = fopen(test_yaml_path, "w");
    assert_non_null(base_fp);
    assert_true(fprintf(base_fp,
        "version: 1\n"
        "system:\n"
        "  device_id: merge-base\n"
        "  log_level: info\n") > 0);
    fclose(base_fp);

    overlay_fp = fopen(test_overlay_path, "w");
    assert_non_null(overlay_fp);
    assert_true(fprintf(overlay_fp,
        "system:\n"
        "  log_level: debug\n") > 0);
    fclose(overlay_fp);

    rc = jz_config_load_merged(&test_cfg, test_yaml_path, test_overlay_path, &test_errors);
    assert_int_equal(0, rc);
    assert_string_equal("merge-base", test_cfg.system.device_id);
    assert_string_equal("debug", test_cfg.system.log_level);
}

/* -- Test: Serialize defaults -- */

static void test_config_serialize_round_trip(void **state)
{
    char *yaml;
    (void)state;

    yaml = jz_config_serialize(&test_cfg);
    assert_non_null(yaml);
    assert_non_null(strstr(yaml, "version: 1"));
    assert_non_null(strstr(yaml, "device_id: jz-sniff-001"));
    assert_non_null(strstr(yaml, "run_dir: /var/run/jz"));
    assert_non_null(strstr(yaml, "default_action: pass"));
    assert_non_null(strstr(yaml, "listen: 0.0.0.0:8443"));
    free(yaml);
}

/* -- Test: Free and NULL safety -- */

static void test_config_free_null_safety(void **state)
{
    (void)state;
    jz_config_free(NULL);
    jz_config_free(&test_cfg);
}

static void test_config_null_pointer_safety(void **state)
{
    (void)state;
    jz_config_defaults(NULL);
    assert_null(jz_config_serialize(NULL));
    assert_int_equal(-1, jz_config_validate(NULL, &test_errors));
    assert_int_equal(-1, jz_config_validate(NULL, NULL));
    assert_int_equal(-1, jz_config_load(NULL, test_yaml_path, &test_errors));
    assert_int_equal(-1, jz_config_load(&test_cfg, NULL, &test_errors));
    assert_int_equal(-1, jz_config_load_merged(NULL, test_yaml_path, test_overlay_path, &test_errors));
    assert_int_equal(-1, jz_config_load_merged(&test_cfg, NULL, test_overlay_path, &test_errors));
    assert_int_equal(-1, jz_config_load_merged(&test_cfg, test_yaml_path, NULL, &test_errors));
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_config_defaults_values, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_valid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_empty_device_id, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_invalid_log_level, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_invalid_stage, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_policy_invalid_action, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_policy_invalid_proto, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_redirect_without_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_threat_invalid_action_drop, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_validate_threat_valid_action_log_drop, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_load_file, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_load_merged, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_serialize_round_trip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_free_null_safety, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_null_pointer_safety, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
