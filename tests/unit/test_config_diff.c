/* SPDX-License-Identifier: MIT */

#include "test_helpers.h"
#include "config_diff.h"
#include "config.h"
#include "db.h"

/* -- Fixtures -- */

static jz_db_t test_db;
static char *test_db_path;

static int setup(void **state)
{
    (void)state;
    test_db_path = test_tmpfile("diff.db");
    assert_int_equal(0, jz_db_open(&test_db, test_db_path));
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    jz_db_close(&test_db);
    test_cleanup_file(test_db_path);
    return 0;
}

/* -- Helpers -- */

static jz_config_t *alloc_default_cfg(void)
{
    jz_config_t *cfg = calloc(1, sizeof(*cfg));
    assert_non_null(cfg);
    jz_config_defaults(cfg);
    return cfg;
}

static void free_cfg(jz_config_t *cfg)
{
    if (!cfg)
        return;
    jz_config_free(cfg);
    free(cfg);
}

static bool diff_has(const jz_config_diff_t *diff,
                     const char *section,
                     const char *action,
                     const char *key_part)
{
    int i;

    for (i = 0; i < diff->count; i++) {
        if (section && !strstr(diff->entries[i].section, section))
            continue;
        if (action && strcmp(diff->entries[i].action, action) != 0)
            continue;
        if (key_part && !strstr(diff->entries[i].key, key_part))
            continue;
        return true;
    }
    return false;
}

/* -- Test: Diff of identical defaults -- */

static void test_config_diff_identical_defaults(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_int_equal(0, diff.count);
    assert_int_equal(0, diff.sections_changed);

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Diff from NULL old config -- */

static void test_config_diff_from_null_old(void **state)
{
    (void)state;
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;
    int i;

    assert_int_equal(0, jz_config_diff(NULL, new_cfg, &diff));
    assert_true(diff.count > 0);
    for (i = 0; i < diff.count; i++)
        assert_string_equal("added", diff.entries[i].action);

    free_cfg(new_cfg);
}

/* -- Test: Diff detects system.log_level modification -- */

static void test_config_diff_log_level_change(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    snprintf(new_cfg->system.log_level, sizeof(new_cfg->system.log_level), "debug");

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_true(diff_has(&diff, "system", "modified", "log_level"));

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Diff detects static guard addition -- */

static void test_config_diff_guard_add(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    new_cfg->guards.static_count = 1;
    snprintf(new_cfg->guards.static_entries[0].ip,
             sizeof(new_cfg->guards.static_entries[0].ip), "10.0.1.50");
    snprintf(new_cfg->guards.static_entries[0].mac,
             sizeof(new_cfg->guards.static_entries[0].mac), "aa:bb:cc:dd:ee:ff");
    new_cfg->guards.static_entries[0].vlan = 100;

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_true(diff_has(&diff, "guards", NULL, NULL));

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Diff detects policy count change -- */

static void test_config_diff_policy_count_change(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    new_cfg->policy_count = 1;
    snprintf(new_cfg->policies[0].src_ip, sizeof(new_cfg->policies[0].src_ip), "10.0.0.1");
    snprintf(new_cfg->policies[0].dst_ip, sizeof(new_cfg->policies[0].dst_ip), "10.0.0.2");
    new_cfg->policies[0].src_port = 1234;
    new_cfg->policies[0].dst_port = 80;
    snprintf(new_cfg->policies[0].proto, sizeof(new_cfg->policies[0].proto), "tcp");
    snprintf(new_cfg->policies[0].action, sizeof(new_cfg->policies[0].action), "pass");

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_true(diff_has(&diff, "policies", NULL, NULL));

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Diff detects uploader.enabled change -- */

static void test_config_diff_uploader_change(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    new_cfg->uploader.enabled = !old_cfg->uploader.enabled;

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_true(diff_has(&diff, "uploader", "modified", "enabled"));

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Diff sections_changed and summary -- */

static void test_config_diff_sections_and_summary(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    snprintf(new_cfg->system.log_level, sizeof(new_cfg->system.log_level), "debug");
    new_cfg->uploader.enabled = !new_cfg->uploader.enabled;

    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_int_equal(2, diff.sections_changed);
    assert_non_null(diff.summary);
    assert_true(strlen(diff.summary) > 0);

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Audit log success path -- */

static void test_config_audit_log_success(void **state)
{
    (void)state;
    jz_config_t *old_cfg = alloc_default_cfg();
    jz_config_t *new_cfg = alloc_default_cfg();
    jz_config_diff_t diff;

    snprintf(new_cfg->system.log_level, sizeof(new_cfg->system.log_level), "debug");
    assert_int_equal(0, jz_config_diff(old_cfg, new_cfg, &diff));
    assert_int_equal(0, jz_config_audit_log(&test_db, "config_reload", "cli:admin", &diff, "success"));

    free_cfg(new_cfg);
    free_cfg(old_cfg);
}

/* -- Test: Audit query returns all entries -- */

static void test_config_audit_query_all(void **state)
{
    (void)state;
    jz_audit_entry_t *results = NULL;
    int count = 0;

    assert_int_equal(0, jz_config_audit_log(&test_db, "config_push", "cli:admin", NULL, "success"));
    assert_int_equal(0, jz_config_audit_log(&test_db, "config_reload", "cli:admin", NULL, "success"));

    assert_int_equal(2, jz_config_audit_query(&test_db, NULL, NULL, NULL, &results, &count));
    assert_int_equal(2, count);
    jz_config_audit_free(results);
}

/* -- Test: Audit query action filter -- */

static void test_config_audit_query_action_filter(void **state)
{
    (void)state;
    jz_audit_entry_t *results = NULL;
    int count = 0;

    assert_int_equal(0, jz_config_audit_log(&test_db, "config_push", "cli:admin", NULL, "success"));
    assert_int_equal(0, jz_config_audit_log(&test_db, "config_reload", "cli:admin", NULL, "success"));

    assert_int_equal(1, jz_config_audit_query(&test_db, NULL, NULL, "config_push", &results, &count));
    assert_int_equal(1, count);
    assert_string_equal("config_push", results[0].action);
    jz_config_audit_free(results);
}

/* -- Test: Audit free NULL-safe -- */

static void test_config_audit_free_null_safe(void **state)
{
    (void)state;
    jz_config_audit_free(NULL);
}

/* -- Test: NULL pointer safety -- */

static void test_config_diff_null_safety(void **state)
{
    (void)state;
    jz_config_t *cfg = alloc_default_cfg();
    jz_config_diff_t diff;
    jz_audit_entry_t *results = NULL;
    int count = 0;

    assert_int_equal(-1, jz_config_diff(NULL, NULL, &diff));
    assert_int_equal(-1, jz_config_diff(cfg, NULL, &diff));
    assert_int_equal(-1, jz_config_diff(cfg, cfg, NULL));

    assert_int_equal(-1, jz_config_audit_log(NULL, "config_push", "cli:admin", NULL, "success"));
    assert_int_equal(-1, jz_config_audit_log(&test_db, NULL, "cli:admin", NULL, "success"));
    assert_int_equal(-1, jz_config_audit_log(&test_db, "config_push", NULL, NULL, "success"));
    assert_int_equal(-1, jz_config_audit_log(&test_db, "config_push", "cli:admin", NULL, NULL));

    assert_int_equal(-1, jz_config_audit_query(NULL, NULL, NULL, NULL, &results, &count));
    assert_int_equal(-1, jz_config_audit_query(&test_db, NULL, NULL, NULL, NULL, &count));
    assert_int_equal(-1, jz_config_audit_query(&test_db, NULL, NULL, NULL, &results, NULL));

    free_cfg(cfg);
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_diff_identical_defaults),
        cmocka_unit_test(test_config_diff_from_null_old),
        cmocka_unit_test(test_config_diff_log_level_change),
        cmocka_unit_test(test_config_diff_guard_add),
        cmocka_unit_test(test_config_diff_policy_count_change),
        cmocka_unit_test(test_config_diff_uploader_change),
        cmocka_unit_test(test_config_diff_sections_and_summary),
        cmocka_unit_test_setup_teardown(test_config_audit_log_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_audit_query_all, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_audit_query_action_filter, setup, teardown),
        cmocka_unit_test(test_config_audit_free_null_safe),
        cmocka_unit_test_setup_teardown(test_config_diff_null_safety, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
