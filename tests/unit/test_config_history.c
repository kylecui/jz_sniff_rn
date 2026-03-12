/* SPDX-License-Identifier: MIT */
/* test_config_history.c -- Unit tests for config history APIs. */

#include "test_helpers.h"
#include "config_history.h"
#include "db.h"

/* -- Fixtures -- */

static jz_db_t test_db;
static char *test_db_path;

static int setup(void **state)
{
    (void)state;
    test_db_path = test_tmpfile("history.db");
    assert_int_equal(0, jz_db_open(&test_db, test_db_path));
    assert_int_equal(0, jz_config_history_init(&test_db));
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    jz_db_close(&test_db);
    test_cleanup_file(test_db_path);
    return 0;
}

/* -- Test: Init returns success -- */

static void test_config_history_init_ok(void **state)
{
    (void)state;
    assert_int_equal(0, jz_config_history_init(&test_db));
}

/* -- Test: Init is idempotent -- */

static void test_config_history_init_idempotent(void **state)
{
    (void)state;
    assert_int_equal(0, jz_config_history_init(&test_db));
    assert_int_equal(0, jz_config_history_init(&test_db));
}

/* -- Test: Save version 1 -- */

static void test_config_history_save_v1(void **state)
{
    (void)state;
    const char *yaml = "version: 1\nsystem:\n  device_id: test\n";

    assert_int_equal(0, jz_config_history_save(&test_db, 1, yaml, "local", "system"));
}

/* -- Test: Current version empty then latest -- */

static void test_config_history_current_version(void **state)
{
    (void)state;
    const char *yaml = "version: 1\nsystem:\n  device_id: test\n";

    assert_int_equal(0, jz_config_history_current_version(&test_db));
    assert_int_equal(0, jz_config_history_save(&test_db, 1, yaml, "local", "system"));
    assert_int_equal(1, jz_config_history_current_version(&test_db));
}

/* -- Test: Get saved version and verify fields -- */

static void test_config_history_get_saved_version(void **state)
{
    (void)state;
    const char *yaml = "version: 1\nsystem:\n  device_id: test\nnetwork:\n  mode: bridge\n";
    jz_config_version_t version;

    assert_int_equal(0, jz_config_history_save(&test_db, 1, yaml, "local", "cli:admin"));
    assert_int_equal(0, jz_config_history_get(&test_db, 1, &version));

    assert_int_equal(1, version.version);
    assert_string_equal(yaml, version.config_data);
    assert_string_equal("local", version.source);
    assert_string_equal("cli:admin", version.applied_by);
    assert_int_equal(0, version.rollback_from);
    assert_string_equal("applied", version.status);
}

/* -- Test: List all versions with limit=0 -- */

static void test_config_history_list_all(void **state)
{
    (void)state;
    jz_config_version_list_t list;

    assert_int_equal(0, jz_config_history_save(&test_db, 1,
        "version: 1\nsystem:\n  device_id: test\n", "local", "system"));
    assert_int_equal(0, jz_config_history_save(&test_db, 2,
        "version: 2\nsystem:\n  device_id: test\n", "remote", "api:token"));
    assert_int_equal(0, jz_config_history_save(&test_db, 3,
        "version: 3\nsystem:\n  device_id: test\n", "cli", "cli:admin"));

    assert_int_equal(0, jz_config_history_list(&test_db, 0, &list));
    assert_int_equal(3, list.count);
    assert_int_equal(3, list.versions[0].version);
    assert_int_equal(2, list.versions[1].version);
    assert_int_equal(1, list.versions[2].version);

    jz_config_version_list_free(&list);
}

/* -- Test: List with limit=2 -- */

static void test_config_history_list_limited(void **state)
{
    (void)state;
    jz_config_version_list_t list;

    assert_int_equal(0, jz_config_history_save(&test_db, 1,
        "version: 1\nsystem:\n  device_id: test\n", "local", "system"));
    assert_int_equal(0, jz_config_history_save(&test_db, 2,
        "version: 2\nsystem:\n  device_id: test\n", "remote", "api:token"));
    assert_int_equal(0, jz_config_history_save(&test_db, 3,
        "version: 3\nsystem:\n  device_id: test\n", "cli", "cli:admin"));

    assert_int_equal(0, jz_config_history_list(&test_db, 2, &list));
    assert_int_equal(2, list.count);
    assert_int_equal(3, list.versions[0].version);
    assert_int_equal(2, list.versions[1].version);

    jz_config_version_list_free(&list);
}

/* -- Test: Rollback creates new version and returns YAML -- */

static void test_config_history_rollback(void **state)
{
    (void)state;
    const char *v1_yaml = "version: 1\nsystem:\n  device_id: test\npolicy:\n  mode: strict\n";
    const char *v2_yaml = "version: 2\nsystem:\n  device_id: test\npolicy:\n  mode: monitor\n";
    char *config_yaml;
    jz_config_version_t v3;
    int new_version;

    config_yaml = calloc(1, JZ_CONFIG_HISTORY_MAX_DATA);
    assert_non_null(config_yaml);

    assert_int_equal(0, jz_config_history_save(&test_db, 1, v1_yaml, "local", "system"));
    assert_int_equal(0, jz_config_history_save(&test_db, 2, v2_yaml, "remote", "api:token"));

    new_version = jz_config_history_rollback(&test_db, 1, "cli:admin",
                                             config_yaml, JZ_CONFIG_HISTORY_MAX_DATA);
    assert_int_equal(3, new_version);
    assert_string_equal(v1_yaml, config_yaml);

    assert_int_equal(0, jz_config_history_get(&test_db, 3, &v3));
    assert_int_equal(3, v3.version);
    assert_int_equal(1, v3.rollback_from);
    assert_string_equal(v1_yaml, v3.config_data);

    free(config_yaml);
}

/* -- Test: Prune keeps latest 2 from 5 -- */

static void test_config_history_prune_keep_two(void **state)
{
    (void)state;
    jz_config_version_list_t list;
    int deleted;

    for (int i = 1; i <= 5; i++) {
        char yaml[128];
        snprintf(yaml, sizeof(yaml), "version: %d\nsystem:\n  device_id: test\n", i);
        assert_int_equal(0, jz_config_history_save(&test_db, i, yaml, "local", "system"));
    }

    deleted = jz_config_history_prune(&test_db, 2);
    assert_int_equal(3, deleted);

    assert_int_equal(0, jz_config_history_list(&test_db, 0, &list));
    assert_int_equal(2, list.count);
    assert_int_equal(5, list.versions[0].version);
    assert_int_equal(4, list.versions[1].version);

    jz_config_version_list_free(&list);
}

/* -- Test: Version list free NULL safety -- */

static void test_config_version_list_free_null_safe(void **state)
{
    (void)state;
    jz_config_version_list_free(NULL);
}

/* -- Test: NULL DB pointer safety -- */

static void test_config_history_null_db_safety(void **state)
{
    (void)state;
    jz_config_version_t version;
    jz_config_version_list_t list = {0};
    char *yaml;

    yaml = calloc(1, JZ_CONFIG_HISTORY_MAX_DATA);
    assert_non_null(yaml);

    assert_int_equal(-1, jz_config_history_init(NULL));
    assert_int_equal(-1, jz_config_history_current_version(NULL));
    assert_int_equal(-1, jz_config_history_save(NULL, 1,
        "version: 1\nsystem:\n  device_id: test\n", "local", "system"));
    assert_int_equal(-1, jz_config_history_get(NULL, 1, &version));
    assert_int_equal(-1, jz_config_history_list(NULL, 0, &list));
    assert_int_equal(-1, jz_config_history_rollback(NULL, 1, "cli:admin",
        yaml, JZ_CONFIG_HISTORY_MAX_DATA));
    assert_int_equal(-1, jz_config_history_prune(NULL, 2));

    jz_config_version_list_free(&list);
    free(yaml);
}

/* -- Test: Operations on invalid/closed DB fail -- */

static void test_config_history_closed_db_operations(void **state)
{
    (void)state;
    jz_db_t closed_db = {0};
    jz_db_t local_db;
    jz_config_version_t version;
    jz_config_version_list_t list = {0};
    char *yaml;
    char *path;

    yaml = calloc(1, JZ_CONFIG_HISTORY_MAX_DATA);
    assert_non_null(yaml);

    assert_int_equal(-1, jz_config_history_init(&closed_db));
    assert_int_equal(-1, jz_config_history_current_version(&closed_db));
    assert_int_equal(-1, jz_config_history_save(&closed_db, 1,
        "version: 1\nsystem:\n  device_id: test\n", "local", "system"));
    assert_int_equal(-1, jz_config_history_get(&closed_db, 1, &version));
    assert_int_equal(-1, jz_config_history_list(&closed_db, 0, &list));
    assert_int_equal(-1, jz_config_history_rollback(&closed_db, 1, "cli:admin",
        yaml, JZ_CONFIG_HISTORY_MAX_DATA));
    assert_int_equal(-1, jz_config_history_prune(&closed_db, 2));
    jz_config_version_list_free(&list);

    path = test_tmpfile("history_closed.db");
    assert_int_equal(0, jz_db_open(&local_db, path));
    jz_db_close(&local_db);

    assert_int_equal(-1, jz_config_history_init(&local_db));
    assert_int_equal(-1, jz_config_history_current_version(&local_db));
    assert_int_equal(-1, jz_config_history_save(&local_db, 1,
        "version: 1\nsystem:\n  device_id: test\n", "local", "system"));
    assert_int_equal(-1, jz_config_history_get(&local_db, 1, &version));
    assert_int_equal(-1, jz_config_history_list(&local_db, 0, &list));
    assert_int_equal(-1, jz_config_history_rollback(&local_db, 1, "cli:admin",
        yaml, JZ_CONFIG_HISTORY_MAX_DATA));
    assert_int_equal(-1, jz_config_history_prune(&local_db, 2));

    jz_config_version_list_free(&list);
    test_cleanup_file(path);
    free(yaml);
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_config_history_init_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_init_idempotent, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_save_v1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_current_version, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_get_saved_version, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_list_all, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_list_limited, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_rollback, setup, teardown),
        cmocka_unit_test_setup_teardown(test_config_history_prune_keep_two, setup, teardown),
        cmocka_unit_test(test_config_version_list_free_null_safe),
        cmocka_unit_test(test_config_history_null_db_safety),
        cmocka_unit_test(test_config_history_closed_db_operations),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
