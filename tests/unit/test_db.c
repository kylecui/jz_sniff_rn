/* test_db.c -- Unit tests for SQLite database wrapper (db.h / db.c)
 *
 * Tests:
 *   - Database open/close lifecycle
 *   - Schema creation (all 6 tables)
 *   - Insert operations for each table
 *   - System state get/set
 *   - Mark uploaded / pending count
 *   - Error handling (NULL inputs, closed DB)
 */

#include "test_helpers.h"
#include "db.h"

/* -- Fixtures -- */

static jz_db_t test_db;
static char *test_db_path;

static int setup(void **state)
{
    (void)state;
    test_db_path = test_tmpfile("test.db");
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

/* -- Test: Open and Close -- */

static void test_db_open_close(void **state)
{
    (void)state;
    jz_db_t db;
    char *path = test_tmpfile("open_close.db");

    assert_int_equal(0, jz_db_open(&db, path));
    assert_true(db.initialized);
    assert_non_null(db.db);

    jz_db_close(&db);
    assert_false(db.initialized);
    assert_null(db.db);

    test_cleanup_file(path);
}

/* -- Test: Open with NULL -- */

static void test_db_open_null(void **state)
{
    (void)state;
    jz_db_t db;
    assert_int_equal(-1, jz_db_open(NULL, "/tmp/test.db"));
    assert_int_equal(-1, jz_db_open(&db, NULL));
}

/* -- Test: Insert Attack -- */

static void test_db_insert_attack(void **state)
{
    (void)state;
    int rc = jz_db_insert_attack(&test_db,
        1,                           /* event_type: JZ_EVENT_ATTACK_ARP */
        "2026-03-01T10:00:00Z",     /* timestamp */
        1709290800000000000ULL,      /* timestamp_ns */
        "10.0.1.100",               /* src_ip */
        "aa:bb:cc:dd:ee:ff",        /* src_mac */
        "10.0.1.50",                /* dst_ip (guarded) */
        "aa:bb:cc:00:00:01",        /* dst_mac (fake) */
        "static",                   /* guard_type */
        "arp",                      /* protocol */
        2,                           /* ifindex */
        0,                           /* threat_level */
        NULL, 0,                     /* packet_sample */
        "{\"detail\":\"test\"}",    /* details */
        0);                          /* vlan_id */
    assert_int_equal(0, rc);
}

/* -- Test: Insert Sniffer -- */

static void test_db_insert_sniffer(void **state)
{
    (void)state;
    int rc = jz_db_insert_sniffer(&test_db,
        "de:ad:be:ef:00:01",        /* mac */
        "10.0.1.200",               /* ip */
        2,                           /* ifindex */
        "2026-03-01T10:00:00Z",     /* first_seen */
        "2026-03-01T10:05:00Z",     /* last_seen */
        3,                           /* response_count */
        "10.0.1.254",               /* probe_ip */
        0);                          /* vlan_id */
    assert_int_equal(0, rc);
}

/* -- Test: Insert BG Capture -- */

static void test_db_insert_bg_capture(void **state)
{
    (void)state;
    int rc = jz_db_insert_bg_capture(&test_db,
        "2026-03-01T10:00:00Z",      /* period_start */
        "2026-03-01T10:05:00Z",      /* period_end */
        "arp",                       /* protocol */
        150,                          /* packet_count */
        12000,                        /* byte_count */
        8,                            /* unique_sources */
        "[{\"src\":\"10.0.1.1\"}]",  /* sample_data */
        0,                            /* vlan_id */
        "10.0.1.1",                   /* src_ip */
        "10.0.1.255",                 /* dst_ip */
        "aa:bb:cc:dd:ee:01",          /* src_mac */
        "ff:ff:ff:ff:ff:ff");         /* dst_mac */
    assert_int_equal(0, rc);
}

/* -- Test: Insert Config History -- */

static void test_db_insert_config(void **state)
{
    (void)state;
    int rc = jz_db_insert_config(&test_db,
        1,                           /* version */
        "version: 1\nsystem: ...",  /* config_data */
        "local",                    /* source */
        "2026-03-01T10:00:00Z",     /* applied_at */
        "system",                   /* applied_by */
        0,                           /* rollback_from (none) */
        "applied");                 /* status */
    assert_int_equal(0, rc);
}

/* -- Test: Insert Audit Log -- */

static void test_db_insert_audit(void **state)
{
    (void)state;
    int rc = jz_db_insert_audit(&test_db,
        "2026-03-01T10:00:00Z",     /* timestamp */
        "guard_add",                /* action */
        "cli:admin",                /* actor */
        "guard:10.0.1.50",          /* target */
        "{\"type\":\"static\"}",    /* details */
        "success");                 /* result */
    assert_int_equal(0, rc);
}

/* -- Test: System State -- */

static void test_db_system_state(void **state)
{
    (void)state;
    char buf[256];

    /* Set state */
    assert_int_equal(0, jz_db_set_state(&test_db, "last_boot", "2026-03-01T10:00:00Z"));

    /* Get state */
    assert_int_equal(0, jz_db_get_state(&test_db, "last_boot", buf, sizeof(buf)));
    assert_string_equal("2026-03-01T10:00:00Z", buf);

    /* Overwrite state */
    assert_int_equal(0, jz_db_set_state(&test_db, "last_boot", "2026-03-01T11:00:00Z"));
    assert_int_equal(0, jz_db_get_state(&test_db, "last_boot", buf, sizeof(buf)));
    assert_string_equal("2026-03-01T11:00:00Z", buf);

    /* Get non-existent key */
    assert_int_equal(-1, jz_db_get_state(&test_db, "nonexistent", buf, sizeof(buf)));
}

/* -- Test: Mark Uploaded -- */

static void test_db_mark_uploaded(void **state)
{
    (void)state;

    /* Insert a few attack records */
    for (int i = 0; i < 3; i++) {
        jz_db_insert_attack(&test_db, 1, "2026-03-01T10:00:00Z",
            1709290800000000000ULL, "10.0.1.100", "aa:bb:cc:dd:ee:ff",
            "10.0.1.50", NULL, "static", "arp", 2, 0, NULL, 0, NULL, 0);
    }

    /* Check pending count */
    int pending = jz_db_pending_count(&test_db, "attack_log");
    assert_true(pending >= 3);

    /* Mark as uploaded */
    int marked = jz_db_mark_uploaded(&test_db, "attack_log", 999999);
    assert_true(marked >= 3);

    /* Verify zero pending */
    pending = jz_db_pending_count(&test_db, "attack_log");
    assert_int_equal(0, pending);
}

/* -- Test: Invalid table name rejected -- */

static void test_db_invalid_table(void **state)
{
    (void)state;
    assert_int_equal(-1, jz_db_mark_uploaded(&test_db, "evil_table; DROP TABLE--", 1));
    assert_int_equal(-1, jz_db_pending_count(&test_db, "nonexistent"));
}

/* -- Test: Operations on closed DB fail -- */

static void test_db_closed_operations(void **state)
{
    (void)state;
    jz_db_t closed_db = {0};

    assert_int_equal(-1, jz_db_insert_attack(&closed_db,
        1, "ts", 0, "ip", "mac", "dip", NULL, "static", "arp", 0, 0, NULL, 0, NULL, 0));
    assert_int_equal(-1, jz_db_set_state(&closed_db, "key", "val"));

    char buf[64];
    assert_int_equal(-1, jz_db_get_state(&closed_db, "key", buf, sizeof(buf)));
}

/* -- Main -- */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_db_open_close),
        cmocka_unit_test(test_db_open_null),
        cmocka_unit_test_setup_teardown(test_db_insert_attack, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_insert_sniffer, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_insert_bg_capture, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_insert_config, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_insert_audit, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_system_state, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_mark_uploaded, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_invalid_table, setup, teardown),
        cmocka_unit_test(test_db_closed_operations),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
