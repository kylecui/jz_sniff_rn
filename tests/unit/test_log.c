/* SPDX-License-Identifier: MIT */
/* test_log.c -- Unit tests for jz_sniff_rn logging framework */

#include "test_helpers.h"
#include "log.h"

/* ── Setup / Teardown ─────────────────────────────────────────── */

static int setup(void **state)
{
    (void)state;
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    jz_log_close();
    return 0;
}

/* ── Test: Level From String ──────────────────────────────────── */

static void test_level_from_str(void **state)
{
    (void)state;

    assert_int_equal(JZ_LOG_DEBUG, jz_log_level_from_str("debug"));
    assert_int_equal(JZ_LOG_DEBUG, jz_log_level_from_str("DEBUG"));
    assert_int_equal(JZ_LOG_DEBUG, jz_log_level_from_str("Debug"));

    assert_int_equal(JZ_LOG_INFO, jz_log_level_from_str("info"));
    assert_int_equal(JZ_LOG_INFO, jz_log_level_from_str("INFO"));

    assert_int_equal(JZ_LOG_WARN, jz_log_level_from_str("warn"));
    assert_int_equal(JZ_LOG_WARN, jz_log_level_from_str("warning"));
    assert_int_equal(JZ_LOG_WARN, jz_log_level_from_str("WARNING"));

    assert_int_equal(JZ_LOG_ERROR, jz_log_level_from_str("error"));
    assert_int_equal(JZ_LOG_ERROR, jz_log_level_from_str("ERROR"));

    assert_int_equal(JZ_LOG_FATAL, jz_log_level_from_str("fatal"));
    assert_int_equal(JZ_LOG_FATAL, jz_log_level_from_str("FATAL"));

    assert_int_equal(JZ_LOG_NONE, jz_log_level_from_str("none"));

    /* Unknown strings default to INFO */
    assert_int_equal(JZ_LOG_INFO, jz_log_level_from_str("garbage"));
    assert_int_equal(JZ_LOG_INFO, jz_log_level_from_str(""));
    assert_int_equal(JZ_LOG_INFO, jz_log_level_from_str(NULL));
}

/* ── Test: Level To String ────────────────────────────────────── */

static void test_level_to_str(void **state)
{
    (void)state;

    assert_string_equal("DEBUG", jz_log_level_str(JZ_LOG_DEBUG));
    assert_string_equal("INFO",  jz_log_level_str(JZ_LOG_INFO));
    assert_string_equal("WARN",  jz_log_level_str(JZ_LOG_WARN));
    assert_string_equal("ERROR", jz_log_level_str(JZ_LOG_ERROR));
    assert_string_equal("FATAL", jz_log_level_str(JZ_LOG_FATAL));
    assert_string_equal("NONE",  jz_log_level_str(JZ_LOG_NONE));

    /* Out of range */
    assert_string_equal("UNKNOWN", jz_log_level_str((jz_log_level_t)99));
}

/* ── Test: Init and Level Control ─────────────────────────────── */

static void test_init_level_control(void **state)
{
    (void)state;

    jz_log_init("test_log", JZ_LOG_WARN, false);

    assert_int_equal(JZ_LOG_WARN, jz_log_get_level());

    jz_log_set_level(JZ_LOG_DEBUG);
    assert_int_equal(JZ_LOG_DEBUG, jz_log_get_level());

    jz_log_set_level(JZ_LOG_NONE);
    assert_int_equal(JZ_LOG_NONE, jz_log_get_level());

    jz_log_close();
}

/* ── Test: Log Write Does Not Crash ───────────────────────────── */

static void test_log_write_no_crash(void **state)
{
    (void)state;

    /* Write without init — should use stderr only */
    jz_log_set_stderr(false);  /* suppress output in tests */

    jz_log_init("test_log", JZ_LOG_DEBUG, false);

    /* These should not crash */
    jz_log_debug("debug message %d", 1);
    jz_log_info("info message %s", "test");
    jz_log_warn("warning");
    jz_log_error("error: %s", "something");
    jz_log_fatal("fatal error");

    /* Level filtering: set to ERROR, debug/info/warn should be suppressed */
    jz_log_set_level(JZ_LOG_ERROR);
    jz_log_debug("should be suppressed");
    jz_log_info("should be suppressed");
    jz_log_warn("should be suppressed");
    jz_log_error("should appear");

    /* NONE suppresses everything */
    jz_log_set_level(JZ_LOG_NONE);
    jz_log_fatal("should be suppressed");

    jz_log_close();
}

/* ── Test: Double Init (Re-initialization) ────────────────────── */

static void test_double_init(void **state)
{
    (void)state;

    jz_log_init("first", JZ_LOG_DEBUG, false);
    jz_log_info("from first");

    /* Re-init should close previous syslog and reopen */
    jz_log_init("second", JZ_LOG_WARN, false);
    assert_int_equal(JZ_LOG_WARN, jz_log_get_level());

    jz_log_close();
}

/* ── Test: Close Without Init ─────────────────────────────────── */

static void test_close_without_init(void **state)
{
    (void)state;

    /* Should not crash */
    jz_log_close();
    jz_log_close();
}

/* ── Test: Stderr Toggle ──────────────────────────────────────── */

static void test_stderr_toggle(void **state)
{
    (void)state;

    jz_log_init("test_log", JZ_LOG_DEBUG, true);

    /* Toggle stderr output */
    jz_log_set_stderr(false);
    jz_log_info("stderr disabled — should only go to syslog");

    jz_log_set_stderr(true);
    jz_log_set_stderr(false);  /* leave disabled for test */

    jz_log_close();
}

/* ── Test: Level Round-trip ───────────────────────────────────── */

static void test_level_roundtrip(void **state)
{
    (void)state;

    /* Verify str → level → str round-trip */
    const char *levels[] = {"debug", "info", "warn", "error", "fatal", "none"};
    const char *expected[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"};

    for (int i = 0; i < 6; i++) {
        jz_log_level_t level = jz_log_level_from_str(levels[i]);
        const char *str = jz_log_level_str(level);
        assert_string_equal(expected[i], str);
    }
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_level_from_str, setup, teardown),
        cmocka_unit_test_setup_teardown(test_level_to_str, setup, teardown),
        cmocka_unit_test_setup_teardown(test_init_level_control, setup, teardown),
        cmocka_unit_test_setup_teardown(test_log_write_no_crash, setup, teardown),
        cmocka_unit_test_setup_teardown(test_double_init, setup, teardown),
        cmocka_unit_test_setup_teardown(test_close_without_init, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stderr_toggle, setup, teardown),
        cmocka_unit_test_setup_teardown(test_level_roundtrip, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
