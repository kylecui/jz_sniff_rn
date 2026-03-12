/* test_helpers.h -- Shared test utilities for jz_sniff_rn */

#ifndef JZ_TEST_HELPERS_H
#define JZ_TEST_HELPERS_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Temporary file helper for test databases */
static inline char *test_tmpfile(const char *suffix)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/jz_test_%d_%s", getpid(), suffix);
    return path;
}

/* Cleanup helper */
static inline void test_cleanup_file(const char *path)
{
    if (path)
        unlink(path);
}

#endif /* JZ_TEST_HELPERS_H */
