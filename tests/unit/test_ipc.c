/* SPDX-License-Identifier: MIT */
/* test_ipc.c -- Unit tests for jz_sniff_rn IPC framework */

#include "test_helpers.h"
#include "ipc.h"

#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>

/* ── Test Socket Path ─────────────────────────────────────────── */

static char *test_sock_path(void)
{
    return test_tmpfile("ipc.sock");
}

/* ── Echo Handler (for server tests) ──────────────────────────── */

/* Echo handler: sends back whatever it receives, prefixed with "RE:" */
static int echo_handler(int client_fd, const jz_ipc_msg_t *msg, void *user_data)
{
    jz_ipc_server_t *srv = (jz_ipc_server_t *)user_data;
    char reply[JZ_IPC_MAX_MSG_LEN];
    int len = snprintf(reply, sizeof(reply), "RE:%.*s", (int)msg->len, msg->payload);
    return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)len);
}

/* ── Server Thread for Async Tests ────────────────────────────── */

struct server_thread_ctx {
    jz_ipc_server_t srv;
    char sock_path[256];
    volatile int ready;
    volatile int stop;
    int poll_count;
};

static void *server_thread_fn(void *arg)
{
    struct server_thread_ctx *ctx = arg;

    if (jz_ipc_server_init(&ctx->srv, ctx->sock_path, 0660,
                           echo_handler, &ctx->srv) < 0) {
        ctx->ready = -1;
        return NULL;
    }

    ctx->ready = 1;

    while (!ctx->stop) {
        int n = jz_ipc_server_poll(&ctx->srv, 50);
        if (n > 0)
            ctx->poll_count += n;
    }

    jz_ipc_server_destroy(&ctx->srv);
    return NULL;
}

/* ── Setup / Teardown ─────────────────────────────────────────── */

static int setup(void **state)
{
    (void)state;
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    /* Clean up any leftover socket files */
    test_cleanup_file(test_sock_path());
    return 0;
}

/* ── Test: Server Init / Destroy ──────────────────────────────── */

static void test_server_init_destroy(void **state)
{
    (void)state;
    jz_ipc_server_t srv;
    const char *path = test_sock_path();

    assert_int_equal(0, jz_ipc_server_init(&srv, path, 0660,
                                           echo_handler, &srv));
    assert_true(srv.listen_fd >= 0);
    assert_true(srv.epoll_fd >= 0);
    assert_true(srv.running);
    assert_int_equal(0, srv.client_count);

    /* Socket file should exist */
    struct stat st;
    assert_int_equal(0, stat(path, &st));
    assert_true(S_ISSOCK(st.st_mode));

    jz_ipc_server_destroy(&srv);

    /* Socket file should be removed */
    assert_int_equal(-1, stat(path, &st));
}

/* ── Test: Server Init with NULL args ─────────────────────────── */

static void test_server_init_null(void **state)
{
    (void)state;
    jz_ipc_server_t srv;

    assert_int_equal(-1, jz_ipc_server_init(NULL, "/tmp/x.sock", 0660,
                                            echo_handler, NULL));
    assert_int_equal(-1, jz_ipc_server_init(&srv, NULL, 0660,
                                            echo_handler, NULL));
    assert_int_equal(-1, jz_ipc_server_init(&srv, "/tmp/x.sock", 0660,
                                            NULL, NULL));
}

/* ── Test: Client Connect to Non-Existent Server ──────────────── */

static void test_client_connect_fail(void **state)
{
    (void)state;
    jz_ipc_client_t cli;
    assert_int_equal(-1, jz_ipc_client_connect(&cli,
                         "/tmp/jz_test_nonexistent.sock", 100));
}

/* ── Test: Client NULL args ───────────────────────────────────── */

static void test_client_null_args(void **state)
{
    (void)state;
    jz_ipc_client_t cli;

    assert_int_equal(-1, jz_ipc_client_connect(NULL, "/tmp/x.sock", 100));
    assert_int_equal(-1, jz_ipc_client_connect(&cli, NULL, 100));
}

/* ── Test: Full Client-Server Round Trip ──────────────────────── */

static void test_client_server_roundtrip(void **state)
{
    (void)state;
    struct server_thread_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    snprintf(ctx.sock_path, sizeof(ctx.sock_path), "%s", test_sock_path());

    pthread_t tid;
    assert_int_equal(0, pthread_create(&tid, NULL, server_thread_fn, &ctx));

    /* Wait for server to be ready */
    for (int i = 0; i < 100 && ctx.ready == 0; i++)
        usleep(10000);
    assert_int_equal(1, ctx.ready);

    /* Connect client */
    jz_ipc_client_t cli;
    assert_int_equal(0, jz_ipc_client_connect(&cli, ctx.sock_path, 2000));
    assert_true(cli.connected);

    /* Send request and get reply */
    const char *msg = "hello";
    jz_ipc_msg_t reply;
    assert_int_equal(0, jz_ipc_client_request(&cli, msg, (uint32_t)strlen(msg),
                                               &reply));

    /* Verify echo reply */
    assert_int_equal(8, reply.len);  /* "RE:hello" */
    assert_memory_equal("RE:hello", reply.payload, 8);

    /* Clean up */
    jz_ipc_client_close(&cli);
    assert_false(cli.connected);

    ctx.stop = 1;
    pthread_join(tid, NULL);
}

/* ── Test: Multiple Messages ──────────────────────────────────── */

static void test_multiple_messages(void **state)
{
    (void)state;
    struct server_thread_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    snprintf(ctx.sock_path, sizeof(ctx.sock_path), "%s", test_sock_path());

    pthread_t tid;
    assert_int_equal(0, pthread_create(&tid, NULL, server_thread_fn, &ctx));

    for (int i = 0; i < 100 && ctx.ready == 0; i++)
        usleep(10000);
    assert_int_equal(1, ctx.ready);

    jz_ipc_client_t cli;
    assert_int_equal(0, jz_ipc_client_connect(&cli, ctx.sock_path, 2000));

    /* Send multiple messages */
    for (int i = 0; i < 10; i++) {
        char msg[64];
        int len = snprintf(msg, sizeof(msg), "msg_%d", i);
        jz_ipc_msg_t reply;
        assert_int_equal(0, jz_ipc_client_request(&cli, msg, (uint32_t)len,
                                                   &reply));
        /* Verify */
        char expected[64];
        int elen = snprintf(expected, sizeof(expected), "RE:msg_%d", i);
        assert_int_equal(elen, (int)reply.len);
        assert_memory_equal(expected, reply.payload, (size_t)elen);
    }

    jz_ipc_client_close(&cli);
    ctx.stop = 1;
    pthread_join(tid, NULL);
}

/* ── Test: Server Poll with No Clients ────────────────────────── */

static void test_server_poll_empty(void **state)
{
    (void)state;
    jz_ipc_server_t srv;
    const char *path = test_sock_path();

    assert_int_equal(0, jz_ipc_server_init(&srv, path, 0660,
                                           echo_handler, &srv));

    /* Poll with short timeout — should return 0 (no events) */
    int n = jz_ipc_server_poll(&srv, 10);
    assert_true(n >= 0);

    jz_ipc_server_destroy(&srv);
}

/* ── Test: Client Close and Reconnect ─────────────────────────── */

static void test_client_close_reuse(void **state)
{
    (void)state;
    jz_ipc_client_t cli;

    /* Close on unconnected client — should not crash */
    memset(&cli, 0, sizeof(cli));
    cli.fd = -1;
    jz_ipc_client_close(&cli);
    jz_ipc_client_close(NULL);  /* NULL should be safe */
}

/* ── Test: Server Destroy Idempotent ──────────────────────────── */

static void test_server_destroy_idempotent(void **state)
{
    (void)state;
    jz_ipc_server_t srv;
    const char *path = test_sock_path();

    assert_int_equal(0, jz_ipc_server_init(&srv, path, 0660,
                                           echo_handler, &srv));
    jz_ipc_server_destroy(&srv);
    jz_ipc_server_destroy(&srv);  /* Double destroy should be safe */
    jz_ipc_server_destroy(NULL);  /* NULL should be safe */
}

/* ── Test: Send on Disconnected Client ────────────────────────── */

static void test_client_send_disconnected(void **state)
{
    (void)state;
    jz_ipc_client_t cli;
    memset(&cli, 0, sizeof(cli));
    cli.fd = -1;
    cli.connected = false;

    assert_int_equal(-1, jz_ipc_client_send(&cli, "test", 4));
}

/* ── Test: Empty Message ──────────────────────────────────────── */

static void test_empty_message(void **state)
{
    (void)state;
    struct server_thread_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    snprintf(ctx.sock_path, sizeof(ctx.sock_path), "%s", test_sock_path());

    pthread_t tid;
    assert_int_equal(0, pthread_create(&tid, NULL, server_thread_fn, &ctx));

    for (int i = 0; i < 100 && ctx.ready == 0; i++)
        usleep(10000);
    assert_int_equal(1, ctx.ready);

    jz_ipc_client_t cli;
    assert_int_equal(0, jz_ipc_client_connect(&cli, ctx.sock_path, 2000));

    /* Send empty message */
    jz_ipc_msg_t reply;
    assert_int_equal(0, jz_ipc_client_request(&cli, "", 0, &reply));

    /* Echo handler should reply "RE:" */
    assert_int_equal(3, reply.len);
    assert_memory_equal("RE:", reply.payload, 3);

    jz_ipc_client_close(&cli);
    ctx.stop = 1;
    pthread_join(tid, NULL);
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_server_init_destroy, setup, teardown),
        cmocka_unit_test_setup_teardown(test_server_init_null, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_connect_fail, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_null_args, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_server_roundtrip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multiple_messages, setup, teardown),
        cmocka_unit_test_setup_teardown(test_server_poll_empty, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_close_reuse, setup, teardown),
        cmocka_unit_test_setup_teardown(test_server_destroy_idempotent, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_send_disconnected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_empty_message, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
