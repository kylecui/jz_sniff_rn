/* SPDX-License-Identifier: MIT */
/*
 * ipc.h - Inter-process communication framework for jz_sniff_rn daemons.
 *
 * Provides Unix domain socket IPC with a simple text-based message protocol.
 * Messages are length-prefixed: 4-byte network-order length + payload.
 * Payload format is caller-defined (typically "cmd:data" key-value pairs).
 *
 * Server side: jz_ipc_server_t with epoll-based accept/read loop.
 * Client side: jz_ipc_client_t with connect/reconnect and sync request/reply.
 */

#ifndef JZ_IPC_H
#define JZ_IPC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* ── Limits ── */
#define JZ_IPC_MAX_MSG_LEN          (64 * 1024)  /* 64 KiB max message */
#define JZ_IPC_MAX_CLIENTS          32
#define JZ_IPC_SOCK_BACKLOG         8
#define JZ_IPC_DEFAULT_TIMEOUT_MS   5000
#define JZ_IPC_RECONNECT_DELAY_MS   1000
#define JZ_IPC_MAX_RECONNECT_TRIES  10
#define JZ_IPC_HDR_LEN              4            /* 4-byte length prefix */

/* ── Socket Paths ── */
#define JZ_IPC_SOCK_DIR             "/var/run/jz"
#define JZ_IPC_SOCK_SNIFFD          "/var/run/jz/sniffd.sock"
#define JZ_IPC_SOCK_CONFIGD         "/var/run/jz/configd.sock"
#define JZ_IPC_SOCK_COLLECTORD      "/var/run/jz/collectord.sock"
#define JZ_IPC_SOCK_UPLOADD         "/var/run/jz/uploadd.sock"

/* ── IPC Message ── */

typedef struct jz_ipc_msg {
    uint32_t len;                     /* payload length (excl. header) */
    char     payload[JZ_IPC_MAX_MSG_LEN];
} jz_ipc_msg_t;

/* ── Server ── */

/* Per-client connection state (internal) */
typedef struct jz_ipc_client_conn {
    int      fd;
    bool     active;
    size_t   recv_offset;              /* partial read accumulator */
    char     recv_buf[JZ_IPC_HDR_LEN + JZ_IPC_MAX_MSG_LEN];
} jz_ipc_client_conn_t;

/* Callback invoked when a complete message arrives from a client.
 * Return: 0 on success, -1 to disconnect the client. */
typedef int (*jz_ipc_handler_fn)(int client_fd,
                                  const jz_ipc_msg_t *msg,
                                  void *user_data);

typedef struct jz_ipc_server {
    int      listen_fd;
    int      epoll_fd;
    char     sock_path[256];
    bool     running;

    jz_ipc_client_conn_t clients[JZ_IPC_MAX_CLIENTS];
    int      client_count;

    jz_ipc_handler_fn handler;
    void    *user_data;
} jz_ipc_server_t;

/* Create server: bind + listen on sock_path, set up epoll.
 * mode: socket file permissions (e.g. 0660 for group access).
 * Returns 0 on success, -1 on error. */
int jz_ipc_server_init(jz_ipc_server_t *srv,
                       const char *sock_path,
                       mode_t mode,
                       jz_ipc_handler_fn handler,
                       void *user_data);

/* Process events for up to timeout_ms. Accepts new clients, reads messages,
 * invokes handler. Returns number of events processed, -1 on error. */
int jz_ipc_server_poll(jz_ipc_server_t *srv, int timeout_ms);

/* Send a response message to a connected client.
 * Returns 0 on success, -1 on error. */
int jz_ipc_server_send(jz_ipc_server_t *srv, int client_fd,
                       const void *data, uint32_t len);

/* Disconnect a specific client. */
void jz_ipc_server_disconnect(jz_ipc_server_t *srv, int client_fd);

/* Shut down server: close all clients, remove socket. */
void jz_ipc_server_destroy(jz_ipc_server_t *srv);

/* ── Client ── */

typedef struct jz_ipc_client {
    int      fd;
    char     sock_path[256];
    bool     connected;
    int      timeout_ms;
} jz_ipc_client_t;

/* Connect to a server socket. Returns 0 on success, -1 on error. */
int jz_ipc_client_connect(jz_ipc_client_t *cli, const char *sock_path,
                          int timeout_ms);

/* Send a message. Returns 0 on success, -1 on error. */
int jz_ipc_client_send(jz_ipc_client_t *cli,
                       const void *data, uint32_t len);

/* Receive a message (blocking up to timeout). Returns 0 on success, -1 on error. */
int jz_ipc_client_recv(jz_ipc_client_t *cli, jz_ipc_msg_t *msg);

/* Send request and wait for response (synchronous RPC).
 * Returns 0 on success, -1 on error. */
int jz_ipc_client_request(jz_ipc_client_t *cli,
                          const void *req_data, uint32_t req_len,
                          jz_ipc_msg_t *reply);

/* Attempt reconnection with exponential backoff.
 * Returns 0 on success, -1 if all retries exhausted. */
int jz_ipc_client_reconnect(jz_ipc_client_t *cli);

/* Close client connection. */
void jz_ipc_client_close(jz_ipc_client_t *cli);

#endif /* JZ_IPC_H */
