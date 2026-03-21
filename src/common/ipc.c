/* SPDX-License-Identifier: MIT */
/*
 * ipc.c - Unix domain socket IPC for jz_sniff_rn daemons.
 *
 * Protocol: 4-byte network-order length prefix + payload.
 * Server: epoll-based non-blocking accept + read.
 * Client: blocking connect with timeout and reconnect logic.
 */

#include "ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>

/* ── Internal helpers ─────────────────────────────────────────── */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* Full write: loop until all bytes sent or error. */
static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/* Send a length-prefixed message on fd. */
static int send_msg(int fd, const void *data, uint32_t len)
{
    if (len > JZ_IPC_MAX_MSG_LEN)
        return -1;

    uint32_t net_len = htonl(len);
    if (write_all(fd, &net_len, JZ_IPC_HDR_LEN) < 0)
        return -1;
    if (len > 0 && write_all(fd, data, len) < 0)
        return -1;

    return 0;
}

/* Find client slot by fd. Returns index or -1. */
static int find_client(jz_ipc_server_t *srv, int fd)
{
    for (int i = 0; i < JZ_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].active && srv->clients[i].fd == fd)
            return i;
    }
    return -1;
}

/* Find free client slot. Returns index or -1. */
static int alloc_client_slot(jz_ipc_server_t *srv)
{
    for (int i = 0; i < JZ_IPC_MAX_CLIENTS; i++) {
        if (!srv->clients[i].active)
            return i;
    }
    return -1;
}

/* ── Server ───────────────────────────────────────────────────── */

int jz_ipc_server_init(jz_ipc_server_t *srv,
                       const char *sock_path,
                       mode_t mode,
                       jz_ipc_handler_fn handler,
                       void *user_data)
{
    if (!srv || !sock_path || !handler)
        return -1;

    memset(srv, 0, sizeof(*srv));
    srv->listen_fd = -1;
    srv->epoll_fd = -1;

    snprintf(srv->sock_path, sizeof(srv->sock_path), "%s", sock_path);
    srv->handler = handler;
    srv->user_data = user_data;

    /* Initialize client slots */
    for (int i = 0; i < JZ_IPC_MAX_CLIENTS; i++) {
        srv->clients[i].fd = -1;
        srv->clients[i].active = false;
    }

    /* Remove stale socket file */
    unlink(sock_path);

    /* Create socket */
    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv->listen_fd < 0)
        goto fail;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail;

    /* Set socket file permissions */
    if (chmod(sock_path, mode) < 0)
        goto fail;

    if (listen(srv->listen_fd, JZ_IPC_SOCK_BACKLOG) < 0)
        goto fail;

    if (set_nonblocking(srv->listen_fd) < 0)
        goto fail;

    /* Create epoll instance */
    srv->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->epoll_fd < 0)
        goto fail;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = srv->listen_fd;
    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev) < 0)
        goto fail;

    srv->running = true;
    return 0;

fail:
    jz_ipc_server_destroy(srv);
    return -1;
}

/* Accept new client connections. */
static void server_accept(jz_ipc_server_t *srv)
{
    for (;;) {
        int client_fd = accept4(srv->listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            break;
        }

        int slot = alloc_client_slot(srv);
        if (slot < 0) {
            /* No room */
            close(client_fd);
            continue;
        }

        if (set_nonblocking(client_fd) < 0) {
            close(client_fd);
            continue;
        }

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            close(client_fd);
            continue;
        }

        jz_ipc_client_conn_t *conn = &srv->clients[slot];
        conn->fd = client_fd;
        conn->active = true;
        conn->recv_offset = 0;
        srv->client_count++;
    }
}

/* Process data from a client connection. Handles partial reads and
 * message framing. Returns 0 to keep connection, -1 to disconnect. */
static int server_read_client(jz_ipc_server_t *srv, int slot)
{
    jz_ipc_client_conn_t *conn = &srv->clients[slot];

    for (;;) {
        size_t buf_space = sizeof(conn->recv_buf) - conn->recv_offset;
        if (buf_space == 0) {
            /* Buffer overflow — protocol violation */
            return -1;
        }

        ssize_t n = read(conn->fd, conn->recv_buf + conn->recv_offset,
                         buf_space);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            /* Client disconnected */
            return -1;
        }

        conn->recv_offset += (size_t)n;

        /* Try to extract complete messages */
        while (conn->recv_offset >= JZ_IPC_HDR_LEN) {
            uint32_t msg_len;
            memcpy(&msg_len, conn->recv_buf, JZ_IPC_HDR_LEN);
            msg_len = ntohl(msg_len);

            if (msg_len > JZ_IPC_MAX_MSG_LEN) {
                /* Message too large — protocol violation */
                return -1;
            }

            size_t total = JZ_IPC_HDR_LEN + msg_len;
            if (conn->recv_offset < total)
                break;  /* Need more data */

            /* Complete message available */
            jz_ipc_msg_t msg;
            msg.len = msg_len;
            memcpy(msg.payload, conn->recv_buf + JZ_IPC_HDR_LEN, msg_len);
            if (msg_len < JZ_IPC_MAX_MSG_LEN)
                msg.payload[msg_len] = '\0';

            /* Shift remaining data */
            size_t remaining = conn->recv_offset - total;
            if (remaining > 0)
                memmove(conn->recv_buf, conn->recv_buf + total, remaining);
            conn->recv_offset = remaining;

            /* Dispatch to handler */
            if (srv->handler(conn->fd, &msg, srv->user_data) < 0)
                return -1;
        }
    }

    return 0;
}

int jz_ipc_server_poll(jz_ipc_server_t *srv, int timeout_ms)
{
    if (!srv || srv->epoll_fd < 0)
        return -1;

    struct epoll_event events[JZ_IPC_MAX_CLIENTS + 1];
    int nfds = epoll_wait(srv->epoll_fd, events,
                          JZ_IPC_MAX_CLIENTS + 1, timeout_ms);
    if (nfds < 0) {
        if (errno == EINTR)
            return 0;
        return -1;
    }

    for (int i = 0; i < nfds; i++) {
        int fd = events[i].data.fd;

        if (fd == srv->listen_fd) {
            server_accept(srv);
            continue;
        }

        int slot = find_client(srv, fd);
        if (slot < 0)
            continue;

        if (events[i].events & (EPOLLERR | EPOLLHUP)) {
            jz_ipc_server_disconnect(srv, fd);
            continue;
        }

        if (events[i].events & EPOLLIN) {
            if (server_read_client(srv, slot) < 0)
                jz_ipc_server_disconnect(srv, fd);
        }
    }

    return nfds;
}

int jz_ipc_server_send(jz_ipc_server_t *srv, int client_fd,
                       const void *data, uint32_t len)
{
    if (!srv)
        return -1;

    int slot = find_client(srv, client_fd);
    if (slot < 0)
        return -1;

    return send_msg(client_fd, data, len);
}

void jz_ipc_server_disconnect(jz_ipc_server_t *srv, int client_fd)
{
    if (!srv)
        return;

    int slot = find_client(srv, client_fd);
    if (slot < 0)
        return;

    epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);

    srv->clients[slot].fd = -1;
    srv->clients[slot].active = false;
    srv->clients[slot].recv_offset = 0;
    srv->client_count--;
}

void jz_ipc_server_destroy(jz_ipc_server_t *srv)
{
    if (!srv)
        return;

    /* Close all client connections */
    for (int i = 0; i < JZ_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].active) {
            close(srv->clients[i].fd);
            srv->clients[i].fd = -1;
            srv->clients[i].active = false;
        }
    }
    srv->client_count = 0;

    if (srv->epoll_fd >= 0) {
        close(srv->epoll_fd);
        srv->epoll_fd = -1;
    }

    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }

    /* Remove socket file */
    if (srv->sock_path[0])
        unlink(srv->sock_path);

    srv->running = false;
}

/* ── Client ───────────────────────────────────────────────────── */

int jz_ipc_client_connect(jz_ipc_client_t *cli, const char *sock_path,
                          int timeout_ms)
{
    if (!cli || !sock_path)
        return -1;

    memset(cli, 0, sizeof(*cli));
    cli->fd = -1;
    cli->timeout_ms = timeout_ms > 0 ? timeout_ms : JZ_IPC_DEFAULT_TIMEOUT_MS;
    snprintf(cli->sock_path, sizeof(cli->sock_path), "%s", sock_path);

    cli->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (cli->fd < 0)
        return -1;

    /* Non-blocking connect for timeout support */
    if (set_nonblocking(cli->fd) < 0)
        goto fail;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    int ret = connect(cli->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS)
        goto fail;

    if (ret < 0) {
        /* Wait for connection with timeout */
        struct pollfd pfd;
        pfd.fd = cli->fd;
        pfd.events = POLLOUT;

        ret = poll(&pfd, 1, cli->timeout_ms);
        if (ret <= 0)
            goto fail;

        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (getsockopt(cli->fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) < 0)
            goto fail;
        if (so_error != 0) {
            errno = so_error;
            goto fail;
        }
    }

    /* Switch back to blocking for normal I/O */
    if (set_blocking(cli->fd) < 0)
        goto fail;

    cli->connected = true;
    return 0;

fail:
    if (cli->fd >= 0) {
        close(cli->fd);
        cli->fd = -1;
    }
    return -1;
}

int jz_ipc_client_send(jz_ipc_client_t *cli,
                       const void *data, uint32_t len)
{
    if (!cli || !cli->connected)
        return -1;
    return send_msg(cli->fd, data, len);
}

int jz_ipc_client_recv(jz_ipc_client_t *cli, jz_ipc_msg_t *msg)
{
    if (!cli || !cli->connected || !msg)
        return -1;

    /* Wait for data with timeout */
    struct pollfd pfd;
    pfd.fd = cli->fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, cli->timeout_ms);
    if (ret <= 0)
        return -1;

    /* Read length header */
    uint32_t net_len;
    size_t hdr_read = 0;
    while (hdr_read < JZ_IPC_HDR_LEN) {
        ssize_t n = read(cli->fd, (char *)&net_len + hdr_read,
                         JZ_IPC_HDR_LEN - hdr_read);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cli->connected = false;
            return -1;
        }
        if (n == 0) {
            cli->connected = false;
            return -1;
        }
        hdr_read += (size_t)n;
    }

    msg->len = ntohl(net_len);
    if (msg->len > JZ_IPC_MAX_MSG_LEN) {
        cli->connected = false;
        return -1;
    }

    /* Read payload */
    size_t payload_read = 0;
    while (payload_read < msg->len) {
        ssize_t n = read(cli->fd, msg->payload + payload_read,
                         msg->len - payload_read);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cli->connected = false;
            return -1;
        }
        if (n == 0) {
            cli->connected = false;
            return -1;
        }
        payload_read += (size_t)n;
    }

    /* NUL-terminate for convenience */
    if (msg->len < JZ_IPC_MAX_MSG_LEN)
        msg->payload[msg->len] = '\0';

    return 0;
}

int jz_ipc_client_request(jz_ipc_client_t *cli,
                          const void *req_data, uint32_t req_len,
                          jz_ipc_msg_t *reply)
{
    if (jz_ipc_client_send(cli, req_data, req_len) < 0)
        return -1;
    return jz_ipc_client_recv(cli, reply);
}

int jz_ipc_client_reconnect(jz_ipc_client_t *cli)
{
    if (!cli || !cli->sock_path[0])
        return -1;

    char saved_path[256];
    int saved_timeout = cli->timeout_ms;
    snprintf(saved_path, sizeof(saved_path), "%s", cli->sock_path);

    /* Close existing connection if any */
    jz_ipc_client_close(cli);

    int delay_ms = JZ_IPC_RECONNECT_DELAY_MS;
    for (int i = 0; i < JZ_IPC_MAX_RECONNECT_TRIES; i++) {
        if (jz_ipc_client_connect(cli, saved_path, saved_timeout) == 0)
            return 0;

        /* Sleep with exponential backoff (capped at 8s) */
        struct timespec ts;
        ts.tv_sec = delay_ms / 1000;
        ts.tv_nsec = (delay_ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);

        delay_ms *= 2;
        if (delay_ms > 8000)
            delay_ms = 8000;
    }

    return -1;
}

void jz_ipc_client_close(jz_ipc_client_t *cli)
{
    if (!cli)
        return;

    if (cli->fd >= 0) {
        close(cli->fd);
        cli->fd = -1;
    }
    cli->connected = false;
}
