/* SPDX-License-Identifier: MIT */
/*
 * sniffd main.c - Main orchestrator daemon for jz_sniff_rn.
 *
 * Responsibilities:
 *   - Load and manage BPF modules in the rSwitch pipeline
 *   - Consume ring buffer events and dispatch via IPC
 *   - Serve IPC commands (status, reload, guard management)
 *   - Daemonize, write PID file, handle signals
 */


#include "api.h"
#include "arp_spoof.h"
#include "bpf_loader.h"
#include "capture_mgr.h"
#include "discovery.h"
#include "guard_auto.h"
#include "guard_mgr.h"
#include "policy_mgr.h"
#include "policy_auto.h"
#include "heartbeat.h"
#include "probe_gen.h"
#include "ringbuf.h"
#include "config.h"
#include "ipc.h"
#include "log.h"
#include "db.h"

#include <net/if.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "../../bpf/include/jz_maps.h"

/* ── Version ──────────────────────────────────────────────────── */

#define SNIFFD_VERSION  "0.8.0"

/* ── Defaults ─────────────────────────────────────────────────── */

#define DEFAULT_CONFIG_PATH   "/etc/jz/base.yaml"
#define DEFAULT_PID_FILE      "/var/run/jz/sniffd.pid"
#define DEFAULT_BPF_DIR       "/etc/jz/bpf"
#define DEFAULT_RUN_DIR       "/var/run/jz"

#define DEFAULT_API_PORT      8443
#define DEFAULT_API_CERT      "/etc/jz/tls/server.crt"
#define DEFAULT_API_KEY       "/etc/jz/tls/server.key"

#define EVENT_MAP_PIN         "/sys/fs/bpf/rs_event_bus"
#define SAMPLE_MAP_PIN        "/sys/fs/bpf/jz/jz_sample_ringbuf"

#define RINGBUF_POLL_MS       100

/* ── Global State ─────────────────────────────────────────────── */

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static volatile sig_atomic_t g_dump_stat = 0;

static struct {
    char config_path[256];
    char pid_file[256];
    char bpf_dir[256];
    bool daemonize;
    bool verbose;

    /* API server options */
    int  api_port;
    char api_cert[256];
    char api_key[256];
    char api_ca[256];
    char api_token[256];

    jz_config_t       config;
    jz_bpf_loader_t   loader;
    jz_ringbuf_t      ringbuf;
    jz_ipc_server_t   ipc;
    jz_db_t           db;
    jz_probe_gen_t    probe_gen;
    jz_guard_mgr_t    guard_mgr;
    jz_discovery_t    discovery;
    jz_guard_auto_t   guard_auto;
    jz_policy_mgr_t   policy_mgr;
    jz_policy_auto_t  policy_auto;
    jz_heartbeat_t    heartbeat;
    jz_ipc_client_t   uploadd_client;
    jz_ipc_client_t   collectord_client;
    jz_arp_spoof_t    arp_spoof;
    jz_capture_mgr_t  capture_mgr;
    jz_api_t          api;
    int               ifindex;

    /* ktime → wall-clock offset for pcap timestamps */
    time_t            ktime_wall_offset;
} g_ctx;

/* ── Signal Handlers ──────────────────────────────────────────── */

static void sig_handler(int sig)
{
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        g_running = 0;
        break;
    case SIGHUP:
        g_reload = 1;
        break;
    case SIGUSR1:
        g_dump_stat = 1;
        break;
    }
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    if (sigaction(SIGINT, &sa, NULL) < 0)  return -1;
    if (sigaction(SIGHUP, &sa, NULL) < 0)  return -1;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) return -1;

    /* Ignore SIGPIPE (broken IPC connections) */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) return -1;

    return 0;
}

/* ── PID File ─────────────────────────────────────────────────── */

static int write_pid_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    int ret = (write(fd, buf, (size_t)len) == len) ? 0 : -1;
    close(fd);
    return ret;
}

static void remove_pid_file(const char *path)
{
    unlink(path);
}

/* ── Daemonize ────────────────────────────────────────────────── */

static int do_daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);  /* Parent exits */

    /* New session */
    if (setsid() < 0)
        return -1;

    /* Second fork to prevent terminal re-acquisition */
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);

    /* Working directory */
    if (chdir("/") < 0)
        return -1;

    /* Close standard file descriptors and redirect to /dev/null */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }

    return 0;
}

/* ── Privilege Drop ───────────────────────────────────────────── */

static int drop_privileges(const char *user, const char *group)
{
    if (getuid() != 0)
        return 0;  /* Not root, nothing to drop */

    struct group *grp = getgrnam(group);
    if (!grp) {
        jz_log_warn("Group '%s' not found, skipping privilege drop", group);
        return 0;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        jz_log_warn("User '%s' not found, skipping privilege drop", user);
        return 0;
    }

    if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
        jz_log_error("prctl(PR_SET_KEEPCAPS) failed: %s", strerror(errno));
        return -1;
    }

    if (setgid(grp->gr_gid) < 0) {
        jz_log_error("setgid(%d) failed: %s", grp->gr_gid, strerror(errno));
        return -1;
    }

    if (setuid(pw->pw_uid) < 0) {
        jz_log_error("setuid(%d) failed: %s", pw->pw_uid, strerror(errno));
        return -1;
    }

    /*
     * Restore BPF-related capabilities after privilege drop.
     * CAP_NET_ADMIN(12) in data[0], CAP_PERFMON(38) + CAP_BPF(39) in data[1].
     * Uses raw syscall to avoid libcap-dev build dependency.
     */
    struct __user_cap_header_struct cap_hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct cap_data[2];
    memset(cap_data, 0, sizeof(cap_data));
    cap_data[0].effective = cap_data[0].permitted = (1U << 12) | (1U << 13); /* CAP_NET_ADMIN + CAP_NET_RAW */
    cap_data[1].effective = cap_data[1].permitted = (1U << 6) | (1U << 7);  /* CAP_PERFMON(38) + CAP_BPF(39) */

    if (syscall(SYS_capset, &cap_hdr, cap_data) < 0) {
        jz_log_error("capset failed: %s (BPF module reload will not work)",
                     strerror(errno));
        /* Non-fatal: daemon still runs, just can't reload BPF */
    } else {
        jz_log_info("Retained CAP_NET_ADMIN + CAP_NET_RAW + CAP_BPF + CAP_PERFMON");
    }

    jz_log_info("Dropped privileges to %s:%s", user, group);
    return 0;
}

/* ── Ensure Runtime Directory ─────────────────────────────────── */

static int ensure_run_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(path, 0750) < 0 && errno != EEXIST) {
        jz_log_error("Cannot create run directory %s: %s",
                      path, strerror(errno));
        return -1;
    }
    return 0;
}

static int discover_business_ifaces(const jz_config_t *cfg, int *ifindexes,
                                    char names[][32], int max_count)
{
    int count = 0;

    for (int i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface = &cfg->system.interfaces[i];
        if (strcmp(iface->role, "manage") == 0)
            continue;

        unsigned int idx = if_nametoindex(iface->name);
        if (idx == 0) {
            jz_log_warn("Configured interface %s not found", iface->name);
            continue;
        }

        if (count >= max_count)
            break;

        ifindexes[count] = (int)idx;
        (void) snprintf(names[count], 32, "%s", iface->name);
        count++;
    }

    if (cfg->system.interface_count == 0) {
        static const char *candidates[] = { "eth0", "ens33", "enp0s3", NULL };
        for (int i = 0; candidates[i] != NULL && count < max_count; i++) {
            unsigned int idx = if_nametoindex(candidates[i]);
            if (idx == 0)
                continue;

            ifindexes[count] = (int)idx;
            (void) snprintf(names[count], 32, "%s", candidates[i]);
            count++;
        }
    }

    return count;
}

static void resolve_redirect_config(const jz_config_t *cfg)
{
    __u32 honeypot_ifindex = 0;
    __u32 mirror_ifindex = 0;

    for (int i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        const jz_config_interface_t *iface = &cfg->system.interfaces[i];

        if (strcmp(iface->role, "honeypot") == 0) {
            unsigned int idx = if_nametoindex(iface->name);
            if (idx > 0)
                honeypot_ifindex = idx;
            else
                jz_log_warn("Configured honeypot interface %s not found", iface->name);
        }

        if (strcmp(iface->role, "mirror") == 0) {
            unsigned int idx = if_nametoindex(iface->name);
            if (idx > 0)
                mirror_ifindex = idx;
            else
                jz_log_warn("Configured mirror interface %s not found", iface->name);
        }
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/jz/jz_redirect_config");
    if (map_fd < 0) {
        jz_log_warn("Cannot open jz_redirect_config map: %s", strerror(errno));
        return;
    }

    __u32 key = 0;
    struct jz_redirect_config val = {
        .honeypot_ifindex = honeypot_ifindex,
        .mirror_ifindex = mirror_ifindex,
        .enabled = 1,
        ._pad = {0, 0, 0}
    };

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
        jz_log_warn("Failed to update jz_redirect_config map: %s", strerror(errno));
        close(map_fd);
        return;
    }

    close(map_fd);
    jz_log_info("Resolved redirect config: honeypot_ifindex=%u mirror_ifindex=%u enabled=1",
                honeypot_ifindex, mirror_ifindex);
}

/* Discover the rSwitch-managed interface index.
 * Reads the XDP link info from the first BPF module's ifindex,
 * or falls back to if_nametoindex("eth0"). */
static int discover_ifindex(const jz_config_t *cfg)
{
    unsigned int idx;

    for (int i = 0; i < cfg->system.interface_count && i < JZ_CONFIG_MAX_INTERFACES; i++) {
        if (strcmp(cfg->system.interfaces[i].role, "monitor") == 0) {
            idx = if_nametoindex(cfg->system.interfaces[i].name);
            if (idx > 0) {
                jz_log_info("Using configured monitor interface %s (ifindex %u)",
                            cfg->system.interfaces[i].name, idx);
                return (int)idx;
            }
            jz_log_warn("Configured interface %s not found",
                        cfg->system.interfaces[i].name);
        }
    }

    static const char *candidates[] = { "eth0", "ens33", "enp0s3", NULL };
    for (int i = 0; candidates[i]; i++) {
        idx = if_nametoindex(candidates[i]);
        if (idx > 0) {
            jz_log_info("Auto-discovered interface %s (ifindex %u)",
                        candidates[i], idx);
            return (int)idx;
        }
    }

    jz_log_warn("No suitable network interface found for probe generator");
    return -1;
}

/* ── IPC Command Handler ─────────────────────────────────────── */

static int ipc_handler(int client_fd, const jz_ipc_msg_t *msg, void *user_data)
{
    jz_ipc_server_t *srv = (jz_ipc_server_t *)user_data;
    const char *cmd = msg->payload;

    /* Simple command dispatch */
    if (strncmp(cmd, "status", 6) == 0) {
        char reply[1024];
        int len = snprintf(reply, sizeof(reply),
                           "sniffd v%s running, %d modules loaded",
                           SNIFFD_VERSION, g_ctx.loader.loaded_count);
        return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)len);
    }

    if (strncmp(cmd, "reload", 6) == 0) {
        g_reload = 1;
        const char *reply = "reload scheduled";
        return jz_ipc_server_send(srv, client_fd, reply,
                                  (uint32_t)strlen(reply));
    }

    if (strncmp(cmd, "module_status", 13) == 0) {
        char reply[4096];
        int off = 0;
        for (int i = 0; i < JZ_MOD_COUNT; i++) {
            const jz_bpf_module_t *mod =
                jz_bpf_loader_get_module(&g_ctx.loader, (jz_mod_id_t)i);
            if (mod) {
                off += snprintf(reply + off, sizeof(reply) - (size_t)off,
                                "%s: loaded=%d enabled=%d stage=%d\n",
                                mod->name, mod->loaded, mod->enabled,
                                mod->stage);
            }
        }
        return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)off);
    }

    if (strncmp(cmd, "version", 7) == 0) {
        const char *reply = SNIFFD_VERSION;
        return jz_ipc_server_send(srv, client_fd, reply,
                                  (uint32_t)strlen(reply));
    }

    /* Guard management commands */
    if (strncmp(cmd, "guard_add|", 10) == 0) {
        /* Format: guard_add|<ip>|<mac>|<type>|<vlan> */
        char ip_str[64], mac_str[32];
        int gtype = 0, vlan = 0;
        if (sscanf(cmd + 10, "%63[^|]|%31[^|]|%d|%d",
                   ip_str, mac_str, &gtype, &vlan) < 2) {
            const char *err = "error: usage guard_add|<ip>|<mac>[|<type>][|<vlan>]";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        uint32_t ip;
        if (inet_pton(AF_INET, ip_str, &ip) != 1) {
            const char *err = "error: invalid IP address";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        uint8_t mac[6] = {0};
        if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2],
                   &mac[3], &mac[4], &mac[5]) != 6) {
            const char *err = "error: invalid MAC address";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        if (gtype == 0)
            gtype = JZ_GUARD_DYNAMIC;
        char reply[512];
        int rlen = jz_guard_mgr_add(&g_ctx.guard_mgr, ip, mac,
                                     (uint8_t)gtype, (uint16_t)vlan,
                                     reply, sizeof(reply));
        if (rlen < 0) {
            const char *err = "error: guard_add failed";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)rlen);
    }

    if (strncmp(cmd, "guard_remove|", 13) == 0) {
        /* Format: guard_remove|<ip> */
        uint32_t ip;
        if (inet_pton(AF_INET, cmd + 13, &ip) != 1) {
            const char *err = "error: invalid IP address";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        char reply[512];
        int rlen = jz_guard_mgr_remove(&g_ctx.guard_mgr, ip,
                                        reply, sizeof(reply));
        if (rlen < 0) {
            const char *err = "error: guard_remove failed";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)rlen);
    }

    if (strncmp(cmd, "guard_list", 10) == 0) {
        char reply[JZ_IPC_MAX_MSG_LEN];
        int rlen = jz_guard_mgr_list(&g_ctx.guard_mgr,
                                      reply, sizeof(reply));
        if (rlen < 0) {
            const char *err = "error: guard_list failed";
            return jz_ipc_server_send(srv, client_fd, err,
                                      (uint32_t)strlen(err));
        }
        return jz_ipc_server_send(srv, client_fd, reply, (uint32_t)rlen);
    }

    /* Unknown command */
    const char *reply = "error: unknown command";
    return jz_ipc_server_send(srv, client_fd, reply,
                              (uint32_t)strlen(reply));
}

/* ── Ring Buffer Event Callback ───────────────────────────────── */

static int event_callback(const void *data, uint32_t data_len, void *user_data)
{
    (void)user_data;

    if (data_len < 8)
        return 0;

    uint32_t event_type;
    memcpy(&event_type, data, sizeof(event_type));

    jz_log_debug("Event received: type=%u len=%u", event_type, data_len);

    if (g_ctx.discovery.initialized && event_type == 6 && data_len >= 56) {
        const uint8_t *ev = (const uint8_t *)data;
        uint8_t bg_proto = ev[48];
        uint16_t vlan_id;
        uint32_t plen;
        memcpy(&vlan_id, ev + 20, 2);
        memcpy(&plen, ev + 52, 4);
        if (plen > 0 && data_len >= 56 + plen)
            jz_discovery_feed_event(&g_ctx.discovery, bg_proto,
                                    ev + 56, plen, vlan_id);
    }

    if (g_ctx.policy_auto.initialized &&
        (event_type == 1 || event_type == 2) && data_len >= 60) {
        uint32_t attacker_ip;
        uint32_t guarded_ip;
        uint8_t protocol;
        memcpy(&attacker_ip, (const uint8_t *)data + 36, 4);
        memcpy(&guarded_ip, (const uint8_t *)data + 56, 4);
        protocol = ((const uint8_t *)data)[49];
        jz_policy_auto_feed_attack(&g_ctx.policy_auto, attacker_ip,
                                   guarded_ip, protocol);
    }

    /* Forward raw event to collectord for persistence.
     * 48 = minimum event header: type(4)+len(4)+ts(8)+ifindex(4)+
     *       vlan_id(2)+pad(2)+src_mac(6)+dst_mac(6)+src_ip(4)+dst_ip(4)
     *       +pad(4) for __u64 alignment */
    if (g_ctx.collectord_client.connected && data_len >= 48) {
        const size_t prefix_len = 6;  /* strlen("event:") */
        size_t msg_len = prefix_len + data_len;
        if (msg_len <= JZ_IPC_MAX_MSG_LEN) {
            uint8_t msg[JZ_IPC_MAX_MSG_LEN];
            memcpy(msg, "event:", prefix_len);
            memcpy(msg + prefix_len, data, data_len);
            if (jz_ipc_client_send(&g_ctx.collectord_client,
                                    msg, (uint32_t)msg_len) < 0) {
                jz_log_warn("Failed to forward event to collectord");
                jz_ipc_client_close(&g_ctx.collectord_client);
            }
        }
    }

    return 0;
}

static int sample_callback(const void *data, uint32_t data_len, void *user_data)
{
    (void)user_data;

    if (!g_ctx.capture_mgr.active)
        return 0;

    /*
     * jz_event_sample layout: jz_event_hdr(48) + threat_level(1) +
     * _pad(3) + payload_len(4) + payload[].
     * Minimum: 48 + 1 + 3 + 4 = 56 bytes header before payload.
     */
    if (data_len < 56)
        return 0;

    const uint8_t *raw = (const uint8_t *)data;
    uint64_t ktime_ns;
    memcpy(&ktime_ns, raw + 8, sizeof(ktime_ns));

    uint32_t payload_len;
    memcpy(&payload_len, raw + 52, sizeof(payload_len));

    if (payload_len == 0 || 56 + payload_len > data_len)
        return 0;

    const void *payload = raw + 56;

    uint64_t wall_ns = (uint64_t)g_ctx.ktime_wall_offset * 1000000000ULL + ktime_ns;
    uint32_t ts_sec  = (uint32_t)(wall_ns / 1000000000ULL);
    uint32_t ts_usec = (uint32_t)((wall_ns % 1000000000ULL) / 1000);

    jz_capture_mgr_write(&g_ctx.capture_mgr, ts_sec, ts_usec,
                          payload, payload_len, payload_len);

    return 0;
}

/* ── Configuration Reload ─────────────────────────────────────── */

static int do_reload(void)
{
    jz_log_info("Reloading configuration from %s", g_ctx.config_path);

    jz_config_t new_config;
    jz_config_defaults(&new_config);
    jz_config_errors_t errors = { .count = 0 };

    if (jz_config_load(&new_config, g_ctx.config_path, &errors) < 0) {
        jz_log_error("Failed to reload config (%d errors)", errors.count);
        for (int i = 0; i < errors.count; i++) {
            jz_log_error("  %s: %s", errors.errors[i].field,
                          errors.errors[i].message);
        }
        jz_config_free(&new_config);
        return -1;
    }

    if (jz_config_validate(&new_config, &errors) < 0) {
        jz_log_error("Config validation failed (%d errors)", errors.count);
        jz_config_free(&new_config);
        return -1;
    }

    /* Apply new log level */
    jz_log_level_t new_level =
        jz_log_level_from_str(new_config.system.log_level);
    jz_log_set_level(new_level);
    jz_log_info("Log level set to %s", jz_log_level_str(new_level));

    /* Swap config */
    jz_config_free(&g_ctx.config);
    memcpy(&g_ctx.config, &new_config, sizeof(jz_config_t));

    /* TODO: Re-apply BPF map configuration via config_map */

    if (g_ctx.probe_gen.initialized)
        jz_probe_gen_update_config(&g_ctx.probe_gen, &g_ctx.config);

    if (g_ctx.guard_mgr.initialized) {
        jz_guard_mgr_update_config(&g_ctx.guard_mgr, &g_ctx.config);
        jz_guard_mgr_load_config(&g_ctx.guard_mgr, &g_ctx.config);
    }

    if (g_ctx.discovery.initialized)
        jz_discovery_update_config(&g_ctx.discovery, &g_ctx.config);

    if (g_ctx.guard_auto.initialized)
        jz_guard_auto_update_config(&g_ctx.guard_auto, &g_ctx.config);

    if (g_ctx.policy_mgr.initialized)
        jz_policy_mgr_update_config(&g_ctx.policy_mgr, &g_ctx.config);

    if (g_ctx.policy_auto.initialized)
        jz_policy_auto_update_config(&g_ctx.policy_auto, &g_ctx.config);

    if (g_ctx.heartbeat.initialized)
        jz_heartbeat_update_config(&g_ctx.heartbeat, &g_ctx.config);

    if (g_ctx.arp_spoof.initialized)
        jz_arp_spoof_update_config(&g_ctx.arp_spoof, &g_ctx.config);

    jz_log_info("Configuration reloaded successfully");
    return 0;
}

/* ── Dump Statistics ──────────────────────────────────────────── */

static void dump_stats(void)
{
    uint64_t ev_recv, ev_drop, sp_recv, sp_drop;
    jz_ringbuf_stats(&g_ctx.ringbuf, &ev_recv, &ev_drop,
                     &sp_recv, &sp_drop);

    jz_log_info("=== sniffd statistics ===");
    jz_log_info("  Modules loaded: %d/%d", g_ctx.loader.loaded_count,
                 JZ_MOD_COUNT);
    jz_log_info("  Events received: %lu, dropped: %lu", ev_recv, ev_drop);
    jz_log_info("  Samples received: %lu, dropped: %lu", sp_recv, sp_drop);
    jz_log_info("  IPC clients: %d", g_ctx.ipc.client_count);
    jz_log_info("  Probe generator: %s, targets=%d",
                 g_ctx.probe_gen.initialized ? "active" : "inactive",
                 g_ctx.probe_gen.target_count);
    jz_log_info("  Guard manager: %s, dynamic=%d",
                 g_ctx.guard_mgr.initialized ? "active" : "inactive",
                 g_ctx.guard_mgr.dynamic_count);
    jz_log_info("  REST API: %s, port=%d",
                 g_ctx.api.enabled ? "active" : "inactive",
                 g_ctx.api_port);
}

/* ── Command Line Parsing ─────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH       Config file (default: %s)\n"
        "  -d, --daemon            Run as daemon\n"
        "  -p, --pidfile PATH      PID file (default: %s)\n"
        "  -b, --bpf-dir PATH      BPF object directory (default: %s)\n"
        "  -v, --verbose           Verbose logging (debug level)\n"
        "  -V, --version           Print version and exit\n"
        "  -h, --help              Show this help\n"
        "\n"
        "API options:\n"
        "  --api-port PORT         REST API port (default: %d)\n"
        "  --api-cert PATH         TLS certificate (default: %s)\n"
        "  --api-key PATH          TLS private key (default: %s)\n"
        "  --api-ca PATH           TLS CA for client cert verification\n"
        "  --api-token TOKEN       Bearer token for API auth\n"
        "  --no-api                Disable REST API server\n",
        prog, DEFAULT_CONFIG_PATH, DEFAULT_PID_FILE, DEFAULT_BPF_DIR,
        DEFAULT_API_PORT, DEFAULT_API_CERT, DEFAULT_API_KEY);
}

static int parse_args(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        { "config",    required_argument, NULL, 'c' },
        { "daemon",    no_argument,       NULL, 'd' },
        { "pidfile",   required_argument, NULL, 'p' },
        { "bpf-dir",   required_argument, NULL, 'b' },
        { "verbose",   no_argument,       NULL, 'v' },
        { "version",   no_argument,       NULL, 'V' },
        { "help",      no_argument,       NULL, 'h' },
        { "api-port",  required_argument, NULL, 0x100 },
        { "api-cert",  required_argument, NULL, 0x101 },
        { "api-key",   required_argument, NULL, 0x102 },
        { "api-ca",    required_argument, NULL, 0x103 },
        { "api-token", required_argument, NULL, 0x104 },
        { "no-api",    no_argument,       NULL, 0x105 },
        { NULL, 0, NULL, 0 }
    };

    snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
             "%s", DEFAULT_CONFIG_PATH);
    snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
             "%s", DEFAULT_PID_FILE);
    snprintf(g_ctx.bpf_dir, sizeof(g_ctx.bpf_dir),
             "%s", DEFAULT_BPF_DIR);
    g_ctx.daemonize = false;
    g_ctx.verbose = false;
    g_ctx.api_port = DEFAULT_API_PORT;
    snprintf(g_ctx.api_cert, sizeof(g_ctx.api_cert), "%s", DEFAULT_API_CERT);
    snprintf(g_ctx.api_key, sizeof(g_ctx.api_key), "%s", DEFAULT_API_KEY);
    g_ctx.api_ca[0] = '\0';
    g_ctx.api_token[0] = '\0';

    int opt;
    while ((opt = getopt_long(argc, argv, "c:dp:b:vVh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            snprintf(g_ctx.config_path, sizeof(g_ctx.config_path),
                     "%s", optarg);
            break;
        case 'd':
            g_ctx.daemonize = true;
            break;
        case 'p':
            snprintf(g_ctx.pid_file, sizeof(g_ctx.pid_file),
                     "%s", optarg);
            break;
        case 'b':
            snprintf(g_ctx.bpf_dir, sizeof(g_ctx.bpf_dir),
                     "%s", optarg);
            break;
        case 'v':
            g_ctx.verbose = true;
            break;
        case 'V':
            printf("sniffd version %s\n", SNIFFD_VERSION);
            exit(0);
        case 'h':
            usage(argv[0]);
            exit(0);
        case 0x100:
            g_ctx.api_port = atoi(optarg);
            break;
        case 0x101:
            snprintf(g_ctx.api_cert, sizeof(g_ctx.api_cert), "%s", optarg);
            break;
        case 0x102:
            snprintf(g_ctx.api_key, sizeof(g_ctx.api_key), "%s", optarg);
            break;
        case 0x103:
            snprintf(g_ctx.api_ca, sizeof(g_ctx.api_ca), "%s", optarg);
            break;
        case 0x104:
            snprintf(g_ctx.api_token, sizeof(g_ctx.api_token), "%s", optarg);
            break;
        case 0x105:
            g_ctx.api_port = 0;
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    memset(&g_ctx, 0, sizeof(g_ctx));

    /* Parse command line */
    if (parse_args(argc, argv) < 0)
        return 1;

    /* Initialize logging (stderr for now, syslog after daemonize) */
    jz_log_level_t log_level = g_ctx.verbose ? JZ_LOG_DEBUG : JZ_LOG_INFO;
    jz_log_init("sniffd", log_level, true);

    jz_log_info("sniffd v%s starting", SNIFFD_VERSION);

    /* Install signal handlers */
    if (install_signal_handlers() < 0) {
        jz_log_fatal("Failed to install signal handlers");
        return 1;
    }

    /* Load configuration */
    jz_config_defaults(&g_ctx.config);
    jz_config_errors_t errors = { .count = 0 };
    if (jz_config_load(&g_ctx.config, g_ctx.config_path, &errors) < 0) {
        jz_log_fatal("Failed to load config %s (%d errors)",
                      g_ctx.config_path, errors.count);
        for (int i = 0; i < errors.count; i++)
            jz_log_error("  %s: %s", errors.errors[i].field,
                          errors.errors[i].message);
        return 1;
    }

    /* Apply config log level (unless --verbose overrides) */
    if (!g_ctx.verbose) {
        jz_log_level_t cfg_level =
            jz_log_level_from_str(g_ctx.config.system.log_level);
        jz_log_set_level(cfg_level);
    }

    /* Ensure runtime directory */
    if (ensure_run_dir(DEFAULT_RUN_DIR) < 0)
        return 1;

    /* Daemonize if requested */
    if (g_ctx.daemonize) {
        jz_log_info("Daemonizing...");
        if (do_daemonize() < 0) {
            jz_log_fatal("Failed to daemonize");
            return 1;
        }
        /* Disable stderr after daemonize */
        jz_log_set_stderr(false);
    }

    /* Write PID file */
    if (write_pid_file(g_ctx.pid_file) < 0) {
        jz_log_fatal("Failed to write PID file %s: %s",
                      g_ctx.pid_file, strerror(errno));
        return 1;
    }

    int exit_code = 0;

    /* Initialize BPF loader */
    if (jz_bpf_loader_init(&g_ctx.loader, g_ctx.bpf_dir) < 0) {
        jz_log_fatal("Failed to initialize BPF loader");
        exit_code = 1;
        goto cleanup;
    }

    /* Load all BPF modules */
    int loaded = jz_bpf_loader_load_all(&g_ctx.loader);
    if (loaded < 0) {
        jz_log_fatal("Fatal error loading BPF modules");
        exit_code = 1;
        goto cleanup;
    }
    if (loaded == 0) {
        jz_log_warn("No BPF modules loaded — running in degraded mode");
    }

    /* Enable modules according to config */
    struct {
        jz_mod_id_t id;
        bool enabled;
    } mod_cfg[] = {
        { JZ_MOD_GUARD_CLASSIFIER, g_ctx.config.modules.guard_classifier.enabled },
        { JZ_MOD_ARP_HONEYPOT,     g_ctx.config.modules.arp_honeypot.common.enabled },
        { JZ_MOD_ICMP_HONEYPOT,    g_ctx.config.modules.icmp_honeypot.common.enabled },
        { JZ_MOD_SNIFFER_DETECT,   g_ctx.config.modules.sniffer_detect.common.enabled },
        { JZ_MOD_TRAFFIC_WEAVER,   g_ctx.config.modules.traffic_weaver.common.enabled },
        { JZ_MOD_BG_COLLECTOR,     g_ctx.config.modules.bg_collector.common.enabled },
        { JZ_MOD_THREAT_DETECT,    g_ctx.config.modules.threat_detect.enabled },
        { JZ_MOD_FORENSICS,        g_ctx.config.modules.forensics.common.enabled },
    };

    for (size_t i = 0; i < sizeof(mod_cfg) / sizeof(mod_cfg[0]); i++) {
        if (mod_cfg[i].enabled) {
            jz_bpf_loader_enable(&g_ctx.loader, mod_cfg[i].id, true);
        }
    }

    if (strcmp(g_ctx.config.system.mode, "inline") == 0)
        jz_log_warn("inline mode not yet implemented, running as bypass");

    int xdp_ifindexes[JZ_MAX_BUSINESS_IFACES] = {0};
    char xdp_names[JZ_MAX_BUSINESS_IFACES][32] = {{0}};
    int xdp_iface_count = discover_business_ifaces(&g_ctx.config,
                                                   xdp_ifindexes,
                                                   xdp_names,
                                                   JZ_MAX_BUSINESS_IFACES);
    if (xdp_iface_count <= 0) {
        jz_log_warn("No business interfaces discovered for XDP attach");
    } else if (jz_bpf_loader_attach_xdp(&g_ctx.loader, xdp_ifindexes,
                                        xdp_names, xdp_iface_count) < 0) {
        jz_log_fatal("Failed to attach XDP on business interfaces");
        exit_code = 1;
        goto cleanup;
    }

    resolve_redirect_config(&g_ctx.config);

    /* Initialize ring buffer consumer */
    if (jz_ringbuf_init(&g_ctx.ringbuf,
                         EVENT_MAP_PIN, SAMPLE_MAP_PIN,
                         event_callback, NULL,
                         sample_callback, NULL) < 0) {
        jz_log_warn("Ring buffer init failed — events will not be consumed");
    }

    /* Initialize guard table manager */
    if (jz_guard_mgr_init(&g_ctx.guard_mgr, &g_ctx.config) < 0) {
        jz_log_warn("Guard manager init failed — guard IPC disabled");
    } else {
        jz_guard_mgr_load_config(&g_ctx.guard_mgr, &g_ctx.config);
    }

    /* Initialize ARP probe generator */
    g_ctx.ifindex = discover_ifindex(&g_ctx.config);
    if (g_ctx.ifindex > 0) {
        if (jz_probe_gen_init(&g_ctx.probe_gen, &g_ctx.config,
                              g_ctx.ifindex) < 0) {
            jz_log_warn("Probe generator init failed — sniffer detection degraded");
        }
    } else {
        jz_log_warn("No interface for probe generator — sniffer detection disabled");
    }

    /* Initialize ARP spoof module (bypass/tap mode traffic capture) */
    if (g_ctx.ifindex > 0) {
        if (jz_arp_spoof_init(&g_ctx.arp_spoof, &g_ctx.config, g_ctx.ifindex) < 0) {
            jz_log_warn("ARP spoof init failed — bypass tap mode unavailable");
        }
    }

    /* Initialize packet capture manager */
    if (jz_capture_mgr_init(&g_ctx.capture_mgr) < 0) {
        jz_log_warn("Capture manager init failed — pcap capture disabled");
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        g_ctx.ktime_wall_offset = time(NULL) - ts.tv_sec;
    }

    /* Initialize passive device discovery + ARP scanner */
    if (jz_discovery_init(&g_ctx.discovery, &g_ctx.config) < 0) {
        jz_log_warn("Discovery init failed — device fingerprinting disabled");
    }

    /* Initialize guard auto-deployment */
    if (jz_guard_auto_init(&g_ctx.guard_auto, &g_ctx.guard_mgr,
                           &g_ctx.config) < 0) {
        jz_log_warn("Guard auto init failed — auto-deployment disabled");
        g_ctx.discovery.guard_auto = NULL;
    } else {
        g_ctx.discovery.guard_auto = &g_ctx.guard_auto;
        jz_guard_auto_set_discovery(&g_ctx.guard_auto, &g_ctx.discovery);
    }

    /* Initialize policy engine */
    if (jz_policy_mgr_init(&g_ctx.policy_mgr, &g_ctx.config) < 0) {
        jz_log_warn("Policy manager init failed — policy engine disabled");
    }

    if (jz_policy_auto_init(&g_ctx.policy_auto, &g_ctx.policy_mgr,
                            &g_ctx.config) < 0) {
        jz_log_warn("Policy auto init failed — auto-policy disabled");
    }

    if (jz_heartbeat_init(&g_ctx.heartbeat, &g_ctx.config,
                          &g_ctx.loader, &g_ctx.guard_mgr,
                          &g_ctx.discovery) < 0) {
        jz_log_warn("Heartbeat init failed — heartbeat disabled");
    }

    /* Initialize IPC server */
    if (jz_ipc_server_init(&g_ctx.ipc, JZ_IPC_SOCK_SNIFFD, 0660,
                           ipc_handler, &g_ctx.ipc) < 0) {
        jz_log_fatal("Failed to initialize IPC server on %s",
                      JZ_IPC_SOCK_SNIFFD);
        exit_code = 1;
        goto cleanup;
    }

    /* Initialize REST API server */
    if (g_ctx.api_port > 0) {
        g_ctx.api.loader = &g_ctx.loader;
        g_ctx.api.guard_mgr = &g_ctx.guard_mgr;
        g_ctx.api.discovery = &g_ctx.discovery;
        g_ctx.api.guard_auto = &g_ctx.guard_auto;
        g_ctx.api.policy_mgr = &g_ctx.policy_mgr;
        g_ctx.api.config = &g_ctx.config;
        g_ctx.api.db = &g_ctx.db;
        g_ctx.api.arp_spoof = &g_ctx.arp_spoof;
        g_ctx.api.capture_mgr = &g_ctx.capture_mgr;
        /* Set DB path from config so API can query logs readonly */
        if (g_ctx.config.collector.db_path[0])
            (void) snprintf(g_ctx.db.path, sizeof(g_ctx.db.path),
                            "%s", g_ctx.config.collector.db_path);
        if (jz_api_init(&g_ctx.api, g_ctx.api_port,
                        g_ctx.api_cert, g_ctx.api_key,
                        g_ctx.api_ca, g_ctx.api_token) < 0) {
            jz_log_warn("REST API init failed — API server disabled");
        } else {
            jz_log_info("REST API listening on port %d", g_ctx.api_port);
        }
    }

    /* BPF pin dir is under /sys/fs/bpf/ (mode 1700, root-only). Chown jz/ subdir so reload works after setuid. */
    {
        struct passwd *bpf_pw = getpwnam("jz");
        struct group  *bpf_gr = getgrnam("jz");
        if (bpf_pw && bpf_gr) {
            uid_t u = bpf_pw->pw_uid;
            gid_t g = bpf_gr->gr_gid;
            (void) chmod("/sys/fs/bpf", 0711);
            if (chown("/sys/fs/bpf/jz", u, g) == 0)
                (void) chmod("/sys/fs/bpf/jz", 0750);

            /* Chown pinned map files so jz user can bpf_obj_get() them */
            DIR *d = opendir("/sys/fs/bpf/jz");
            if (d) {
                struct dirent *ent;
                char path[512];
                while ((ent = readdir(d)) != NULL) {
                    if (ent->d_name[0] == '.')
                        continue;
                    snprintf(path, sizeof(path), "/sys/fs/bpf/jz/%s", ent->d_name);
                    if (chown(path, u, g) < 0) { }
                }
                closedir(d);
            }

            /* Also chown all pinned BPF maps under /sys/fs/bpf/ (rSwitch + jz) */
            d = opendir("/sys/fs/bpf");
            if (d) {
                struct dirent *ent;
                char path[512];
                while ((ent = readdir(d)) != NULL) {
                    if (ent->d_name[0] == '.')
                        continue;
                    snprintf(path, sizeof(path), "/sys/fs/bpf/%s", ent->d_name);
                    if (chown(path, u, g) < 0) { }
                }
                closedir(d);
            }

            /* Chown IPC sockets so jz user can connect to peer daemons */
            d = opendir("/var/run/jz");
            if (d) {
                struct dirent *ent;
                char path[512];
                while ((ent = readdir(d)) != NULL) {
                    if (ent->d_name[0] == '.')
                        continue;
                    snprintf(path, sizeof(path), "/var/run/jz/%s", ent->d_name);
                    if (chown(path, u, g) < 0) { }
                }
                closedir(d);
            }
        }
    }

    /* Drop privileges after binding sockets and loading BPF */
    drop_privileges("jz", "jz");

    jz_log_info("sniffd ready — entering main loop");

    /* ── Main Loop ── */
    time_t collectord_retry_after = 0;

    while (g_running) {
        jz_ipc_server_poll(&g_ctx.ipc, 10);

        if (!g_ctx.collectord_client.connected) {
            time_t now = time(NULL);
            if (now >= collectord_retry_after) {
                jz_ipc_client_connect(&g_ctx.collectord_client,
                                      JZ_IPC_SOCK_COLLECTORD,
                                      JZ_IPC_DEFAULT_TIMEOUT_MS);
                if (!g_ctx.collectord_client.connected)
                    collectord_retry_after = now + 5;
            }
        }

        if (g_ctx.ringbuf.initialized)
            jz_ringbuf_poll(&g_ctx.ringbuf, RINGBUF_POLL_MS);

        if (g_ctx.probe_gen.initialized)
            jz_probe_gen_tick(&g_ctx.probe_gen);

        if (g_ctx.guard_mgr.initialized)
            jz_guard_mgr_tick(&g_ctx.guard_mgr);

        if (g_ctx.discovery.initialized) {
            jz_discovery_tick(&g_ctx.discovery);
            jz_discovery_recv_arp(&g_ctx.discovery);
        }

        if (g_ctx.guard_auto.initialized)
            jz_guard_auto_tick(&g_ctx.guard_auto);

        if (g_ctx.policy_mgr.initialized)
            jz_policy_mgr_tick(&g_ctx.policy_mgr);

        if (g_ctx.policy_auto.initialized)
            jz_policy_auto_tick(&g_ctx.policy_auto);

        if (g_ctx.arp_spoof.initialized)
            jz_arp_spoof_tick(&g_ctx.arp_spoof);

        if (g_ctx.heartbeat.initialized) {
            char *hb_json = jz_heartbeat_tick(&g_ctx.heartbeat);
            if (hb_json) {
                if (g_ctx.db.path[0]) {
                    jz_db_t hb_db;
                    if (jz_db_open(&hb_db, g_ctx.db.path) == 0) {
                        char ts[32];
                        time_t now = time(NULL);
                        struct tm tmv;
                        if (gmtime_r(&now, &tmv))
                            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
                        else
                            snprintf(ts, sizeof(ts), "unknown");
                        jz_db_insert_heartbeat(&hb_db, ts, hb_json);
                        jz_db_close(&hb_db);
                    }
                }
                if (!g_ctx.uploadd_client.connected) {
                    jz_ipc_client_connect(&g_ctx.uploadd_client,
                                          JZ_IPC_SOCK_UPLOADD,
                                          JZ_IPC_DEFAULT_TIMEOUT_MS);
                }
                if (g_ctx.uploadd_client.connected) {
                    char ipc_buf[JZ_IPC_MAX_MSG_LEN];
                    int ipc_len = snprintf(ipc_buf, sizeof(ipc_buf),
                                           "heartbeat:%s", hb_json);
                    if (ipc_len > 0 && (size_t)ipc_len < sizeof(ipc_buf)) {
                        jz_ipc_msg_t reply;
                        if (jz_ipc_client_request(&g_ctx.uploadd_client,
                                                   ipc_buf, (uint32_t)ipc_len,
                                                   &reply) < 0) {
                            jz_ipc_client_close(&g_ctx.uploadd_client);
                            jz_ipc_client_close(&g_ctx.collectord_client);
                        }
                    }
                }
                free(hb_json);
            }
        }

        if (g_ctx.api.enabled)
            jz_api_poll(&g_ctx.api, 0);

        if (g_reload) {
            g_reload = 0;
            do_reload();
        }
        if (g_dump_stat) {
            g_dump_stat = 0;
            dump_stats();
        }
    }

    jz_log_info("sniffd shutting down...");

cleanup:
    jz_api_destroy(&g_ctx.api);
    jz_capture_mgr_destroy(&g_ctx.capture_mgr);
    jz_arp_spoof_destroy(&g_ctx.arp_spoof);
    jz_heartbeat_destroy(&g_ctx.heartbeat);
    jz_ipc_client_close(&g_ctx.uploadd_client);
    jz_policy_auto_destroy(&g_ctx.policy_auto);
    jz_policy_mgr_destroy(&g_ctx.policy_mgr);
    jz_guard_auto_destroy(&g_ctx.guard_auto);
    jz_discovery_destroy(&g_ctx.discovery);
    jz_probe_gen_destroy(&g_ctx.probe_gen);
    jz_guard_mgr_destroy(&g_ctx.guard_mgr);
    jz_ringbuf_destroy(&g_ctx.ringbuf);
    jz_ipc_server_destroy(&g_ctx.ipc);
    jz_bpf_loader_detach_xdp(&g_ctx.loader);
    jz_bpf_loader_destroy(&g_ctx.loader);
    jz_config_free(&g_ctx.config);
    remove_pid_file(g_ctx.pid_file);
    jz_log_info("sniffd stopped");
    jz_log_close();

    return exit_code;
}
