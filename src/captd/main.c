// SPDX-License-Identifier: MIT
// captd - Standalone capture daemon for threat detection ring buffer

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "log.h"
#include "pcap_writer.h"
#include "config_map.h"

#define CAPTD_CAPTURE_DIR       "/var/lib/jz/captures"
#define CAPTD_PIN_PATH          "/sys/fs/bpf/jz/jz_threat_capture_rb"
#define CAPTD_MAX_FILE_SIZE     (100 * 1024 * 1024)  /* 100 MB */
#define CAPTD_MAX_FILE_AGE_SEC  3600                  /* 1 hour */
#define CAPTD_MAX_FILES         10
#define CAPTD_POLL_TIMEOUT_MS   1000

static volatile sig_atomic_t g_running = 1;

static jz_pcap_writer_t g_pcap;
static time_t g_file_start_time;

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static int ensure_capture_dir(void)
{
    struct stat st;

    if (stat(CAPTD_CAPTURE_DIR, &st) == 0)
        return 0;

    if (mkdir(CAPTD_CAPTURE_DIR, 0755) != 0 && errno != EEXIST) {
        jz_log_error("mkdir %s: %s", CAPTD_CAPTURE_DIR, strerror(errno));
        return -1;
    }

    return 0;
}

static int open_new_pcap(void)
{
    char path[512];
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);
    snprintf(path, sizeof(path),
             CAPTD_CAPTURE_DIR "/capture_%04d%02d%02d_%02d%02d%02d.pcap",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    jz_pcap_close(&g_pcap);
    memset(&g_pcap, 0, sizeof(g_pcap));

    if (jz_pcap_open(&g_pcap, path, JZ_PCAP_DEFAULT_SNAPLEN) != 0) {
        jz_log_error("Failed to open pcap: %s", path);
        return -1;
    }

    g_file_start_time = now;
    jz_log_info("Opened capture file: %s", path);
    return 0;
}

static bool needs_rotation(void)
{
    if (g_pcap.bytes_written >= CAPTD_MAX_FILE_SIZE)
        return true;

    if (time(NULL) - g_file_start_time >= CAPTD_MAX_FILE_AGE_SEC)
        return true;

    return false;
}

static void cleanup_old_files(void)
{
    /*
     * Simple cleanup: list directory, count .pcap files, remove oldest
     * if count exceeds CAPTD_MAX_FILES. Uses popen(ls) for simplicity
     * since this runs once per rotation, not on the hot path.
     */
    char cmd[1024];
    FILE *fp;
    char files[64][512];
    int count = 0;

    snprintf(cmd, sizeof(cmd),
             "ls -1t %s/capture_*.pcap 2>/dev/null", CAPTD_CAPTURE_DIR);

    fp = popen(cmd, "r");
    if (!fp)
        return;

    while (count < 64 && fgets(files[count], (int)sizeof(files[count]), fp)) {
        size_t len = strlen(files[count]);
        if (len > 0 && files[count][len - 1] == '\n')
            files[count][len - 1] = '\0';
        count++;
    }
    pclose(fp);

    for (int i = CAPTD_MAX_FILES; i < count; i++) {
        jz_log_info("Removing old capture: %s", files[i]);
        unlink(files[i]);
    }
}

static int handle_sample(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct jz_capture_meta))
        return 0;

    const struct jz_capture_meta *meta = (const struct jz_capture_meta *)data;
    const void *pkt_data = (const uint8_t *)data + sizeof(struct jz_capture_meta);
    size_t pkt_avail = data_sz - sizeof(struct jz_capture_meta);

    uint32_t cap_len = meta->cap_len;
    if (cap_len > pkt_avail)
        cap_len = (uint32_t)pkt_avail;

    if (cap_len == 0)
        return 0;

    if (needs_rotation()) {
        if (open_new_pcap() != 0)
            return 0;
        cleanup_old_files();
    }

    if (!g_pcap.fp)
        return 0;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    jz_pcap_write_packet(&g_pcap,
                         (uint32_t)ts.tv_sec,
                         (uint32_t)(ts.tv_nsec / 1000),
                         pkt_data,
                         cap_len,
                         meta->wire_len);

    return 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    struct ring_buffer *rb = NULL;
    int fd;

    jz_log_init("captd", JZ_LOG_INFO, true);
    jz_log_info("captd starting");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (ensure_capture_dir() != 0) {
        jz_log_fatal("Cannot create capture directory");
        return 1;
    }

    fd = bpf_obj_get(CAPTD_PIN_PATH);
    if (fd < 0) {
        jz_log_error("Cannot open pinned ring buffer %s: %s",
                     CAPTD_PIN_PATH, strerror(errno));
        jz_log_info("Waiting for ring buffer to appear...");

        while (g_running && fd < 0) {
            sleep(5);
            fd = bpf_obj_get(CAPTD_PIN_PATH);
        }

        if (fd < 0) {
            jz_log_fatal("Ring buffer never appeared, exiting");
            jz_log_close();
            return 1;
        }
    }

    jz_log_info("Ring buffer attached (fd=%d)", fd);

    rb = ring_buffer__new(fd, handle_sample, NULL, NULL);
    if (!rb) {
        jz_log_fatal("ring_buffer__new failed: %s", strerror(errno));
        close(fd);
        jz_log_close();
        return 1;
    }

    memset(&g_pcap, 0, sizeof(g_pcap));
    if (open_new_pcap() != 0) {
        jz_log_fatal("Cannot open initial pcap file");
        ring_buffer__free(rb);
        close(fd);
        jz_log_close();
        return 1;
    }

    jz_log_info("captd ready, polling ring buffer");

    while (g_running) {
        int err = ring_buffer__poll(rb, CAPTD_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            jz_log_error("ring_buffer__poll: %s", strerror(-err));
            break;
        }
    }

    jz_log_info("captd shutting down");
    jz_pcap_close(&g_pcap);
    ring_buffer__free(rb);
    close(fd);
    jz_log_close();

    return 0;
}
