/* SPDX-License-Identifier: MIT */
/* capture_mgr.c - Packet capture session manager for sniffd. */

#include "capture_mgr.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>

#define SAMPLE_CONFIG_PIN "/sys/fs/bpf/jz/jz_sample_config"
#define SAMPLE_CONFIG_PIN_FLAT "/sys/fs/bpf/jz_sample_config"

struct jz_sample_config_user {
    uint32_t enabled;
    uint32_t sample_rate;
    uint16_t max_payload_bytes;
    uint16_t _pad;
};

static int ensure_capture_dir(void)
{
    struct stat st;
    if (stat(JZ_CAPTURE_DIR, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(JZ_CAPTURE_DIR, 0750) < 0 && errno != EEXIST) {
        jz_log_error("capture: cannot create %s: %s",
                      JZ_CAPTURE_DIR, strerror(errno));
        return -1;
    }
    return 0;
}

static void set_bpf_sampling(jz_capture_mgr_t *mgr, bool enable)
{
    if (mgr->sample_config_fd < 0)
        return;

    uint32_t key = 0;
    struct jz_sample_config_user cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (enable) {
        cfg.enabled = 1;
        cfg.sample_rate = 1;
        cfg.max_payload_bytes = JZ_CAPTURE_SNAPLEN;
    }

    if (bpf_map_update_elem(mgr->sample_config_fd, &key, &cfg, BPF_ANY) < 0)
        jz_log_warn("capture: failed to update sample config: %s",
                     strerror(errno));
}

int jz_capture_mgr_init(jz_capture_mgr_t *mgr)
{
    if (!mgr)
        return -1;

    memset(mgr, 0, sizeof(*mgr));
    mgr->sample_config_fd = -1;
    mgr->max_bytes = JZ_CAPTURE_DEFAULT_MAX_BYTES;

    int fd = bpf_obj_get(SAMPLE_CONFIG_PIN);
    if (fd < 0)
        fd = bpf_obj_get(SAMPLE_CONFIG_PIN_FLAT);
    if (fd >= 0) {
        mgr->sample_config_fd = fd;
    } else {
        jz_log_warn("capture: cannot open sample config map (capture will work without BPF sampling)");
    }

    if (ensure_capture_dir() < 0)
        return -1;

    mgr->initialized = true;
    jz_log_info("capture: initialized (dir=%s, max=%llu MB)",
                 JZ_CAPTURE_DIR,
                 (unsigned long long)(mgr->max_bytes / (1024 * 1024)));
    return 0;
}

void jz_capture_mgr_destroy(jz_capture_mgr_t *mgr)
{
    if (!mgr)
        return;

    if (mgr->active)
        jz_capture_mgr_stop(mgr);

    if (mgr->sample_config_fd >= 0) {
        close(mgr->sample_config_fd);
        mgr->sample_config_fd = -1;
    }

    mgr->initialized = false;
}

int jz_capture_mgr_start(jz_capture_mgr_t *mgr, uint64_t max_bytes)
{
    char path[384];
    time_t now;
    struct tm tm;

    if (!mgr || !mgr->initialized)
        return -1;

    if (mgr->active) {
        jz_log_warn("capture: already active, stopping previous");
        jz_capture_mgr_stop(mgr);
    }

    if (ensure_capture_dir() < 0)
        return -1;

    now = time(NULL);
    gmtime_r(&now, &tm);
    snprintf(path, sizeof(path),
             "%s/capture_%04d%02d%02d_%02d%02d%02d.pcap",
             JZ_CAPTURE_DIR,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (jz_pcap_open(&mgr->writer, path, JZ_CAPTURE_SNAPLEN) < 0)
        return -1;

    mgr->max_bytes = (max_bytes > 0) ? max_bytes : JZ_CAPTURE_DEFAULT_MAX_BYTES;
    mgr->start_time = now;
    mgr->active = true;

    set_bpf_sampling(mgr, true);

    jz_log_info("capture: started → %s (max %llu MB)",
                 path, (unsigned long long)(mgr->max_bytes / (1024 * 1024)));
    return 0;
}

int jz_capture_mgr_stop(jz_capture_mgr_t *mgr)
{
    if (!mgr || !mgr->active)
        return -1;

    set_bpf_sampling(mgr, false);

    jz_log_info("capture: stopped %s (%u packets, %llu bytes)",
                 mgr->writer.path,
                 mgr->writer.pkt_count,
                 (unsigned long long)mgr->writer.bytes_written);

    jz_pcap_close(&mgr->writer);
    mgr->active = false;
    return 0;
}

int jz_capture_mgr_write(jz_capture_mgr_t *mgr,
                          uint32_t ts_sec, uint32_t ts_usec,
                          const void *data, uint32_t caplen,
                          uint32_t origlen)
{
    if (!mgr || !mgr->active)
        return -1;

    if (mgr->writer.bytes_written + sizeof(jz_pcap_rec_hdr_t) + caplen > mgr->max_bytes) {
        jz_log_info("capture: size limit reached, auto-stopping");
        jz_capture_mgr_stop(mgr);
        return 1;
    }

    return jz_pcap_write_packet(&mgr->writer, ts_sec, ts_usec,
                                 data, caplen, origlen);
}

int jz_capture_mgr_list(jz_capture_info_t *info, int max_count)
{
    DIR *dir;
    struct dirent *ent;
    struct stat st;
    char path[384];
    int count = 0;

    if (!info || max_count <= 0)
        return 0;

    dir = opendir(JZ_CAPTURE_DIR);
    if (!dir)
        return 0;

    while ((ent = readdir(dir)) != NULL && count < max_count) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 5 || strcmp(ent->d_name + nlen - 5, ".pcap") != 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", JZ_CAPTURE_DIR, ent->d_name);
        if (stat(path, &st) < 0)
            continue;

        snprintf(info[count].filename, sizeof(info[count].filename),
                 "%s", ent->d_name);
        info[count].size_bytes = (uint64_t)st.st_size;
        info[count].created = st.st_mtime;
        info[count].pkt_count = 0;
        count++;
    }

    closedir(dir);
    return count;
}

int jz_capture_mgr_delete(const char *filename)
{
    char path[384];

    if (!filename || !filename[0])
        return -1;

    if (strchr(filename, '/') || strchr(filename, '\\') || strstr(filename, ".."))
        return -1;

    size_t nlen = strlen(filename);
    if (nlen < 5 || strcmp(filename + nlen - 5, ".pcap") != 0)
        return -1;

    snprintf(path, sizeof(path), "%s/%s", JZ_CAPTURE_DIR, filename);

    if (unlink(path) < 0) {
        jz_log_error("capture: cannot delete %s: %s", path, strerror(errno));
        return -1;
    }

    jz_log_info("capture: deleted %s", filename);
    return 0;
}
