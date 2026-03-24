/* SPDX-License-Identifier: MIT */
#ifndef JZ_CAPTURE_MGR_H
#define JZ_CAPTURE_MGR_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "pcap_writer.h"

#define JZ_CAPTURE_DIR        "/var/lib/jz/captures"
#define JZ_CAPTURE_MAX_FILES  64
#define JZ_CAPTURE_DEFAULT_MAX_BYTES  (100ULL * 1024 * 1024)  /* 100 MB */
#define JZ_CAPTURE_SNAPLEN    512   /* match JZ_FORENSIC_PAYLOAD_MAX */

typedef struct {
    char     filename[128];
    uint64_t size_bytes;
    time_t   created;
    uint32_t pkt_count;
} jz_capture_info_t;

typedef struct jz_capture_mgr {
    bool              active;
    bool              initialized;
    jz_pcap_writer_t  writer;
    uint64_t          max_bytes;
    time_t            start_time;
    int               sample_config_fd;   /* fd to jz_sample_config BPF map */
} jz_capture_mgr_t;

int  jz_capture_mgr_init(jz_capture_mgr_t *mgr);
void jz_capture_mgr_destroy(jz_capture_mgr_t *mgr);

int  jz_capture_mgr_start(jz_capture_mgr_t *mgr, uint64_t max_bytes);
int  jz_capture_mgr_stop(jz_capture_mgr_t *mgr);

/* Write a raw Ethernet packet to the active capture. Auto-stops on size limit. */
int  jz_capture_mgr_write(jz_capture_mgr_t *mgr,
                           uint32_t ts_sec, uint32_t ts_usec,
                           const void *data, uint32_t caplen,
                           uint32_t origlen);

/* List completed capture files. Returns count, fills info[] up to max_count. */
int  jz_capture_mgr_list(jz_capture_info_t *info, int max_count);

/* Delete a capture file by filename. Returns 0 on success. */
int  jz_capture_mgr_delete(const char *filename);

#endif /* JZ_CAPTURE_MGR_H */
