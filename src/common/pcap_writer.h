/* SPDX-License-Identifier: MIT */
/*
 * pcap_writer.h - Minimal libpcap-compatible pcap file writer.
 *
 * Writes standard pcap files (magic 0xa1b2c3d4, version 2.4) in native
 * byte order with microsecond timestamps. No libpcap dependency.
 *
 * File format:
 *   [Global Header 24B] [Packet Record 16B + data] [Packet Record] ...
 */

#ifndef JZ_PCAP_WRITER_H
#define JZ_PCAP_WRITER_H

#include <stdint.h>
#include <stdio.h>

/* ── Constants ────────────────────────────────────────────────── */

#define JZ_PCAP_MAGIC          0xa1b2c3d4u   /* µs timestamps, native byte order */
#define JZ_PCAP_VERSION_MAJOR  2
#define JZ_PCAP_VERSION_MINOR  4
#define JZ_PCAP_LINKTYPE_ETH   1             /* DLT_EN10MB: raw Ethernet frames  */
#define JZ_PCAP_DEFAULT_SNAPLEN 65535

/* ── On-disk Structures (packed, native byte order) ───────────── */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;      /* always 0 */
    uint32_t sigfigs;       /* always 0 */
    uint32_t snaplen;
    uint32_t linktype;
} jz_pcap_file_hdr_t;      /* 24 bytes */

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;        /* seconds since Unix epoch      */
    uint32_t ts_usec;       /* microseconds (0–999999)       */
    uint32_t caplen;        /* bytes present in file         */
    uint32_t origlen;       /* original wire length          */
} jz_pcap_rec_hdr_t;       /* 16 bytes */

/* ── Writer Handle ────────────────────────────────────────────── */

typedef struct {
    FILE    *fp;
    char     path[256];
    uint64_t bytes_written;  /* total file bytes (header + records) */
    uint32_t pkt_count;
    uint32_t snaplen;
} jz_pcap_writer_t;

/* ── API ──────────────────────────────────────────────────────── */

/*
 * Open a new pcap file for writing.
 * Returns 0 on success, -1 on failure.
 * The writer must be zeroed before first call.
 */
int  jz_pcap_open(jz_pcap_writer_t *w, const char *path, uint32_t snaplen);

/*
 * Write a single packet record.
 * ts_sec/ts_usec: packet timestamp (seconds since epoch / microseconds).
 * data: raw Ethernet frame bytes.
 * caplen: bytes to write (may be < origlen if truncated).
 * origlen: original packet length on wire.
 * Returns 0 on success, -1 on failure.
 */
int  jz_pcap_write_packet(jz_pcap_writer_t *w,
                           uint32_t ts_sec, uint32_t ts_usec,
                           const void *data, uint32_t caplen,
                           uint32_t origlen);

/*
 * Flush and close the pcap file.
 * Safe to call on an uninitialized/already-closed writer.
 */
void jz_pcap_close(jz_pcap_writer_t *w);

#endif /* JZ_PCAP_WRITER_H */
