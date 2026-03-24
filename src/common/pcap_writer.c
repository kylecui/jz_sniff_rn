/* SPDX-License-Identifier: MIT */
/* pcap_writer.c - Minimal libpcap-compatible pcap file writer. */

#include "pcap_writer.h"
#include "log.h"

#include <string.h>
#include <errno.h>

int jz_pcap_open(jz_pcap_writer_t *w, const char *path, uint32_t snaplen)
{
    jz_pcap_file_hdr_t hdr;

    if (!w || !path || !path[0])
        return -1;

    memset(w, 0, sizeof(*w));

    if (snaplen == 0)
        snaplen = JZ_PCAP_DEFAULT_SNAPLEN;

    w->fp = fopen(path, "wb");
    if (!w->fp) {
        jz_log_error("pcap: cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    snprintf(w->path, sizeof(w->path), "%s", path);
    w->snaplen = snaplen;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic         = JZ_PCAP_MAGIC;
    hdr.version_major = JZ_PCAP_VERSION_MAJOR;
    hdr.version_minor = JZ_PCAP_VERSION_MINOR;
    hdr.thiszone      = 0;
    hdr.sigfigs       = 0;
    hdr.snaplen       = snaplen;
    hdr.linktype      = JZ_PCAP_LINKTYPE_ETH;

    if (fwrite(&hdr, sizeof(hdr), 1, w->fp) != 1) {
        jz_log_error("pcap: failed to write header to %s", path);
        fclose(w->fp);
        w->fp = NULL;
        return -1;
    }

    w->bytes_written = sizeof(hdr);
    return 0;
}

int jz_pcap_write_packet(jz_pcap_writer_t *w,
                          uint32_t ts_sec, uint32_t ts_usec,
                          const void *data, uint32_t caplen,
                          uint32_t origlen)
{
    jz_pcap_rec_hdr_t rec;

    if (!w || !w->fp || !data || caplen == 0)
        return -1;

    if (caplen > w->snaplen)
        caplen = w->snaplen;

    rec.ts_sec  = ts_sec;
    rec.ts_usec = ts_usec;
    rec.caplen  = caplen;
    rec.origlen = origlen;

    if (fwrite(&rec, sizeof(rec), 1, w->fp) != 1)
        return -1;
    if (fwrite(data, caplen, 1, w->fp) != 1)
        return -1;

    w->bytes_written += sizeof(rec) + caplen;
    w->pkt_count++;
    return 0;
}

void jz_pcap_close(jz_pcap_writer_t *w)
{
    if (!w)
        return;
    if (w->fp) {
        fflush(w->fp);
        fclose(w->fp);
        w->fp = NULL;
    }
}
