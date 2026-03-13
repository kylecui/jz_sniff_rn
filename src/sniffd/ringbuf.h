/* SPDX-License-Identifier: MIT */
/*
 * ringbuf.h - BPF ring buffer consumer for sniffd.
 *
 * Polls rs_event_bus (shared rSwitch ring buffer) and jz_sample_ringbuf
 * (dedicated forensics ring buffer) for events, parses them, and
 * dispatches to registered callbacks.
 */

#ifndef JZ_RINGBUF_H
#define JZ_RINGBUF_H

#include <stdbool.h>
#include <stdint.h>

/* Forward declare BPF event header */
struct jz_event_hdr;

/* ── Event Callback ── */

/* Callback invoked for each event received from ring buffers.
 * data points to the raw event (starts with jz_event_hdr).
 * data_len is the total event size in bytes.
 * Return 0 to continue, non-zero to stop polling. */
typedef int (*jz_ringbuf_event_fn)(const void *data, uint32_t data_len,
                                    void *user_data);

/* ── Ring Buffer Consumer ── */

typedef struct jz_ringbuf {
    void  *event_rb;       /* ring_buffer for rs_event_bus */
    void  *sample_rb;      /* ring_buffer for jz_sample_ringbuf */
    int    event_map_fd;   /* fd for rs_event_bus ring buffer map */
    int    sample_map_fd;  /* fd for jz_sample_ringbuf ring buffer map */

    jz_ringbuf_event_fn event_handler;
    jz_ringbuf_event_fn sample_handler;
    void  *event_user_data;
    void  *sample_user_data;

    bool   initialized;
    volatile bool running;

    /* Statistics */
    uint64_t events_received;
    uint64_t events_dropped;
    uint64_t samples_received;
    uint64_t samples_dropped;
} jz_ringbuf_t;

/* Initialize ring buffer consumer. Opens pinned ring buffer maps
 * and sets up polling. Either handler can be NULL to skip that buffer.
 *
 * event_map_pin:  path to pinned rs_event_bus map
 *                 (e.g. "/sys/fs/bpf/rswitch/rs_event_bus")
 * sample_map_pin: path to pinned jz_sample_ringbuf map
 *                 (e.g. "/sys/fs/bpf/jz/jz_sample_ringbuf")
 *
 * Returns 0 on success, -1 on error. */
int jz_ringbuf_init(jz_ringbuf_t *rb,
                    const char *event_map_pin,
                    const char *sample_map_pin,
                    jz_ringbuf_event_fn event_handler,
                    void *event_user_data,
                    jz_ringbuf_event_fn sample_handler,
                    void *sample_user_data);

/* Poll ring buffers for up to timeout_ms milliseconds.
 * Returns number of events consumed, or -1 on error.
 * Returns 0 if timeout with no events. */
int jz_ringbuf_poll(jz_ringbuf_t *rb, int timeout_ms);

/* Signal consumer to stop (for use from signal handler). */
void jz_ringbuf_stop(jz_ringbuf_t *rb);

/* Get statistics snapshot. */
void jz_ringbuf_stats(const jz_ringbuf_t *rb,
                      uint64_t *events_received,
                      uint64_t *events_dropped,
                      uint64_t *samples_received,
                      uint64_t *samples_dropped);

/* Destroy consumer and release resources. */
void jz_ringbuf_destroy(jz_ringbuf_t *rb);

#endif /* JZ_RINGBUF_H */
