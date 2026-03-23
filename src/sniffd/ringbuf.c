/* SPDX-License-Identifier: MIT */
/*
 * ringbuf.c - BPF ring buffer consumer implementation for sniffd.
 *
 * Consumes events from rs_event_bus and jz_sample_ringbuf using
 * libbpf's ring_buffer API. Events are dispatched to user callbacks.
 */


#include "ringbuf.h"
#include "log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* jz_common.h defines the event header struct but uses BPF types.
 * We only need the size/offsets here — the callback gets raw data. */

/* Minimum event size: just the header */
#define JZ_EVENT_HDR_SIZE  32  /* sizeof(struct jz_event_hdr) */

/* ── Internal libbpf Callbacks ────────────────────────────────── */

/* libbpf ring_buffer sample callback for event bus. */
static int event_rb_callback(void *ctx, void *data, size_t data_sz)
{
    jz_ringbuf_t *rb = (jz_ringbuf_t *)ctx;

    if (data_sz < JZ_EVENT_HDR_SIZE) {
        rb->events_dropped++;
        return 0;  /* Skip malformed events, keep consuming */
    }

    rb->events_received++;

    if (rb->event_handler) {
        return rb->event_handler(data, (uint32_t)data_sz,
                                 rb->event_user_data);
    }

    return 0;
}

/* libbpf ring_buffer sample callback for forensic samples. */
static int sample_rb_callback(void *ctx, void *data, size_t data_sz)
{
    jz_ringbuf_t *rb = (jz_ringbuf_t *)ctx;

    if (data_sz < JZ_EVENT_HDR_SIZE) {
        rb->samples_dropped++;
        return 0;
    }

    rb->samples_received++;

    if (rb->sample_handler) {
        return rb->sample_handler(data, (uint32_t)data_sz,
                                  rb->sample_user_data);
    }

    return 0;
}

/* ── Public API ───────────────────────────────────────────────── */

int jz_ringbuf_init(jz_ringbuf_t *rb,
                    const char *event_map_pin,
                    const char *sample_map_pin,
                    jz_ringbuf_event_fn event_handler,
                    void *event_user_data,
                    jz_ringbuf_event_fn sample_handler,
                    void *sample_user_data)
{
    if (!rb)
        return -1;

    memset(rb, 0, sizeof(*rb));
    rb->event_map_fd = -1;
    rb->sample_map_fd = -1;
    rb->event_handler = event_handler;
    rb->event_user_data = event_user_data;
    rb->sample_handler = sample_handler;
    rb->sample_user_data = sample_user_data;

    bool have_event = false;
    bool have_sample = false;

    /* Open event ring buffer */
    if (event_map_pin && event_handler) {
        rb->event_map_fd = bpf_obj_get(event_map_pin);
        if (rb->event_map_fd < 0) {
            const char *name = strrchr(event_map_pin, '/');
            if (name) {
                char flat[256];
                snprintf(flat, sizeof(flat), "/sys/fs/bpf%s", name);
                rb->event_map_fd = bpf_obj_get(flat);
            }
        }
        if (rb->event_map_fd < 0) {
            jz_log_error("Cannot open event ring buffer at %s: %s",
                          event_map_pin, strerror(errno));
            goto fail;
        }

        rb->event_rb = ring_buffer__new(rb->event_map_fd,
                                         event_rb_callback, rb, NULL);
        if (!rb->event_rb) {
            jz_log_error("Failed to create event ring buffer: %s",
                          strerror(errno));
            goto fail;
        }
        have_event = true;
    }

    /* Open sample ring buffer */
    if (sample_map_pin && sample_handler) {
        rb->sample_map_fd = bpf_obj_get(sample_map_pin);
        if (rb->sample_map_fd < 0) {
            const char *name = strrchr(sample_map_pin, '/');
            if (name) {
                char flat[256];
                snprintf(flat, sizeof(flat), "/sys/fs/bpf%s", name);
                rb->sample_map_fd = bpf_obj_get(flat);
            }
        }
        if (rb->sample_map_fd < 0) {
            jz_log_error("Cannot open sample ring buffer at %s: %s",
                          sample_map_pin, strerror(errno));
            goto fail;
        }

        rb->sample_rb = ring_buffer__new(rb->sample_map_fd,
                                          sample_rb_callback, rb, NULL);
        if (!rb->sample_rb) {
            jz_log_error("Failed to create sample ring buffer: %s",
                          strerror(errno));
            goto fail;
        }
        have_sample = true;
    }

    if (!have_event && !have_sample) {
        jz_log_error("No ring buffers configured");
        goto fail;
    }

    rb->initialized = true;
    rb->running = true;

    jz_log_info("Ring buffer consumer initialized (event=%s, sample=%s)",
                 have_event ? "yes" : "no",
                 have_sample ? "yes" : "no");
    return 0;

fail:
    jz_ringbuf_destroy(rb);
    return -1;
}

int jz_ringbuf_poll(jz_ringbuf_t *rb, int timeout_ms)
{
    if (!rb || !rb->initialized || !rb->running)
        return -1;

    int total = 0;

    /* Poll event ring buffer */
    if (rb->event_rb) {
        int n = ring_buffer__poll((struct ring_buffer *)rb->event_rb,
                                  timeout_ms);
        if (n < 0 && n != -EINTR) {
            jz_log_error("Event ring buffer poll error: %s",
                          strerror(-n));
            return -1;
        }
        if (n > 0)
            total += n;
    }

    /* Poll sample ring buffer (with short timeout since event
     * polling already consumed most of the time budget) */
    if (rb->sample_rb) {
        int n = ring_buffer__poll((struct ring_buffer *)rb->sample_rb, 0);
        if (n < 0 && n != -EINTR) {
            jz_log_error("Sample ring buffer poll error: %s",
                          strerror(-n));
            return -1;
        }
        if (n > 0)
            total += n;
    }

    return total;
}

void jz_ringbuf_stop(jz_ringbuf_t *rb)
{
    if (rb)
        rb->running = false;
}

void jz_ringbuf_stats(const jz_ringbuf_t *rb,
                      uint64_t *events_received,
                      uint64_t *events_dropped,
                      uint64_t *samples_received,
                      uint64_t *samples_dropped)
{
    if (!rb)
        return;
    if (events_received)  *events_received  = rb->events_received;
    if (events_dropped)   *events_dropped   = rb->events_dropped;
    if (samples_received) *samples_received = rb->samples_received;
    if (samples_dropped)  *samples_dropped  = rb->samples_dropped;
}

void jz_ringbuf_destroy(jz_ringbuf_t *rb)
{
    if (!rb)
        return;

    rb->running = false;

    if (rb->event_rb) {
        ring_buffer__free((struct ring_buffer *)rb->event_rb);
        rb->event_rb = NULL;
    }

    if (rb->sample_rb) {
        ring_buffer__free((struct ring_buffer *)rb->sample_rb);
        rb->sample_rb = NULL;
    }

    if (rb->event_map_fd >= 0) {
        close(rb->event_map_fd);
        rb->event_map_fd = -1;
    }

    if (rb->sample_map_fd >= 0) {
        close(rb->sample_map_fd);
        rb->sample_map_fd = -1;
    }

    rb->initialized = false;
}
