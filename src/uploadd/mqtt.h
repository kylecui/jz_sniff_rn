/* SPDX-License-Identifier: MIT */
/* mqtt.h — MQTT client wrapper for uploadd (Paho Embedded-C). */

#ifndef JZ_MQTT_H
#define JZ_MQTT_H

#include <stdbool.h>

/* Opaque MQTT context */
typedef struct jz_mqtt jz_mqtt_t;

/* MQTT configuration */
typedef struct jz_mqtt_cfg {
    const char *broker_host;        /* e.g. "10.0.1.100" */
    int         broker_port;        /* e.g. 1883 */
    const char *client_id;          /* e.g. "jz-sniff-001" */
    const char *topic_prefix;       /* e.g. "jz/jz-sniff-001" */
    int         qos;                /* 0, 1, or 2 */
    int         keepalive_sec;      /* MQTT keepalive (default 60) */
    /* Last Will & Testament */
    const char *lwt_topic;          /* e.g. "jz/jz-sniff-001/status" */
    const char *lwt_message;        /* e.g. "{\"online\":false}" */
} jz_mqtt_cfg_t;

/* Create MQTT context. Returns NULL on failure. */
jz_mqtt_t *jz_mqtt_create(const jz_mqtt_cfg_t *cfg);

/* Connect to broker. Returns 0 on success. */
int jz_mqtt_connect(jz_mqtt_t *m);

/* Publish a message to topic_prefix/subtopic.
 * subtopic: e.g. "logs/attack", "heartbeat"
 * payload: JSON string
 * Returns 0 on success. */
int jz_mqtt_publish(jz_mqtt_t *m, const char *subtopic,
                    const char *payload, int payload_len);

/* Yield to process keepalive/acks. Call from main loop.
 * timeout_ms: 0 for non-blocking. */
int jz_mqtt_yield(jz_mqtt_t *m, int timeout_ms);

/* Check if connected. */
bool jz_mqtt_is_connected(jz_mqtt_t *m);

/* Reconnect if disconnected. Returns 0 on success. */
int jz_mqtt_reconnect(jz_mqtt_t *m);

/* Disconnect and free. */
void jz_mqtt_destroy(jz_mqtt_t *m);

#endif /* JZ_MQTT_H */
