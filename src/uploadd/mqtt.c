/* SPDX-License-Identifier: MIT */
/* mqtt.c — MQTT client wrapper using Paho Embedded-C. */

#include "mqtt.h"

#if __has_include("log.h")
#include "log.h"
#elif __has_include("../common/log.h")
#include "../common/log.h"
#else
#include "log.h"
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#if __has_include("MQTTLinux.h")
#include "MQTTLinux.h"
#elif __has_include("../../third_party/paho-embed/MQTTLinux.h")
#include "../../third_party/paho-embed/MQTTLinux.h"
#else
#include "MQTTLinux.h"
#endif

#if __has_include("MQTTClient.h")
#include "MQTTClient.h"
#elif __has_include("../../third_party/paho-embed/MQTTClient.h")
#include "../../third_party/paho-embed/MQTTClient.h"
#else
#include "MQTTClient.h"
#endif

struct jz_mqtt {
    Network       net;
    MQTTClient    client;
    jz_mqtt_cfg_t cfg;             /* copy of config */
    unsigned char sendbuf[1024];
    unsigned char readbuf[1024];
    bool          connected;
    char          topic_buf[256];  /* scratch for building full topic */
};

static void jz_log(int prio, const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0)
        return;

    switch (prio) {
    case LOG_ERR:
        jz_log_error("%s", buf);
        break;
    case LOG_WARNING:
        jz_log_warn("%s", buf);
        break;
    default:
        jz_log_info("%s", buf);
        break;
    }
}

static char *jz_strdup_or_null(const char *s)
{
    if (!s)
        return NULL;
    return strdup(s);
}

static int jz_mqtt_dup_cfg(jz_mqtt_t *m, const jz_mqtt_cfg_t *cfg)
{
    m->cfg.broker_host = jz_strdup_or_null(cfg->broker_host);
    if (cfg->broker_host && !m->cfg.broker_host)
        return -1;

    m->cfg.client_id = jz_strdup_or_null(cfg->client_id);
    if (cfg->client_id && !m->cfg.client_id)
        return -1;

    m->cfg.topic_prefix = jz_strdup_or_null(cfg->topic_prefix);
    if (cfg->topic_prefix && !m->cfg.topic_prefix)
        return -1;

    m->cfg.lwt_topic = jz_strdup_or_null(cfg->lwt_topic);
    if (cfg->lwt_topic && !m->cfg.lwt_topic)
        return -1;

    m->cfg.lwt_message = jz_strdup_or_null(cfg->lwt_message);
    if (cfg->lwt_message && !m->cfg.lwt_message)
        return -1;

    m->cfg.broker_port = cfg->broker_port;
    m->cfg.qos = cfg->qos;
    m->cfg.keepalive_sec = cfg->keepalive_sec;

    return 0;
}

static void jz_mqtt_free_cfg(jz_mqtt_t *m)
{
    if (!m)
        return;

    free((void *)m->cfg.broker_host);
    free((void *)m->cfg.client_id);
    free((void *)m->cfg.topic_prefix);
    free((void *)m->cfg.lwt_topic);
    free((void *)m->cfg.lwt_message);

    m->cfg.broker_host = NULL;
    m->cfg.client_id = NULL;
    m->cfg.topic_prefix = NULL;
    m->cfg.lwt_topic = NULL;
    m->cfg.lwt_message = NULL;
}

static int jz_mqtt_build_topic(jz_mqtt_t *m, const char *subtopic)
{
    int n;

    n = snprintf(m->topic_buf, sizeof(m->topic_buf), "%s/%s",
                 m->cfg.topic_prefix ? m->cfg.topic_prefix : "",
                 subtopic ? subtopic : "");
    if (n < 0 || (size_t)n >= sizeof(m->topic_buf)) {
        jz_log(LOG_WARNING,
               "mqtt: topic too long (prefix='%s', subtopic='%s')",
               m->cfg.topic_prefix ? m->cfg.topic_prefix : "",
               subtopic ? subtopic : "");
        return -1;
    }

    return 0;
}

jz_mqtt_t *jz_mqtt_create(const jz_mqtt_cfg_t *cfg)
{
    jz_mqtt_t *m;

    if (!cfg)
        return NULL;

    m = malloc(sizeof(jz_mqtt_t));
    if (!m)
        return NULL;
    memset(m, 0, sizeof(*m));

    if (jz_mqtt_dup_cfg(m, cfg) < 0)
        goto fail;

    NetworkInit(&m->net);
    MQTTClientInit(&m->client, &m->net, 5000,
                   m->sendbuf, sizeof(m->sendbuf),
                   m->readbuf, sizeof(m->readbuf));

    return m;

fail:
    jz_mqtt_free_cfg(m);
    free(m);
    return NULL;
}

int jz_mqtt_connect(jz_mqtt_t *m)
{
    MQTTPacket_connectData opts = MQTTPacket_connectData_initializer;
    int rc;

    if (!m || !m->cfg.broker_host)
        return -1;

    rc = NetworkConnect(&m->net, (char *)m->cfg.broker_host, m->cfg.broker_port);
    if (rc != 0) {
        jz_log(LOG_ERR, "mqtt: TCP connect to %s:%d failed: %d",
               m->cfg.broker_host, m->cfg.broker_port, rc);
        return -1;
    }

    opts.MQTTVersion = 4;  /* MQTT 3.1.1 */
    opts.clientID.cstring = (char *)m->cfg.client_id;
    opts.keepAliveInterval = m->cfg.keepalive_sec;
    opts.cleansession = 1;

    /* Last Will & Testament */
    if (m->cfg.lwt_topic && m->cfg.lwt_message) {
        opts.willFlag = 1;
        opts.will.topicName.cstring = (char *)m->cfg.lwt_topic;
        opts.will.message.cstring = (char *)m->cfg.lwt_message;
        opts.will.retained = 1;
        opts.will.qos = 1;
    }

    rc = MQTTConnect(&m->client, &opts);
    if (rc != SUCCESS) {
        jz_log(LOG_ERR, "mqtt: CONNECT to %s:%d failed: %d",
               m->cfg.broker_host, m->cfg.broker_port, rc);
        NetworkDisconnect(&m->net);
        return -1;
    }

    m->connected = true;
    jz_log(LOG_INFO, "mqtt: connected to %s:%d as '%s'",
           m->cfg.broker_host, m->cfg.broker_port,
           m->cfg.client_id ? m->cfg.client_id : "");
    return 0;
}

int jz_mqtt_publish(jz_mqtt_t *m, const char *subtopic,
                    const char *payload, int payload_len)
{
    MQTTMessage msg;
    int rc;
    if (!m || !m->connected)
        return -1;
    if (!payload || payload_len < 0)
        return -1;

    /* Build full topic: {prefix}/{subtopic} */
    if (jz_mqtt_build_topic(m, subtopic) < 0)
        return -1;

    memset(&msg, 0, sizeof(msg));
    msg.qos = (enum QoS)m->cfg.qos;
    msg.retained = 0;
    msg.payload = (void *)payload;
    msg.payloadlen = (size_t)payload_len;

    rc = MQTTPublish(&m->client, m->topic_buf, &msg);
    if (rc != SUCCESS) {
        jz_log(LOG_WARNING, "mqtt: publish to '%s' failed: %d", m->topic_buf, rc);
        m->connected = false;
        return -1;
    }

    return 0;
}

int jz_mqtt_yield(jz_mqtt_t *m, int timeout_ms)
{
    int rc;

    if (!m || !m->connected)
        return -1;

    rc = MQTTYield(&m->client, timeout_ms);
    if (rc != SUCCESS) {
        m->connected = false;
        return -1;
    }
    return 0;
}

bool jz_mqtt_is_connected(jz_mqtt_t *m)
{
    return m && m->connected;
}

int jz_mqtt_reconnect(jz_mqtt_t *m)
{
    if (!m)
        return -1;

    /* Disconnect old connection if any */
    if (m->connected) {
        MQTTDisconnect(&m->client);
        NetworkDisconnect(&m->net);
        m->connected = false;
    } else {
        NetworkDisconnect(&m->net);
    }

    /* Re-init client state */
    NetworkInit(&m->net);
    MQTTClientInit(&m->client, &m->net, 5000,
                   m->sendbuf, sizeof(m->sendbuf),
                   m->readbuf, sizeof(m->readbuf));

    return jz_mqtt_connect(m);
}

void jz_mqtt_destroy(jz_mqtt_t *m)
{
    if (!m)
        return;

    if (m->connected) {
        MQTTDisconnect(&m->client);
        NetworkDisconnect(&m->net);
    }

    /* Free strdup'd strings */
    free((void *)m->cfg.broker_host);
    free((void *)m->cfg.client_id);
    free((void *)m->cfg.topic_prefix);
    free((void *)m->cfg.lwt_topic);
    free((void *)m->cfg.lwt_message);

    free(m);
}
