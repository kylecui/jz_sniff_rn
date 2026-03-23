#include "staged.h"
#include "../common/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cJSON.h>

static void staged_free_change(jz_staged_change_t *change)
{
    if (!change)
        return;

    free(change->json);
    change->json = NULL;
    change->section[0] = '\0';
    change->staged_at = (time_t)0;
}

void jz_staged_init(jz_staged_t *s, int ttl_sec)
{
    if (!s)
        return;

    memset(s, 0, sizeof(*s));
    s->ttl_sec = (ttl_sec <= 0) ? JZ_STAGED_DEFAULT_TTL : ttl_sec;
}

void jz_staged_destroy(jz_staged_t *s)
{
    if (!s)
        return;

    for (int i = 0; i < s->count; i++)
        staged_free_change(&s->changes[i]);

    memset(s, 0, sizeof(*s));
}

int jz_staged_add(jz_staged_t *s, const char *section, const char *json)
{
    time_t now;
    char *dup;

    if (!s || !section || !json)
        return -1;

    if (section[0] == '\0' || strlen(section) >= sizeof(s->changes[0].section))
        return -1;

    now = time(NULL);
    dup = strdup(json);
    if (!dup)
        return -1;

    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->changes[i].section, section) != 0)
            continue;

        free(s->changes[i].json);
        s->changes[i].json = dup;
        s->changes[i].staged_at = now;
        s->last_stage_time = now;
        return 0;
    }

    if (s->count >= JZ_STAGED_MAX_CHANGES) {
        free(dup);
        return -1;
    }

    jz_staged_change_t *change = &s->changes[s->count++];
    snprintf(change->section, sizeof(change->section), "%s", section);
    change->json = dup;
    change->staged_at = now;
    s->last_stage_time = now;

    return 0;
}

int jz_staged_count(const jz_staged_t *s)
{
    if (!s)
        return 0;
    return s->count;
}

char *jz_staged_serialize(const jz_staged_t *s)
{
    time_t now;
    int age_sec = 0;
    cJSON *root;
    cJSON *arr;

    if (!s)
        return NULL;

    now = time(NULL);
    if (s->count > 0 && s->last_stage_time > 0) {
        time_t delta = now - s->last_stage_time;
        if (delta > 0)
            age_sec = (int)delta;
    }

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    if (!cJSON_AddNumberToObject(root, "count", s->count) ||
        !cJSON_AddNumberToObject(root, "ttl", s->ttl_sec) ||
        !cJSON_AddNumberToObject(root, "age_sec", age_sec)) {
        cJSON_Delete(root);
        return NULL;
    }

    arr = cJSON_AddArrayToObject(root, "changes");
    if (!arr) {
        cJSON_Delete(root);
        return NULL;
    }

    for (int i = 0; i < s->count; i++) {
        const jz_staged_change_t *ch = &s->changes[i];
        cJSON *item = cJSON_CreateObject();
        cJSON *parsed = NULL;

        if (!item) {
            cJSON_Delete(root);
            return NULL;
        }

        if (!cJSON_AddStringToObject(item, "section", ch->section)) {
            cJSON_Delete(item);
            cJSON_Delete(root);
            return NULL;
        }

        parsed = cJSON_Parse(ch->json ? ch->json : "");
        if (parsed) {
            if (!cJSON_AddItemToObject(item, "json", parsed)) {
                cJSON_Delete(parsed);
                cJSON_Delete(item);
                cJSON_Delete(root);
                return NULL;
            }
        } else {
            if (!cJSON_AddStringToObject(item, "json", ch->json ? ch->json : "")) {
                cJSON_Delete(item);
                cJSON_Delete(root);
                return NULL;
            }
        }

        if (!cJSON_AddItemToArray(arr, item)) {
            cJSON_Delete(item);
            cJSON_Delete(root);
            return NULL;
        }
    }

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *jz_staged_merge(const jz_staged_t *s, const jz_config_t *current)
{
    cJSON *root;
    char *out;
    char *base;

    if (!s || !current)
        return NULL;

    base = jz_config_serialize(current);
    if (!base)
        return NULL;
    free(base);

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    for (int i = 0; i < s->count; i++) {
        const jz_staged_change_t *ch = &s->changes[i];
        cJSON *parsed = cJSON_Parse(ch->json ? ch->json : "");

        if (parsed) {
            if (!cJSON_AddItemToObject(root, ch->section, parsed)) {
                cJSON_Delete(parsed);
                cJSON_Delete(root);
                return NULL;
            }
        }
        else if (!cJSON_AddStringToObject(root, ch->section, ch->json ? ch->json : "")) {
            cJSON_Delete(root);
            return NULL;
        }
    }

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!out)
        jz_log_error("staged merge: failed to serialize staged object");

    return out;
}

void jz_staged_discard(jz_staged_t *s)
{
    if (!s)
        return;

    for (int i = 0; i < s->count; i++)
        staged_free_change(&s->changes[i]);

    s->count = 0;
    s->last_stage_time = (time_t)0;
}

int jz_staged_check_expiry(jz_staged_t *s)
{
    time_t now;
    time_t age;
    int ttl_sec;

    if (!s || s->count == 0)
        return 0;

    now = time(NULL);
    age = now - s->last_stage_time;
    if (age < (time_t)0)
        age = (time_t)0;

    ttl_sec = (s->ttl_sec <= 0) ? JZ_STAGED_DEFAULT_TTL : s->ttl_sec;

    if (age < (time_t)ttl_sec)
        return 0;

    jz_staged_discard(s);
    return 1;
}
