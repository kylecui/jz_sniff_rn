/* SPDX-License-Identifier: MIT */

#include "fingerprint.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FP_ETH_HDR_LEN           14U
#define FP_IPV4_HDR_MIN_LEN      20U
#define FP_UDP_HDR_LEN           8U
#define FP_DHCP_OPT_OFFSET       282U
#define FP_MDNS_PAYLOAD_OFFSET   42U
#define FP_SSDP_PAYLOAD_OFFSET   42U
#define FP_LLDP_OFFSET           14U
#define FP_CDP_OFFSET            22U

typedef struct {
    uint32_t prefix;
    const char *vendor;
} fp_oui_entry_t;

typedef struct {
    uint8_t seq[16];
    uint8_t seq_len;
    uint8_t match_len;
    const char *os_class;
    const char *device_class;
} fp_dhcp_opt55_fp_t;

typedef struct {
    const char *needle;
    const char *vendor;
    const char *os_class;
    const char *device_class;
} fp_signature_t;

static fp_oui_entry_t g_oui_table[] = {
#include "oui_table.inc"
};

static const fp_dhcp_opt55_fp_t g_opt55_table[] = {
    { {1, 3, 6, 15, 31, 33, 43, 44}, 8, 6, "Windows 10/11", "Computer" },
    { {1, 3, 6, 15, 31, 33, 43, 44, 46}, 9, 7, "Windows 10/11", "Computer" },
    { {1, 15, 3, 6, 44, 46, 47, 31}, 8, 6, "Windows 7/8", "Computer" },
    { {1, 3, 6, 12, 15, 26, 28, 51}, 8, 6, "Windows", "Computer" },
    { {1, 3, 6, 12, 15, 31, 33, 43}, 8, 6, "Windows", "Computer" },
    { {1, 3, 6, 12, 15, 28, 51, 58}, 8, 6, "Windows", "Computer" },
    { {1, 3, 6, 15, 119, 252, 95, 44}, 8, 6, "Windows 10/11", "Computer" },
    { {1, 121, 3, 6, 15, 119, 252}, 7, 5, "Windows 10/11", "Computer" },
    { {1, 3, 6, 15, 119, 44, 46, 47}, 8, 6, "Windows", "Computer" },
    { {1, 33, 3, 6, 15, 119, 252}, 7, 5, "Windows", "Computer" },
    { {1, 3, 6, 15, 119, 252, 42, 44}, 8, 6, "Windows", "Computer" },
    { {1, 3, 6, 15, 26, 28, 51, 58}, 8, 6, "Windows", "Computer" },
    { {1, 3, 6, 15, 119, 252}, 6, 4, "macOS", "Computer" },
    { {1, 3, 6, 15, 119, 252, 95}, 7, 5, "macOS", "Computer" },
    { {1, 121, 3, 6, 15, 119, 252, 95}, 8, 6, "macOS", "Computer" },
    { {1, 3, 6, 15, 119, 252, 95, 114}, 8, 6, "macOS", "Computer" },
    { {1, 3, 6, 15, 119, 252, 95, 44, 46}, 9, 7, "macOS", "Computer" },
    { {1, 3, 6, 15, 119, 252, 95, 17}, 8, 6, "iOS", "Phone" },
    { {1, 3, 6, 15, 119, 252, 95, 17, 43}, 9, 7, "iOS", "Phone" },
    { {1, 3, 6, 15, 119, 252, 17}, 7, 5, "iOS", "Phone" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59}, 9, 7, "Android", "Phone" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59, 43}, 10, 8, "Android", "Phone" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114}, 11, 8, "Android", "Phone" },
    { {1, 3, 6, 15, 28, 51, 58, 59}, 8, 6, "Android", "Phone" },
    { {1, 3, 6, 15, 119, 252, 26, 28}, 8, 6, "Android", "Phone" },
    { {1, 3, 6, 12, 15, 28, 51, 58, 59}, 9, 7, "Android", "Phone" },
    { {1, 28, 2, 3, 15, 6, 12}, 7, 5, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 28}, 7, 5, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 28, 42}, 8, 6, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 42, 51}, 8, 6, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 42, 51, 58}, 9, 7, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 42, 51, 58, 59}, 10, 7, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 42, 51}, 8, 6, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 42, 51, 58}, 9, 7, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 42, 51, 58, 59}, 10, 7, "Linux", "Computer" },
    { {1, 3, 6, 12, 15, 26, 42, 51, 58, 59, 119}, 11, 8, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 42}, 7, 5, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 51}, 7, 5, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59, 119}, 10, 8, "Linux", "Computer" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59, 119, 252}, 11, 8, "ChromeOS", "Computer" },
    { {1, 3, 6, 15, 26, 28, 51, 58, 59, 119, 252, 114}, 12, 8, "ChromeOS", "Computer" },
    { {1, 3, 6, 12, 15, 43, 150, 119}, 8, 6, "Cisco IOS", "Phone" },
    { {1, 3, 6, 12, 15, 43, 150}, 7, 5, "Cisco IOS", "Phone" },
    { {1, 3, 6, 12, 15, 44, 46, 47}, 8, 6, "Cisco IOS", "Phone" },
    { {1, 3, 6, 12, 15, 43, 66, 150}, 8, 6, "Cisco IOS", "Phone" },
    { {1, 3, 6, 12, 15, 43, 60, 66}, 8, 6, "HP Embedded", "Printer" },
    { {1, 3, 6, 12, 15, 43, 60, 81}, 8, 6, "HP Embedded", "Printer" },
    { {1, 3, 6, 12, 15, 43, 60, 119}, 8, 6, "HP Embedded", "Printer" },
    { {1, 3, 6, 12, 15, 43, 60}, 7, 5, "Printer Firmware", "Printer" },
    { {1, 3, 6, 12, 15, 26}, 6, 4, "IoT Linux", "IoT" },
    { {1, 3, 6, 12, 15, 26, 28, 42, 114}, 9, 6, "IoT Linux", "IoT" },
    { {1, 3, 6, 12, 15, 26, 28, 42, 43}, 9, 6, "IoT Linux", "IoT" },
    { {1, 3, 6, 12, 15, 26, 28, 42, 43, 119}, 10, 7, "IoT Linux", "IoT" }
};

static const fp_signature_t g_opt60_table[] = {
    { "MSFT", "Microsoft", "Windows", "Computer" },
    { "android-dhcp", "Google", "Android", "Phone" },
    { "dhcpcd", "Linux", "Linux", "Computer" },
    { "udhcp", "Linux", "Linux", "IoT" },
    { "systemd", "Linux", "Linux", "Computer" },
    { "apple", "Apple", "iOS", "Phone" },
    { "iphone", "Apple", "iOS", "Phone" },
    { "ipad", "Apple", "iOS", "Phone" },
    { "macbook", "Apple", "macOS", "Computer" },
    { "chromebook", "Google", "ChromeOS", "Computer" },
    { "cisco", "Cisco", "Cisco IOS", "Switch" },
    { "ipphone", "Cisco", "Cisco IOS", "Phone" },
    { "printer", "HP", "Printer Firmware", "Printer" },
    { "hp jetdirect", "HP", "HP Embedded", "Printer" },
    { "fortinet", "Fortinet", "FortiOS", "Firewall" },
    { "vmware", "VMware", "VMware", "Computer" },
    { "espressif", "Espressif", "IoT RTOS", "IoT" },
    { "ubnt", "Ubiquiti", "Linux", "Switch" },
    { "mikrotik", "MikroTik", "RouterOS", "Switch" },
    { "synology", "Synology", "Linux", "IoT" }
};

static const fp_signature_t g_mdns_sigs[] = {
    { "_airplay._tcp", "Apple", "iOS", "Phone" },
    { "_raop._tcp", "Apple", "iOS", "Phone" },
    { "_googlecast._tcp", "Google", "Android", "IoT" },
    { "_spotify-connect._tcp", "Spotify", "Linux", "IoT" },
    { "_printer._tcp", "Unknown", "Printer Firmware", "Printer" },
    { "_ipp._tcp", "Unknown", "Printer Firmware", "Printer" },
    { "_ipps._tcp", "Unknown", "Printer Firmware", "Printer" },
    { "_smb._tcp", "Microsoft", "Windows", "Computer" },
    { "_workstation._tcp", "Microsoft", "Windows", "Computer" },
    { "_hap._tcp", "Apple", "iOS", "IoT" }
};

static const fp_signature_t g_ssdp_sigs[] = {
    { "upnp/1.0 dlnadoc", "Unknown", "Media Firmware", "IoT" },
    { "microsoft-windows", "Microsoft", "Windows", "Computer" },
    { "linux/", "Linux", "Linux", "Computer" },
    { "ubuntu", "Linux", "Linux", "Computer" },
    { "synology", "Synology", "Linux", "IoT" },
    { "xbox", "Microsoft", "Xbox OS", "IoT" },
    { "playstation", "Sony", "Orbis OS", "IoT" },
    { "roku", "Roku", "Linux", "IoT" },
    { "smarttv", "Samsung", "Tizen", "IoT" }
};

static bool g_oui_sorted;

static int cmp_oui_key(const void *a, const void *b)
{
    const uint32_t *key = (const uint32_t *)a;
    const fp_oui_entry_t *entry = (const fp_oui_entry_t *)b;

    if (*key < entry->prefix)
        return -1;
    if (*key > entry->prefix)
        return 1;
    return 0;
}

static uint32_t fp_now_sec(void)
{
    time_t t = time(NULL);

    if (t < 0)
        return 0;
    return (uint32_t)t;
}

static size_t fp_strnlen_local(const char *s, size_t max_len)
{
    size_t i;

    if (!s)
        return 0;

    for (i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    return max_len;
}

static void fp_copy_cstr(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0)
        return;

    if (!src) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_sz, "%s", src);
}

static bool fp_assign_if_empty(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0 || !src || src[0] == '\0')
        return false;

    if (dst[0] != '\0')
        return false;

    fp_copy_cstr(dst, dst_sz, src);
    return true;
}

static bool fp_assign_or_update(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0 || !src || src[0] == '\0')
        return false;

    if (strncmp(dst, src, dst_sz) == 0)
        return false;

    fp_copy_cstr(dst, dst_sz, src);
    return true;
}

static void fp_copy_printable(char *dst, size_t dst_sz, const uint8_t *src, size_t src_len)
{
    size_t i;
    size_t w;

    if (!dst || dst_sz == 0) {
        return;
    }

    dst[0] = '\0';
    if (!src || src_len == 0)
        return;

    w = 0;
    for (i = 0; i < src_len && w + 1 < dst_sz; i++) {
        unsigned char c = src[i];
        if (c == '\0')
            break;
        if (isprint(c))
            dst[w++] = (char)c;
        else if (c == '\r' || c == '\n' || c == '\t')
            dst[w++] = ' ';
    }

    while (w > 0 && dst[w - 1] == ' ')
        w--;

    dst[w] = '\0';
}

static void fp_to_lower_ascii(char *buf)
{
    size_t i;
    size_t len;

    if (!buf)
        return;

    len = strlen(buf);
    for (i = 0; i < len; i++)
        buf[i] = (char)tolower((unsigned char)buf[i]);
}

static bool fp_mem_case_contains(const uint8_t *buf, size_t len, const char *needle)
{
    size_t nlen;
    size_t i;
    size_t j;

    if (!buf || !needle)
        return false;

    nlen = strlen(needle);
    if (nlen == 0 || nlen > len)
        return false;

    for (i = 0; i + nlen <= len; i++) {
        bool ok = true;
        for (j = 0; j < nlen; j++) {
            unsigned char a = (unsigned char)buf[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (tolower(a) != tolower(b)) {
                ok = false;
                break;
            }
        }
        if (ok)
            return true;
    }

    return false;
}

static bool fp_set_signature(fp_signature_t sig, device_profile_t *profile)
{
    bool changed = false;

    if (!profile)
        return false;

    if (sig.vendor && strcmp(sig.vendor, "Unknown") != 0)
        changed = fp_assign_if_empty(profile->vendor, sizeof(profile->vendor), sig.vendor) || changed;
    if (sig.os_class)
        changed = fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), sig.os_class) || changed;
    if (sig.device_class)
        changed = fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), sig.device_class) || changed;

    return changed;
}

static bool fp_dhcp_opt55_match(const uint8_t *opt, uint8_t opt_len,
                                const fp_dhcp_opt55_fp_t *fp)
{
    uint8_t i;
    uint8_t need;

    if (!opt || !fp)
        return false;
    if (fp->seq_len == 0 || fp->match_len == 0)
        return false;

    need = fp->match_len;
    if (need > fp->seq_len)
        need = fp->seq_len;
    if (need > opt_len)
        return false;

    for (i = 0; i < need; i++) {
        if (opt[i] != fp->seq[i])
            return false;
    }

    return true;
}

static uint8_t fp_recalc_confidence(const device_profile_t *profile)
{
    uint16_t score = 0;

    if (!profile)
        return 0;

    if ((profile->signals & FP_SIG_OUI) != 0)
        score += FP_SCORE_OUI;

    if ((profile->signals & FP_SIG_DHCP) != 0) {
        if (profile->os_class[0] != '\0')
            score += FP_SCORE_DHCP_OPT55;
        if (profile->vendor[0] != '\0')
            score += FP_SCORE_DHCP_OPT60;
    }

    if ((profile->signals & FP_SIG_MDNS) != 0)
        score += FP_SCORE_MDNS;

    if ((profile->signals & FP_SIG_SSDP) != 0)
        score += FP_SCORE_SSDP;

    if ((profile->signals & FP_SIG_LLDP) != 0)
        score += FP_SCORE_LLDP;

    if ((profile->signals & FP_SIG_CDP) != 0)
        score += FP_SCORE_LLDP;

    if (fp_mem_case_contains((const uint8_t *)profile->device_model,
                             fp_strnlen_local(profile->device_model, sizeof(profile->device_model)),
                             "lldp-med")) {
        score += (uint16_t)(FP_SCORE_LLDP_MED - FP_SCORE_LLDP);
    }

    if (score > 100)
        score = 100;

    return (uint8_t)score;
}

static int fp_parse_dhcp(device_profile_t *profile,
                         const uint8_t *payload,
                         uint32_t payload_len)
{
    uint32_t off;
    bool got_opt55 = false;
    bool got_opt60 = false;

    if (!profile || !payload)
        return -1;

    if (payload_len <= FP_DHCP_OPT_OFFSET)
        return -1;

    off = FP_DHCP_OPT_OFFSET;

    while (off < payload_len) {
        uint8_t code;
        uint8_t len;

        code = payload[off++];
        if (code == 0)
            continue;
        if (code == 255)
            break;
        if (off >= payload_len)
            break;

        len = payload[off++];
        if ((uint32_t)len > payload_len - off)
            break;

        if (code == 12 && len > 0) {
            char host[sizeof(profile->hostname)];
            fp_copy_printable(host, sizeof(host), payload + off, len);
            if (host[0] != '\0')
                fp_assign_or_update(profile->hostname, sizeof(profile->hostname), host);
        } else if (code == 55 && len > 0) {
            size_t i;

            for (i = 0; i < sizeof(g_opt55_table) / sizeof(g_opt55_table[0]); i++) {
                const fp_dhcp_opt55_fp_t *fp = &g_opt55_table[i];
                if (fp_dhcp_opt55_match(payload + off, len, fp)) {
                    if (fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), fp->os_class))
                        got_opt55 = true;
                    if (fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), fp->device_class))
                        got_opt55 = true;
                    break;
                }
            }
        } else if (code == 60 && len > 0) {
            char opt60[96];
            char opt60_lc[96];
            size_t i;

            fp_copy_printable(opt60, sizeof(opt60), payload + off, len);
            fp_copy_cstr(opt60_lc, sizeof(opt60_lc), opt60);
            fp_to_lower_ascii(opt60_lc);

            if (opt60[0] != '\0') {
                bool vendor_changed = fp_assign_if_empty(profile->vendor, sizeof(profile->vendor), opt60);
                if (vendor_changed)
                    got_opt60 = true;
            }

            for (i = 0; i < sizeof(g_opt60_table) / sizeof(g_opt60_table[0]); i++) {
                if (strstr(opt60_lc, g_opt60_table[i].needle)) {
                    if (fp_set_signature(g_opt60_table[i], profile))
                        got_opt60 = true;
                    break;
                }
            }
        }

        off += len;
    }

    if (got_opt55 || got_opt60)
        return 0;

    return 0;
}

static void fp_mdns_name_from_labels(const uint8_t *buf,
                                     size_t len,
                                     size_t start,
                                     char *out,
                                     size_t out_sz)
{
    size_t p;
    size_t w;

    if (!buf || !out || out_sz == 0 || start >= len) {
        return;
    }

    out[0] = '\0';
    p = start;
    w = 0;

    while (p < len) {
        uint8_t l = buf[p++];
        size_t i;

        if (l == 0)
            break;

        if ((l & 0xC0U) == 0xC0U)
            break;

        if (l > 63 || p + l > len)
            break;

        for (i = 0; i < l && w + 1 < out_sz; i++) {
            unsigned char c = buf[p + i];
            out[w++] = (char)tolower(c);
        }

        p += l;
        if (w + 1 < out_sz)
            out[w++] = '.';
    }

    if (w > 0 && out[w - 1] == '.')
        w--;
    out[w] = '\0';
}

static int fp_parse_mdns(device_profile_t *profile,
                         const uint8_t *payload,
                         uint32_t payload_len)
{
    uint32_t off;
    size_t i;
    bool matched = false;

    if (!profile || !payload)
        return -1;

    if (payload_len <= FP_MDNS_PAYLOAD_OFFSET + 12U)
        return -1;

    off = FP_MDNS_PAYLOAD_OFFSET;

    for (i = off; i + 4 < payload_len; i++) {
        char name[128];
        size_t s;

        if (payload[i] == 0 || payload[i] > 63)
            continue;

        fp_mdns_name_from_labels(payload, payload_len, i, name, sizeof(name));
        if (name[0] == '\0')
            continue;

        for (s = 0; s < sizeof(g_mdns_sigs) / sizeof(g_mdns_sigs[0]); s++) {
            if (strstr(name, g_mdns_sigs[s].needle) != NULL) {
                if (fp_set_signature(g_mdns_sigs[s], profile))
                    matched = true;
            }
        }

        if (strstr(name, "_tcp.local") != NULL || strstr(name, "_udp.local") != NULL)
            matched = true;
    }

    return matched ? 0 : 0;
}

static void fp_trim(char *s)
{
    size_t len;
    size_t i;

    if (!s)
        return;

    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';

    i = 0;
    while (s[i] && isspace((unsigned char)s[i]))
        i++;

    if (i > 0)
        memmove(s, s + i, strlen(s + i) + 1U);
}

static void fp_ssdp_apply_signature(device_profile_t *profile, const char *line)
{
    char lower[256];
    size_t i;

    if (!profile || !line)
        return;

    fp_copy_cstr(lower, sizeof(lower), line);
    fp_to_lower_ascii(lower);

    for (i = 0; i < sizeof(g_ssdp_sigs) / sizeof(g_ssdp_sigs[0]); i++) {
        if (strstr(lower, g_ssdp_sigs[i].needle) != NULL)
            fp_set_signature(g_ssdp_sigs[i], profile);
    }
}

static int fp_parse_ssdp(device_profile_t *profile,
                         const uint8_t *payload,
                         uint32_t payload_len)
{
    uint32_t off;
    uint32_t p;
    bool any = false;

    if (!profile || !payload)
        return -1;

    if (payload_len <= FP_SSDP_PAYLOAD_OFFSET)
        return -1;

    off = FP_SSDP_PAYLOAD_OFFSET;
    p = off;

    while (p < payload_len) {
        char line[256];
        size_t w = 0;

        while (p < payload_len && payload[p] != '\n' && w + 1 < sizeof(line)) {
            unsigned char c = payload[p++];
            if (c == '\r')
                continue;
            if (isprint(c) || c == '\t')
                line[w++] = (char)c;
        }

        while (p < payload_len && payload[p] != '\n')
            p++;
        if (p < payload_len && payload[p] == '\n')
            p++;

        line[w] = '\0';
        fp_trim(line);
        if (line[0] == '\0')
            continue;

        if (strncasecmp(line, "SERVER:", 7) == 0) {
            char *val = line + 7;
            fp_trim(val);
            fp_ssdp_apply_signature(profile, val);
            any = true;
        } else if (strncasecmp(line, "USN:", 4) == 0) {
            char *val = line + 4;
            fp_trim(val);
            fp_ssdp_apply_signature(profile, val);
            if (fp_mem_case_contains((const uint8_t *)val, strlen(val), "synology"))
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "IoT");
            any = true;
        }
    }

    return any ? 0 : 0;
}

static int fp_parse_lldp(device_profile_t *profile,
                         const uint8_t *payload,
                         uint32_t payload_len)
{
    uint32_t off;
    bool seen = false;

    if (!profile || !payload)
        return -1;
    if (payload_len <= FP_LLDP_OFFSET + 2U)
        return -1;

    off = FP_LLDP_OFFSET;

    while (off + 2U <= payload_len) {
        uint16_t hdr;
        uint16_t tlv_type;
        uint16_t tlv_len;
        const uint8_t *val;

        memcpy(&hdr, payload + off, sizeof(hdr));
        hdr = ntohs(hdr);
        off += 2U;

        tlv_type = (uint16_t)((hdr >> 9) & 0x7FU);
        tlv_len = (uint16_t)(hdr & 0x1FFU);

        if (off + tlv_len > payload_len)
            break;

        val = payload + off;
        if (tlv_type == 0)
            break;

        if (tlv_type == 5 && tlv_len > 0) {
            char sys_name[sizeof(profile->hostname)];
            fp_copy_printable(sys_name, sizeof(sys_name), val, tlv_len);
            if (sys_name[0] != '\0') {
                fp_assign_or_update(profile->hostname, sizeof(profile->hostname), sys_name);
                seen = true;
            }
        } else if (tlv_type == 6 && tlv_len > 0) {
            char sys_desc[128];
            char sys_desc_lc[128];

            fp_copy_printable(sys_desc, sizeof(sys_desc), val, tlv_len);
            fp_copy_cstr(sys_desc_lc, sizeof(sys_desc_lc), sys_desc);
            fp_to_lower_ascii(sys_desc_lc);

            if (sys_desc[0] != '\0') {
                fp_assign_if_empty(profile->device_model, sizeof(profile->device_model), sys_desc);
                seen = true;
            }

            if (strstr(sys_desc_lc, "cisco ios") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "Cisco IOS");
            else if (strstr(sys_desc_lc, "windows") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "Windows");
            else if (strstr(sys_desc_lc, "linux") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "Linux");
            else if (strstr(sys_desc_lc, "ios") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "iOS");

            if (strstr(sys_desc_lc, "switch") != NULL)
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "Switch");
            else if (strstr(sys_desc_lc, "router") != NULL)
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "Switch");
        } else if (tlv_type == 127 && tlv_len >= 4) {
            if (val[0] == 0x00U && val[1] == 0x12U && val[2] == 0xBBU) {
                char med_hint[sizeof(profile->device_model)];
                fp_copy_cstr(med_hint, sizeof(med_hint), "LLDP-MED endpoint");
                fp_assign_or_update(profile->device_model, sizeof(profile->device_model), med_hint);
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "Phone");
                seen = true;
            }
        }

        off += tlv_len;
    }

    return seen ? 0 : 0;
}

static int fp_parse_cdp(device_profile_t *profile,
                        const uint8_t *payload,
                        uint32_t payload_len)
{
    uint32_t off;
    bool seen = false;

    if (!profile || !payload)
        return -1;
    if (payload_len <= FP_CDP_OFFSET + 4U)
        return -1;

    off = FP_CDP_OFFSET + 4U;

    while (off + 4U <= payload_len) {
        uint16_t t;
        uint16_t l;

        memcpy(&t, payload + off, sizeof(t));
        memcpy(&l, payload + off + 2U, sizeof(l));
        t = ntohs(t);
        l = ntohs(l);

        if (l < 4)
            break;
        if (off + l > payload_len)
            break;

        if (t == 0x0001U) {
            char id[sizeof(profile->hostname)];
            fp_copy_printable(id, sizeof(id), payload + off + 4U, l - 4U);
            if (id[0] != '\0') {
                fp_assign_or_update(profile->hostname, sizeof(profile->hostname), id);
                seen = true;
            }
        } else if (t == 0x0005U) {
            char ver[96];
            char ver_lc[96];

            fp_copy_printable(ver, sizeof(ver), payload + off + 4U, l - 4U);
            fp_copy_cstr(ver_lc, sizeof(ver_lc), ver);
            fp_to_lower_ascii(ver_lc);

            if (strstr(ver_lc, "ios") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "Cisco IOS");
            else if (strstr(ver_lc, "nx-os") != NULL)
                fp_assign_if_empty(profile->os_class, sizeof(profile->os_class), "Cisco NX-OS");

            seen = true;
        } else if (t == 0x0006U) {
            char platform[sizeof(profile->device_model)];
            fp_copy_printable(platform, sizeof(platform), payload + off + 4U, l - 4U);
            if (platform[0] != '\0') {
                fp_assign_or_update(profile->device_model, sizeof(profile->device_model), platform);
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "Switch");
                seen = true;
            }
        }

        off += l;
    }

    return seen ? 0 : 0;
}

int fp_init(void)
{
    /* OUI table from oui_table.inc is already sorted by prefix.
     * No need for runtime qsort(). */
    g_oui_sorted = true;

    return 0;
}

void fp_destroy(void)
{
}

const char *fp_lookup_oui(const uint8_t mac[6])
{
    uint32_t key;
    fp_oui_entry_t *entry;

    if (!mac)
        return "Unknown";

    if (!g_oui_sorted)
        fp_init();

    key = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];

    entry = (fp_oui_entry_t *)bsearch(&key,
                                      g_oui_table,
                                      sizeof(g_oui_table) / sizeof(g_oui_table[0]),
                                      sizeof(g_oui_table[0]),
                                      cmp_oui_key);
    if (!entry)
        return "Unknown";

    return entry->vendor;
}

uint8_t fp_get_confidence(const device_profile_t *profile)
{
    if (!profile)
        return 0;
    return profile->confidence;
}

int fp_update_profile(device_profile_t *profile,
                      uint8_t proto,
                      const uint8_t *payload,
                      uint32_t payload_len)
{
    uint8_t signal = 0;
    int rc = -1;
    uint32_t now;

    if (!profile || !payload || payload_len == 0)
        return -1;

    now = fp_now_sec();
    if (profile->first_seen == 0)
        profile->first_seen = now;
    profile->last_seen = now;

    if (profile->vendor[0] == '\0') {
        const char *v = fp_lookup_oui(profile->mac);
        if (v && strcmp(v, "Unknown") != 0) {
            fp_assign_if_empty(profile->vendor, sizeof(profile->vendor), v);
            signal |= FP_SIG_OUI;
            if (profile->device_class[0] == '\0')
                fp_assign_if_empty(profile->device_class, sizeof(profile->device_class), "Computer");
        }
    } else if (profile->signals & FP_SIG_OUI) {
        signal |= FP_SIG_OUI;
    }

    switch (proto) {
    case FP_PROTO_ARP:
        rc = 0;
        break;
    case FP_PROTO_DHCP:
        rc = fp_parse_dhcp(profile, payload, payload_len);
        if (rc == 0)
            signal |= FP_SIG_DHCP;
        break;
    case FP_PROTO_MDNS:
        rc = fp_parse_mdns(profile, payload, payload_len);
        if (rc == 0)
            signal |= FP_SIG_MDNS;
        break;
    case FP_PROTO_SSDP:
        rc = fp_parse_ssdp(profile, payload, payload_len);
        if (rc == 0)
            signal |= FP_SIG_SSDP;
        break;
    case FP_PROTO_LLDP:
        rc = fp_parse_lldp(profile, payload, payload_len);
        if (rc == 0)
            signal |= FP_SIG_LLDP;
        break;
    case FP_PROTO_CDP:
        rc = fp_parse_cdp(profile, payload, payload_len);
        if (rc == 0)
            signal |= FP_SIG_CDP;
        break;
    default:
        return -1;
    }

    profile->signals |= signal;
    profile->confidence = fp_recalc_confidence(profile);

    return rc;
}
