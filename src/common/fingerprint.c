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
    { 0x001122U, "Cisco" },
    { 0x001A8CU, "Juniper" },
    { 0x001B63U, "Apple" },
    { 0x001B77U, "Intel" },
    { 0x001C23U, "Dell" },
    { 0x001D7EU, "HP" },
    { 0x001E8CU, "Apple" },
    { 0x001F3CU, "Apple" },
    { 0x002128U, "Apple" },
    { 0x002241U, "Apple" },
    { 0x002312U, "Cisco" },
    { 0x00236CU, "Aruba" },
    { 0x00248CU, "Intel" },
    { 0x0024D7U, "Dell" },
    { 0x00259CU, "HP" },
    { 0x002590U, "Huawei" },
    { 0x0026B9U, "Dell" },
    { 0x0026F2U, "Netgear" },
    { 0x0026B0U, "Cisco" },
    { 0x0026F1U, "Aruba" },
    { 0x00270EU, "Ubiquiti" },
    { 0x00270FU, "Cisco" },
    { 0x002722U, "Aruba" },
    { 0x00272DU, "Juniper" },
    { 0x00273CU, "HP" },
    { 0x002788U, "Cisco" },
    { 0x0028F8U, "HP" },
    { 0x0029B8U, "Cisco" },
    { 0x002A10U, "Cisco" },
    { 0x002A6AU, "Aruba" },
    { 0x002B67U, "Apple" },
    { 0x002B8FU, "Dell" },
    { 0x002C6AU, "Huawei" },
    { 0x002D6FU, "Juniper" },
    { 0x00303EU, "Cisco" },
    { 0x003048U, "Cisco" },
    { 0x003065U, "Apple" },
    { 0x0030ABU, "Dell" },
    { 0x0030C1U, "HP" },
    { 0x00313AU, "Cisco" },
    { 0x00316BU, "Synology" },
    { 0x0031C4U, "Dell" },
    { 0x0031D2U, "Juniper" },
    { 0x003248U, "Cisco" },
    { 0x0032A1U, "HP" },
    { 0x0033B7U, "Apple" },
    { 0x0034FEU, "Cisco" },
    { 0x0035A0U, "Dell" },
    { 0x00362AU, "Aruba" },
    { 0x0036B4U, "Lenovo" },
    { 0x0037B7U, "Cisco" },
    { 0x00388EU, "Juniper" },
    { 0x003A9DU, "Cisco" },
    { 0x003B95U, "Aruba" },
    { 0x003C10U, "Cisco" },
    { 0x003C7DU, "HP" },
    { 0x003CC5U, "Dell" },
    { 0x003D23U, "Huawei" },
    { 0x003D73U, "Ruckus" },
    { 0x003E5CU, "Cisco" },
    { 0x003EE1U, "Apple" },
    { 0x004026U, "Cisco" },
    { 0x004052U, "Cisco" },
    { 0x00407FU, "Netgear" },
    { 0x0040D0U, "HP" },
    { 0x0041D2U, "Ubiquiti" },
    { 0x0042A1U, "Samsung" },
    { 0x0043A8U, "Dell" },
    { 0x0044B3U, "Huawei" },
    { 0x00452EU, "Apple" },
    { 0x00458CU, "Aruba" },
    { 0x0045D1U, "Cisco" },
    { 0x0046A5U, "Microsoft" },
    { 0x004742U, "Intel" },
    { 0x0047B3U, "Juniper" },
    { 0x00480FU, "TP-Link" },
    { 0x00498FU, "Ruckus" },
    { 0x004A77U, "Dell" },
    { 0x004B10U, "Ubiquiti" },
    { 0x004BD9U, "Aruba" },
    { 0x004C77U, "HP" },
    { 0x004D7FU, "Cisco" },
    { 0x0050F2U, "Microsoft" },
    { 0x005056U, "VMware" },
    { 0x00507FU, "Cisco" },
    { 0x0050BAU, "D-Link" },
    { 0x0050C2U, "IEEE Registration" },
    { 0x0050D1U, "MikroTik" },
    { 0x0050F3U, "Microsoft" },
    { 0x0050F9U, "Fortinet" },
    { 0x006008U, "Cisco" },
    { 0x00601DU, "Dell" },
    { 0x00602FU, "HP" },
    { 0x006037U, "Cisco" },
    { 0x006047U, "Huawei" },
    { 0x006052U, "Aruba" },
    { 0x00608CU, "3Com" },
    { 0x0060B0U, "HP" },
    { 0x0060DDU, "Apple" },
    { 0x0060E9U, "D-Link" },
    { 0x0060F5U, "Netgear" },
    { 0x006171U, "Cisco" },
    { 0x0061F4U, "TP-Link" },
    { 0x0062ECU, "Cisco" },
    { 0x0062F0U, "Intel" },
    { 0x006320U, "HP" },
    { 0x00635BU, "Aruba" },
    { 0x0063D1U, "Huawei" },
    { 0x0064F1U, "Cisco" },
    { 0x0065A3U, "Juniper" },
    { 0x0067B4U, "Ubiquiti" },
    { 0x0068EBU, "Dell" },
    { 0x006976U, "Apple" },
    { 0x0069FBU, "MikroTik" },
    { 0x006B8EU, "Ruckus" },
    { 0x006C0BU, "HP" },
    { 0x006D52U, "Cisco" },
    { 0x006E4BU, "Samsung" },
    { 0x006F64U, "Aruba" },
    { 0x00704CU, "Apple" },
    { 0x007056U, "Cisco" },
    { 0x007089U, "Juniper" },
    { 0x0070B3U, "Dell" },
    { 0x0070EEU, "HP" },
    { 0x0071CCU, "MikroTik" },
    { 0x00723FU, "Aruba" },
    { 0x0072CFU, "Intel" },
    { 0x00731BU, "Ubiquiti" },
    { 0x0073A6U, "Cisco" },
    { 0x0074D4U, "Ruckus" },
    { 0x00750CU, "TP-Link" },
    { 0x0076B3U, "D-Link" },
    { 0x0077CBU, "Huawei" },
    { 0x00789EU, "Apple" },
    { 0x007A95U, "Cisco" },
    { 0x007B18U, "Netgear" },
    { 0x007C2DU, "Synology" },
    { 0x007D13U, "Lenovo" },
    { 0x008048U, "Compex" },
    { 0x00804FU, "IBM" },
    { 0x008055U, "Cisco" },
    { 0x008069U, "Intel" },
    { 0x00809FU, "HP" },
    { 0x0080C2U, "IEEE Registration" },
    { 0x0080F0U, "Samsung" },
    { 0x0081C4U, "Cisco" },
    { 0x00827BU, "Aruba" },
    { 0x0082A9U, "Ubiquiti" },
    { 0x00830FU, "Dell" },
    { 0x00844BU, "Cisco" },
    { 0x0084D4U, "Huawei" },
    { 0x0085A0U, "Juniper" },
    { 0x0085C2U, "MikroTik" },
    { 0x0086A0U, "HP" },
    { 0x0087B2U, "Ruckus" },
    { 0x0088B8U, "TP-Link" },
    { 0x0089CCU, "D-Link" },
    { 0x008A76U, "Dell" },
    { 0x008B8BU, "Aruba" },
    { 0x008CFAU, "Apple" },
    { 0x008D4CU, "Synology" },
    { 0x008DFBU, "Fortinet" },
    { 0x008E71U, "Cisco" },
    { 0x00904CU, "Epigram" },
    { 0x00906CU, "Cisco" },
    { 0x0090A9U, "Intel" },
    { 0x0090B8U, "Juniper" },
    { 0x0090D0U, "MikroTik" },
    { 0x0090F5U, "Huawei" },
    { 0x00912AU, "HP" },
    { 0x00916CU, "Dell" },
    { 0x00920DU, "Ubiquiti" },
    { 0x0092A6U, "Aruba" },
    { 0x00931AU, "Cisco" },
    { 0x0093B4U, "Raspberry Pi" },
    { 0x00945AU, "Lenovo" },
    { 0x0094D4U, "Samsung" },
    { 0x0095F9U, "Apple" },
    { 0x0096A8U, "TP-Link" },
    { 0x0097C2U, "Espressif" },
    { 0x0098E8U, "D-Link" },
    { 0x0099CCU, "Fortinet" },
    { 0x009ACDU, "VMware" },
    { 0x009B7DU, "Cisco" },
    { 0x009C02U, "Aruba" },
    { 0x009D8EU, "Juniper" },
    { 0x009E63U, "Dell" },
    { 0x009F7DU, "Synology" },
    { 0x00A040U, "Apple" },
    { 0x00A0C9U, "Intel" },
    { 0x00A0D1U, "Cisco" },
    { 0x00A0F8U, "Dell" },
    { 0x00A1B2U, "Ubiquiti" },
    { 0x00A1E3U, "Samsung" },
    { 0x00A2EEU, "Aruba" },
    { 0x00A3D1U, "Huawei" },
    { 0x00A45EU, "HP" },
    { 0x00A5BFU, "MikroTik" },
    { 0x00A6CAU, "Cisco" },
    { 0x00A7C5U, "Ruckus" },
    { 0x00A86BU, "TP-Link" },
    { 0x00A8CDU, "D-Link" },
    { 0x00A9FAU, "Netgear" },
    { 0x00AA00U, "Intel" },
    { 0x00ABCDU, "Juniper" },
    { 0x00ACDEU, "Cisco" },
    { 0x00ADFEU, "Fortinet" },
    { 0x00AEF3U, "Raspberry Pi" },
    { 0x00B052U, "Apple" },
    { 0x00B0D0U, "Dell" },
    { 0x00B0E2U, "HP" },
    { 0x00B1C0U, "Cisco" },
    { 0x00B2D1U, "Aruba" },
    { 0x00B3EFU, "Huawei" },
    { 0x00B4F2U, "Ubiquiti" },
    { 0x00B58DU, "TP-Link" },
    { 0x00B5D0U, "Synology" },
    { 0x00B63BU, "Lenovo" },
    { 0x00B7A4U, "Asus" },
    { 0x00B8C2U, "Espressif" },
    { 0x00B9D8U, "Microsoft" },
    { 0x00BAADU, "VMware" },
    { 0x00BC61U, "MikroTik" },
    { 0x00BD3AU, "Ruckus" },
    { 0x00BE43U, "Fortinet" },
    { 0x00BF26U, "Netgear" },
    { 0x00C02BU, "Cisco" },
    { 0x00C03FU, "Dell" },
    { 0x00C04FU, "HP" },
    { 0x00C0CAU, "Intel" },
    { 0x00C0F0U, "Samsung" },
    { 0x00C1D2U, "Aruba" },
    { 0x00C2B3U, "Ubiquiti" },
    { 0x00C3F4U, "Cisco" },
    { 0x00C4B1U, "Juniper" },
    { 0x00C5A6U, "Lenovo" },
    { 0x00C62BU, "Asus" },
    { 0x00C7E3U, "Huawei" },
    { 0x00C8D7U, "TP-Link" },
    { 0x00C9AFU, "D-Link" },
    { 0x00CAFEU, "Raspberry Pi" },
    { 0x00CB6AU, "Synology" },
    { 0x00CC44U, "Fortinet" },
    { 0x00CD18U, "MikroTik" },
    { 0x00CEA1U, "Ruckus" },
    { 0x00CF8EU, "Espressif" }
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

static int cmp_oui_entry(const void *a, const void *b)
{
    const fp_oui_entry_t *ea = (const fp_oui_entry_t *)a;
    const fp_oui_entry_t *eb = (const fp_oui_entry_t *)b;

    if (ea->prefix < eb->prefix)
        return -1;
    if (ea->prefix > eb->prefix)
        return 1;
    return 0;
}

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
    if (!g_oui_sorted) {
        qsort(g_oui_table,
              sizeof(g_oui_table) / sizeof(g_oui_table[0]),
              sizeof(g_oui_table[0]),
              cmp_oui_entry);
        g_oui_sorted = true;
    }

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
