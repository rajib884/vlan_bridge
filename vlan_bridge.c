/*
 * vlan_bridge.c
 *
 * Adds VLAN tags to outgoing packets and removes VLAN tags from incoming packets.
 *
 * Build (MinGW/MSYS2, adjust paths to your Npcap SDK):
 *   gcc -o vlan_bridge.exe vlan_bridge.c -I"C:/npcap-sdk/Include" \
 *       -L"C:/npcap-sdk/Lib/x64" -lwpcap -lws2_32 -liphlpapi
 *
 * Usage:
 *   vlan_bridge.exe -i <interface> -t <target_mac> -v <vlan_id>
 *
 *   -i   Npcap interface name, e.g. "\Device\NPF_{GUID}"
 *        (run with -l to list available interfaces)
 *   -t   Target machine MAC address, e.g. AA:BB:CC:DD:EE:FF
 *   -v   VLAN ID (1-4094)
 *   -l   List available interfaces and exit
 *
 * Behaviour:
 *   OUTGOING UNICAST
 *             src MAC == my MAC, dst MAC == target MAC, no VLAN tag
 *             If IP packet with DF set and payload > 1496 bytes (1500 - 4
 *             byte VLAN tag):
 *               --> drop packet
 *               --> inject ICMP Type 3 Code 4 (Fragmentation Needed) to
 *                   local stack with Next-Hop MTU = 1496
 *             Otherwise if IP packet and payload > 1496 bytes:
 *               --> fragment IP payload into <=1496-byte chunks (RFC 791)
 *               --> tag each fragment and fix checksums, send each via
 *                   pcap_sendpacket
 *             Otherwise:
 *               --> insert 802.1Q tag (0x8100, given VLAN ID, PCP=0, DEI=0)
 *               --> fix IP/TCP/UDP/ICMP checksums (NIC offload bypass)
 *               --> re-send tagged packet via pcap_sendpacket
 *             (the original untagged packet also leaves the wire but is
 *              ignored/dropped by the VLAN-aware target device)
 *
 *   OUTGOING BROADCAST
 *             src MAC == my MAC, dst MAC == FF:FF:FF:FF:FF:FF, no VLAN tag
 *             Same MTU / fragmentation logic as OUTGOING UNICAST.
 *             --> insert 802.1Q tag, dst remains FF:FF:FF:FF:FF:FF
 *             --> re-send tagged broadcast via pcap_sendpacket
 *
 *   INCOMING UNICAST
 *             src MAC == target MAC, dst MAC == my MAC, has VLAN tag
 *             --> strip the 802.1Q tag
 *             --> re-inject untagged packet via pcap_sendpacket
 *             --> local OS network stack consumes the clean packet
 *
 *   INCOMING BROADCAST
 *             src MAC == target MAC, dst MAC == FF:FF:FF:FF:FF:FF, has VLAN tag
 *             --> strip the 802.1Q tag, dst remains FF:FF:FF:FF:FF:FF
 *             --> re-inject untagged broadcast via pcap_sendpacket
 */

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>

#include "fast_log.h"

// #pragma comment(lib, "wpcap.lib")
// #pragma comment(lib, "ws2_32.lib")
// #pragma comment(lib, "iphlpapi.lib")

/* ── constants ──────────────────────────────────────────────────────────── */
#define ETH_ALEN        6
#define ETHERTYPE_VLAN  0x8100
#define SNAP_LEN        65535
#define PROMISC         1
#define TIMEOUT_MS      1          /* short timeout so the loop stays responsive */

static const uint8_t BROADCAST_MAC[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

#if 0
/* ── MTU / fragmentation constants ─────────────────────────────────────────
 * Standard Ethernet payload MTU is 1500 bytes.  Adding a 4-byte 802.1Q tag
 * reduces the usable IP payload to 1496 bytes.  Any IP packet larger than
 * this must either be fragmented (DF=0) or rejected with ICMP (DF=1).
 * ──────────────────────────────────────────────────────────────────────── */
#define ETH_MTU          1500        /* standard Ethernet payload MTU        */
#define VLAN_TAG_LEN     4           /* 802.1Q tag size                      */
#define VLAN_MTU         (ETH_MTU - VLAN_TAG_LEN)   /* 1496: max IP after tag*/
#define ETH_HDR_LEN      14          /* untagged Ethernet header             */
#define VLAN_ETH_HDR_LEN (ETH_HDR_LEN + VLAN_TAG_LEN) /* 18: tagged header  */
#define MY_IP_FLAG_DF       0x4000      /* Don't Fragment bit in flags+frag_off */
#define MY_IP_FLAG_MF       0x2000      /* More Fragments bit                   */
#define MY_IP_FRAG_MASK     0x1FFF      /* fragment offset mask (in frag field) */

/* ── deduplication cache ────────────────────────────────────────────────────
 * npcap on Windows can deliver the same outbound frame twice: once as the OS
 * sends it, and once as our own pcap_sendpacket re-injection comes back.
 * We keep a small ring of recently-seen (hash, timestamp) pairs and drop any
 * frame whose hash we have seen within DEDUP_WINDOW_MS milliseconds.
 *
 * Hash: FNV-1a 32-bit over the full captured frame bytes.
 * ──────────────────────────────────────────────────────────────────────── */
#define DEDUP_SLOTS      64          /* power-of-2 ring buffer              */
#define DEDUP_WINDOW_MS  500         /* ignore repeats within 500 ms        */

typedef struct {
    uint32_t hash;
    DWORD    ts_ms;                  /* GetTickCount() at insertion          */
} dedup_entry_t;

typedef struct {
    dedup_entry_t slots[DEDUP_SLOTS];
    int           next;              /* next write position (ring)           */
} dedup_cache_t;


static uint32_t fnv1a_32(const uint8_t *data, uint32_t len)
{
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < len; i++)
        h = (h ^ data[i]) * 0x01000193u;
    return h;
}

/* Returns 1 if this packet is a duplicate and should be dropped.
 * Otherwise records it and returns 0.
 */
static int dedup_check_and_record(dedup_cache_t *dc,
                                   const uint8_t *pkt, uint32_t len)
{
    uint32_t h   = fnv1a_32(pkt, len);
    DWORD    now = GetTickCount();

    /* scan for an existing live entry with the same hash */
    for (int i = 0; i < DEDUP_SLOTS; i++) {
        dedup_entry_t *e = &dc->slots[i];
        if (e->hash == h && e->ts_ms != 0 &&
            (now - e->ts_ms) < DEDUP_WINDOW_MS)
            return 1;  /* duplicate */
    }

    /* record in ring */
    dc->slots[dc->next].hash  = h;
    dc->slots[dc->next].ts_ms = now;
    dc->next = (dc->next + 1) & (DEDUP_SLOTS - 1);
    return 0;
}
#endif

/* ── Ethernet / 802.1Q structures ───────────────────────────────────────── */
#pragma pack(push, 1)

typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t tpid;          /* 0x8100 */
    uint16_t tci;           /* PCP(3) | DEI(1) | VID(12) */
    uint16_t ethertype;     /* original ethertype */
} eth_vlan_hdr_t;

#pragma pack(pop)

/* ── global state passed to the packet handler ──────────────────────────── */
typedef struct {
    pcap_t  *handle;
    uint8_t  my_mac[ETH_ALEN];
    uint8_t  target_mac[ETH_ALEN];
    uint16_t vlan_id;
#if 0
    dedup_cache_t dedup;
#endif
    /* stats */
    uint64_t tagged_sent;       /* unicast OUT: tag added         */
    uint64_t bcast_tagged_sent; /* broadcast OUT: tag added       */
    uint64_t frag_sent;         /* fragment packets sent          */
    uint64_t df_dropped;        /* DF-set oversized packets dropped + ICMP sent */
    uint64_t stripped_sent;     /* unicast IN:  tag removed       */
    uint64_t bcast_stripped;    /* broadcast IN: tag removed      */
    uint64_t dedup_dropped;     /* duplicate frames suppressed    */
    uint64_t ignored;
} proxy_ctx_t;

/* ── discovery mode state ───────────────────────────────────────────────────
 * Passive scan that records each unique (VLAN, source MAC) seen in tagged
 * ARP/ICMP traffic, along with an associated IP, to reveal the -t / -v values
 * needed for bridge mode. Never sends anything.
 * ──────────────────────────────────────────────────────────────────────── */
#define DISC_MAX 256

typedef struct {
    uint16_t vlan_id;
    uint8_t  mac[ETH_ALEN];
    uint32_t ip;            /* first associated IP, network order (0 if none) */
    uint64_t count;         /* matching frames seen                           */
} disc_entry_t;

typedef struct {
    uint32_t     filter_ip; /* network order; 0 = no filter                   */
    int          verbose;   /* -d: also log every matching packet             */
    int          n;         /* entries in use                                 */
    disc_entry_t e[DISC_MAX];
} disc_ctx_t;

/* ── helpers ────────────────────────────────────────────────────────────── */

static int parse_mac(const char *str, uint8_t *mac)
{
    unsigned int b[ETH_ALEN];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != ETH_ALEN)
        return -1;
    for (int i = 0; i < ETH_ALEN; i++) mac[i] = (uint8_t)b[i];
    return 0;
}

static void print_mac(const uint8_t *mac)
{
    log_printf(LOG_INFO, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static int mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, ETH_ALEN) == 0;
}

/* Extract the adapter GUID ("{...}") from an Npcap device name
 * ("\Device\NPF_{GUID}"). Returns a pointer into pcap_name, or NULL if the
 * name has no GUID component. The GUID (with braces) is what IPHLPAPI reports
 * as an adapter's AdapterName, so it is the key we match both here and in
 * list_devices(). */
static const char *pcap_name_to_guid(const char *pcap_name)
{
    return pcap_name ? strchr(pcap_name, '{') : NULL;
}

/* Retrieve the MAC address of the chosen interface via IPHLPAPI */
static int get_interface_mac(const char *pcap_name, uint8_t *mac)
{
    /* pcap_name looks like "\Device\NPF_{GUID}" – extract the GUID */
    const char *guid = pcap_name_to_guid(pcap_name);
    if (!guid) return -1;

    IP_ADAPTER_INFO *info_buf = NULL;
    ULONG buf_len = 0;

    GetAdaptersInfo(NULL, &buf_len);
    info_buf = (IP_ADAPTER_INFO *)malloc(buf_len);
    if (!info_buf) return -1;

    if (GetAdaptersInfo(info_buf, &buf_len) != ERROR_SUCCESS) {
        free(info_buf);
        return -1;
    }

    int found = 0;
    for (IP_ADAPTER_INFO *a = info_buf; a; a = a->Next) {
        /* AdapterName is the GUID string, e.g. "{XXXXXXXX-...}" */
        if (_stricmp(a->AdapterName, guid) == 0) {
            log_printf(LOG_INFO, "Selected: %s\n", a->AdapterName);
            memcpy(mac, a->Address, ETH_ALEN);
            found = 1;
            break;
        }
    }
    free(info_buf);
    return found ? 0 : -1;
}

#if 0

static void list_interfaces(void)
{
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        log_printf(LOG_ERROR, "pcap_findalldevs: %s\n", errbuf);
        return;
    }
    log_printf(LOG_INFO, "Available interfaces:\n");
    for (d = alldevs; d; d = d->next) {
        log_printf(LOG_INFO, "  %s\n", d->name);
        if (d->description)
            log_printf(LOG_INFO, "    -> %s\n", d->description);
    }
    pcap_freealldevs(alldevs);
}
#else
static void list_devices()
{
    char buf[1024] = "";

    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    ULONG bufferSize = 0;
    DWORD result = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrent = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

    // First call to get bufferSize
    result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!pAddresses) goto err;
        // Retrieve adapter information
        result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    }

    if (result != ERROR_SUCCESS) goto err;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) goto err;
    for (dev = alldevs; dev; dev = dev->next){
        pCurrent = pAddresses;
        for (; pCurrent != NULL; pCurrent = pCurrent->Next) {
            if (pCurrent->OperStatus != IfOperStatusUp) continue;
            const char *guid = pcap_name_to_guid(dev->name);
            if (pCurrent->PhysicalAddressLength == 6 && guid &&
                _stricmp(pCurrent->AdapterName, guid) == 0) {
                pUnicast = pCurrent->FirstUnicastAddress;
                for (; pUnicast != NULL; pUnicast = pUnicast->Next){
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) break;
                }
                
                log_printf(LOG_INFO, "Interface: %s\n", dev->name);
                if (pUnicast) {
                    log_printf(LOG_INFO, "  -> IP  : %s/%u\n", inet_ntoa(((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr), pUnicast->OnLinkPrefixLength);
                    // curr->mask = (pUnicast->OnLinkPrefixLength == 0) ? 0 : htonl(~0u << (32 - pUnicast->OnLinkPrefixLength));
                }
                if (pCurrent->FriendlyName) {
                    WideCharToMultiByte(CP_UTF8, 0, pCurrent->FriendlyName, -1, buf, sizeof(buf), NULL, NULL);
                    log_printf(LOG_INFO, "  -> Name: %s\n", buf);
                }
                // memcpy(curr->mac, pCurrent->PhysicalAddress, sizeof(curr->mac));
                log_printf(LOG_INFO, "  -> Desc: %s\n\n", dev->description);
                break;
            }
        }
    }

err:
    if (alldevs) pcap_freealldevs(alldevs);
    if (pAddresses) free(pAddresses);
    return;
}
#endif

/* Build BPF filter string.
 * Captures exactly four frame classes:
 *   1. my MAC  -> target MAC    (outgoing unicast,   no tag expected)
 *   2. my MAC  -> broadcast     (outgoing broadcast, no tag expected)
 *   3. target  -> my MAC        (incoming unicast,   tag expected)
 *   4. target  -> broadcast     (incoming broadcast, tag expected)
 */
static void build_bpf(char *buf, size_t sz,
                      const uint8_t *my_mac, const uint8_t *target_mac)
{
    snprintf(buf, sz,
        /* 1. outgoing unicast */
        "(ether src %02x:%02x:%02x:%02x:%02x:%02x and "
        " ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether[12:2] != 0x8100) or "
        /* 2. outgoing broadcast */
        "(ether src %02x:%02x:%02x:%02x:%02x:%02x and "
        " ether dst ff:ff:ff:ff:ff:ff and ether[12:2] != 0x8100) or "
        /* 3. incoming unicast */
        "(ether src %02x:%02x:%02x:%02x:%02x:%02x and "
        " ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether[12:2] == 0x8100) or "
        /* 4. incoming broadcast */
        "(ether src %02x:%02x:%02x:%02x:%02x:%02x and "
        " ether dst ff:ff:ff:ff:ff:ff and ether[12:2] == 0x8100)",
        /* 1 */
        my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5],
        target_mac[0],target_mac[1],target_mac[2],
        target_mac[3],target_mac[4],target_mac[5],
        /* 2 */
        my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5],
        /* 3 */
        target_mac[0],target_mac[1],target_mac[2],
        target_mac[3],target_mac[4],target_mac[5],
        my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5],
        /* 4 */
        target_mac[0],target_mac[1],target_mac[2],
        target_mac[3],target_mac[4],target_mac[5]);
}

/* ── shared helpers for tag insertion / removal ─────────────────────────── */

/* Insert a 4-byte 802.1Q tag after the first 12 bytes (dst+src) of a frame.
 * Returns a malloc'd buffer of (orig_len + 4) bytes, or NULL on OOM.
 * Caller must free().
 */
static uint8_t *insert_vlan_tag(const u_char *pkt, uint32_t orig_len,
                                 uint16_t vlan_id, uint32_t *new_len_out)
{
    uint32_t new_len = orig_len + 4;
    uint8_t *np = (uint8_t *)malloc(new_len);
    if (!np) return NULL;

    memcpy(np, pkt, 12);                            /* dst + src          */
    uint16_t tpid = htons(ETHERTYPE_VLAN);
    uint16_t tci  = htons(vlan_id & 0x0FFF);        /* PCP=0, DEI=0       */
    memcpy(np + 12, &tpid, 2);
    memcpy(np + 14, &tci,  2);
    memcpy(np + 16, pkt + 12, orig_len - 12);       /* ethertype + payload */

    *new_len_out = new_len;
    return np;
}

/* Strip the 4-byte 802.1Q tag from a frame that starts at byte 12.
 * Returns a malloc'd buffer of (orig_len - 4) bytes, or NULL on OOM.
 * Caller must free().
 */
static uint8_t *strip_vlan_tag(const u_char *pkt, uint32_t orig_len,
                                uint32_t *new_len_out)
{
    if (orig_len < 18) return NULL;                 /* sanity check        */
    uint32_t new_len = orig_len - 4;
    uint8_t *np = (uint8_t *)malloc(new_len);
    if (!np) return NULL;

    memcpy(np, pkt, 12);                            /* dst + src           */
    memcpy(np + 12, pkt + 16, orig_len - 16);       /* skip tag, copy rest */

    *new_len_out = new_len;
    return np;
}

void print_raw_data(const uint8_t *data, size_t len)
{
    size_t i, j;
    const size_t BREAK_AFTER = 256;
    const size_t PER_ROW = 16;

    if (len > BREAK_AFTER) 
    {
        print_raw_data(data, BREAK_AFTER);
        i = BREAK_AFTER * (len / BREAK_AFTER);
        if (i == len) i -= BREAK_AFTER;
        log_printf(LOG_INFO, "    ");
        for (j = 0; j < PER_ROW; j++) log_printf(LOG_INFO, "----");
        log_printf(LOG_INFO, "---\n");
    } else i = 0;

    for (; i < len; i += PER_ROW)
    {
        /* Hex part */
        log_printf(LOG_INFO, "    ");
        for (j = 0; j < PER_ROW; j++)
        {
            if (i + j < len)
                log_printf(LOG_INFO, "%02X ", data[i + j]);
            else
                log_printf(LOG_INFO, "   "); /* padding for last line */
        }

        /* ASCII part */
        log_printf(LOG_INFO, " |");
        for (j = 0; j < PER_ROW && i + j < len; j++)
        {
            uint8_t c = data[i + j];
            log_printf(LOG_INFO, "%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        log_printf(LOG_INFO, "|\n");
    }
}

/* ── checksum helpers ───────────────────────────────────────────────────────
 *
 * Windows TCP/IP offloads checksum computation to the NIC.  Captured outbound
 * frames therefore have zeroed checksum fields.  When we re-inject a tagged
 * copy via pcap_sendpacket the NIC sends it verbatim (it does not offload for
 * raw injected frames), so the remote end receives packets with bad checksums
 * and drops them.
 *
 * We fix this only on the OUTGOING path (tag-insertion).  Incoming frames
 * from the target already have correct checksums computed by the remote NIC,
 * so the strip path needs no fixup.
 *
 * Protocols handled:  IPv4 header, TCP, UDP, ICMP.
 * IPv6 is passed through unchanged (its checksums are also offloaded, but
 * fixing them requires more work and can be added later if needed).
 * ──────────────────────────────────────────────────────────────────────── */

#define ETHERTYPE_IPV4  0x0800
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

/* RFC 1071 one's-complement sum over 'len' bytes.
 * 'init' lets callers chain multiple regions (pass 0 to start fresh).
 */
static uint32_t cksum_add(uint32_t init, const void *data, uint32_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = init;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;   /* odd trailing byte */
    return sum;
}

static uint16_t cksum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* IPv4 header checksum.
 * 'ip' points to the start of the IP header inside the packet buffer.
 * The header checksum field must be zeroed by the caller before calling.
 */
static void fix_ip_checksum(uint8_t *ip)
{
    uint8_t ihl = (ip[0] & 0x0f) * 4;      /* header length in bytes */
    uint16_t *csum = (uint16_t *)(ip + 10); /* checksum field at offset 10 */
    *csum = 0;
    *csum = cksum_fold(cksum_add(0, ip, ihl));
}

/* Transport-layer (TCP/UDP/ICMP) checksum using the IPv4 pseudo-header.
 * 'ip'        – pointer to IPv4 header
 * 'transport' – pointer to transport header (TCP/UDP/ICMP)
 * 'tlen'      – length of transport segment (bytes), i.e. total_len - ihl
 * 'proto'     – IP protocol number
 * 'csum_off'  – byte offset of the checksum field within 'transport'
 */
static void fix_transport_checksum(uint8_t *ip,
                                    uint8_t *transport,
                                    uint16_t tlen,
                                    uint8_t  proto,
                                    uint16_t csum_off)
{
    /* build pseudo-header: src_ip(4) dst_ip(4) zero(1) proto(1) tlen(2) */
    uint8_t pseudo[12];
    memcpy(pseudo,     ip + 12, 4);         /* src IP  */
    memcpy(pseudo + 4, ip + 16, 4);         /* dst IP  */
    pseudo[8]  = 0;
    pseudo[9]  = proto;
    pseudo[10] = (uint8_t)(tlen >> 8);
    pseudo[11] = (uint8_t)(tlen & 0xff);

    uint16_t *csum = (uint16_t *)(transport + csum_off);
    *csum = 0;
    uint32_t sum = cksum_add(0, pseudo, 12);
    sum = cksum_add(sum, transport, tlen);
    uint16_t folded = cksum_fold(sum);
    /* RFC 768: a computed UDP checksum of 0x0000 must be sent as 0xFFFF, since
     * zero is reserved to mean "no checksum". TCP has no such rule. */
    if (folded == 0 && proto == IP_PROTO_UDP)
        folded = 0xFFFF;
    *csum = folded;
}

#if 0
/* ── ICMP Fragmentation Needed (Type 3, Code 4) ─────────────────────────────
 *
 * When an outgoing IP packet has DF=1 and its IP payload exceeds VLAN_MTU,
 * we must drop it and inject an ICMP "Fragmentation Needed" message back
 * into the local OS stack so PMTUD can reduce the segment size.
 *
 * The injected frame is an untagged Ethernet frame addressed to my_mac
 * (looped back into the OS stack via pcap_sendpacket), containing:
 *   IP:   src=original dst IP, dst=original src IP, proto=ICMP
 *   ICMP: Type=3 Code=4, Next-Hop MTU=VLAN_MTU, original IP header + 8 bytes
 * ──────────────────────────────────────────────────────────────────────── */
static void send_icmp_frag_needed(pcap_t *handle,
                                   const uint8_t *my_mac,
                                   const uint8_t *orig_eth,  /* original frame  */
                                   const uint8_t *orig_ip)   /* points into orig_eth */
{
    /* We embed: original IP header + first 8 bytes of original IP payload */
    uint8_t orig_ihl = (orig_ip[0] & 0x0f) * 4;
    uint16_t quoted_len = orig_ihl + 8;  /* RFC 792 mandates at least 8 bytes */

    /* Total ICMP data = 8 (ICMP header) + quoted_len */
    uint16_t icmp_len  = 8 + quoted_len;
    /* Total IP payload = icmp_len */
    uint16_t ip_total  = 20 + icmp_len;
    /* Total frame = 14 (eth) + ip_total */
    uint16_t frame_len = 14 + ip_total;

    uint8_t *frame = (uint8_t *)calloc(1, frame_len);
    if (!frame) return;

    /* ── Ethernet header: dst=my_mac (loopback to OS), src=my_mac ──── */
    memcpy(frame,     my_mac, ETH_ALEN);   /* dst */
    memcpy(frame + 6, my_mac, ETH_ALEN);   /* src (router-generated, use ours) */
    frame[12] = 0x08; frame[13] = 0x00;    /* EtherType IPv4 */

    /* ── IP header ──────────────────────────────────────────────────── */
    uint8_t *ip = frame + 14;
    ip[0]  = 0x45;                          /* version=4, IHL=5 (20 bytes)  */
    ip[1]  = 0;                             /* DSCP/ECN                     */
    ip[2]  = (uint8_t)(ip_total >> 8);
    ip[3]  = (uint8_t)(ip_total & 0xff);
    ip[4]  = 0; ip[5] = 0;                  /* identification               */
    ip[6]  = 0; ip[7] = 0;                  /* flags=0, frag offset=0       */
    ip[8]  = 64;                            /* TTL                          */
    ip[9]  = IP_PROTO_ICMP;
    ip[10] = 0; ip[11] = 0;                 /* checksum (filled below)      */
    memcpy(ip + 12, orig_ip + 16, 4);       /* src = original dst IP        */
    memcpy(ip + 16, orig_ip + 12, 4);       /* dst = original src IP        */

    /* ── ICMP header (8 bytes) ──────────────────────────────────────── */
    uint8_t *icmp = ip + 20;
    icmp[0] = 3;                            /* Type: Destination Unreachable */
    icmp[1] = 4;                            /* Code: Fragmentation Needed   */
    icmp[2] = 0; icmp[3] = 0;              /* checksum (filled below)       */
    icmp[4] = 0;                            /* unused                        */
    icmp[5] = 0;
    icmp[6] = (uint8_t)(VLAN_MTU >> 8);    /* Next-Hop MTU high byte        */
    icmp[7] = (uint8_t)(VLAN_MTU & 0xff);  /* Next-Hop MTU low byte         */

    /* ── Quoted original IP header + first 8 bytes of payload ──────── */
    memcpy(icmp + 8, orig_ip, quoted_len);

    /* ── Fix checksums ──────────────────────────────────────────────── */
    /* IP header checksum */
    {
        uint16_t *cs = (uint16_t *)(ip + 10);
        *cs = 0;
        *cs = cksum_fold(cksum_add(0, ip, 20));
    }
    /* ICMP checksum over entire ICMP message */
    {
        uint16_t *cs = (uint16_t *)(icmp + 2);
        *cs = 0;
        *cs = cksum_fold(cksum_add(0, icmp, icmp_len));
    }

    if (pcap_sendpacket(handle, frame, frame_len) != 0)
        log_printf(LOG_ERROR, "[ICMP-FN] pcap_sendpacket: %s\n",
                pcap_geterr(handle));
    else
        log_printf(LOG_INFO, "[ICMP-FN] Sent Fragmentation Needed (MTU=%u) to ",
               VLAN_MTU);

    /* print original src IP in dotted decimal */
    log_printf(LOG_INFO, "%u.%u.%u.%u\n",
           orig_ip[12], orig_ip[13], orig_ip[14], orig_ip[15]);

    free(frame);
}

/* ── IP fragmentation + VLAN tagging ────────────────────────────────────────
 *
 * Splits an outgoing untagged Ethernet/IP frame into fragments that each fit
 * within VLAN_MTU (1496) bytes of IP payload, then tags and sends each one.
 *
 * 'orig_eth'   – original captured Ethernet frame (untagged, 14-byte header)
 * 'orig_len'   – total length of orig_eth
 * 'vlan_id'    – VLAN ID to tag each fragment with
 * 'handle'     – pcap handle for sending
 *
 * Returns the number of fragments successfully sent.
 *
 * Fragment layout per RFC 791:
 *   - Each fragment carries the original IP header (with options, if any)
 *   - Fragment payload size must be a multiple of 8 bytes, except the last
 *   - MF bit set on all fragments except the last
 *   - Fragment offset field = byte offset of this fragment's data / 8
 * ──────────────────────────────────────────────────────────────────────── */
static int send_fragments(pcap_t *handle,
                           const uint8_t *orig_eth, uint32_t orig_len,
                           uint16_t vlan_id,
                           const uint8_t *my_mac)
{
    (void)my_mac; /* reserved for future use */

    if (orig_len < ETH_HDR_LEN + 20) return 0;

    const uint8_t *orig_ip  = orig_eth + ETH_HDR_LEN;
    uint8_t        orig_ihl = (orig_ip[0] & 0x0f) * 4;
    if (orig_ihl < 20 || orig_len < ETH_HDR_LEN + orig_ihl) return 0;

    uint16_t orig_total = (uint16_t)((orig_ip[2] << 8) | orig_ip[3]);
    uint16_t orig_flags_frag = (uint16_t)((orig_ip[6] << 8) | orig_ip[7]);
    uint16_t orig_frag_off   = (orig_flags_frag & MY_IP_FRAG_MASK) * 8; /* bytes */

    /* Original payload (everything after the IP header) */
    const uint8_t *orig_payload = orig_ip + orig_ihl;
    uint16_t       payload_len  = orig_total - orig_ihl;

    /*
     * Maximum payload bytes per fragment:
     *   VLAN_MTU (1496) - orig_ihl, rounded DOWN to nearest multiple of 8.
     * We must account for the IP header being repeated in every fragment.
     */
    uint16_t max_frag_data = (uint16_t)((VLAN_MTU - orig_ihl) & ~7u);
    if (max_frag_data == 0) return 0;  /* IP header alone exceeds MTU — can't fragment */

    int frags_sent = 0;
    uint16_t offset = 0;   /* byte offset into original payload */

    /* Tagged frame buffer: VLAN_ETH_HDR_LEN + orig_ihl + max_frag_data */
    uint32_t buf_size = VLAN_ETH_HDR_LEN + orig_ihl + max_frag_data;
    uint8_t *frag_frame = (uint8_t *)malloc(buf_size);
    if (!frag_frame) return 0;

    while (offset < payload_len) {

        uint16_t this_data = payload_len - offset;
        int      last_frag = 1;
        if (this_data > max_frag_data) {
            this_data = max_frag_data;
            last_frag = 0;
        }

        uint16_t frag_ip_total  = orig_ihl + this_data;
        uint32_t frag_frame_len = VLAN_ETH_HDR_LEN + frag_ip_total;

        memset(frag_frame, 0, frag_frame_len);

        /* ── Tagged Ethernet header ──────────────────────────────────── */
        memcpy(frag_frame,      orig_eth,      6);    /* dst MAC             */
        memcpy(frag_frame + 6,  orig_eth + 6,  6);    /* src MAC             */
        frag_frame[12] = 0x81; frag_frame[13] = 0x00; /* TPID 0x8100         */
        frag_frame[14] = (uint8_t)(vlan_id >> 8);
        frag_frame[15] = (uint8_t)(vlan_id & 0xff);   /* TCI (PCP=0,DEI=0)   */
        memcpy(frag_frame + 16, orig_eth + 12, 2);    /* inner EtherType      */

        /* ── IP header copy + fixups ─────────────────────────────────── */
        uint8_t *fip = frag_frame + VLAN_ETH_HDR_LEN;
        memcpy(fip, orig_ip, orig_ihl);

        /* Update Total Length */
        fip[2] = (uint8_t)(frag_ip_total >> 8);
        fip[3] = (uint8_t)(frag_ip_total & 0xff);

        /* Update Flags + Fragment Offset
         * Offset field = (orig_frag_off + offset) / 8
         * MF bit inherited from original if not last, cleared if last */
        uint16_t new_frag_off_field = (orig_frag_off + offset) / 8;
        uint16_t new_flags = 0;
        if (!last_frag)
            new_flags |= MY_IP_FLAG_MF;
        else if (orig_flags_frag & MY_IP_FLAG_MF)
            new_flags |= MY_IP_FLAG_MF;  /* pass through MF if original was a fragment too */
        /* DF is always 0 in fragments (we already checked DF above) */
        uint16_t flags_frag_field = new_flags | (new_frag_off_field & MY_IP_FRAG_MASK);
        fip[6] = (uint8_t)(flags_frag_field >> 8);
        fip[7] = (uint8_t)(flags_frag_field & 0xff);

        /* ── Payload ─────────────────────────────────────────────────── */
        memcpy(fip + orig_ihl, orig_payload + offset, this_data);

        /* ── Fix IP header checksum ──────────────────────────────────── */
        fix_ip_checksum(fip);

        /* ── Send ────────────────────────────────────────────────────── */
        if (pcap_sendpacket(handle, frag_frame, (int)frag_frame_len) == 0) {
            frags_sent++;
            log_printf(LOG_INFO, "[FRAG]    Sent frag %d  offset=%u  data=%u  len=%u  MF=%d\n",
                   frags_sent, (unsigned)(orig_frag_off + offset),
                   this_data, frag_frame_len, !last_frag);
        } else {
            log_printf(LOG_ERROR, "[FRAG]    pcap_sendpacket: %s\n",
                    pcap_geterr(handle));
        }

        offset += this_data;
    }

    free(frag_frame);
    return frags_sent;
}
#endif

/*
 * 'frame'     - writable pointer to the full Ethernet frame
 * 'frame_len' - total frame length
 *
 * This must be called AFTER insert_vlan_tag so that 'frame' is the
 * already-tagged buffer and the Ethernet header is 18 bytes (14 + 4 tag).
 * The IP header therefore starts at offset 18.
 */
static void fix_checksums_in_tagged_frame(uint8_t *frame, uint32_t frame_len)
{
    /* Sanity: need at least the VLAN Ethernet header + IP header minimum */
    if (frame_len < 18 + 20) return;

    /* Check ethertype after VLAN tag (offset 16 in tagged frame) */
    uint16_t inner_etype = (uint16_t)((frame[16] << 8) | frame[17]);
    if (inner_etype != ETHERTYPE_IPV4) return;  /* only handle IPv4 for now */

    uint8_t *ip  = frame + 18;                  /* IP header starts here     */
    uint8_t  ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || frame_len < 18u + ihl) return;

    uint16_t total_len = (uint16_t)((ip[2] << 8) | ip[3]);
    if (frame_len < 18u + total_len) return;

    uint8_t  proto = ip[9];
    uint16_t tlen  = total_len - ihl;           /* transport segment length  */
    uint8_t *tp    = ip + ihl;                  /* transport header          */

    /* ── fix IP header checksum first ─────────────────────────────────── */
    fix_ip_checksum(ip);

    /* ── fix transport checksum ────────────────────────────────────────── */
    if (tlen < 8) return;                       /* too short for any header  */

    switch (proto) {
        case IP_PROTO_TCP:
            if (tlen >= 20)
                fix_transport_checksum(ip, tp, tlen, IP_PROTO_TCP, 16);
            break;
        case IP_PROTO_UDP:
            if (tlen >= 8)
                fix_transport_checksum(ip, tp, tlen, IP_PROTO_UDP, 6);
            break;
        case IP_PROTO_ICMP:
            /* ICMP uses a simple checksum over its own data, no pseudo-hdr */
            {
                uint16_t *csum = (uint16_t *)(tp + 2);
                *csum = 0;
                *csum = cksum_fold(cksum_add(0, tp, tlen));
            }
            break;
        default:
            break;                              /* other protos: leave as-is */
    }
}

/* ── packet handler ─────────────────────────────────────────────────────── */

static void packet_handler(u_char *user,
                            const struct pcap_pkthdr *hdr,
                            const u_char *pkt)
{
    proxy_ctx_t *ctx = (proxy_ctx_t *)user;

    if (hdr->caplen < sizeof(eth_hdr_t)) return;
#if 0
    /* ── deduplication: drop frames we have already processed recently ── */
    if (dedup_check_and_record(&ctx->dedup, pkt, hdr->caplen)) {
        ctx->dedup_dropped++;
        log_flush();
        return;
    }
#endif

    const eth_hdr_t    *eth   = (const eth_hdr_t *)pkt;
    const eth_vlan_hdr_t *veth = (const eth_vlan_hdr_t *)pkt;
    uint16_t ethertype = ntohs(eth->ethertype);

    int from_me      = mac_eq(eth->src, ctx->my_mac);
    int from_target  = mac_eq(eth->src, ctx->target_mac);
    int to_target    = mac_eq(eth->dst, ctx->target_mac);
    int to_me        = mac_eq(eth->dst, ctx->my_mac);
    int to_bcast     = mac_eq(eth->dst, BROADCAST_MAC);

    uint8_t  *new_pkt  = NULL;
    uint32_t  new_len  = 0;

    /* ── OUTGOING UNICAST: my MAC -> target MAC, no VLAN tag ─────────── */
    if (from_me && to_target && ethertype != ETHERTYPE_VLAN) {

#if 0
        if (ethertype == ETHERTYPE_IPV4 && hdr->caplen >= ETH_HDR_LEN + 20) {
            const uint8_t *ip      = pkt + ETH_HDR_LEN;
            uint16_t ip_total      = (uint16_t)((ip[2] << 8) | ip[3]);
            uint16_t flags_frag    = (uint16_t)((ip[6] << 8) | ip[7]);
            int      df_set        = (flags_frag & MY_IP_FLAG_DF) != 0;

            if (ip_total > VLAN_MTU) {
                if (df_set) {
                    /* DF set and too large: drop + send ICMP Frag Needed */
                    send_icmp_frag_needed(ctx->handle, ctx->my_mac, pkt, ip);
                    ctx->df_dropped++;
                    log_printf(LOG_INFO, "[OUT-UC]  DF drop  ip_total=%u > VLAN_MTU=%u\n",
                           ip_total, VLAN_MTU);
                } else {
                    /* Fragment, tag each fragment, send */
                    int n = send_fragments(ctx->handle, pkt, hdr->caplen,
                                           ctx->vlan_id, ctx->my_mac);
                    ctx->frag_sent += n;
                    log_printf(LOG_INFO, "[OUT-UC]  Fragmented into %d tagged fragments"
                           "  VLAN %u\n", n, ctx->vlan_id);
                }
                goto done;
            }
        }
#endif

        /* Fits within MTU: normal tag + checksum fix + send */
        new_pkt = insert_vlan_tag(pkt, hdr->caplen, ctx->vlan_id, &new_len);
        if (!new_pkt) {
            log_flush();
            return;
        }
        fix_checksums_in_tagged_frame(new_pkt, new_len);

        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            ctx->tagged_sent++;
            log_printf(LOG_INFO, "[OUT-UC]  Tagged+sent  len %u->%u  VLAN %u  dst ",
                   hdr->caplen, new_len, ctx->vlan_id);
            print_mac(eth->dst);
            log_printf(LOG_INFO, "  etype 0x%04X\n", ethertype);
        } else {
            log_printf(LOG_ERROR, "[OUT-UC]  pcap_sendpacket: %s\n",
                    pcap_geterr(ctx->handle));
        }
        // print_raw_data(new_pkt, new_len);

    /* ── OUTGOING BROADCAST: my MAC -> FF:FF:FF:FF:FF:FF, no VLAN tag ── */
    } else if (from_me && to_bcast && ethertype != ETHERTYPE_VLAN) {

#if 0
        if (ethertype == ETHERTYPE_IPV4 && hdr->caplen >= ETH_HDR_LEN + 20) {
            const uint8_t *ip      = pkt + ETH_HDR_LEN;
            uint16_t ip_total      = (uint16_t)((ip[2] << 8) | ip[3]);
            uint16_t flags_frag    = (uint16_t)((ip[6] << 8) | ip[7]);
            int      df_set        = (flags_frag & MY_IP_FLAG_DF) != 0;

            if (ip_total > VLAN_MTU) {
                if (df_set) {
                    send_icmp_frag_needed(ctx->handle, ctx->my_mac, pkt, ip);
                    ctx->df_dropped++;
                    log_printf(LOG_INFO, "[OUT-BC]  DF drop  ip_total=%u > VLAN_MTU=%u\n",
                           ip_total, VLAN_MTU);
                } else {
                    int n = send_fragments(ctx->handle, pkt, hdr->caplen,
                                           ctx->vlan_id, ctx->my_mac);
                    ctx->frag_sent += n;
                    log_printf(LOG_INFO, "[OUT-BC]  Fragmented into %d tagged fragments"
                           "  VLAN %u\n", n, ctx->vlan_id);
                }
                goto done;
            }
        }
#endif

        /* Fits within MTU: normal tag + checksum fix + send */
        new_pkt = insert_vlan_tag(pkt, hdr->caplen, ctx->vlan_id, &new_len);
        if (!new_pkt) {
            log_flush();
            return;
        }
        fix_checksums_in_tagged_frame(new_pkt, new_len);

        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            ctx->bcast_tagged_sent++;
            log_printf(LOG_INFO, "[OUT-BC]  Tagged+sent  len %u->%u  VLAN %u  dst BROADCAST"
                   "  etype 0x%04X\n",
                   hdr->caplen, new_len, ctx->vlan_id, ethertype);
        } else {
            log_printf(LOG_ERROR, "[OUT-BC]  pcap_sendpacket: %s\n",
                    pcap_geterr(ctx->handle));
        }

    /* ── INCOMING UNICAST: target MAC -> my MAC, with VLAN tag ──────── */
    } else if (from_target && to_me && ethertype == ETHERTYPE_VLAN) {

        if (hdr->caplen < sizeof(eth_vlan_hdr_t)) {
            log_flush();
            return;
        }
        uint16_t vid = ntohs(veth->tci) & 0x0FFF;
        if (vid != ctx->vlan_id) {
            ctx->ignored++; 
            log_flush();
            return;
        }

        new_pkt = strip_vlan_tag(pkt, hdr->caplen, &new_len);
        if (!new_pkt) {
            log_flush();
            return;
        }

        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            ctx->stripped_sent++;
            log_printf(LOG_INFO, "[IN-UC]   Stripped+sent  len %u->%u  VLAN %u  src ",
                   hdr->caplen, new_len, vid);
            print_mac(eth->src);
            log_printf(LOG_INFO, "  inner etype 0x%04X\n", ntohs(veth->ethertype));
        } else {
            log_printf(LOG_ERROR, "[IN-UC]   pcap_sendpacket: %s\n",
                    pcap_geterr(ctx->handle));
        }

    /* ── INCOMING BROADCAST: target MAC -> FF:FF:FF:FF:FF:FF, with tag ─ */
    } else if (from_target && to_bcast && ethertype == ETHERTYPE_VLAN) {

        if (hdr->caplen < sizeof(eth_vlan_hdr_t)) {
            log_flush();
            return;
        }
        uint16_t vid = ntohs(veth->tci) & 0x0FFF;
        if (vid != ctx->vlan_id) {
            ctx->ignored++;
            log_flush();
            return;
        }

        new_pkt = strip_vlan_tag(pkt, hdr->caplen, &new_len);
        if (!new_pkt) {
            log_flush();
            return;
        }

        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            ctx->bcast_stripped++;
            log_printf(LOG_INFO, "[IN-BC]   Stripped+sent  len %u->%u  VLAN %u  src ",
                   hdr->caplen, new_len, vid);
            print_mac(eth->src);
            log_printf(LOG_INFO, "  inner etype 0x%04X  dst BROADCAST\n",
                   ntohs(veth->ethertype));
        } else {
            log_printf(LOG_ERROR, "[IN-BC]   pcap_sendpacket: %s\n",
                    pcap_geterr(ctx->handle));
        }

    } else {
        ctx->ignored++;
    }

#if 0
done:
#endif
    free(new_pkt);
    log_flush();
    return;
}

/* ── main ───────────────────────────────────────────────────────────────── */

/* Handle set in main so the console-control handler can break the capture loop
 * on Ctrl+C, Ctrl+Break, or console close. */
static pcap_t *g_pcap_handle = NULL;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            if (g_pcap_handle)
                pcap_breakloop(g_pcap_handle);  /* makes pcap_loop return */
            return TRUE;
        default:
            return FALSE;
    }
}

/* ── discovery mode ─────────────────────────────────────────────────────── */

/* Format a network-order IPv4 address into dotted decimal. 'buf' must hold at
 * least 16 bytes. Avoids inet_ntoa's shared static buffer (which would alias
 * when two addresses are printed in one log line). */
static void ip_to_str(uint32_t ip_net, char *buf, size_t sz)
{
    const uint8_t *b = (const uint8_t *)&ip_net;
    snprintf(buf, sz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* BPF: VLAN-tagged ARP, or VLAN-tagged IPv4/ICMP. Manual offsets match the
 * style of build_bpf(). In a tagged frame the inner ethertype is at [16:2] and
 * the IP protocol byte is at 18 (IP header start) + 9 = 27. */
static void build_discovery_bpf(char *buf, size_t sz)
{
    snprintf(buf, sz,
        "ether[12:2] = 0x8100 and ("
        "ether[16:2] = 0x0806 or "
        "(ether[16:2] = 0x0800 and ether[27] = 1))");
}

static void discovery_handler(u_char *user,
                              const struct pcap_pkthdr *hdr,
                              const u_char *pkt)
{
    disc_ctx_t *dc = (disc_ctx_t *)user;

    if (hdr->caplen < 18) return;                       /* tagged eth header  */
    uint16_t tpid = (uint16_t)((pkt[12] << 8) | pkt[13]);
    if (tpid != ETHERTYPE_VLAN) return;                 /* BPF already ensures */

    uint16_t vid   = (uint16_t)(((pkt[14] << 8) | pkt[15]) & 0x0FFF);
    uint16_t inner = (uint16_t)((pkt[16] << 8) | pkt[17]);
    const uint8_t *src_mac = pkt + 6;

    uint32_t ip_a = 0, ip_b = 0;    /* ARP: sender/target; IPv4: src/dst */
    const char *proto;

    if (inner == 0x0806) {                              /* ARP */
        if (hdr->caplen < 46) return;                   /* need through tpa   */
        memcpy(&ip_a, pkt + 32, 4);                     /* spa (sender IP)    */
        memcpy(&ip_b, pkt + 42, 4);                     /* tpa (target IP)    */
        proto = "ARP";
    } else if (inner == ETHERTYPE_IPV4) {               /* IPv4 */
        if (hdr->caplen < 38) return;                   /* need through dst IP */
        if (pkt[27] != IP_PROTO_ICMP) return;
        memcpy(&ip_a, pkt + 30, 4);                     /* src IP */
        memcpy(&ip_b, pkt + 34, 4);                     /* dst IP */
        proto = "ICMP";
    } else {
        return;
    }

    /* IP filter: keep only frames where the target IP is on either side. */
    if (dc->filter_ip != 0 && dc->filter_ip != ip_a && dc->filter_ip != ip_b)
        return;

    /* Find an existing (VLAN, source MAC) entry. */
    int idx = -1;
    for (int i = 0; i < dc->n; i++) {
        if (dc->e[i].vlan_id == vid && mac_eq(dc->e[i].mac, src_mac)) {
            idx = i;
            break;
        }
    }

    char ipa[16], ipb[16];
    ip_to_str(ip_a, ipa, sizeof(ipa));
    ip_to_str(ip_b, ipb, sizeof(ipb));

    if (idx < 0) {
        if (dc->n >= DISC_MAX) return;                  /* table full */
        idx = dc->n++;
        dc->e[idx].vlan_id = vid;
        memcpy(dc->e[idx].mac, src_mac, ETH_ALEN);
        dc->e[idx].ip    = ip_a;                        /* device's own IP */
        dc->e[idx].count = 1;
        log_printf(LOG_INFO, "[DISC] New: VLAN %-4u ", vid);
        print_mac(src_mac);
        log_printf(LOG_INFO, "  IP %-15s  via %s\n", ipa, proto);
    } else {
        dc->e[idx].count++;
        if (dc->e[idx].ip == 0) dc->e[idx].ip = ip_a;
    }

    if (dc->verbose) {
        log_printf(LOG_INFO, "[DISC] VLAN %-4u ", vid);
        print_mac(src_mac);
        log_printf(LOG_INFO, "  %-4s %s->%s\n", proto, ipa, ipb);
    }
    log_flush();
}

/* Sort discovered entries by VLAN, then MAC (insertion sort; n <= DISC_MAX). */
static void disc_sort(disc_ctx_t *dc)
{
    for (int i = 1; i < dc->n; i++) {
        disc_entry_t key = dc->e[i];
        int j = i - 1;
        while (j >= 0 &&
               (dc->e[j].vlan_id > key.vlan_id ||
                (dc->e[j].vlan_id == key.vlan_id &&
                 memcmp(dc->e[j].mac, key.mac, ETH_ALEN) > 0))) {
            dc->e[j + 1] = dc->e[j];
            j--;
        }
        dc->e[j + 1] = key;
    }
}

/* Open the interface, capture tagged ARP/ICMP, and print a summary on exit. */
static int run_discovery(const char *iface, uint32_t filter_ip, int verbose)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);
    if (!handle) {
        log_printf(LOG_ERROR, "pcap_open_live: %s\n", errbuf);
        log_flush();
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        log_printf(LOG_ERROR, "Interface is not Ethernet (DLT_EN10MB).\n");
        pcap_close(handle);
        log_flush();
        return 1;
    }

    char filter_str[256];
    build_discovery_bpf(filter_str, sizeof(filter_str));

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        log_printf(LOG_ERROR, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        log_flush();
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        log_printf(LOG_ERROR, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        log_flush();
        return 1;
    }
    pcap_freecode(&fp);

    disc_ctx_t *dc = (disc_ctx_t *)calloc(1, sizeof(disc_ctx_t));
    if (!dc) {
        log_printf(LOG_ERROR, "Out of memory\n");
        pcap_close(handle);
        log_flush();
        return 1;
    }
    dc->filter_ip = filter_ip;
    dc->verbose   = verbose;

    /* Ctrl+C breaks the loop so the summary prints (reuses the bridge's handler). */
    g_pcap_handle = handle;
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    log_printf(LOG_INFO, "Discovery on %s  (Ctrl+C to stop)\n", iface);
    if (filter_ip) {
        char f[16];
        ip_to_str(filter_ip, f, sizeof(f));
        log_printf(LOG_INFO, "IP filter : %s (either side)\n", f);
    }
    log_printf(LOG_INFO, "BPF filter: %s\n\n", filter_str);
    log_flush();

    pcap_loop(handle, 0, discovery_handler, (u_char *)dc);

    /* ── summary table ────────────────────────────────────────────────── */
    disc_sort(dc);
    log_printf(LOG_INFO, "\n--- Discovered %d device(s) ---\n", dc->n);
    if (dc->n == 0) {
        log_printf(LOG_INFO,
            "(no tagged ARP/ICMP seen — verify the NIC delivers VLAN tags to "
            "Npcap; hardware VLAN offload may strip them)\n");
    } else {
        log_printf(LOG_INFO, "VLAN  MAC                IP               pkts\n");
        for (int i = 0; i < dc->n; i++) {
            char ipbuf[16];
            ip_to_str(dc->e[i].ip, ipbuf, sizeof(ipbuf));
            log_printf(LOG_INFO, "%-4u  ", dc->e[i].vlan_id);
            print_mac(dc->e[i].mac);
            log_printf(LOG_INFO, "  %-15s  %llu\n", ipbuf, dc->e[i].count);
        }
    }

    free(dc);
    pcap_close(handle);
    log_close();
    return 0;
}

/* Usage goes straight to stderr so it works before the logger is initialised
 * (argument parsing happens before log_init so -o can choose the log target). */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <interface> -t <target_mac> -v <vlan_id> [-o <logfile>] [-d]\n"
        "       %s -s -i <interface> [-f <ip>] [-o <logfile>] [-d]\n"
        "       %s -l\n\n"
        "  -i   Npcap interface name (e.g. \\Device\\NPF_{GUID})\n"
        "  -t   Target MAC address   (e.g. AA:BB:CC:DD:EE:FF)\n"
        "  -v   VLAN ID              (1-4094)\n"
        "  -s   Discovery mode: scan tagged ARP/ICMP to find target MAC + VLAN\n"
        "  -f   Discovery IP filter: only frames with this IP on either side\n"
        "  -o   Write log to <logfile> instead of stdout\n"
        "  -d   Verbose: keep per-packet logging during capture\n"
        "  -l   List interfaces and exit\n",
        prog, prog, prog);
}

int main(int argc, char *argv[])
{
    char    *iface      = NULL;
    char    *target_str = NULL;
    char    *logfile    = NULL;
    char    *filter_str_ip = NULL;
    int      vlan_id    = -1;
    int      do_list    = 0;
    int      do_scan    = 0;
    int      verbose    = 0;

    /* ── parse args ──────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            do_list = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            do_scan = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            target_str = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 && i+1 < argc) {
            vlan_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            filter_str_ip = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            logfile = argv[++i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    /* Logger writes to stdout unless -o names a file. Must come after parsing
     * so -o can pick the target, but before any log_printf below. */
    log_init(logfile, LOG_INFO);

    if (do_list) {
#if 0
        list_interfaces();
#else
        list_devices();
#endif
        log_close();
        return 0;
    }

    /* ── discovery mode ──────────────────────────────────────────────── */
    if (do_scan) {
        if (!iface) {
            usage(argv[0]);
            log_close();
            return 1;
        }
        uint32_t filter_ip = 0;   /* 0 = no filter */
        if (filter_str_ip) {
            filter_ip = inet_addr(filter_str_ip);   /* network order */
            if (filter_ip == INADDR_NONE) {
                log_printf(LOG_ERROR, "Invalid -f IP address: %s\n", filter_str_ip);
                log_close();
                return 1;
            }
        }
        return run_discovery(iface, filter_ip, verbose);
    }

    if (!iface || !target_str || vlan_id < 1 || vlan_id > 4094) {
        usage(argv[0]);
        log_close();
        return 1;
    }

    /* ── init context ────────────────────────────────────────────────── */
    proxy_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.vlan_id = (uint16_t)vlan_id;

    if (parse_mac(target_str, ctx.target_mac) != 0) {
        log_printf(LOG_ERROR, "Invalid target MAC address: %s\n", target_str);
        log_flush();
        return 1;
    }

    if (get_interface_mac(iface, ctx.my_mac) != 0) {
        log_printf(LOG_ERROR,
            "Could not auto-detect MAC for interface: %s\n"
            "Ensure the interface name is correct (use -l to list).\n", iface);
        log_flush();
        return 1;
    }

    log_printf(LOG_INFO, "Interface : %s\n", iface);
    log_printf(LOG_INFO, "My MAC    : "); print_mac(ctx.my_mac);    log_printf(LOG_INFO, "\n");
    log_printf(LOG_INFO, "Target MAC: "); print_mac(ctx.target_mac); log_printf(LOG_INFO, "\n");
    log_printf(LOG_INFO, "VLAN ID   : %u\n\n", ctx.vlan_id);

    /* ── open pcap handle ────────────────────────────────────────────── */
    char errbuf[PCAP_ERRBUF_SIZE];
    ctx.handle = pcap_open_live(iface, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);
    if (!ctx.handle) {
        log_printf(LOG_ERROR, "pcap_open_live: %s\n", errbuf);
        log_flush();
        return 1;
    }

    /* Verify this is an Ethernet link */
    if (pcap_datalink(ctx.handle) != DLT_EN10MB) {
        log_printf(LOG_ERROR, "Interface is not Ethernet (DLT_EN10MB).\n");
        pcap_close(ctx.handle);
        log_flush();
        return 1;
    }

    /* ── compile and set BPF filter ──────────────────────────────────── */
    char filter_str[1024];
    build_bpf(filter_str, sizeof(filter_str), ctx.my_mac, ctx.target_mac);
    log_printf(LOG_INFO, "BPF filter: %s\n\n", filter_str);

    struct bpf_program fp;
    if (pcap_compile(ctx.handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        log_printf(LOG_ERROR, "pcap_compile: %s\n", pcap_geterr(ctx.handle));
        pcap_close(ctx.handle);
        log_flush();
        return 1;
    }
    if (pcap_setfilter(ctx.handle, &fp) == -1) {
        log_printf(LOG_ERROR, "pcap_setfilter: %s\n", pcap_geterr(ctx.handle));
        pcap_freecode(&fp);
        pcap_close(ctx.handle);
        log_flush();
        return 1;
    }
    pcap_freecode(&fp);

    /* Install a console-control handler so Ctrl+C breaks the capture loop
     * cleanly (lets us print stats and flush the log instead of dying). */
    g_pcap_handle = ctx.handle;
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    log_printf(LOG_INFO, "Listening... (Ctrl+C to stop)\n\n");
    /* Quiet the per-packet INFO logging during capture unless -d was given
     * (per-packet logging is expensive on a busy link). */
    if (!verbose)
        log_set_level(LOG_ERROR);
    log_flush();

    /* ── capture loop ────────────────────────────────────────────────── */
    pcap_loop(ctx.handle, 0, packet_handler, (u_char *)&ctx);

    /* ── cleanup / stats ─────────────────────────────────────────────── */
    log_set_level(LOG_INFO);   /* restore so the stats below actually print */
    log_printf(LOG_INFO, "\n--- Stats ---\n");
    log_printf(LOG_INFO, "Unicast   tagged   (OUT): %llu\n", ctx.tagged_sent);
    log_printf(LOG_INFO, "Broadcast tagged   (OUT): %llu\n", ctx.bcast_tagged_sent);
    log_printf(LOG_INFO, "Fragments sent     (OUT): %llu\n", ctx.frag_sent);
    log_printf(LOG_INFO, "DF dropped + ICMP  (OUT): %llu\n", ctx.df_dropped);
    log_printf(LOG_INFO, "Unicast   stripped (IN) : %llu\n", ctx.stripped_sent);
    log_printf(LOG_INFO, "Broadcast stripped (IN) : %llu\n", ctx.bcast_stripped);
    log_printf(LOG_INFO, "Dedup dropped           : %llu\n", ctx.dedup_dropped);
    log_printf(LOG_INFO, "Ignored                 : %llu\n", ctx.ignored);

    pcap_close(ctx.handle);
    log_close();   /* flush remaining log data and close the handle */
    return 0;
}