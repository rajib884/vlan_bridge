/*
 * engine.c — VLAN bridge core (multi-rule). See engine.h.
 *
 * Adapted from the original single-target vlan_bridge.c: the tag/strip and
 * checksum helpers are unchanged; the context, BPF builder, and packet handler
 * are generalized to an arbitrary list of (target MAC -> VLAN) rules, and the
 * capture/discovery loops are made stoppable from another thread so a GUI can
 * drive them on a worker thread.
 */
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>

#include "engine.h"
#include "fast_log.h"

/* ── constants ──────────────────────────────────────────────────────────── */
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_IPV4  0x0800
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define SNAP_LEN        65535
#define PROMISC         1
#define TIMEOUT_MS      1

static const uint8_t BROADCAST_MAC[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

#pragma pack(push, 1)
typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t tpid;
    uint16_t tci;
    uint16_t ethertype;
} eth_vlan_hdr_t;
#pragma pack(pop)

/* ── internal run contexts ──────────────────────────────────────────────── */
typedef struct {
    pcap_t        *handle;
    uint8_t        my_mac[ETH_ALEN];
    engine_rule_t *rules;                  /* owned by caller (cfg->rules)      */
    int            n_rules;
    uint16_t       vlans[ENGINE_MAX_RULES];/* distinct VLANs for bcast replicate*/
    int            n_vlans;
    int            verbose;
    engine_stats_t stats;
} bridge_ctx_t;

typedef struct {
    uint32_t filter_ip;
    int      verbose;
    int      n;
    disc_row_t e[ENGINE_DISC_MAX];
} disc_ctx_t;

/* ── shared engine state (guarded by g_lock) ────────────────────────────── */
static CRITICAL_SECTION g_lock;
static int              g_lock_init = 0;
static pcap_t          *g_active_handle = NULL;   /* for engine_stop           */
static bridge_ctx_t    *g_active_bridge = NULL;   /* for stats snapshot        */
static engine_stats_t   g_last_stats;             /* preserved after a run     */
static disc_ctx_t       g_disc;                   /* discovery table + result  */

static void lock(void)   { if (g_lock_init) EnterCriticalSection(&g_lock); }
static void unlock(void) { if (g_lock_init) LeaveCriticalSection(&g_lock); }

void engine_init(void)
{
    if (!g_lock_init) {
        InitializeCriticalSection(&g_lock);
        g_lock_init = 1;
    }
    memset(&g_last_stats, 0, sizeof(g_last_stats));
    memset(&g_disc, 0, sizeof(g_disc));
}

/* ── small helpers ──────────────────────────────────────────────────────── */
int engine_parse_mac(const char *str, uint8_t *mac)
{
    unsigned int b[ETH_ALEN];
    if (!str) return -1;
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != ETH_ALEN)
        return -1;
    for (int i = 0; i < ETH_ALEN; i++) mac[i] = (uint8_t)b[i];
    return 0;
}

void engine_format_mac(const uint8_t *mac, char *buf, size_t sz)
{
    snprintf(buf, sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static void print_mac_log(const uint8_t *mac)
{
    log_printf(LOG_INFO, "%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static int mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, ETH_ALEN) == 0;
}

static void ip_to_str(uint32_t ip_net, char *buf, size_t sz)
{
    const uint8_t *b = (const uint8_t *)&ip_net;
    snprintf(buf, sz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* Extract the adapter GUID ("{...}") from "\Device\NPF_{GUID}". */
static const char *pcap_name_to_guid(const char *pcap_name)
{
    return pcap_name ? strchr(pcap_name, '{') : NULL;
}

int engine_get_interface_mac(const char *pcap_name, uint8_t *mac)
{
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
        if (_stricmp(a->AdapterName, guid) == 0) {
            memcpy(mac, a->Address, ETH_ALEN);
            found = 1;
            break;
        }
    }
    free(info_buf);
    return found ? 0 : -1;
}

/* Enumerate up-and-running Ethernet interfaces with a MAC. Returns the count
 * written to out[] (<= max). Reuses GetAdaptersAddresses + pcap_findalldevs. */
int engine_enumerate_interfaces(iface_info_t *out, int max)
{
    pcap_if_t *alldevs = NULL, *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    ULONG bufferSize = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL, pCurrent = NULL;
    DWORD result;
    int count = 0;

    result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!pAddresses) return 0;
        result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    }
    if (result != ERROR_SUCCESS) { free(pAddresses); return 0; }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) { free(pAddresses); return 0; }

    for (dev = alldevs; dev && count < max; dev = dev->next) {
        const char *guid = pcap_name_to_guid(dev->name);
        if (!guid) continue;
        for (pCurrent = pAddresses; pCurrent; pCurrent = pCurrent->Next) {
            if (pCurrent->OperStatus != IfOperStatusUp) continue;
            if (pCurrent->PhysicalAddressLength != 6) continue;
            if (_stricmp(pCurrent->AdapterName, guid) != 0) continue;

            iface_info_t *it = &out[count];
            memset(it, 0, sizeof(*it));
            snprintf(it->npf_name, sizeof(it->npf_name), "%s", dev->name);
            memcpy(it->mac, pCurrent->PhysicalAddress, ETH_ALEN);
            it->has_mac = 1;

            PIP_ADAPTER_UNICAST_ADDRESS ua = pCurrent->FirstUnicastAddress;
            for (; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sin =
                        (struct sockaddr_in *)ua->Address.lpSockaddr;
                    snprintf(it->ip, sizeof(it->ip), "%s", inet_ntoa(sin->sin_addr));
                    break;
                }
            }
            if (pCurrent->FriendlyName)
                WideCharToMultiByte(CP_UTF8, 0, pCurrent->FriendlyName, -1,
                                    it->friendly, sizeof(it->friendly), NULL, NULL);
            count++;
            break;
        }
    }

    pcap_freealldevs(alldevs);
    free(pAddresses);
    return count;
}

/* ── multi-rule BPF ─────────────────────────────────────────────────────────
 * Per rule: outgoing-unicast (src my, dst mac_i, untagged), incoming-unicast
 * (src mac_i, dst my, tagged), incoming-broadcast (src mac_i, dst bcast,
 * tagged). Plus one shared outgoing-broadcast clause (src my, dst bcast,
 * untagged). Built into a malloc'd buffer; caller frees.
 * ──────────────────────────────────────────────────────────────────────── */
static char *build_bpf(const uint8_t *my_mac,
                       const engine_rule_t *rules, int n_rules)
{
    size_t cap = 256 + (size_t)n_rules * 400;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    char my[18];
    engine_format_mac(my_mac, my, sizeof(my));

    size_t off = 0;
    #define APPEND(...) do { \
        int _n = snprintf(buf + off, cap - off, __VA_ARGS__); \
        if (_n < 0 || (size_t)_n >= cap - off) { free(buf); return NULL; } \
        off += (size_t)_n; \
    } while (0)

    /* shared outgoing broadcast */
    APPEND("(ether src %s and ether dst ff:ff:ff:ff:ff:ff and ether[12:2] != 0x8100)", my);

    for (int i = 0; i < n_rules; i++) {
        char t[18];
        engine_format_mac(rules[i].mac, t, sizeof(t));
        APPEND(" or (ether src %s and ether dst %s and ether[12:2] != 0x8100)", my, t);
        APPEND(" or (ether src %s and ether dst %s and ether[12:2] == 0x8100)", t, my);
        APPEND(" or (ether src %s and ether dst ff:ff:ff:ff:ff:ff and ether[12:2] == 0x8100)", t);
    }
    #undef APPEND
    return buf;
}

/* ── tag insert / strip (unchanged) ─────────────────────────────────────── */
static uint8_t *insert_vlan_tag(const u_char *pkt, uint32_t orig_len,
                                uint16_t vlan_id, uint32_t *new_len_out)
{
    uint32_t new_len = orig_len + 4;
    uint8_t *np = (uint8_t *)malloc(new_len);
    if (!np) return NULL;
    memcpy(np, pkt, 12);
    uint16_t tpid = htons(ETHERTYPE_VLAN);
    uint16_t tci  = htons(vlan_id & 0x0FFF);
    memcpy(np + 12, &tpid, 2);
    memcpy(np + 14, &tci,  2);
    memcpy(np + 16, pkt + 12, orig_len - 12);
    *new_len_out = new_len;
    return np;
}

static uint8_t *strip_vlan_tag(const u_char *pkt, uint32_t orig_len,
                               uint32_t *new_len_out)
{
    if (orig_len < 18) return NULL;
    uint32_t new_len = orig_len - 4;
    uint8_t *np = (uint8_t *)malloc(new_len);
    if (!np) return NULL;
    memcpy(np, pkt, 12);
    memcpy(np + 12, pkt + 16, orig_len - 16);
    *new_len_out = new_len;
    return np;
}

/* ── checksums (unchanged) ──────────────────────────────────────────────── */
static uint32_t cksum_add(uint32_t init, const void *data, uint32_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = init;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    return sum;
}

static uint16_t cksum_fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void fix_ip_checksum(uint8_t *ip)
{
    uint8_t ihl = (ip[0] & 0x0f) * 4;
    uint16_t *csum = (uint16_t *)(ip + 10);
    *csum = 0;
    *csum = cksum_fold(cksum_add(0, ip, ihl));
}

static void fix_transport_checksum(uint8_t *ip, uint8_t *transport,
                                   uint16_t tlen, uint8_t proto, uint16_t csum_off)
{
    uint8_t pseudo[12];
    memcpy(pseudo,     ip + 12, 4);
    memcpy(pseudo + 4, ip + 16, 4);
    pseudo[8]  = 0;
    pseudo[9]  = proto;
    pseudo[10] = (uint8_t)(tlen >> 8);
    pseudo[11] = (uint8_t)(tlen & 0xff);

    uint16_t *csum = (uint16_t *)(transport + csum_off);
    *csum = 0;
    uint32_t sum = cksum_add(0, pseudo, 12);
    sum = cksum_add(sum, transport, tlen);
    uint16_t folded = cksum_fold(sum);
    if (folded == 0 && proto == IP_PROTO_UDP)
        folded = 0xFFFF;
    *csum = folded;
}

static void fix_checksums_in_tagged_frame(uint8_t *frame, uint32_t frame_len)
{
    if (frame_len < 18 + 20) return;
    uint16_t inner_etype = (uint16_t)((frame[16] << 8) | frame[17]);
    if (inner_etype != ETHERTYPE_IPV4) return;

    uint8_t *ip  = frame + 18;
    uint8_t  ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || frame_len < 18u + ihl) return;

    uint16_t total_len = (uint16_t)((ip[2] << 8) | ip[3]);
    if (frame_len < 18u + total_len) return;

    uint8_t  proto = ip[9];
    uint16_t tlen  = total_len - ihl;
    uint8_t *tp    = ip + ihl;

    fix_ip_checksum(ip);
    if (tlen < 8) return;

    switch (proto) {
        case IP_PROTO_TCP:
            if (tlen >= 20) fix_transport_checksum(ip, tp, tlen, IP_PROTO_TCP, 16);
            break;
        case IP_PROTO_UDP:
            if (tlen >= 8)  fix_transport_checksum(ip, tp, tlen, IP_PROTO_UDP, 6);
            break;
        case IP_PROTO_ICMP: {
            uint16_t *csum = (uint16_t *)(tp + 2);
            *csum = 0;
            *csum = cksum_fold(cksum_add(0, tp, tlen));
            break;
        }
        default: break;
    }
}

/* ── packet handler (multi-rule) ────────────────────────────────────────── */
static int find_rule_by_mac(bridge_ctx_t *ctx, const uint8_t *mac)
{
    for (int i = 0; i < ctx->n_rules; i++)
        if (mac_eq(ctx->rules[i].mac, mac)) return i;
    return -1;
}

static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    bridge_ctx_t *ctx = (bridge_ctx_t *)user;
    if (hdr->caplen < sizeof(eth_hdr_t)) return;

    const eth_hdr_t      *eth  = (const eth_hdr_t *)pkt;
    const eth_vlan_hdr_t *veth = (const eth_vlan_hdr_t *)pkt;
    uint16_t ethertype = ntohs(eth->ethertype);
    int tagged  = (ethertype == ETHERTYPE_VLAN);
    int from_me = mac_eq(eth->src, ctx->my_mac);
    int to_me   = mac_eq(eth->dst, ctx->my_mac);
    int to_bcast= mac_eq(eth->dst, BROADCAST_MAC);

    uint8_t *new_pkt = NULL;
    uint32_t new_len = 0;

    if (from_me && !tagged && to_bcast) {
        /* OUTGOING BROADCAST: replicate into every distinct VLAN. */
        for (int v = 0; v < ctx->n_vlans; v++) {
            uint32_t len;
            uint8_t *np = insert_vlan_tag(pkt, hdr->caplen, ctx->vlans[v], &len);
            if (!np) continue;
            fix_checksums_in_tagged_frame(np, len);
            if (pcap_sendpacket(ctx->handle, np, (int)len) == 0) {
                ctx->stats.out_bcast++;
                if (ctx->verbose)
                    log_printf(LOG_INFO, "[OUT-BC] tagged VLAN %u  len %u->%u\n",
                               ctx->vlans[v], hdr->caplen, len);
            } else {
                log_printf(LOG_ERROR, "[OUT-BC] pcap_sendpacket: %s\n",
                           pcap_geterr(ctx->handle));
            }
            free(np);
        }
    } else if (from_me && !tagged) {
        /* OUTGOING UNICAST: tag with the destination rule's VLAN. */
        int idx = find_rule_by_mac(ctx, eth->dst);
        if (idx < 0) { ctx->stats.ignored++; log_flush(); return; }
        new_pkt = insert_vlan_tag(pkt, hdr->caplen, ctx->rules[idx].vlan_id, &new_len);
        if (!new_pkt) { log_flush(); return; }
        fix_checksums_in_tagged_frame(new_pkt, new_len);
        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            ctx->stats.out_tagged++;
            ctx->rules[idx].out_tagged++;
            if (ctx->verbose) {
                log_printf(LOG_INFO, "[OUT-UC] tagged VLAN %u  dst ",
                           ctx->rules[idx].vlan_id);
                print_mac_log(eth->dst);
                log_printf(LOG_INFO, "  len %u->%u\n", hdr->caplen, new_len);
            }
        } else {
            log_printf(LOG_ERROR, "[OUT-UC] pcap_sendpacket: %s\n",
                       pcap_geterr(ctx->handle));
        }
    } else if (tagged) {
        /* INCOMING (unicast or broadcast): src must be a known target and the
         * VID must match that target's rule. */
        if (hdr->caplen < sizeof(eth_vlan_hdr_t)) { log_flush(); return; }
        int idx = find_rule_by_mac(ctx, eth->src);
        uint16_t vid = ntohs(veth->tci) & 0x0FFF;
        if (idx < 0 || vid != ctx->rules[idx].vlan_id || !(to_me || to_bcast)) {
            ctx->stats.ignored++; log_flush(); return;
        }
        new_pkt = strip_vlan_tag(pkt, hdr->caplen, &new_len);
        if (!new_pkt) { log_flush(); return; }
        if (pcap_sendpacket(ctx->handle, new_pkt, (int)new_len) == 0) {
            if (to_bcast) ctx->stats.in_bcast++; else ctx->stats.in_stripped++;
            ctx->rules[idx].in_stripped++;
            if (ctx->verbose) {
                log_printf(LOG_INFO, "[IN] stripped VLAN %u  src ", vid);
                print_mac_log(eth->src);
                log_printf(LOG_INFO, "  len %u->%u%s\n",
                           hdr->caplen, new_len, to_bcast ? "  (bcast)" : "");
            }
        } else {
            log_printf(LOG_ERROR, "[IN] pcap_sendpacket: %s\n",
                       pcap_geterr(ctx->handle));
        }
    } else {
        ctx->stats.ignored++;
    }

    free(new_pkt);
    log_flush();
}

/* ── bridge runner ──────────────────────────────────────────────────────── */
int engine_bridge_run(engine_config_t *cfg)
{
    if (!cfg || cfg->n_rules <= 0) {
        log_printf(LOG_ERROR, "No rules configured.\n");
        log_flush();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(cfg->iface, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);
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

    char *filter = build_bpf(cfg->my_mac, cfg->rules, cfg->n_rules);
    if (!filter) {
        log_printf(LOG_ERROR, "Failed to build BPF filter.\n");
        pcap_close(handle);
        log_flush();
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        log_printf(LOG_ERROR, "pcap_compile: %s\n", pcap_geterr(handle));
        free(filter); pcap_close(handle); log_flush();
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        log_printf(LOG_ERROR, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp); free(filter); pcap_close(handle); log_flush();
        return 1;
    }
    pcap_freecode(&fp);
    free(filter);

    bridge_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.handle  = handle;
    memcpy(ctx.my_mac, cfg->my_mac, ETH_ALEN);
    ctx.rules   = cfg->rules;
    ctx.n_rules = cfg->n_rules;
    ctx.verbose = cfg->verbose;

    /* distinct VLANs for broadcast replication */
    for (int i = 0; i < cfg->n_rules; i++) {
        int seen = 0;
        for (int j = 0; j < ctx.n_vlans; j++)
            if (ctx.vlans[j] == cfg->rules[i].vlan_id) { seen = 1; break; }
        if (!seen) ctx.vlans[ctx.n_vlans++] = cfg->rules[i].vlan_id;
    }

    lock();
    g_active_handle = handle;
    g_active_bridge = &ctx;
    unlock();

    pcap_loop(handle, 0, packet_handler, (u_char *)&ctx);

    lock();
    g_last_stats    = ctx.stats;   /* preserve for post-run snapshots */
    g_active_bridge = NULL;
    g_active_handle = NULL;
    unlock();

    pcap_close(handle);
    return 0;
}

/* ── discovery ──────────────────────────────────────────────────────────── */
static void build_discovery_bpf(char *buf, size_t sz)
{
    snprintf(buf, sz,
        "ether[12:2] = 0x8100 and ("
        "ether[16:2] = 0x0806 or "
        "(ether[16:2] = 0x0800 and ether[27] = 1))");
}

static void discovery_handler(u_char *user,
                              const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    disc_ctx_t *dc = (disc_ctx_t *)user;
    if (hdr->caplen < 18) return;
    uint16_t tpid = (uint16_t)((pkt[12] << 8) | pkt[13]);
    if (tpid != ETHERTYPE_VLAN) return;

    uint16_t vid   = (uint16_t)(((pkt[14] << 8) | pkt[15]) & 0x0FFF);
    uint16_t inner = (uint16_t)((pkt[16] << 8) | pkt[17]);
    const uint8_t *src_mac = pkt + 6;

    uint32_t ip_a = 0, ip_b = 0;
    const char *proto;

    if (inner == 0x0806) {
        if (hdr->caplen < 46) return;
        memcpy(&ip_a, pkt + 32, 4);
        memcpy(&ip_b, pkt + 42, 4);
        proto = "ARP";
    } else if (inner == ETHERTYPE_IPV4) {
        if (hdr->caplen < 38) return;
        if (pkt[27] != IP_PROTO_ICMP) return;
        memcpy(&ip_a, pkt + 30, 4);
        memcpy(&ip_b, pkt + 34, 4);
        proto = "ICMP";
    } else {
        return;
    }

    if (dc->filter_ip != 0 && dc->filter_ip != ip_a && dc->filter_ip != ip_b)
        return;

    lock();
    int idx = -1;
    for (int i = 0; i < dc->n; i++) {
        if (dc->e[i].vlan_id == vid && mac_eq(dc->e[i].mac, src_mac)) { idx = i; break; }
    }
    int is_new = 0;
    if (idx < 0) {
        if (dc->n < ENGINE_DISC_MAX) {
            idx = dc->n++;
            dc->e[idx].vlan_id = vid;
            memcpy(dc->e[idx].mac, src_mac, ETH_ALEN);
            dc->e[idx].ip    = ip_a;
            dc->e[idx].count = 1;
            is_new = 1;
        }
    } else {
        dc->e[idx].count++;
        if (dc->e[idx].ip == 0) dc->e[idx].ip = ip_a;
    }
    unlock();

    char ipa[16], ipb[16];
    ip_to_str(ip_a, ipa, sizeof(ipa));
    ip_to_str(ip_b, ipb, sizeof(ipb));

    if (is_new) {
        log_printf(LOG_INFO, "[DISC] New: VLAN %-4u ", vid);
        print_mac_log(src_mac);
        log_printf(LOG_INFO, "  IP %-15s  via %s\n", ipa, proto);
    }
    if (dc->verbose) {
        log_printf(LOG_INFO, "[DISC] VLAN %-4u ", vid);
        print_mac_log(src_mac);
        log_printf(LOG_INFO, "  %-4s %s->%s\n", proto, ipa, ipb);
    }
    log_flush();
}

int engine_discovery_run(const char *iface, uint32_t filter_ip, int verbose)
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
        pcap_close(handle); log_flush();
        return 1;
    }

    char filter_str[256];
    build_discovery_bpf(filter_str, sizeof(filter_str));

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        log_printf(LOG_ERROR, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle); log_flush();
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        log_printf(LOG_ERROR, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp); pcap_close(handle); log_flush();
        return 1;
    }
    pcap_freecode(&fp);

    /* Reset the shared discovery table for this run. */
    lock();
    memset(&g_disc, 0, sizeof(g_disc));
    g_disc.filter_ip = filter_ip;
    g_disc.verbose   = verbose;
    g_active_handle  = handle;
    unlock();

    log_printf(LOG_INFO, "Discovery on %s\n", iface);
    if (filter_ip) {
        char f[16]; ip_to_str(filter_ip, f, sizeof(f));
        log_printf(LOG_INFO, "IP filter : %s (either side)\n", f);
    }
    log_printf(LOG_INFO, "BPF filter: %s\n\n", filter_str);
    log_flush();

    pcap_loop(handle, 0, discovery_handler, (u_char *)&g_disc);

    lock();
    g_active_handle = NULL;
    unlock();

    pcap_close(handle);
    return 0;
}

/* ── control + snapshots ────────────────────────────────────────────────── */
void engine_stop(void)
{
    lock();
    if (g_active_handle) pcap_breakloop(g_active_handle);
    unlock();
}

void engine_get_stats(engine_stats_t *out)
{
    lock();
    if (g_active_bridge) *out = g_active_bridge->stats;
    else                 *out = g_last_stats;
    unlock();
}

int engine_get_rule_stats(engine_rule_t *out, int max)
{
    int n = 0;
    lock();
    if (g_active_bridge) {
        n = g_active_bridge->n_rules;
        if (n > max) n = max;
        for (int i = 0; i < n; i++) out[i] = g_active_bridge->rules[i];
    }
    unlock();
    return n;
}

int engine_discovery_snapshot(disc_row_t *out, int max)
{
    lock();
    int n = g_disc.n;
    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = g_disc.e[i];
    unlock();
    return n;
}
