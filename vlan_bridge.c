/*
 * vlan_bridge.c — command-line front-end for the VLAN bridge engine.
 *
 * Build (MinGW/MSYS2, adjust paths to your Npcap SDK):
 *   gcc -o vlan_bridge.exe vlan_bridge.c engine.c fast_log.c \
 *       -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib/x64" \
 *       -lwpcap -lws2_32 -liphlpapi
 *
 * Modes:
 *   vlan_bridge -l                                   list interfaces
 *   vlan_bridge -s -i <iface> [-f <ip>]              discovery scan
 *   vlan_bridge -i <iface> -t <mac> -v <vid>         bridge one target
 *   vlan_bridge -i <iface> -r <mac>:<vid> [-r ...]   bridge multiple targets
 *
 * The heavy lifting lives in engine.c; this file only parses arguments,
 * configures rules, and prints results.
 */
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>

#include "engine.h"
#include "fast_log.h"

/* Ctrl+C / console close breaks whichever engine loop is running. */
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            engine_stop();
            return TRUE;
        default:
            return FALSE;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <iface> -t <mac> -v <vid> [-o <logfile>] [-d]\n"
        "       %s -i <iface> -r <mac>:<vid> [-r <mac>:<vid> ...] [-o log] [-d]\n"
        "       %s -s -i <iface> [-f <ip>] [-o <logfile>] [-d]\n"
        "       %s -l\n\n"
        "  -i   Npcap interface name (e.g. \\Device\\NPF_{GUID})\n"
        "  -t   Target MAC address   (e.g. AA:BB:CC:DD:EE:FF)\n"
        "  -v   VLAN ID              (1-4094)\n"
        "  -r   Target rule <mac>:<vid> (repeatable, for multiple targets)\n"
        "  -s   Discovery mode: scan tagged ARP/ICMP to find target MAC + VLAN\n"
        "  -f   Discovery IP filter: only frames with this IP on either side\n"
        "  -o   Write log to <logfile> instead of stdout\n"
        "  -d   Verbose: per-packet logging during capture\n"
        "  -l   List interfaces and exit\n",
        prog, prog, prog, prog);
}

/* Parse "AA:BB:CC:DD:EE:FF:20" — a MAC and VLAN joined by the final ':'. */
static int parse_rule(const char *arg, engine_rule_t *rule)
{
    const char *colon = strrchr(arg, ':');
    if (!colon || colon == arg) return -1;
    char macbuf[64];
    size_t maclen = (size_t)(colon - arg);
    if (maclen >= sizeof(macbuf)) return -1;
    memcpy(macbuf, arg, maclen);
    macbuf[maclen] = '\0';
    if (engine_parse_mac(macbuf, rule->mac) != 0) return -1;
    int vid = atoi(colon + 1);
    if (vid < 1 || vid > 4094) return -1;
    rule->vlan_id = (uint16_t)vid;
    rule->out_tagged = rule->in_stripped = 0;
    return 0;
}

static void do_list_interfaces(void)
{
    iface_info_t ifs[ENGINE_MAX_IFACES];
    int n = engine_enumerate_interfaces(ifs, ENGINE_MAX_IFACES);
    if (n == 0) {
        log_printf(LOG_INFO, "No up Ethernet interfaces found.\n");
        return;
    }
    for (int i = 0; i < n; i++) {
        char mac[18];
        engine_format_mac(ifs[i].mac, mac, sizeof(mac));
        log_printf(LOG_INFO, "Interface: %s\n", ifs[i].npf_name);
        log_printf(LOG_INFO, "  -> Name: %s\n", ifs[i].friendly);
        log_printf(LOG_INFO, "  -> IP  : %s\n", ifs[i].ip[0] ? ifs[i].ip : "(none)");
        log_printf(LOG_INFO, "  -> MAC : %s\n\n", mac);
    }
}

/* Sort + print the discovery results captured by the engine. */
static void print_discovery_summary(void)
{
    disc_row_t rows[ENGINE_DISC_MAX];
    int n = engine_discovery_snapshot(rows, ENGINE_DISC_MAX);

    /* insertion sort by VLAN, then MAC */
    for (int i = 1; i < n; i++) {
        disc_row_t key = rows[i];
        int j = i - 1;
        while (j >= 0 &&
               (rows[j].vlan_id > key.vlan_id ||
                (rows[j].vlan_id == key.vlan_id &&
                 memcmp(rows[j].mac, key.mac, ETH_ALEN) > 0))) {
            rows[j + 1] = rows[j];
            j--;
        }
        rows[j + 1] = key;
    }

    log_printf(LOG_INFO, "\n--- Discovered %d device(s) ---\n", n);
    if (n == 0) {
        log_printf(LOG_INFO,
            "(no tagged ARP/ICMP seen — verify the NIC delivers VLAN tags to "
            "Npcap; hardware VLAN offload may strip them)\n");
        return;
    }
    log_printf(LOG_INFO, "VLAN  MAC                IP               pkts\n");
    for (int i = 0; i < n; i++) {
        const uint8_t *b = (const uint8_t *)&rows[i].ip;
        char mac[18];
        engine_format_mac(rows[i].mac, mac, sizeof(mac));
        log_printf(LOG_INFO, "%-4u  %s  %u.%u.%u.%-7u %llu\n",
                   rows[i].vlan_id, mac, b[0], b[1], b[2], b[3],
                   (unsigned long long)rows[i].count);
    }
}

int main(int argc, char *argv[])
{
    const char *iface = NULL, *target_str = NULL, *logfile = NULL;
    const char *filter_str_ip = NULL;
    int vlan_id = -1, do_list = 0, do_scan = 0, verbose = 0;

    engine_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-l") == 0) do_list = 1;
        else if (strcmp(argv[i], "-s") == 0) do_scan = 1;
        else if (strcmp(argv[i], "-d") == 0) verbose = 1;
        else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "-v") == 0 && i+1 < argc) vlan_id = atoi(argv[++i]);
        else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) filter_str_ip = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) logfile = argv[++i];
        else if (strcmp(argv[i], "-r") == 0 && i+1 < argc) {
            if (cfg.n_rules >= ENGINE_MAX_RULES) {
                fprintf(stderr, "Too many -r rules (max %d)\n", ENGINE_MAX_RULES);
                return 1;
            }
            if (parse_rule(argv[++i], &cfg.rules[cfg.n_rules]) != 0) {
                fprintf(stderr, "Invalid -r rule: %s (expected <mac>:<vid>)\n", argv[i]);
                return 1;
            }
            cfg.n_rules++;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    log_init(logfile, LOG_INFO);
    engine_init();
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    if (do_list) {
        do_list_interfaces();
        log_close();
        return 0;
    }

    if (do_scan) {
        if (!iface) { usage(argv[0]); log_close(); return 1; }
        uint32_t filter_ip = 0;
        if (filter_str_ip) {
            filter_ip = inet_addr(filter_str_ip);
            if (filter_ip == INADDR_NONE) {
                log_printf(LOG_ERROR, "Invalid -f IP address: %s\n", filter_str_ip);
                log_close();
                return 1;
            }
        }
        log_printf(LOG_INFO, "Listening... (Ctrl+C to stop)\n\n");
        log_flush();
        engine_discovery_run(iface, filter_ip, verbose);
        print_discovery_summary();
        log_close();
        return 0;
    }

    /* ── bridge mode ─────────────────────────────────────────────────────── */
    /* Single -t/-v shorthand becomes one rule (appended after any -r rules). */
    if (target_str || vlan_id != -1) {
        if (!target_str || vlan_id < 1 || vlan_id > 4094) {
            usage(argv[0]); log_close(); return 1;
        }
        if (cfg.n_rules >= ENGINE_MAX_RULES) {
            log_printf(LOG_ERROR, "Too many rules.\n"); log_close(); return 1;
        }
        engine_rule_t *r = &cfg.rules[cfg.n_rules];
        if (engine_parse_mac(target_str, r->mac) != 0) {
            log_printf(LOG_ERROR, "Invalid target MAC address: %s\n", target_str);
            log_close();
            return 1;
        }
        r->vlan_id = (uint16_t)vlan_id;
        cfg.n_rules++;
    }

    if (!iface || cfg.n_rules == 0) { usage(argv[0]); log_close(); return 1; }

    snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface);
    cfg.verbose = verbose;

    if (engine_get_interface_mac(iface, cfg.my_mac) != 0) {
        log_printf(LOG_ERROR,
            "Could not auto-detect MAC for interface: %s\n"
            "Ensure the interface name is correct (use -l to list).\n", iface);
        log_close();
        return 1;
    }

    char mymac[18];
    engine_format_mac(cfg.my_mac, mymac, sizeof(mymac));
    log_printf(LOG_INFO, "Interface : %s\n", iface);
    log_printf(LOG_INFO, "My MAC    : %s\n", mymac);
    log_printf(LOG_INFO, "Rules     : %d\n", cfg.n_rules);
    for (int i = 0; i < cfg.n_rules; i++) {
        char tmac[18];
        engine_format_mac(cfg.rules[i].mac, tmac, sizeof(tmac));
        log_printf(LOG_INFO, "  %s -> VLAN %u\n", tmac, cfg.rules[i].vlan_id);
    }
    log_printf(LOG_INFO, "\nListening... (Ctrl+C to stop)\n\n");
    log_flush();

    engine_bridge_run(&cfg);

    /* ── stats ───────────────────────────────────────────────────────────── */
    engine_stats_t st;
    engine_get_stats(&st);
    log_printf(LOG_INFO, "\n--- Stats ---\n");
    log_printf(LOG_INFO, "Unicast   tagged   (OUT): %llu\n", (unsigned long long)st.out_tagged);
    log_printf(LOG_INFO, "Broadcast tagged   (OUT): %llu\n", (unsigned long long)st.out_bcast);
    log_printf(LOG_INFO, "Unicast   stripped (IN) : %llu\n", (unsigned long long)st.in_stripped);
    log_printf(LOG_INFO, "Broadcast stripped (IN) : %llu\n", (unsigned long long)st.in_bcast);
    log_printf(LOG_INFO, "Ignored                 : %llu\n", (unsigned long long)st.ignored);
    for (int i = 0; i < cfg.n_rules; i++) {
        char tmac[18];
        engine_format_mac(cfg.rules[i].mac, tmac, sizeof(tmac));
        log_printf(LOG_INFO, "  %s VLAN %u:  out %llu  in %llu\n",
                   tmac, cfg.rules[i].vlan_id,
                   (unsigned long long)cfg.rules[i].out_tagged,
                   (unsigned long long)cfg.rules[i].in_stripped);
    }

    log_close();
    return 0;
}
