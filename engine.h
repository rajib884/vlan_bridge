/*
 * engine.h — VLAN bridge core, shared by the CLI (vlan_bridge.c) and the
 * GUI (vlan_bridge_gui.c).
 *
 * The engine supports MULTIPLE (target MAC -> VLAN) rules at once. Outgoing
 * unicast to a target MAC is tagged with that target's VLAN; outgoing
 * broadcasts are replicated once into every distinct VLAN in the rule set;
 * incoming tagged frames from a target are stripped when their VID matches
 * that target's VLAN.
 *
 * Runners (engine_bridge_run / engine_discovery_run) block in pcap_loop until
 * engine_stop() is called from another thread (or a fatal error). This lets the
 * GUI run capture on a worker thread and stop it from the UI thread.
 */
#ifndef ENGINE_H
#define ENGINE_H

#include <stdint.h>
#include <stddef.h>

#define ETH_ALEN          6
#define ENGINE_MAX_RULES  64
#define ENGINE_MAX_IFACES 64
#define ENGINE_DISC_MAX   256

/* One (target MAC -> VLAN) rule, plus live per-rule counters. */
typedef struct {
    uint8_t  mac[ETH_ALEN];
    uint16_t vlan_id;
    uint64_t out_tagged;    /* outgoing unicast frames tagged for this target  */
    uint64_t in_stripped;   /* incoming frames from this target, tag removed    */
} engine_rule_t;

/* Aggregate capture statistics. */
typedef struct {
    uint64_t out_tagged;    /* outgoing unicast tagged (all rules)             */
    uint64_t out_bcast;     /* outgoing broadcast copies sent (per VLAN)       */
    uint64_t in_stripped;   /* incoming unicast stripped (all rules)           */
    uint64_t in_bcast;      /* incoming broadcast stripped                     */
    uint64_t ignored;       /* frames captured but not matched                 */
} engine_stats_t;

/* Configuration for one bridge run. rules[] is owned by the caller and must
 * stay valid for the duration of engine_bridge_run(). */
typedef struct {
    char          iface[300];              /* \Device\NPF_{GUID}               */
    uint8_t       my_mac[ETH_ALEN];
    engine_rule_t rules[ENGINE_MAX_RULES];
    int           n_rules;
    int           verbose;                 /* per-packet logging               */
} engine_config_t;

/* An interface as reported by engine_enumerate_interfaces(). */
typedef struct {
    char    npf_name[300];                 /* pass to -i / engine runners      */
    char    friendly[160];                 /* human-friendly adapter name      */
    char    ip[16];                        /* first IPv4, dotted (may be "")   */
    uint8_t mac[ETH_ALEN];
    int     has_mac;
} iface_info_t;

/* A discovered device (snapshot of the discovery table). */
typedef struct {
    uint16_t vlan_id;
    uint8_t  mac[ETH_ALEN];
    uint32_t ip;                           /* network order, 0 if none         */
    uint64_t count;
} disc_row_t;

/* ── lifecycle ──────────────────────────────────────────────────────────── */
void engine_init(void);      /* call once at startup (inits internal lock)     */

/* Load Npcap's wpcap.dll. Must be called (and must succeed) before any other
 * engine call that touches pcap; wpcap is delay-loaded, so calling pcap with
 * the DLL missing would terminate the process in the delay-load helper.
 * Returns 0 on success, -1 if Npcap is not installed.                        */
int  engine_load_npcap(void);

/* ── helpers ────────────────────────────────────────────────────────────── */
int  engine_parse_mac(const char *s, uint8_t *mac);              /* 0 = ok     */
void engine_format_mac(const uint8_t *mac, char *buf, size_t sz);/* "AA:BB:.." */
int  engine_get_interface_mac(const char *npf_name, uint8_t *mac);
int  engine_enumerate_interfaces(iface_info_t *out, int max);    /* count      */

/* ── runners (blocking until engine_stop) ───────────────────────────────── */
int  engine_bridge_run(engine_config_t *cfg);                    /* 0 = ok     */
int  engine_discovery_run(const char *iface, uint32_t filter_ip, int verbose);
void engine_stop(void);      /* thread-safe; breaks the active runner's loop   */

/* ── live snapshots for the GUI (thread-safe) ───────────────────────────── */
void engine_get_stats(engine_stats_t *out);                      /* aggregate  */
int  engine_get_rule_stats(engine_rule_t *out, int max);         /* per-rule   */
int  engine_discovery_snapshot(disc_row_t *out, int max);        /* disc rows  */

#endif /* ENGINE_H */
