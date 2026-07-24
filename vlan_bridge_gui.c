/*
 * vlan_bridge_gui.c — native Win32 front-end for the VLAN bridge engine.
 *
 * Single window, single process. Capture runs on a worker thread against the
 * shared engine_config_t; the UI thread refreshes stats/discovery/log on a
 * timer and never touches pcap directly. Runs at the caller's privilege level
 * (manifest requests asInvoker, no UAC); Npcap serves non-admin users unless
 * installed with "Restrict to Administrators".
 *
 * Build: see the `gui` target in the Makefile.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "engine.h"
#include "fast_log.h"

/* ── control IDs ────────────────────────────────────────────────────────── */
#define IDC_IFACE_COMBO   1001
#define IDC_SCAN_BTN      1002
#define IDC_DISC_LIST     1003
#define IDC_ADD_SEL_BTN   1004
#define IDC_MAC_EDIT      1005
#define IDC_VLAN_EDIT     1006
#define IDC_ADD_RULE_BTN  1007
#define IDC_REMOVE_BTN    1008
#define IDC_RULES_LIST    1009
#define IDC_START_BTN     1010
#define IDC_VERBOSE_CHK   1011
#define IDC_STATS_LBL     1012
#define IDC_LOG_EDIT      1013
#define IDC_DISC_TOGGLE   1014
#define IDC_AUTOSTART_CHK 1015

#define IDM_TRAY_SHOW     2001    /* tray context-menu items                    */
#define IDM_TRAY_EXIT     2002

#define WM_APP_BRIDGE_DONE (WM_APP + 1)
#define WM_APP_SCAN_DONE   (WM_APP + 2)
#define WM_APP_TRAY        (WM_APP + 3)   /* tray icon callback                 */
#define WM_APP_AUTOSTART   (WM_APP + 4)   /* deferred auto-start after startup  */
#define TRAY_UID           1
#define TIMER_ID           1
#define TIMER_MS           250

/* The log EDIT silently stops accepting text at its internal limit and would
 * otherwise grow without bound, so trim the oldest lines past LOG_MAX_CHARS
 * back down to about LOG_KEEP_CHARS. */
#define LOG_MAX_CHARS  400000
#define LOG_KEEP_CHARS 250000

enum { ST_IDLE = 0, ST_SCANNING, ST_BRIDGING };

/* ── globals ────────────────────────────────────────────────────────────── */
static HWND g_main, g_iface, g_scan, g_disc, g_addsel, g_macedit, g_vlanedit;
static HWND g_addrule, g_remove, g_rules, g_start, g_verbose, g_stats, g_log;
static HWND g_lbl_iface, g_lbl_disc, g_lbl_rules, g_lbl_log, g_disc_toggle;
static HWND g_autostart;
static HFONT g_font;
static HBRUSH g_bg;            /* window/static background, matches the class  */
static int    g_dpi = 96;

/* All layout constants below are in 96-DPI logical pixels; S() maps them to
 * device pixels so the window is laid out correctly on scaled displays. */
#define S(x) MulDiv((x), g_dpi, 96)

static iface_info_t g_ifaces[ENGINE_MAX_IFACES];
static int          g_n_ifaces;

static engine_config_t g_cfg;             /* rules edited by UI, read by worker */
static disc_row_t      g_disc_rows[ENGINE_DISC_MAX];  /* mirrors disc list order */
static int             g_disc_shown;
static disc_row_t      g_disc_prev[ENGINE_DISC_MAX];  /* last-rendered rows       */
static int             g_disc_prev_n;
static int             g_disc_collapsed;              /* hide the scan section    */
static int             g_disc_sort_col = 0;           /* 0=VLAN 1=MAC 2=IP 3=pkts */
static int             g_disc_sort_asc = 1;
static int             g_rules_sort_col = -1;         /* -1 = insertion order     */
static int             g_rules_sort_asc = 1;

static HANDLE g_worker = NULL;
static int    g_state  = ST_IDLE;

/* per-rule rate tracking (packets/sec, updated on the timer while bridging) */
static uint64_t  g_prev_out[ENGINE_MAX_RULES], g_prev_in[ENGINE_MAX_RULES];
static double    g_rate_out[ENGINE_MAX_RULES], g_rate_in[ENGINE_MAX_RULES];
static ULONGLONG g_rate_last;

static NOTIFYICONDATAA g_nid;         /* system-tray icon                       */
static int             g_tray_added;

static RECT g_win_rect;               /* saved window placement (0 = none)      */
static int  g_have_win_rect;

static void layout(int cw, int ch);      /* defined in the layout section below */
static void config_save(void);           /* defined in the config section below */

/* ── helpers ────────────────────────────────────────────────────────────── */
static void set_font(HWND h) { if (g_font) SendMessage(h, WM_SETFONT, (WPARAM)g_font, TRUE); }

/* Pick up the shell's DPI and its UI font (Segoe UI on Vista+) instead of
 * DEFAULT_GUI_FONT, which is the ancient bitmap font and never scales. */
static void ui_metrics_init(void)
{
    HDC dc = GetDC(NULL);
    if (dc) {
        g_dpi = GetDeviceCaps(dc, LOGPIXELSX);
        ReleaseDC(NULL, dc);
    }
    if (g_dpi <= 0) g_dpi = 96;

    NONCLIENTMETRICSA ncm;
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        g_font = CreateFontIndirectA(&ncm.lfMessageFont);
    if (!g_font)
        g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g_bg = GetSysColorBrush(COLOR_BTNFACE);
}

static void lv_add_col(HWND lv, int i, const char *title, int width)
{
    LVCOLUMNA c; memset(&c, 0, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = (char *)title;
    c.cx = width;
    c.iSubItem = i;
    SendMessageA(lv, LVM_INSERTCOLUMNA, i, (LPARAM)&c);
}

static int lv_add_row(HWND lv, int row, const char *text)
{
    LVITEMA it; memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.pszText = (char *)text;
    return (int)SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
}

static void lv_set(HWND lv, int row, int col, const char *text)
{
    LVITEMA it; memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.iSubItem = col;
    it.pszText = (char *)text;
    SendMessageA(lv, LVM_SETITEMA, 0, (LPARAM)&it);
}

static int lv_selected(HWND lv)
{
    return (int)SendMessage(lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
}

/* Stretch a report-view's last column so the header fills the control instead
 * of leaving a blank stub to the right of the final column. */
static void lv_fill_last_col(HWND lv, int n_cols)
{
    RECT rc;
    GetClientRect(lv, &rc);
    int used = 0;
    for (int i = 0; i < n_cols - 1; i++)
        used += (int)SendMessage(lv, LVM_GETCOLUMNWIDTH, (WPARAM)i, 0);

    int last = (rc.right - rc.left) - used - GetSystemMetrics(SM_CXVSCROLL);
    if (last < S(60)) last = S(60);
    SendMessage(lv, LVM_SETCOLUMNWIDTH, (WPARAM)(n_cols - 1), (LPARAM)last);
}

/* Append raw log bytes (may contain '\n') to the read-only edit, converting to
 * CRLF so the multiline control renders newlines. */
static void log_append(const char *data, int len)
{
    /* Trim the oldest lines when the control gets large. Deleting from the top
     * (rather than clearing everything, and rather than letting it silently
     * hit its limit and stop) keeps recent output visible without a hard reset. */
    int cur = GetWindowTextLengthA(g_log);
    if (cur > LOG_MAX_CHARS) {
        int cut  = cur - LOG_KEEP_CHARS;
        int line = (int)SendMessageA(g_log, EM_LINEFROMCHAR, (WPARAM)cut, 0);
        int idx  = (int)SendMessageA(g_log, EM_LINEINDEX, (WPARAM)(line + 1), 0);
        if (idx > 0) cut = idx;                /* snap the cut to a line start */
        SendMessageA(g_log, EM_SETSEL, 0, (LPARAM)cut);
        SendMessageA(g_log, EM_REPLACESEL, FALSE, (LPARAM)"");
    }

    char *tmp = (char *)malloc((size_t)len * 2 + 1);
    if (!tmp) return;
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (data[i] == '\n') tmp[j++] = '\r';
        tmp[j++] = data[i];
    }
    tmp[j] = '\0';

    int end = GetWindowTextLengthA(g_log);
    SendMessageA(g_log, EM_SETSEL, (WPARAM)end, (LPARAM)end);
    SendMessageA(g_log, EM_REPLACESEL, FALSE, (LPARAM)tmp);
    SendMessageA(g_log, EM_SCROLLCARET, 0, 0);
    free(tmp);
}

static void pump_log(void)
{
    char buf[8192];
    int n;
    while ((n = log_drain(buf, sizeof(buf))) > 0)
        log_append(buf, n);
}

/* ── rules view ─────────────────────────────────────────────────────────── */
static int rule_cmp(const engine_rule_t *a, const engine_rule_t *b)
{
    int r;
    switch (g_rules_sort_col) {
    case 1:  r = (int)a->vlan_id - (int)b->vlan_id; break;
    case 2:  r = (a->out_tagged > b->out_tagged) - (a->out_tagged < b->out_tagged); break;
    case 3:  r = (a->in_stripped > b->in_stripped) - (a->in_stripped < b->in_stripped); break;
    case 0:
    default: r = memcmp(a->mac, b->mac, ETH_ALEN); break;
    }
    return g_rules_sort_asc ? r : -r;
}

/* Reorder the underlying rules array (not just the view) so row indices still
 * map to g_cfg.rules[] for Remove. Only ever called while idle. */
static void rules_sort(void)
{
    if (g_rules_sort_col < 0) return;
    for (int i = 1; i < g_cfg.n_rules; i++) {
        engine_rule_t key = g_cfg.rules[i];
        int j = i - 1;
        while (j >= 0 && rule_cmp(&g_cfg.rules[j], &key) > 0) {
            g_cfg.rules[j + 1] = g_cfg.rules[j];
            j--;
        }
        g_cfg.rules[j + 1] = key;
    }
}

static void rules_refresh(void)
{
    rules_sort();
    SendMessage(g_rules, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_cfg.n_rules; i++) {
        char mac[18], vlan[8], num[24];
        engine_format_mac(g_cfg.rules[i].mac, mac, sizeof(mac));
        lv_add_row(g_rules, i, mac);
        snprintf(vlan, sizeof(vlan), "%u", g_cfg.rules[i].vlan_id);
        lv_set(g_rules, i, 1, vlan);
        snprintf(num, sizeof(num), "%llu", (unsigned long long)g_cfg.rules[i].out_tagged);
        lv_set(g_rules, i, 2, num);
        snprintf(num, sizeof(num), "%llu", (unsigned long long)g_cfg.rules[i].in_stripped);
        lv_set(g_rules, i, 3, num);
        lv_set(g_rules, i, 4, "0");     /* Out/s */
        lv_set(g_rules, i, 5, "0");     /* In/s  */
    }
}

/* Zero the per-rule rate baseline for a fresh run (called from on_start). */
static void rates_reset(void)
{
    for (int i = 0; i < g_cfg.n_rules; i++) {
        g_prev_out[i] = g_prev_in[i] = 0;
        g_rate_out[i] = g_rate_in[i] = 0.0;
    }
    g_rate_last = GetTickCount64();
}

/* Update the live counter + rate columns (called on the timer while bridging).
 * Rates are packets/sec over the tick interval, lightly EMA-smoothed. */
static void rules_update_counts(void)
{
    ULONGLONG now = GetTickCount64();
    double dt = (double)(now - g_rate_last) / 1000.0;
    if (dt <= 0.0) dt = (double)TIMER_MS / 1000.0;
    g_rate_last = now;

    for (int i = 0; i < g_cfg.n_rules; i++) {
        uint64_t out = g_cfg.rules[i].out_tagged;
        uint64_t in  = g_cfg.rules[i].in_stripped;
        double ro = (double)(out - g_prev_out[i]) / dt;
        double ri = (double)(in  - g_prev_in[i])  / dt;
        g_prev_out[i] = out;
        g_prev_in[i]  = in;
        g_rate_out[i] = g_rate_out[i] * 0.5 + ro * 0.5;
        g_rate_in[i]  = g_rate_in[i]  * 0.5 + ri * 0.5;

        char num[24];
        snprintf(num, sizeof(num), "%llu", (unsigned long long)out);
        lv_set(g_rules, i, 2, num);
        snprintf(num, sizeof(num), "%llu", (unsigned long long)in);
        lv_set(g_rules, i, 3, num);
        snprintf(num, sizeof(num), "%.0f", g_rate_out[i]);
        lv_set(g_rules, i, 4, num);
        snprintf(num, sizeof(num), "%.0f", g_rate_in[i]);
        lv_set(g_rules, i, 5, num);
    }
}

static int rule_exists(const uint8_t *mac)
{
    for (int i = 0; i < g_cfg.n_rules; i++)
        if (memcmp(g_cfg.rules[i].mac, mac, ETH_ALEN) == 0) return 1;
    return 0;
}

static void rule_add(const uint8_t *mac, uint16_t vlan)
{
    if (g_cfg.n_rules >= ENGINE_MAX_RULES) {
        MessageBoxA(g_main, "Rule limit reached.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    if (rule_exists(mac)) {
        MessageBoxA(g_main, "That MAC already has a rule.", "vlan_bridge", MB_OK | MB_ICONINFORMATION);
        return;
    }
    engine_rule_t *r = &g_cfg.rules[g_cfg.n_rules++];
    memset(r, 0, sizeof(*r));
    memcpy(r->mac, mac, ETH_ALEN);
    r->vlan_id = vlan;
    rules_refresh();
    config_save();
}

/* ── discovery view ─────────────────────────────────────────────────────── */
static int disc_cmp(const disc_row_t *a, const disc_row_t *b)
{
    int r;
    switch (g_disc_sort_col) {
    case 1:  r = memcmp(a->mac, b->mac, ETH_ALEN); break;
    case 2:  r = memcmp(&a->ip, &b->ip, sizeof(a->ip)); break;  /* net order */
    case 3:  r = (a->count > b->count) - (a->count < b->count); break;
    case 0:
    default: r = (int)a->vlan_id - (int)b->vlan_id; break;
    }
    if (r == 0) {                          /* stable tiebreak: VLAN then MAC */
        r = (int)a->vlan_id - (int)b->vlan_id;
        if (r == 0) r = memcmp(a->mac, b->mac, ETH_ALEN);
    }
    return g_disc_sort_asc ? r : -r;
}

static void disc_refresh(void)
{
    int n = engine_discovery_snapshot(g_disc_rows, ENGINE_DISC_MAX);

    for (int i = 1; i < n; i++) {                    /* sort by current key */
        disc_row_t key = g_disc_rows[i];
        int j = i - 1;
        while (j >= 0 && disc_cmp(&g_disc_rows[j], &key) > 0) {
            g_disc_rows[j + 1] = g_disc_rows[j];
            j--;
        }
        g_disc_rows[j + 1] = key;
    }

    /* Fast path: same devices in the same order as last tick — only the packet
     * counts can differ, so patch those cells in place. Deleting and rebuilding
     * every 250 ms is what made the list flicker and drop the selection. */
    int same = (n == g_disc_prev_n);
    for (int i = 0; same && i < n; i++)
        if (g_disc_rows[i].vlan_id != g_disc_prev[i].vlan_id ||
            g_disc_rows[i].ip      != g_disc_prev[i].ip      ||
            memcmp(g_disc_rows[i].mac, g_disc_prev[i].mac, ETH_ALEN) != 0)
            same = 0;

    if (same) {
        for (int i = 0; i < n; i++)
            if (g_disc_rows[i].count != g_disc_prev[i].count) {
                char num[24];
                snprintf(num, sizeof(num), "%llu",
                         (unsigned long long)g_disc_rows[i].count);
                lv_set(g_disc, i, 3, num);
            }
    } else {
        SendMessage(g_disc, WM_SETREDRAW, (WPARAM)FALSE, 0);
        SendMessage(g_disc, LVM_DELETEALLITEMS, 0, 0);
        for (int i = 0; i < n; i++) {
            char vlan[8], mac[18], ip[16], num[24];
            const uint8_t *b = (const uint8_t *)&g_disc_rows[i].ip;
            snprintf(vlan, sizeof(vlan), "%u", g_disc_rows[i].vlan_id);
            engine_format_mac(g_disc_rows[i].mac, mac, sizeof(mac));
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            snprintf(num, sizeof(num), "%llu", (unsigned long long)g_disc_rows[i].count);
            lv_add_row(g_disc, i, vlan);
            lv_set(g_disc, i, 1, mac);
            lv_set(g_disc, i, 2, ip);
            lv_set(g_disc, i, 3, num);
        }
        SendMessage(g_disc, WM_SETREDRAW, (WPARAM)TRUE, 0);
        InvalidateRect(g_disc, NULL, FALSE);
    }

    memcpy(g_disc_prev, g_disc_rows, sizeof(disc_row_t) * (size_t)n);
    g_disc_prev_n = n;
    g_disc_shown  = n;
}

/* ── stats label ────────────────────────────────────────────────────────── */
static void stats_refresh(void)
{
    engine_stats_t s;
    engine_get_stats(&s);
    char buf[256];
    snprintf(buf, sizeof(buf),
        "OUT tagged %llu  bcast %llu   |   IN stripped %llu  bcast %llu   |   ignored %llu",
        (unsigned long long)s.out_tagged, (unsigned long long)s.out_bcast,
        (unsigned long long)s.in_stripped, (unsigned long long)s.in_bcast,
        (unsigned long long)s.ignored);
    SetWindowTextA(g_stats, buf);
}

/* ── config persistence ─────────────────────────────────────────────────── */
/* Rules, the chosen interface, verbose, and the collapse state are saved to
 * %APPDATA%\vlan_bridge\config.ini so they survive a restart. APPDATA is used
 * (not the exe dir) because it is always writable without elevation. */
static int config_path(char *out, size_t n)
{
    const char *appdata = getenv("APPDATA");
    if (!appdata || !appdata[0]) return 0;
    char dir[MAX_PATH];
    snprintf(dir, sizeof(dir), "%s\\vlan_bridge", appdata);
    CreateDirectoryA(dir, NULL);                 /* harmless if it exists */
    snprintf(out, n, "%s\\config.ini", dir);
    return 1;
}

static void config_save(void)
{
    char path[MAX_PATH];
    if (!config_path(path, sizeof(path))) return;
    FILE *f = fopen(path, "w");
    if (!f) return;

    int sel = (int)SendMessage(g_iface, CB_GETCURSEL, 0, 0);
    if (sel >= 0 && sel < g_n_ifaces)
        fprintf(f, "iface=%s\n", g_ifaces[sel].npf_name);
    fprintf(f, "verbose=%d\n",
            SendMessage(g_verbose, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0);
    fprintf(f, "autostart=%d\n",
            SendMessage(g_autostart, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0);
    fprintf(f, "collapsed=%d\n", g_disc_collapsed);

    WINDOWPLACEMENT wpl; wpl.length = sizeof(wpl);
    if (GetWindowPlacement(g_main, &wpl)) {       /* restored (non-min) rect */
        RECT r = wpl.rcNormalPosition;
        fprintf(f, "window=%ld %ld %ld %ld\n",
                r.left, r.top, r.right, r.bottom);
    }
    for (int i = 0; i < g_cfg.n_rules; i++) {
        char mac[18];
        engine_format_mac(g_cfg.rules[i].mac, mac, sizeof(mac));
        fprintf(f, "rule=%s %u\n", mac, g_cfg.rules[i].vlan_id);
    }
    fclose(f);
}

/* Load saved config into the UI. Called once at startup after the interface
 * list is populated. Silently ignores a missing or partly malformed file. */
static void config_load(void)
{
    char path[MAX_PATH];
    if (!config_path(path, sizeof(path))) return;
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512], saved_iface[300] = "";
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "iface=", 6) == 0) {
            snprintf(saved_iface, sizeof(saved_iface), "%s", line + 6);
        } else if (strncmp(line, "verbose=", 8) == 0) {
            SendMessage(g_verbose, BM_SETCHECK,
                        atoi(line + 8) ? BST_CHECKED : BST_UNCHECKED, 0);
        } else if (strncmp(line, "autostart=", 10) == 0) {
            SendMessage(g_autostart, BM_SETCHECK,
                        atoi(line + 10) ? BST_CHECKED : BST_UNCHECKED, 0);
        } else if (strncmp(line, "window=", 7) == 0) {
            RECT r;
            if (sscanf(line + 7, "%ld %ld %ld %ld",
                       &r.left, &r.top, &r.right, &r.bottom) == 4 &&
                r.right - r.left >= 100 && r.bottom - r.top >= 100) {
                g_win_rect = r;
                g_have_win_rect = 1;
            }
        } else if (strncmp(line, "collapsed=", 10) == 0) {
            g_disc_collapsed = atoi(line + 10) ? 1 : 0;
            SetWindowTextA(g_disc_toggle, g_disc_collapsed ? "Show" : "Hide");
        } else if (strncmp(line, "rule=", 5) == 0) {
            char macbuf[64]; int vid = 0;
            if (sscanf(line + 5, "%63s %d", macbuf, &vid) == 2) {
                uint8_t mac[ETH_ALEN];
                if (engine_parse_mac(macbuf, mac) == 0 && vid >= 1 && vid <= 4094 &&
                    g_cfg.n_rules < ENGINE_MAX_RULES && !rule_exists(mac)) {
                    engine_rule_t *r = &g_cfg.rules[g_cfg.n_rules++];
                    memset(r, 0, sizeof(*r));
                    memcpy(r->mac, mac, ETH_ALEN);
                    r->vlan_id = (uint16_t)vid;
                }
            }
        }
    }
    fclose(f);

    rules_refresh();
    if (saved_iface[0]) {                         /* re-select the saved NIC */
        for (int i = 0; i < g_n_ifaces; i++)
            if (strcmp(g_ifaces[i].npf_name, saved_iface) == 0) {
                SendMessage(g_iface, CB_SETCURSEL, i, 0);
                break;
            }
    }
}

/* ── worker threads ─────────────────────────────────────────────────────── */
static DWORD WINAPI bridge_thread(LPVOID p)
{
    (void)p;
    engine_bridge_run(&g_cfg);
    PostMessage(g_main, WM_APP_BRIDGE_DONE, 0, 0);
    return 0;
}

static DWORD WINAPI scan_thread(LPVOID p)
{
    char *iface = (char *)p;
    engine_discovery_run(iface, 0, 0);
    free(iface);
    PostMessage(g_main, WM_APP_SCAN_DONE, 0, 0);
    return 0;
}

/* ── UI enable/disable per state ────────────────────────────────────────── */
static void ui_set_state(int state)
{
    g_state = state;
    int idle     = (state == ST_IDLE);
    int scanning = (state == ST_SCANNING);
    int bridging = (state == ST_BRIDGING);

    EnableWindow(g_iface,   idle);
    EnableWindow(g_scan,    idle || scanning);
    EnableWindow(g_addsel,  idle);
    EnableWindow(g_macedit, idle);
    EnableWindow(g_vlanedit,idle);
    EnableWindow(g_addrule, idle);
    EnableWindow(g_remove,  idle);
    EnableWindow(g_verbose, idle);
    EnableWindow(g_start,   idle || bridging);

    SetWindowTextA(g_scan,  scanning ? "Stop Scan" : "Scan");
    SetWindowTextA(g_start, bridging ? "Stop"      : "Start");
}

/* ── actions ────────────────────────────────────────────────────────────── */
static int selected_iface(iface_info_t **out)
{
    int sel = (int)SendMessage(g_iface, CB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_n_ifaces) return 0;
    *out = &g_ifaces[sel];
    return 1;
}

static void on_scan(void)
{
    if (g_state == ST_SCANNING) { engine_stop(); return; }  /* thread posts DONE */
    if (g_state != ST_IDLE) return;
    iface_info_t *ifc;
    if (!selected_iface(&ifc)) {
        MessageBoxA(g_main, "Select an interface first.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    char *arg = _strdup(ifc->npf_name);
    if (!arg) return;
    ui_set_state(ST_SCANNING);
    g_worker = CreateThread(NULL, 0, scan_thread, arg, 0, NULL);
    if (!g_worker) { free(arg); ui_set_state(ST_IDLE); }
}

static void on_add_selected(void)
{
    int sel = lv_selected(g_disc);
    if (sel < 0 || sel >= g_disc_shown) {
        MessageBoxA(g_main, "Select a discovered device first.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    rule_add(g_disc_rows[sel].mac, g_disc_rows[sel].vlan_id);
}

static void on_add_rule(void)
{
    char macbuf[64], vlanbuf[16];
    GetWindowTextA(g_macedit, macbuf, sizeof(macbuf));
    GetWindowTextA(g_vlanedit, vlanbuf, sizeof(vlanbuf));

    uint8_t mac[ETH_ALEN];
    if (engine_parse_mac(macbuf, mac) != 0) {
        MessageBoxA(g_main, "Enter a MAC like AA:BB:CC:DD:EE:FF.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    int vid = atoi(vlanbuf);
    if (vid < 1 || vid > 4094) {
        MessageBoxA(g_main, "VLAN must be 1-4094.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    rule_add(mac, (uint16_t)vid);
    SetWindowTextA(g_macedit, "");
    SetWindowTextA(g_vlanedit, "");
}

static void on_remove_rule(void)
{
    int sel = lv_selected(g_rules);
    if (sel < 0 || sel >= g_cfg.n_rules) return;
    for (int i = sel; i < g_cfg.n_rules - 1; i++)
        g_cfg.rules[i] = g_cfg.rules[i + 1];
    g_cfg.n_rules--;
    rules_refresh();
    config_save();
}

static void on_toggle_disc(void)
{
    /* Collapsing hides the Scan button, so end any running scan first. */
    if (!g_disc_collapsed && g_state == ST_SCANNING) engine_stop();
    g_disc_collapsed = !g_disc_collapsed;
    SetWindowTextA(g_disc_toggle, g_disc_collapsed ? "Show" : "Hide");
    RECT rc; GetClientRect(g_main, &rc);
    layout(rc.right, rc.bottom);
    config_save();
}

static void on_disc_colclick(int col)
{
    if (col < 0 || col > 3) return;
    if (col == g_disc_sort_col) g_disc_sort_asc = !g_disc_sort_asc;
    else { g_disc_sort_col = col; g_disc_sort_asc = 1; }
    g_disc_prev_n = 0;                    /* force a rebuild in the new order */
    disc_refresh();
}

static void on_rules_colclick(int col)
{
    /* The worker reads g_cfg.rules[] while bridging; only reorder when idle. */
    if (g_state != ST_IDLE || col < 0 || col > 3) return;
    if (col == g_rules_sort_col) g_rules_sort_asc = !g_rules_sort_asc;
    else { g_rules_sort_col = col; g_rules_sort_asc = 1; }
    rules_refresh();
}

static void on_start(void)
{
    if (g_state == ST_BRIDGING) { engine_stop(); return; }  /* thread posts DONE */
    if (g_state != ST_IDLE) return;

    iface_info_t *ifc;
    if (!selected_iface(&ifc)) {
        MessageBoxA(g_main, "Select an interface first.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }
    if (g_cfg.n_rules == 0) {
        MessageBoxA(g_main, "Add at least one (MAC -> VLAN) rule.", "vlan_bridge", MB_OK | MB_ICONWARNING);
        return;
    }

    snprintf(g_cfg.iface, sizeof(g_cfg.iface), "%s", ifc->npf_name);
    if (ifc->has_mac) memcpy(g_cfg.my_mac, ifc->mac, ETH_ALEN);
    else if (engine_get_interface_mac(ifc->npf_name, g_cfg.my_mac) != 0) {
        MessageBoxA(g_main, "Could not determine this interface's MAC.", "vlan_bridge", MB_OK | MB_ICONERROR);
        return;
    }
    g_cfg.verbose = (SendMessage(g_verbose, BM_GETCHECK, 0, 0) == BST_CHECKED);
    config_save();                       /* persist iface + verbose choice */

    /* reset per-rule counters + rate baseline for a fresh run */
    for (int i = 0; i < g_cfg.n_rules; i++)
        g_cfg.rules[i].out_tagged = g_cfg.rules[i].in_stripped = 0;
    rates_reset();

    ui_set_state(ST_BRIDGING);
    g_worker = CreateThread(NULL, 0, bridge_thread, NULL, 0, NULL);
    if (!g_worker) ui_set_state(ST_IDLE);
}

static void worker_done(void)
{
    if (g_worker) {
        WaitForSingleObject(g_worker, INFINITE);
        CloseHandle(g_worker);
        g_worker = NULL;
    }
    pump_log();
    if (g_state == ST_BRIDGING) {
        rules_update_counts();
        stats_refresh();
        for (int i = 0; i < g_cfg.n_rules; i++) {   /* traffic stopped: rate 0 */
            lv_set(g_rules, i, 4, "0");
            lv_set(g_rules, i, 5, "0");
        }
    } else if (g_state == ST_SCANNING) {
        disc_refresh();
    }
    ui_set_state(ST_IDLE);
}

/* ── layout ─────────────────────────────────────────────────────────────── */
/*
 * Single top-to-bottom flow: every row advances a running `y`, so rows can
 * never drift out of alignment and there is no dead space between sections.
 * Widths key off the client width; the log pane absorbs all leftover height.
 */
static void layout(int cw, int ch)
{
    const int M     = S(11);   /* outer margin                                */
    const int GAP   = S(8);    /* between rows inside a section               */
    const int SGAP  = S(14);   /* between sections                            */
    const int LBL_H = S(16);   /* section caption                             */
    const int CTL_H = S(23);   /* edit / combo row height                     */
    const int BTN_H = S(26);
    const int LGAP  = S(3);    /* caption to the control it labels            */

    const int x = M;
    const int w = cw - 2 * M;
    int y = M;

    /* interface row — caption is vertically centred against the combo */
    const int iflbl_w = S(62);
    MoveWindow(g_iface, x + iflbl_w + S(6), y, w - iflbl_w - S(6), S(220), TRUE);
    RECT rc;
    GetWindowRect(g_iface, &rc);              /* closed height, font-dependent */
    int combo_h = rc.bottom - rc.top;
    MoveWindow(g_lbl_iface, x, y, iflbl_w, combo_h, TRUE);
    y += combo_h + GAP;

    /* discovery header: caption on the left, collapse toggle on the right */
    const int HDR_H = S(22);
    const int tog_w = S(64);
    MoveWindow(g_lbl_disc,    x,             y, w - tog_w - S(8), HDR_H, TRUE);
    MoveWindow(g_disc_toggle, x + w - tog_w, y, tog_w,            HDR_H, TRUE);
    y += HDR_H + LGAP;

    /* discovery body (scan buttons + list) — hidden when collapsed, freeing
     * its vertical space for the log pane below */
    const int show = !g_disc_collapsed;
    ShowWindow(g_scan,   show ? SW_SHOW : SW_HIDE);
    ShowWindow(g_addsel, show ? SW_SHOW : SW_HIDE);
    ShowWindow(g_disc,   show ? SW_SHOW : SW_HIDE);
    if (show) {
        MoveWindow(g_scan,   x,           y, S(96),  BTN_H, TRUE);
        MoveWindow(g_addsel, x + S(96+8), y, S(190), BTN_H, TRUE);
        y += BTN_H + GAP;
        MoveWindow(g_disc, x, y, w, S(126), TRUE);
        lv_fill_last_col(g_disc, 4);
        y += S(126) + SGAP;
    } else {
        y += SGAP;
    }

    /* rules section */
    MoveWindow(g_lbl_rules, x, y, w, LBL_H, TRUE);
    y += LBL_H + LGAP;

    /* edits are CTL_H, buttons BTN_H — centre them on a shared baseline */
    const int row_h = BTN_H;
    const int ey    = y + (row_h - CTL_H) / 2;
    int bx = x;
    MoveWindow(g_macedit,  bx, ey, S(150), CTL_H, TRUE);  bx += S(150 + 8);
    MoveWindow(g_vlanedit, bx, ey, S(64),  CTL_H, TRUE);  bx += S(64 + 8);
    MoveWindow(g_addrule,  bx, y,  S(100), BTN_H, TRUE);  bx += S(100 + 8);
    MoveWindow(g_remove,   bx, y,  S(110), BTN_H, TRUE);
    y += row_h + GAP;

    MoveWindow(g_rules, x, y, w, S(112), TRUE);
    lv_fill_last_col(g_rules, 6);
    y += S(112) + SGAP;

    /* run row: Start + verbose + auto-start checkboxes, centred on the button */
    const int chk_h = S(20);
    const int chk_y = y + (S(28) - chk_h) / 2;
    MoveWindow(g_start,     x,                       y,     S(100), S(28),  TRUE);
    MoveWindow(g_verbose,   x + S(100 + 12),         chk_y, S(110), chk_h,  TRUE);
    MoveWindow(g_autostart, x + S(100 + 12 + 110 + 8), chk_y, S(120), chk_h, TRUE);
    y += S(28) + GAP;

    /* stats gets a full-width line of its own — the string is long and was
     * being clipped when it shared the run row */
    MoveWindow(g_stats, x, y, w, S(18), TRUE);
    y += S(18) + SGAP;

    MoveWindow(g_lbl_log, x, y, w, LBL_H, TRUE);
    y += LBL_H + LGAP;

    int log_h = ch - y - M;
    if (log_h < S(60)) log_h = S(60);
    MoveWindow(g_log, x, y, w, log_h, TRUE);
}

/* ── window creation ────────────────────────────────────────────────────── */
static HWND mk_ex(DWORD exstyle, const char *cls, const char *text, DWORD style,
                  int id, HWND parent)
{
    HWND h = CreateWindowExA(exstyle, cls, text, WS_CHILD | WS_VISIBLE | style,
                             0, 0, 10, 10, parent, (HMENU)(INT_PTR)id,
                             GetModuleHandle(NULL), NULL);
    set_font(h);
    return h;
}

static HWND mk(const char *cls, const char *text, DWORD style, int id, HWND parent)
{
    return mk_ex(0, cls, text, style, id, parent);
}


static void create_controls(HWND w)
{
    /* SS_CENTERIMAGE vertically centres the caption inside its rect, so a
     * label sitting next to a taller control lines up on the text baseline. */
    g_lbl_iface = mk("STATIC", "Interface:", SS_LEFT | SS_CENTERIMAGE, -1, w);

    g_iface  = mk("COMBOBOX", "",
                  CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, IDC_IFACE_COMBO, w);
    g_scan   = mk("BUTTON", "&Scan", BS_PUSHBUTTON | WS_TABSTOP, IDC_SCAN_BTN, w);
    g_addsel = mk("BUTTON", "Add Se&lected -> Rules",
                  BS_PUSHBUTTON | WS_TABSTOP, IDC_ADD_SEL_BTN, w);

    g_lbl_disc = mk("STATIC", "Discovered devices",
                    SS_LEFT | SS_CENTERIMAGE, -1, w);
    g_disc_toggle = mk("BUTTON", "Hide",
                       BS_PUSHBUTTON | WS_TABSTOP, IDC_DISC_TOGGLE, w);
    /* WS_EX_CLIENTEDGE, not WS_BORDER: a themed border drawn via WS_BORDER
     * wraps only the client area, leaving any scrollbar outside the frame. */
    g_disc = mk_ex(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                   LVS_REPORT | LVS_SINGLESEL | WS_TABSTOP, IDC_DISC_LIST, w);
    SendMessage(g_disc, LVM_SETEXTENDEDLISTVIEWSTYLE,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    lv_add_col(g_disc, 0, "VLAN", S(60));
    lv_add_col(g_disc, 1, "MAC",  S(160));
    lv_add_col(g_disc, 2, "IP",   S(140));
    lv_add_col(g_disc, 3, "pkts", S(80));

    g_lbl_rules = mk("STATIC", "Rules  (target MAC -> VLAN)", SS_LEFT, -1, w);

    g_macedit  = mk("EDIT", "",
                    ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, IDC_MAC_EDIT, w);
    g_vlanedit = mk("EDIT", "",
                    ES_AUTOHSCROLL | ES_NUMBER | WS_BORDER | WS_TABSTOP, IDC_VLAN_EDIT, w);
    /* EM_SETCUEBANNER is Unicode-only — it must go through SendMessageW. */
    SendMessageW(g_macedit,  EM_SETCUEBANNER, TRUE, (LPARAM)L"AA:BB:CC:DD:EE:FF");
    SendMessageW(g_vlanedit, EM_SETCUEBANNER, TRUE, (LPARAM)L"VLAN");
    g_addrule  = mk("BUTTON", "Add &Rule",   BS_PUSHBUTTON | WS_TABSTOP, IDC_ADD_RULE_BTN, w);
    g_remove   = mk("BUTTON", "Re&move Rule", BS_PUSHBUTTON | WS_TABSTOP, IDC_REMOVE_BTN, w);

    g_rules = mk_ex(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                    LVS_REPORT | LVS_SINGLESEL | WS_TABSTOP, IDC_RULES_LIST, w);
    SendMessage(g_rules, LVM_SETEXTENDEDLISTVIEWSTYLE,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    lv_add_col(g_rules, 0, "Target MAC", S(170));
    lv_add_col(g_rules, 1, "VLAN",  S(55));
    lv_add_col(g_rules, 2, "Out",   S(85));
    lv_add_col(g_rules, 3, "In",    S(85));
    lv_add_col(g_rules, 4, "Out/s", S(65));
    lv_add_col(g_rules, 5, "In/s",  S(65));

    g_start     = mk("BUTTON", "Start", BS_DEFPUSHBUTTON | WS_TABSTOP, IDC_START_BTN, w);
    g_verbose   = mk("BUTTON", "&Verbose log",
                     BS_AUTOCHECKBOX | WS_TABSTOP, IDC_VERBOSE_CHK, w);
    g_autostart = mk("BUTTON", "&Auto-start",
                     BS_AUTOCHECKBOX | WS_TABSTOP, IDC_AUTOSTART_CHK, w);
    g_stats   = mk("STATIC", "", SS_LEFT | SS_ENDELLIPSIS, IDC_STATS_LBL, w);

    g_lbl_log = mk("STATIC", "Log", SS_LEFT, -1, w);
    g_log     = mk_ex(WS_EX_CLIENTEDGE, "EDIT", "",
                      ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL |
                      WS_TABSTOP,
                      IDC_LOG_EDIT, w);
    /* Lift the edit control's default text cap (~30 KB) so appends don't
     * silently stop; log_append() trims the oldest lines instead. */
    SendMessageA(g_log, EM_SETLIMITTEXT, 0, 0);
}

static void populate_ifaces(void)
{
    g_n_ifaces = engine_enumerate_interfaces(g_ifaces, ENGINE_MAX_IFACES);
    SendMessage(g_iface, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_n_ifaces; i++) {
        char line[400];
        /* explicit precisions: the ternaries defeat gcc's truncation analysis */
        snprintf(line, sizeof(line), "%.320s  [%.16s]",
                 g_ifaces[i].friendly[0] ? g_ifaces[i].friendly : g_ifaces[i].npf_name,
                 g_ifaces[i].ip[0] ? g_ifaces[i].ip : "no ip");
        SendMessageA(g_iface, CB_ADDSTRING, 0, (LPARAM)line);
    }
    if (g_n_ifaces > 0) SendMessage(g_iface, CB_SETCURSEL, 0, 0);
}

/* ── system tray ────────────────────────────────────────────────────────── */
static void tray_add(void)
{
    if (g_tray_added) return;
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = g_main;
    g_nid.uID              = TRAY_UID;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_APP_TRAY;
    g_nid.hIcon            = LoadIcon(NULL, IDI_APPLICATION);
    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s",
             g_state == ST_BRIDGING ? "VLAN Bridge - running" : "VLAN Bridge");
    if (Shell_NotifyIconA(NIM_ADD, &g_nid)) g_tray_added = 1;
}

static void tray_remove(void)
{
    if (!g_tray_added) return;
    Shell_NotifyIconA(NIM_DELETE, &g_nid);
    g_tray_added = 0;
}

static void tray_restore(void)
{
    tray_remove();
    ShowWindow(g_main, SW_SHOW);
    ShowWindow(g_main, SW_RESTORE);
    SetForegroundWindow(g_main);
}

static void tray_menu(void)
{
    POINT pt;
    GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuA(m, MF_STRING, IDM_TRAY_SHOW, "Show");
    AppendMenuA(m, MF_SEPARATOR, 0, NULL);
    AppendMenuA(m, MF_STRING, IDM_TRAY_EXIT, "Exit");
    SetForegroundWindow(g_main);           /* so the menu closes on click-away */
    TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, NULL);
    DestroyMenu(m);
}

static LRESULT CALLBACK WndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_main = w;
        create_controls(w);
        populate_ifaces();
        config_load();        /* restore rules / iface / verbose / window / etc */
        if (g_have_win_rect) {                    /* restore saved placement */
            RECT r = g_win_rect;
            int ww = r.right - r.left, wh = r.bottom - r.top;
            int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
            if (r.left > vx + vw - 60) r.left = vx + vw - ww;   /* keep on-screen */
            if (r.top  > vy + vh - 60) r.top  = vy + vh - wh;
            if (r.left < vx) r.left = vx;
            if (r.top  < vy) r.top  = vy;
            MoveWindow(w, r.left, r.top, ww, wh, FALSE);
        }
        ui_set_state(ST_IDLE);
        stats_refresh();      /* show zeroed counters rather than a blank line */
        SetTimer(w, TIMER_ID, TIMER_MS, NULL);
        if (SendMessage(g_autostart, BM_GETCHECK, 0, 0) == BST_CHECKED &&
            g_cfg.n_rules > 0 &&
            SendMessage(g_iface, CB_GETCURSEL, 0, 0) >= 0)
            PostMessage(w, WM_APP_AUTOSTART, 0, 0);
        return 0;

    case WM_SIZE:
        if (wp == SIZE_MINIMIZED) {               /* minimize hides to the tray */
            tray_add();
            ShowWindow(w, SW_HIDE);
            return 0;
        }
        layout(LOWORD(lp), HIWORD(lp));
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        /* wide enough for the rule-editor row, tall enough to leave the log
         * pane usable once every fixed-height section is placed */
        mmi->ptMinTrackSize.x = S(560);
        mmi->ptMinTrackSize.y = S(700);
        return 0;
    }

    /* Paint STATIC captions, the checkbox and the stats line on the window's
     * own background instead of the control default. The log EDIT is read-only
     * (so it also sends WM_CTLCOLORSTATIC) but must stay a white text field. */
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_log) {
            SetBkColor((HDC)wp, GetSysColor(COLOR_WINDOW));
            SetTextColor((HDC)wp, GetSysColor(COLOR_WINDOWTEXT));
            return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
        }
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, GetSysColor(COLOR_BTNTEXT));
        return (LRESULT)g_bg;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_SCAN_BTN:     on_scan();        return 0;
        case IDC_ADD_SEL_BTN:  on_add_selected();return 0;
        case IDC_ADD_RULE_BTN: on_add_rule();    return 0;
        case IDC_REMOVE_BTN:   on_remove_rule(); return 0;
        case IDC_START_BTN:    on_start();       return 0;
        case IDC_DISC_TOGGLE:  on_toggle_disc(); return 0;
        case IDC_IFACE_COMBO:
            if (HIWORD(wp) == CBN_SELCHANGE) config_save();
            return 0;
        case IDC_VERBOSE_CHK:
        case IDC_AUTOSTART_CHK:
            if (HIWORD(wp) == BN_CLICKED) config_save();
            return 0;
        case IDM_TRAY_SHOW:  tray_restore();          return 0;
        case IDM_TRAY_EXIT:  SendMessage(w, WM_CLOSE, 0, 0); return 0;
        }
        return 0;

    case WM_APP_TRAY:
        if (LOWORD(lp) == WM_LBUTTONDBLCLK) tray_restore();
        else if (LOWORD(lp) == WM_RBUTTONUP) tray_menu();
        return 0;

    case WM_APP_AUTOSTART:
        on_start();
        return 0;

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_DISC_LIST && nh->code == NM_DBLCLK) {
            on_add_selected();
            return 0;
        }
        if (nh->code == LVN_COLUMNCLICK) {
            int col = ((LPNMLISTVIEW)lp)->iSubItem;
            if (nh->idFrom == IDC_DISC_LIST)  on_disc_colclick(col);
            else if (nh->idFrom == IDC_RULES_LIST) on_rules_colclick(col);
            return 0;
        }
        break;
    }

    case WM_TIMER:
        pump_log();
        if (g_state == ST_SCANNING) disc_refresh();
        else if (g_state == ST_BRIDGING) { rules_update_counts(); stats_refresh(); }
        return 0;

    case WM_APP_BRIDGE_DONE:
    case WM_APP_SCAN_DONE:
        worker_done();
        return 0;

    case WM_CLOSE:
        config_save();                      /* persist final UI state */
        tray_remove();
        if (g_state != ST_IDLE) {           /* stop capture before exiting */
            engine_stop();
            if (g_worker) {
                WaitForSingleObject(g_worker, 3000);
                CloseHandle(g_worker);
                g_worker = NULL;
            }
        }
        KillTimer(w, TIMER_ID);
        DestroyWindow(w);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(w, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    (void)hPrev; (void)cmd;

    /* logging into the in-RAM ring, drained by the UI timer */
    log_init(NULL, LOG_INFO);
    log_set_memory_sink(1);
    engine_init();

    if (engine_load_npcap() != 0) {
        MessageBoxA(NULL,
            "Could not load wpcap.dll.\n\n"
            "Npcap does not appear to be installed. Install it from "
            "https://npcap.com/ and run this again.",
            "VLAN Bridge", MB_OK | MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    ui_metrics_init();

    WNDCLASSA wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "VlanBridgeGui";
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    if (!RegisterClassA(&wc)) return 1;

    /* ASCII only: the window is created with the -A API, and a UTF-8 em dash
     * in the source would reach it as mojibake. */
    HWND w = CreateWindowExA(0, wc.lpszClassName,
        "VLAN Bridge - multi-target",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, S(780), S(760),
        NULL, NULL, hInst, NULL);
    if (!w) return 1;

    ShowWindow(w, show);
    UpdateWindow(w);

    MSG m;
    while (GetMessage(&m, NULL, 0, 0) > 0) {
        if (IsDialogMessage(w, &m)) continue;   /* Tab navigation between controls */
        TranslateMessage(&m);
        DispatchMessage(&m);
    }

    if (g_font) DeleteObject(g_font);
    log_close();
    return 0;
}
