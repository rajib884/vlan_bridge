# Handover — GUI + multi-target VLAN bridge

**Branch:** `feature/gui-multitarget` (temporary; will be deleted after validation)
**Author environment:** Linux (aarch64) cross-compiling to Windows x64 via mingw-w64.
**Status:** Compiles and links **cleanly** (`-Wall -Wextra`, zero warnings) into valid
PE32+ binaries. **NOT yet run on Windows** — runtime behavior is unvalidated. That
is what you (the Windows-side AI) need to do.

The prebuilt binaries `vlan_bridge.exe` (CLI) and `vlan_bridge_gui.exe` (GUI) are
committed to this branch for convenience, but **rebuild from source on Windows** to
be sure (see Build below).

---

## What changed in this branch

Previously the tool bridged a single `(target MAC, VLAN)` configured via `-t/-v`.
This branch generalizes it to **N `(MAC → VLAN)` rules** and adds a **native Win32
GUI**. Design decisions locked with the user:

- **Native Win32** GUI (C, common controls), **single process**, capture on a
  **worker thread**.
- **One VLAN per MAC** (each target MAC maps to exactly one VLAN).
- **Outgoing broadcasts replicated into every distinct VLAN** in the rule set.

### File layout (refactor)
| File | Role |
|------|------|
| `engine.c` / `engine.h` | **New.** The whole core, extracted from the old `vlan_bridge.c` and generalized to multiple rules. Tag/strip + checksum helpers are byte-for-byte the same as before. |
| `vlan_bridge.c` | **Rewritten.** Now just the CLI `main()` over the engine. |
| `vlan_bridge_gui.c` | **New.** Win32 GUI (`WinMain`). |
| `vlan_bridge_gui.rc` / `.manifest` | **New.** Embeds an `asInvoker` (no UAC) + comctl6 manifest. |
| `fast_log.c` / `fast_log.h` | Added a thread-safe memory sink: `log_set_memory_sink()` + `log_drain()`, plus a `CRITICAL_SECTION` guarding all ring ops. File/stdout behavior for the CLI is unchanged. |
| `Makefile` | Added `make gui`. `make` still builds the CLI. |

### Engine API (`engine.h`)
- `engine_init()` — call once at startup (inits the lock).
- `engine_enumerate_interfaces()`, `engine_get_interface_mac()`, `engine_parse_mac()`, `engine_format_mac()`.
- `engine_bridge_run(engine_config_t*)` — blocks in `pcap_loop` until `engine_stop()`.
- `engine_discovery_run(iface, filter_ip, verbose)` — blocks likewise.
- `engine_stop()` — thread-safe; calls `pcap_breakloop` on the active handle.
- `engine_get_stats()`, `engine_get_rule_stats()`, `engine_discovery_snapshot()` — thread-safe snapshots for the GUI.

### Threading model (the main new risk area — please validate)
- GUI thread owns `engine_config_t g_cfg`. Rules are edited **only while stopped**,
  so the worker reads an immutable snapshot — no lock on the rules.
- Worker runs `engine_bridge_run(&g_cfg)` / `engine_discovery_run(...)`. When it
  returns (user Stop → `engine_stop`, or fatal error), it `PostMessage`s
  `WM_APP_BRIDGE_DONE` / `WM_APP_SCAN_DONE`; the GUI handler joins the thread and
  resets UI. Both self-exit and user-stop funnel through the same path.
- Per-rule counters live in `g_cfg.rules[]` and are written by the worker and read
  by the GUI timer (benign races on aligned 64-bit reads on x64). Aggregate stats
  and discovery rows are copied under the engine's `CRITICAL_SECTION`.
- The bridge hot path does **not** lock (perf). Discovery locks per packet (ARP/ICMP
  is low volume).

---

## Build

### Cross-compile (Linux, how these binaries were made)
```bash
sudo apt-get install gcc-mingw-w64-x86-64
make            SDK=<path-to-npcap-sdk>   # or omit SDK= to auto-download
make gui        SDK=<path-to-npcap-sdk>
```
Note: on this image the bare `x86_64-w64-mingw32-gcc` symlink is broken, so the
Makefile defaults `CC` to the `-posix` variant and passes an explicit
`--preprocessor` to `windres`. On a normal toolchain these are harmless.

### Native Windows (MSYS2/MinGW) — recommended for validation
```bash
# CLI
gcc -O2 -Wall -Wextra -o vlan_bridge.exe vlan_bridge.c engine.c fast_log.c \
    -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib/x64" -lwpcap -lws2_32 -liphlpapi

# GUI
windres vlan_bridge_gui.rc -O coff -o gui_res.o
gcc -O2 -Wall -Wextra -mwindows -o vlan_bridge_gui.exe \
    vlan_bridge_gui.c engine.c fast_log.c gui_res.o \
    -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib/x64" \
    -lwpcap -lws2_32 -liphlpapi -lcomctl32 -lgdi32 -luser32
```
Or just `make` / `make gui` under MSYS2 with `SDK=/c/npcap-sdk CC=gcc`.

---

## Validation checklist (please run on Windows + Npcap)

### GUI (`vlan_bridge_gui.exe`)
1. Launches with **no UAC prompt** (manifest is `asInvoker`). Window opens
   ~760×620, **resizes** cleanly (log/lists stretch; min size enforced). If Npcap
   was installed "admin-only", capture fails at Start with an access error — that
   is expected; run elevated in that case.
2. **Interface** dropdown lists up Ethernet adapters with name + IP.
3. **Scan** → discovery list fills with `(VLAN, MAC, IP, pkts)` as tagged ARP/ICMP
   arrives; button toggles to **Stop Scan** and back.
4. **Double-click** a discovered row (or select + **Add Selected → Rules**) adds a
   rule. Duplicate MAC is rejected with a message box.
5. **Add Rule** with manual MAC + VLAN validates input; **Remove Rule** works.
6. **Start** with ≥2 rules on different VLANs → per-rule **Out/In** counts climb,
   the **stats** line updates, and the **log pane** streams. **Stop** returns to
   idle **without hanging**; rules become editable again; Start again works.
7. Closing the window while running stops capture cleanly (no crash/hang).
8. In **Wireshark** on the trunk: unicast to each target is tagged with **that
   target's** VLAN; a local broadcast (ARP) appears **once per distinct VLAN**.

### CLI (`vlan_bridge.exe`) — regression
- `vlan_bridge -l` lists interfaces (name/IP/MAC).
- `vlan_bridge -s -i <iface> [-f <ip>]` scans, prints summary table on Ctrl+C.
- `vlan_bridge -i <iface> -t <mac> -v <vid>` bridges one target (old behavior).
- `vlan_bridge -i <iface> -r <mac>:<vid> -r <mac>:<vid>` bridges multiple targets.
- Ctrl+C prints the stats block (aggregate + per-rule) and exits.

---

## Known nits / things a validator may want to polish
- **Cosmetic:** STATIC labels and the checkbox don't handle `WM_CTLCOLORSTATIC`, so
  their backgrounds may not perfectly match the window's button-face gray on some
  themes. Add a `WM_CTLCOLORSTATIC` handler returning `GetSysColorBrush(COLOR_BTNFACE)`
  if it looks off. Purely visual.
- **`EM_SETCUEBANNER`** placeholder text needs comctl6 (provided by the manifest);
  if cue text doesn't show, it's harmless.
- **Log growth:** the log EDIT is cleared when it exceeds ~500 KB of text (simple
  cap). The in-RAM ring drops oldest bytes if the UI ever fails to drain in time
  (shouldn't happen at 250 ms).
- **VLAN offload caveat (important):** discovery and the bridge's incoming path only
  work if the NIC delivers 802.1Q tags to Npcap. If it strips tags in hardware,
  nothing tagged is seen — disable VLAN offload on the adapter (or enable Npcap's
  VLAN tag support). This is unchanged from the original tool.
- **Not implemented (out of scope, `#if 0` in history):** IP fragmentation and ICMP
  Frag-Needed. IPv6 checksums are passed through unchanged.

## Suggested first move for the Windows AI
Rebuild both targets natively (`make gui CC=gcc SDK=/c/npcap-sdk` under MSYS2, or
the explicit gcc commands above), confirm zero warnings, then walk the GUI
checklist. If capture works in the CLI (`-r` multi-target) but not the GUI, the
delta is almost certainly in the GUI's threading/lifecycle, not the engine.
