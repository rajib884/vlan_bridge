# VLAN Bridge

A Windows utility that adds 802.1Q VLAN tags to outgoing Ethernet frames and strips them from incoming frames, enabling a non-VLAN-aware machine to communicate over a VLAN trunk port. Available as a **command-line tool** (`vlan_bridge.exe`) and a **native GUI** (`vlan_bridge_gui.exe`).

It supports **multiple targets at once**: each target MAC is mapped to its own VLAN, and the local machine's broadcasts are replicated into every VLAN in use.

## How it works

The program sits on an interface via [Npcap](https://npcap.com/) in promiscuous mode, applies a BPF filter to capture only traffic to/from the configured target MACs, and rewrites frames on the fly:

- **Outgoing unicast** – to a target MAC: inserts a 4-byte 802.1Q tag (TPID `0x8100`) with **that target's VLAN**, and fixes IP/TCP/UDP/ICMP checksums that Windows NIC offload leaves zeroed.
- **Outgoing broadcast** – replicated once per distinct VLAN across all targets.
- **Incoming unicast/broadcast** – from a target: strips the VLAN tag (when the VID matches that target's rule) and re-injects the clean frame so the local OS stack consumes it normally.

The core lives in `engine.c` (shared by both front-ends); `vlan_bridge.c` is the CLI and `vlan_bridge_gui.c` is the Win32 GUI.

## Requirements

- Windows (Vista or later, x64)
- [Npcap](https://npcap.com/) installed in WinPcap API-compatible mode
- Raw packet access via Npcap. This works for non-admin users unless Npcap was
  installed with "Restrict Npcap driver's access to Administrators only" — in
  that case run elevated.

## Build

Native (MinGW/MSYS2 on Windows), adjusting paths to your Npcap SDK:

```bash
gcc -o vlan_bridge.exe vlan_bridge.c fast_log.c \
    -I"C:/npcap-sdk/Include" \
    -L"C:/npcap-sdk/Lib/x64" \
    -lwpcap -lws2_32 -liphlpapi
```

Or cross-compile Windows x64 binaries from Linux (fetches the Npcap SDK
automatically via the `Makefile`):

```bash
sudo apt-get install gcc-mingw-w64-x86-64
make          # builds the CLI  -> vlan_bridge.exe
make gui      # builds the GUI  -> vlan_bridge_gui.exe
```

## GUI

Run `vlan_bridge_gui.exe` (no elevation needed — it runs as the current user;
Npcap grants access to non-admin users unless installed with "Restrict to
Administrators"). One
window covers the whole workflow:

1. Pick the trunk **interface** from the dropdown.
2. **Scan** to discover VLAN-tagged devices; double-click a row (or select it and
   **Add Selected → Rules**) to turn it into a `(MAC → VLAN)` rule.
3. Or type a MAC + VLAN and **Add Rule**. Build as many rules as you need.
4. **Start** the bridge. The rules table shows live per-target Out/In totals and
   **Out/s / In/s** packet rates, the stats line shows aggregate counters, and
   the log pane streams engine output. **Stop** to edit rules and start again.

Rules, the selected interface, checkboxes, and the window size/position are
saved to `%APPDATA%\vlan_bridge\config.ini` and restored on the next launch.
Tick **Auto-start** to begin bridging automatically at startup. **Minimizing**
hides the app to a system-tray icon (double-click to restore, right-click for a
menu).

## CLI usage

```
vlan_bridge -l                                           # list interfaces
vlan_bridge -s -i <iface> [-f <ip>] [-o log] [-d]        # discover MAC + VLAN
vlan_bridge -i <iface> -t <mac> -v <vid> [-o log] [-d]   # bridge one target
vlan_bridge -i <iface> -r <mac>:<vid> [-r <mac>:<vid>] ... # bridge multiple targets
```

| Flag | Description |
|------|-------------|
| `-i` | Npcap interface name (e.g. `\Device\NPF_{GUID}`) |
| `-t` | Target MAC address (e.g. `AA:BB:CC:DD:EE:FF`) |
| `-v` | VLAN ID (1–4094) |
| `-r` | Target rule `<mac>:<vid>`, repeatable — for bridging multiple targets |
| `-s` | Discovery mode: passively scan tagged ARP/ICMP to find the target MAC and VLAN |
| `-f` | Discovery IP filter: only report frames with this IP on either side |
| `-o` | Write log to the given file instead of stdout |
| `-d` | Verbose: keep per-packet logging during capture (off by default for throughput) |
| `-l` | List interfaces and exit |

Multiple targets, e.g. two devices on different VLANs:

```
> vlan_bridge -i \Device\NPF_{GUID} -r AA:BB:CC:DD:EE:01:20 -r AA:BB:CC:DD:EE:02:30
```

### Finding the MAC and VLAN (discovery mode)

If you don't already know the target's MAC and VLAN ID, run discovery first. It
listens passively (it never sends anything) for VLAN-tagged ARP and ICMP frames
and prints each unique `(VLAN, MAC, IP)` it sees, then a summary table on `Ctrl+C`:

```
> vlan_bridge -s -i \Device\NPF_{GUID}
[DISC] New: VLAN 20   AA:BB:CC:DD:EE:FF  IP 192.168.20.5     via ARP
^C
--- Discovered 1 device(s) ---
VLAN  MAC                IP               pkts
20    AA:BB:CC:DD:EE:FF  192.168.20.5     142
```

Then feed those values into bridge mode:

```
> vlan_bridge -i \Device\NPF_{GUID} -t AA:BB:CC:DD:EE:FF -v 20
```

Use `-f <ip>` to narrow discovery to a single host, and `-d` to log every
matching packet instead of just first-seen.

## Behavior

| Direction | Condition | Action |
|-----------|-----------|--------|
| Outgoing unicast | src=my MAC, dst=a target MAC, no VLAN tag | Insert 802.1Q tag with that target's VLAN, fix checksums, re-send |
| Outgoing broadcast | src=my MAC, dst=FF:FF:FF:FF:FF:FF, no VLAN tag | Tag + send once per **distinct VLAN** across all rules |
| Incoming unicast | src=a target MAC, dst=my MAC, tag VID matches that target's rule | Strip tag, re-inject |
| Incoming broadcast | src=a target MAC, dst=FF:FF:FF:FF:FF:FF, tag VID matches | Strip tag, re-inject |
| Any other frame | – | Ignored (counted in stats) |

## Limitations

- Only handles IPv4 checksums; IPv6 is passed through unchanged.
- Fragmentation support (DF=0 oversized IP packets) and ICMP Fragmentation Needed (DF=1) are currently stubbed out (`#if 0`).
- The original untagged outgoing frame also reaches the wire; the target device must ignore it based on the missing VLAN tag.
- Broadcast replication multiplies local broadcast traffic (one tagged copy per distinct VLAN).
- Each target MAC maps to exactly one VLAN.
- Both discovery mode and the bridge's incoming path depend on the NIC delivering 802.1Q tags to Npcap. If the adapter strips tags in hardware (VLAN offload), no tagged frames are seen — disable VLAN offload on the adapter (or enable Npcap's VLAN tag support) if discovery reports nothing.
