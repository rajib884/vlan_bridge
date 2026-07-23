# VLAN Bridge

A Windows utility that adds 802.1Q VLAN tags to outgoing Ethernet frames and strips them from incoming frames, enabling a non-VLAN-aware machine to communicate over a VLAN trunk port.

## How it works

The program sits on an interface via [Npcap](https://npcap.com/) in promiscuous mode, applies a BPF filter to capture only traffic to/from a designated target MAC, and rewrites frames on the fly:

- **Outgoing unicast/broadcast** – inserts a 4-byte 802.1Q tag (TPID `0x8100`) and fixes IP/TCP/UDP/ICMP checksums that Windows NIC offload leaves zeroed.
- **Incoming unicast/broadcast** – strips the VLAN tag and re-injects the clean frame so the local OS stack consumes it normally.

## Requirements

- Windows (Vista or later, x64)
- [Npcap](https://npcap.com/) installed in WinPcap API-compatible mode
- Administrator privileges (required for raw packet access)

## Build

```bash
gcc -o vlan_bridge.exe vlan_bridge.c fast_log.c \
    -I"C:/npcap-sdk/Include" \
    -L"C:/npcap-sdk/Lib/x64" \
    -lwpcap -lws2_32 -liphlpapi
```

## Usage

```
vlan_bridge -l                                    # list available interfaces
vlan_bridge -i <iface> -t <mac> -v <vid> [-o log] [-d]  # start bridge
```

| Flag | Description |
|------|-------------|
| `-i` | Npcap interface name (e.g. `\Device\NPF_{GUID}`) |
| `-t` | Target MAC address (e.g. `AA:BB:CC:DD:EE:FF`) |
| `-v` | VLAN ID (1–4094) |
| `-o` | Write log to the given file instead of stdout |
| `-d` | Verbose: keep per-packet logging during capture (off by default for throughput) |
| `-l` | List interfaces and exit |

## Behavior

| Direction | Condition | Action |
|-----------|-----------|--------|
| Outgoing unicast | src=my MAC, dst=target MAC, no VLAN tag | Insert 802.1Q tag, fix checksums, re-send |
| Outgoing broadcast | src=my MAC, dst=FF:FF:FF:FF:FF:FF, no VLAN tag | Same as above |
| Incoming unicast | src=target MAC, dst=my MAC, has VLAN tag | Strip tag, re-inject |
| Incoming broadcast | src=target MAC, dst=FF:FF:FF:FF:FF:FF, has VLAN tag | Strip tag, re-inject |
| Any other frame | – | Ignored (counted in stats) |

## Limitations

- Only handles IPv4 checksums; IPv6 is passed through unchanged.
- Fragmentation support (DF=0 oversized IP packets) and ICMP Fragmentation Needed (DF=1) are currently stubbed out (`#if 0`).
- The original untagged outgoing frame also reaches the wire; the target device must ignore it based on the missing VLAN tag.
