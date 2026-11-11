# netscan

A dependency-free local IPv4 inventory scanner for Windows. It combines a
concurrent ICMP ping sweep with ARP cache inspection, so it maps not only hosts
that answer ping but also devices that silently drop ICMP while still answering
ARP.

> **Authorized use only.** Scan only networks you own or have explicit written
> permission to audit. The tool prints this reminder on every startup.

## Requirements

- Windows 10 or 11 (uses `iphlpapi.dll`; no raw sockets or administrator rights)
- Python 3.14 or newer
- Standard library only; no pip packages
- Optional: `nbtstat` with NetBT enabled for `--netbios`

## Install and run

This repository is a uv project with a `src/` layout. The package is
`random_bs` and it installs two equivalent commands, `netscan` and
`random-bs`:

```bash
uv sync
uv run netscan --help
```

You can also run it without installing:

```bash
uv run python -m random_bs.cli --help
```

## Usage

```text
netscan [--cidr CIDR] [--timeout MS] [--workers N]
        [--no-resolve] [--netbios] [--watch SECONDS]
        [--csv FILE] [--json FILE] [--verbose]
```

| Option | Meaning |
| --- | --- |
| `--cidr CIDR` | Scan this IPv4 subnet, e.g. `192.168.1.0/24`. Auto-detects a /24 when omitted. A prefix length is required. |
| `--timeout MS` | Per-host ICMP timeout, 50–10000 ms. Default `1000`. |
| `--workers N` | Concurrent ping workers, 1–512. Default `64`. |
| `--no-resolve` | Disable reverse DNS hostname lookups. |
| `--netbios` | Also query Windows NetBIOS names with `nbtstat -A`. |
| `--watch SECONDS` | Rescan every N seconds (1–86400) and diff the inventory. |
| `--csv FILE` | Write the final inventory as CSV. |
| `--json FILE` | Write the final inventory as JSON. |
| `--verbose` | Log adapter selection, ARP counts, methods and timing to stderr. |

### Examples

Auto-detect the active subnet and scan it:

```bash
uv run netscan
```

Scan an explicit subnet and save both formats:

```bash
uv run netscan --cidr 192.168.1.0/24 --csv inventory.csv --json inventory.json
```

Skip DNS, query NetBIOS names, and keep watching every 30 seconds:

```bash
uv run netscan --cidr 192.168.1.0/24 --no-resolve --netbios --watch 30
```

## What it finds

After the sweep, stdout contains a final inventory table:

```text
Inventory: 192.168.1.0/24  (4 active, 2026-01-01 12:00:00)
+-----------------+-------------------+--------------+------------------+--------+-----------+
| IP              | MAC               | Vendor       | Hostname         | RTT    | State     |
+-----------------+-------------------+--------------+------------------+--------+-----------+
| 192.168.1.1 *   | AA:BB:CC:DD:EE:FF | Cisco        | router.lan       | 2 ms   | up        |
| 192.168.1.20    | B8:27:EB:11:22:33 | Raspberry Pi | pi.lan           | <1 ms  | up        |
| 192.168.1.50    | 76:8A:54:7C:7C:B0 | randomized   | -                | -      | ARP only  |
| 192.168.1.100   | 8C:8B:5B:42:B1:53 | WNC Corporation | workstation      | <1 ms  | self      |
+-----------------+-------------------+--------------+------------------+--------+-----------+
4 active: 3 responding, 1 ARP only (ICMP filtered).
Local 192.168.1.100/24 on WiFi | gateway 192.168.1.1
Scanned 254/254 addresses in 3.6s | ping: icmp-dll | arp: iphlpapi
  * default gateway
```

States:

- **up** — the host answered ICMP; `RTT` is the measured round-trip time.
- **self** — the interface running the scanner.
- **ARP only** — no ICMP reply, but the device answered ARP. This is the
  important case for firewalls that block ping; the host is still in the
  inventory with its MAC address.
- `*` after an IP marks the adapter's default gateway.
- Vendor lookup tries bundled 36-bit and 28-bit registrations first, then the
  curated OUI table, then the bundled 24-bit list. The bundled `mac-vendor.txt`
  is a 2025-01-29 IEEE snapshot from arp-scan's generated `ieee-oui.txt`.
  Globally administered prefixes missing from all sources show `-`; locally
  administered (randomized) MACs, common on modern phones and laptops, are
  labeled `randomized`.

On an interactive terminal the same table is redrawn live while addresses are
being probed. When stdout is redirected, each ICMP-confirmed device is printed
on its own line as soon as it is found, followed by the complete table.

## How it works

1. **Subnet detection.** `GetAdaptersAddresses` from `iphlpapi.dll` is called
   through `ctypes` to enumerate IPv4 unicast addresses, netmasks, MAC
   addresses and default gateways. The adapter with a gateway is preferred,
   and physical Ethernet/Wi-Fi adapters win over virtual ones. If the API is
   unavailable, the tool parses `ipconfig` instead. Auto-detection scans a /24
   around the local address even if the interface has a larger prefix; use
   `--cidr` for anything else. The maximum accepted range is /20 (4094 hosts).
2. **ICMP sweep.** Every host address is probed concurrently with
   `ThreadPoolExecutor` (64 workers by default). The preferred probe is
   `IcmpSendEcho` from `iphlpapi.dll`, which needs no administrator privileges.
   If the ICMP API cannot be initialized, the tool falls back to
   `ping -n 1 -w <timeout>`. Every probe is bounded, and the whole sweep has an
   internal 30–120 second budget derived from host count, workers and timeout.
3. **ARP cache, before and after.** The system ARP cache is read with
   `GetIpNetTable` (fallback: parse `arp -a`) before the sweep and again after
   it. The ping attempt forces the TCP/IP stack to resolve the next-hop MAC even
   when the host drops the ICMP echo, so ARP-only devices appear in the second
   snapshot. The scanner merges both snapshots, filters to the scanned subnet,
   and associates each IP with a MAC and interface.
4. **Name resolution.** Reverse DNS runs through `socket.gethostbyaddr` on
   daemon threads with a short aggregate timeout, so a dead resolver cannot
   stall the scan. `--no-resolve` disables it. `--netbios` additionally runs
   `nbtstat -A` for hosts lacking a DNS name.
5. **Display and diffing.** The live display uses ANSI cursor movement on a
   real terminal and plain streaming lines otherwise. `--watch` rescans on a
   fixed interval and prints `NEW` and `GONE` entries between the full
   inventories.
6. **Exports.** CSV and JSON are written through a temporary sibling file and
   atomically replaced, so a failed write never leaves a partial inventory.

## Exports

CSV columns:

```text
ip, mac, vendor, hostname, netbios, rtt_ms, state, interface, gateway
```

JSON contains:

- `network` — CIDR, local address, prefix, gateway, adapter name, detection source
- `scan` — timeout, workers, scanned/total counts, probe methods, ARP entry counts, timeout flag
- `summary` — active, responding, ARP-only counts
- `hosts` — one object per device with the same fields as the table plus interface and gateway

In watch mode both files are replaced after every completed cycle.

## Exit codes and interruption

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, or the user stopped it with Ctrl+C |
| `1` | Network/runtime error (no usable adapter, I/O failure, unexpected error) |
| `2` | Bad usage (invalid CIDR, oversized range, invalid option) |

Ctrl+C clears the live display, prints `interrupted by user`, and exits without
writing a partial inventory. Files from an earlier watch cycle are left intact.

## Running the tests

The test suite uses only the standard library and needs no network access:

```bash
uv run python -m unittest discover -s tests
```

## Limitations

- IPv4 only. There is no IPv6 inventory.
- ARP is link-local: devices behind a router are not discoverable with ARP,
  even if they are pingable. Scan the local subnet.
- ARP cache entries can be a few minutes old; a recently disconnected device
  may appear until its cache entry expires.
- Vendor lookup is best effort: it combines a small curated table with a
  static bundled IEEE snapshot (36,857 OUI, 5,683 IAB/MA-M and 10,901
  OUI36/MA-S entries). The snapshot is not the live IEEE registry, so newer
  registrations may still show `-`.
- A host that both blocks ICMP and has no ARP entry (for example, across a
  routed boundary) cannot be found by this design.
- `--netbios` only works when the NetBT driver is loaded and the target exposes
  a `<00>` UNIQUE name.
- Virtual adapters (VMware, VirtualBox, Hyper-V) can create several candidate
  subnets; use `--cidr` to pin the one you want.
- No packet capture, port scanning, OS fingerprinting, or raw sockets.
