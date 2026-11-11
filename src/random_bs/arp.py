"""ARP cache access and MAC address helpers.

The Windows ARP table is read with ``GetIpNetTable`` through ctypes and,
if that fails, by parsing ``arp -a``.  Reading the cache before and after
the ping sweep is what lets the scanner see devices that block ICMP: an
ICMP attempt (echo request or the follow-up ARP lookup the TCP/IP stack
performs) still triggers ARP resolution, and the resulting IP-to-MAC
mapping stays in the cache for a few minutes.

The curated OUI table below is deliberately small and best effort.  It covers
the vendors seen most often on home, office and virtual networks.  A bundled
IEEE OUI snapshot supplies additional fallback labels for 24-, 28- and 36-bit
prefixes; the longest matching prefix wins, and neither source is a live copy
of the IEEE registry.
"""

from __future__ import annotations

import ctypes
import functools
import locale
import logging
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Mapping

LOGGER = logging.getLogger(__name__)

_IS_WINDOWS = os.name == "nt"
_CREATE_NO_WINDOW = 0x0800_0000
_ERROR_INSUFFICIENT_BUFFER = 122
_MAX_PHYSICAL_ADDRESS_LENGTH = 8
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ROW_RE = re.compile(
    r"^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"
    r"(?:\s+(?P<type>\S+))?",
    re.MULTILINE,
)
_INTERFACE_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+---\s+(?P<index>0x[0-9A-Fa-f]+)"
)
_OUI_DATA_FILE = Path(__file__).with_name("data") / "mac-vendor.txt"
_VENDOR_PREFIX_LENGTHS = frozenset({6, 7, 9})
_NON_VENDOR_LABELS = frozenset({"ieee registration authority", "private"})


@dataclass(frozen=True, slots=True)
class ArpEntry:
    """One usable entry from the system ARP cache."""

    ip: str
    mac: str
    interface: str = ""
    if_index: int = 0
    entry_type: str = "dynamic"


@dataclass(slots=True)
class ArpTable:
    """ARP entries keyed by IPv4 address, plus the method used to read them."""

    entries: dict[str, ArpEntry] = field(default_factory=dict)
    method: str = "unavailable"


# ---------------------------------------------------------------------------
# Windows GetIpNetTable
# ---------------------------------------------------------------------------


class _MIBIpNetRow(ctypes.Structure):
    _fields_ = [
        ("dwIndex", ctypes.c_uint32),
        ("dwPhysAddrLen", ctypes.c_uint32),
        ("bPhysAddr", ctypes.c_ubyte * _MAX_PHYSICAL_ADDRESS_LENGTH),
        ("dwAddr", ctypes.c_uint32),
        ("dwType", ctypes.c_uint32),
    ]


@functools.lru_cache(maxsize=1)
def _get_ip_net_table():
    """Return the configured ``GetIpNetTable`` function, or ``None``."""
    if not _IS_WINDOWS:
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        dll = win_dll("iphlpapi.dll", use_last_error=True)
        function = dll.GetIpNetTable
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int]
        function.restype = ctypes.c_uint32
        return function
    except (AttributeError, OSError) as exc:
        LOGGER.warning("GetIpNetTable unavailable: %s", exc)
        return None


def _read_via_ctypes(interface_names: Mapping[int, str]) -> dict[str, ArpEntry]:
    function = _get_ip_net_table()
    if function is None:
        raise OSError("GetIpNetTable is not available")
    size = ctypes.c_uint32(0)
    result = function(None, ctypes.byref(size), False)
    if result not in (0, _ERROR_INSUFFICIENT_BUFFER) or size.value == 0:
        raise OSError(f"GetIpNetTable sizing failed (code {result})")
    buffer = ctypes.create_string_buffer(size.value)
    result = function(
        ctypes.cast(buffer, ctypes.c_void_p), ctypes.byref(size), False
    )
    if result != 0:
        raise OSError(f"GetIpNetTable failed (code {result})")

    count = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint32)).contents.value
    header_size = ctypes.sizeof(ctypes.c_uint32)
    row_size = ctypes.sizeof(_MIBIpNetRow)
    entries: dict[str, ArpEntry] = {}
    for index in range(int(count)):
        offset = header_size + index * row_size
        if offset + row_size > len(buffer):
            break
        row = _MIBIpNetRow.from_address(ctypes.addressof(buffer) + offset)
        entry = _row_to_entry(
            ip=socket.inet_ntoa(struct.pack("<I", int(row.dwAddr))),
            raw_mac=bytes(row.bPhysAddr[: int(row.dwPhysAddrLen)]),
            if_index=int(row.dwIndex),
            entry_type=_type_name(int(row.dwType)),
            interface_names=interface_names,
        )
        if entry is not None:
            entries[entry.ip] = entry
    return entries


def _type_name(value: int) -> str:
    return {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}.get(value, "other")


def _row_to_entry(
    *,
    ip: str,
    raw_mac: bytes,
    if_index: int,
    entry_type: str,
    interface_names: Mapping[int, str],
) -> ArpEntry | None:
    if entry_type == "invalid" or len(raw_mac) not in (6, 8):
        return None
    mac = format_mac_bytes(raw_mac)
    if mac is None or not _is_unicast_ip(ip) or not _is_usable_mac(mac):
        return None
    interface = interface_names.get(if_index, f"if{if_index}" if if_index else "")
    return ArpEntry(ip, mac, interface, if_index, entry_type)


# ---------------------------------------------------------------------------
# `arp -a` fallback
# ---------------------------------------------------------------------------


def _decode_console(data: bytes) -> str:
    """Decode command output using the console code page when possible."""
    encodings = ["utf-8", locale.getpreferredencoding(False), "mbcs", "cp437"]
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _read_via_command(interface_names: Mapping[int, str]) -> dict[str, ArpEntry]:
    command = ["arp", "-a"]
    kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "timeout": 10.0,
    }
    if _IS_WINDOWS:
        kwargs["creationflags"] = _CREATE_NO_WINDOW
    completed = subprocess.run(command, **kwargs)  # type: ignore[arg-type]
    if completed.returncode != 0:
        raise OSError(f"arp -a exited with code {completed.returncode}")
    text = _decode_console(completed.stdout)

    entries: dict[str, ArpEntry] = {}
    current_index = 0
    for line in text.splitlines():
        header = _INTERFACE_RE.search(line)
        if header:
            current_index = int(header.group("index"), 16)
            continue
        match = _ROW_RE.match(line)
        if not match:
            continue
        raw_type = (match.group("type") or "").lower()
        if raw_type.startswith("dyn") or raw_type.startswith("dynam"):
            entry_type = "dynamic"
        elif raw_type.startswith("stat"):
            entry_type = "static"
        else:
            entry_type = "other"
        entry = _row_to_entry(
            ip=match.group("ip"),
            raw_mac=_parse_mac_text(match.group("mac")),
            if_index=current_index,
            entry_type=entry_type,
            interface_names=interface_names,
        )
        if entry is not None:
            entries[entry.ip] = entry
    return entries


def _parse_mac_text(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def read_arp_table(
    interface_names: Mapping[int, str] | None = None,
) -> ArpTable:
    """Read the system ARP cache, preferring ``GetIpNetTable``.

    Returns every usable unicast entry from every interface.  The caller
    is responsible for restricting the result to the scanned subnet.
    """
    names = dict(interface_names or {})
    if _IS_WINDOWS:
        try:
            entries = _read_via_ctypes(names)
            return ArpTable(entries, "iphlpapi")
        except (OSError, ValueError) as exc:
            LOGGER.warning("Could not read the ARP table with GetIpNetTable: %s", exc)
    try:
        entries = _read_via_command(names)
        return ArpTable(entries, "arp -a")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        LOGGER.warning("Could not read the ARP cache: %s", exc)
        return ArpTable({}, "unavailable")


def format_mac_bytes(raw: bytes) -> str | None:
    """Format a 6 or 8 byte hardware address as ``AA:BB:CC:DD:EE:FF``."""
    if len(raw) not in (6, 8):
        return None
    return ":".join(f"{byte:02X}" for byte in raw)


def normalize_mac(text: str) -> str | None:
    """Normalize the common textual MAC formats to colon-separated hex."""
    return format_mac_bytes(_parse_mac_text(text))


def _is_usable_mac(mac: str) -> bool:
    try:
        first = int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    if mac == "FF:FF:FF:FF:FF:FF":
        return False
    if mac == "00:00:00:00:00:00":
        return False
    # Bit 0 of the first octet marks multicast/broadcast addresses.
    return not (first & 0x01)


def _is_unicast_ip(ip: str) -> bool:
    try:
        address = socket.inet_aton(ip)
    except OSError:
        return False
    first = address[0]
    return ip not in ("0.0.0.0", "255.255.255.255") and not 224 <= first <= 239


def is_locally_administered(mac: str | None) -> bool:
    """Return True when the MAC's U/L bit marks a locally administered address.

    Phones and laptops commonly use randomized MAC addresses, which set this
    bit.  Only complete 6- or 8-byte addresses are considered; malformed
    values return ``False``.
    """
    if not mac:
        return False
    raw = _parse_mac_text(mac)
    if len(raw) not in (6, 8):
        return False
    return bool(raw[0] & 0x02)


# ---------------------------------------------------------------------------
# Vendor lookup
# ---------------------------------------------------------------------------

_OUI_VENDORS: dict[str, str] = {
    # Network infrastructure
    "00000C": "Cisco",
    "001AA1": "Cisco",
    "001B54": "Cisco",
    "00260B": "Cisco",
    "000585": "Juniper",
    "2C2172": "Juniper",
    "000B86": "Aruba",
    "24DEC6": "Aruba",
    "00090F": "Fortinet",
    "704CA5": "Fortinet",
    "000C42": "MikroTik",
    "488F5A": "MikroTik",
    "744D28": "MikroTik",
    "00156D": "Ubiquiti",
    "245A4C": "Ubiquiti",
    "788A20": "Ubiquiti",
    "8C8B5B": "WNC Corporation",
    "E063DA": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "001D0F": "TP-Link",
    "50C7BF": "TP-Link",
    "A42BB0": "TP-Link",
    "C04A00": "TP-Link",
    "EC086B": "TP-Link",
    "00146C": "Netgear",
    "204E7F": "Netgear",
    "A00460": "Netgear",
    "A040A0": "Netgear",
    "00055D": "D-Link",
    "001B11": "D-Link",
    "1C7EE5": "D-Link",
    # Computers and phones
    "000393": "Apple",
    "000A27": "Apple",
    "001B63": "Apple",
    "001EC2": "Apple",
    "3C22FB": "Apple",
    "A483E7": "Apple",
    "ACBC32": "Apple",
    "F01898": "Apple",
    "001422": "Dell",
    "001EC9": "Dell",
    "180373": "Dell",
    "B82A72": "Dell",
    "D4BED9": "Dell",
    "F8B156": "Dell",
    "001F29": "HP",
    "3CD92B": "HP",
    "9457A5": "HP",
    "D48564": "HP",
    "001B21": "Intel",
    "001E64": "Intel",
    "3C970E": "Intel",
    "8C1645": "Intel",
    "A0369F": "Intel",
    "F0D415": "Intel",
    "001BFC": "ASUS",
    "04D4C4": "ASUS",
    "2C56DC": "ASUS",
    "AC220B": "ASUS",
    "005907": "Lenovo",
    "54EE75": "Lenovo",
    "E86A64": "Lenovo",
    "0012FB": "Samsung",
    "001632": "Samsung",
    "342387": "Samsung",
    "8C7712": "Samsung",
    "E8508B": "Samsung",
    "0003FF": "Microsoft",
    "00125A": "Microsoft",
    "281878": "Microsoft",
    "7C1E52": "Microsoft",
    "00E04C": "Realtek",
    "001C62": "LG Electronics",
    # Phones, tablets, media and consoles
    "3C5AB4": "Google",
    "F4F5D8": "Google",
    "18B430": "Google Nest",
    "00FC8B": "Amazon",
    "44650D": "Amazon",
    "6837E9": "Amazon",
    "F0272D": "Amazon",
    "000E58": "Sonos",
    "5CAAFD": "Sonos",
    "B8E937": "Sonos",
    "B0A737": "Roku",
    "CC6DA0": "Roku",
    "D83134": "Roku",
    "00041F": "Sony",
    "001315": "Sony",
    "FC0FE6": "Sony",
    "0009BF": "Nintendo",
    "58BDA3": "Nintendo",
    "98B6E9": "Nintendo",
    "009EC8": "Xiaomi",
    "640980": "Xiaomi",
    "7811DC": "Xiaomi",
    "00E0FC": "Huawei",
    "001882": "Huawei",
    "4846FB": "Huawei",
    "70723C": "Huawei",
    # IoT and embedded
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "240AC4": "Espressif",
    "30AEA4": "Espressif",
    "3C71BF": "Espressif",
    "7C9EBD": "Espressif",
    "84F3EB": "Espressif",
    "AC67B2": "Espressif",
    "DC4F22": "Espressif",
    "001788": "Philips Lighting",
    # Printers
    "000085": "Canon",
    "001E8F": "Canon",
    "0000AA": "Xerox",
    "000048": "Epson",
    "008077": "Brother",
    # Virtualisation and storage
    "000569": "VMware",
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "525400": "QEMU/KVM",
    "001C42": "Parallels",
    "001132": "Synology",
    "9009D0": "Synology",
    "00089B": "QNAP",
    "245EBE": "QNAP",
}


@functools.lru_cache(maxsize=1)
def _supplemental_oui_vendors() -> dict[str, str]:
    """Load the bundled tab-separated IEEE prefix list, ignoring bad rows.

    The snapshot contains 24-bit OUI, 28-bit IAB/MA-M and 36-bit OUI36/MA-S
    registrations.  It is static and best effort rather than a live copy of
    the IEEE registry.  Comment lines and rows with unknown prefix lengths are
    skipped, and only the first vendor column is used.  Placeholder labels are
    not vendors.  A missing or unreadable file yields no fallback entries.
    """
    try:
        lines = _OUI_DATA_FILE.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError as exc:
        LOGGER.debug("supplemental OUI list unavailable: %s", exc)
        return {}

    vendors: dict[str, str] = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        prefix, separator, remainder = line.partition("\t")
        prefix = prefix.strip().upper()
        if (
            not separator
            or len(prefix) not in _VENDOR_PREFIX_LENGTHS
            or any(char not in "0123456789ABCDEF" for char in prefix)
        ):
            continue
        vendor = remainder.split("\t", 1)[0].strip()
        if not vendor or vendor.casefold() in _NON_VENDOR_LABELS:
            continue
        vendors.setdefault(prefix, vendor)
    return vendors


def vendor_for_mac(mac: str | None) -> str:
    """Return a vendor label, or ``randomized`` for a locally administered MAC.

    The most specific bundled prefix wins (36 bits, then 28, then 24), and a
    curated 24-bit entry wins over the bundled 24-bit list.  A global OUI
    found in neither returns an empty string; callers render that as ``-``.
    Locally administered addresses are marked separately because their OUI
    cannot identify a manufacturer.
    """
    if not mac:
        return ""
    raw = _parse_mac_text(mac)
    if len(raw) not in (6, 8):
        return ""
    if is_locally_administered(mac):
        return "randomized"
    key = raw.hex().upper()
    vendors = _supplemental_oui_vendors()
    for length in (9, 7):
        vendor = vendors.get(key[:length])
        if vendor:
            return vendor
    vendor = _OUI_VENDORS.get(key[:6])
    if vendor:
        return vendor
    return vendors.get(key[:6], "")


__all__ = [
    "ArpEntry",
    "ArpTable",
    "format_mac_bytes",
    "is_locally_administered",
    "normalize_mac",
    "read_arp_table",
    "vendor_for_mac",
]
