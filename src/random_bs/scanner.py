"""Subnet detection and the scan orchestration.

The scan is deliberately built from two complementary sources:

* an ICMP sweep finds hosts that answer echo requests and gives an RTT;
* the ARP cache, read before and after the sweep, maps IP addresses to
  hardware addresses and also reveals hosts that silently drop ICMP.

The second point matters: even when a firewall discards the echo request,
the TCP/IP stack still performs an ARP lookup for the destination (needed
to transmit the request at all).  A host that answers ARP therefore shows
up in the cache with its MAC address even though it never replied to the
ping.  That is how the two mechanisms complement each other.
"""

from __future__ import annotations

import ctypes
import functools
import ipaddress
import locale
import logging
import math
import os
import queue
import re
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .arp import ArpEntry, format_mac_bytes, read_arp_table, vendor_for_mac
from .icmp import IcmpPinger, PingResult

LOGGER = logging.getLogger(__name__)

MAX_HOSTS = 4096
DEFAULT_PREFIX = 24
_MAX_SCAN_SECONDS = 120.0
_CREATE_NO_WINDOW = 0x0800_0000

_AF_INET = 2
_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_SKIP_DNS_SERVER = 0x0008
_GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
_ERROR_BUFFER_OVERFLOW = 111
_IF_OPER_STATUS_UP = 1
_IF_TYPE_ETHERNET = 6
_IF_TYPE_WIFI = 71
_IF_TYPE_LOOPBACK = 24
_MAX_ADAPTER_ADDRESS_LENGTH = 8

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NETBIOS_RE = re.compile(r"^\s*(\S+)\s+<00>\s+UNIQUE", re.IGNORECASE)


class ScanError(RuntimeError):
    """Base class for errors that abort a scan."""


class NetworkDetectionError(ScanError):
    """The local interface or subnet could not be determined."""


class NetworkScopeError(ValueError):
    """The requested CIDR is invalid or too large for this tool."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AdapterInfo:
    """One IPv4 address configured on a local interface."""

    if_index: int
    name: str
    description: str
    ip: str
    prefix_length: int
    gateway: str | None
    mac: str | None
    if_type: int
    is_up: bool


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    """The subnet being scanned and the local context used to reach it."""

    ip_network: ipaddress.IPv4Network
    local_ip: str | None = None
    prefix_length: int | None = None
    gateway: str | None = None
    interface: str = ""
    mac: str | None = None
    source: str = "auto"
    interfaces: tuple[tuple[int, str], ...] = ()


@dataclass(slots=True)
class Host:
    """A device found by ICMP, ARP, or both."""

    ip: str
    mac: str | None = None
    vendor: str = ""
    hostname: str = ""
    netbios: str = ""
    rtt_ms: float | None = None
    state: str = "up"
    interface: str = ""
    gateway: bool = False


@dataclass(slots=True)
class ScanProgress:
    """Live state handed to the display after a batch of probes."""

    scanned: int
    total: int
    hosts: list[Host]
    elapsed_seconds: float
    phase: str = "scanning"


@dataclass(slots=True)
class ScanResult:
    """Final inventory and metadata for one sweep."""

    network: NetworkInfo
    hosts: list[Host]
    started_at: datetime
    finished_at: datetime
    scanned: int
    total: int
    timeout_ms: int
    workers: int
    ping_method: str
    arp_method: str
    arp_before: int
    arp_after: int
    timed_out: bool = False

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    @property
    def icmp_count(self) -> int:
        return sum(1 for host in self.hosts if host.state != "arp-only")

    @property
    def arp_only_count(self) -> int:
        return sum(1 for host in self.hosts if host.state == "arp-only")


# ---------------------------------------------------------------------------
# GetAdaptersAddresses (ctypes)
# ---------------------------------------------------------------------------


class _Sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_char * 14),
    ]


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _SocketAddress(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.POINTER(_Sockaddr)),
        ("iSockaddrLength", ctypes.c_int),
    ]


class _IpAdapterUnicastAddress(ctypes.Structure):
    pass


class _IpAdapterGatewayAddress(ctypes.Structure):
    pass


class _IpAdapterAddresses(ctypes.Structure):
    pass


_IpAdapterUnicastAddress._fields_ = [
    ("Length", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IpAdapterUnicastAddress)),
    ("Address", _SocketAddress),
    ("PrefixOrigin", ctypes.c_uint32),
    ("SuffixOrigin", ctypes.c_uint32),
    ("DadState", ctypes.c_uint32),
    ("ValidLifetime", ctypes.c_uint32),
    ("PreferredLifetime", ctypes.c_uint32),
    ("LeaseLifetime", ctypes.c_uint32),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]

_IpAdapterGatewayAddress._fields_ = [
    ("Length", ctypes.c_uint32),
    ("Reserved", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IpAdapterGatewayAddress)),
    ("Address", _SocketAddress),
]

_IpAdapterAddresses._fields_ = [
    ("Length", ctypes.c_uint32),
    ("IfIndex", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IpAdapterAddresses)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IpAdapterUnicastAddress)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Mtu", ctypes.c_uint32),
    ("IfType", ctypes.c_uint32),
    ("OperStatus", ctypes.c_uint32),
    ("Ipv6IfIndex", ctypes.c_uint32),
    ("ZoneIndices", ctypes.c_uint32 * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_uint64),
    ("ReceiveLinkSpeed", ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(_IpAdapterGatewayAddress)),
]


@functools.lru_cache(maxsize=1)
def _load_adapter_api() -> Any | None:
    """Load and configure ``GetAdaptersAddresses`` once."""
    if os.name != "nt":
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        dll = win_dll("iphlpapi.dll", use_last_error=True)
        function = dll.GetAdaptersAddresses
        function.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        function.restype = ctypes.c_uint32
        return function
    except (AttributeError, OSError) as exc:
        LOGGER.warning("GetAdaptersAddresses unavailable: %s", exc)
        return None


def _sockaddr_to_ipv4(address: _SocketAddress) -> str | None:
    if not address.lpSockaddr or address.iSockaddrLength < ctypes.sizeof(_SockaddrIn):
        return None
    data = ctypes.cast(address.lpSockaddr, ctypes.POINTER(_SockaddrIn)).contents
    if int(data.sin_family) != _AF_INET:
        return None
    packed = struct.pack("<I", int(data.sin_addr))
    try:
        return str(ipaddress.IPv4Address(packed))
    except ipaddress.AddressValueError:
        return None


def _first_gateway(
    pointer: ctypes.POINTER(_IpAdapterGatewayAddress) | None,
) -> str | None:
    node = pointer
    while node:
        entry = node.contents
        ip = _sockaddr_to_ipv4(entry.Address)
        if ip and ip != "0.0.0.0":
            return ip
        node = entry.Next
    return None


def list_ipv4_adapters() -> list[AdapterInfo]:
    """Enumerate local IPv4 interfaces with gateway, MAC and prefix data.

    Uses ``GetAdaptersAddresses`` from iphlpapi.dll.  Returns an empty list
    when the API is unavailable; the caller may then fall back to parsing
    ``ipconfig``.
    """
    api = _load_adapter_api()
    if api is None:
        return []
    flags = (
        _GAA_FLAG_SKIP_ANYCAST
        | _GAA_FLAG_SKIP_MULTICAST
        | _GAA_FLAG_SKIP_DNS_SERVER
        | _GAA_FLAG_INCLUDE_GATEWAYS
    )
    size = ctypes.c_uint32(16 * 1024)
    buffer: ctypes.Array[ctypes.c_char] | None = None
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        result = api(
            _AF_INET,
            flags,
            None,
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(size),
        )
        if result == 0:
            break
        if result != _ERROR_BUFFER_OVERFLOW:
            LOGGER.warning("GetAdaptersAddresses failed (code %d)", result)
            return []
    else:
        LOGGER.warning("GetAdaptersAddresses kept requesting a larger buffer")
        return []
    if buffer is None:  # pragma: no cover - defensive
        return []

    adapters: list[AdapterInfo] = []
    node = ctypes.cast(buffer, ctypes.POINTER(_IpAdapterAddresses))
    while node:
        data = node.contents
        if_index = int(data.IfIndex)
        name = data.FriendlyName or data.Description or f"adapter {if_index}"
        description = data.Description or name
        if_type = int(data.IfType)
        is_up = int(data.OperStatus) == _IF_OPER_STATUS_UP
        length = int(data.PhysicalAddressLength)
        mac = (
            format_mac_bytes(bytes(data.PhysicalAddress[:length]))
            if 0 < length <= _MAX_ADAPTER_ADDRESS_LENGTH
            else None
        )
        gateway = _first_gateway(data.FirstGatewayAddress)

        unicast = data.FirstUnicastAddress
        while unicast:
            entry = unicast.contents
            ip = _sockaddr_to_ipv4(entry.Address)
            if ip and ip != "0.0.0.0":
                adapters.append(
                    AdapterInfo(
                        if_index=if_index,
                        name=name,
                        description=description,
                        ip=ip,
                        prefix_length=int(entry.OnLinkPrefixLength),
                        gateway=gateway,
                        mac=mac,
                        if_type=if_type,
                        is_up=is_up,
                    )
                )
            unicast = entry.Next
        node = data.Next
    return adapters


# ---------------------------------------------------------------------------
# Detection fallbacks and selection
# ---------------------------------------------------------------------------


def _is_netmask(value: str) -> bool:
    try:
        number = int(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return False
    if number == 0:
        return False
    inverted = (~number) & 0xFFFFFFFF
    return (inverted & (inverted + 1)) == 0


def _prefix_from_mask(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _decode_console(data: bytes) -> str:
    for encoding in ("utf-8", locale.getpreferredencoding(False), "mbcs", "cp437"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _detect_via_ipconfig() -> AdapterInfo | None:
    """Parse ``ipconfig`` when the ctypes adapter API is unavailable.

    The parsing is label-agnostic wherever possible: IPv4 addresses and
    netmask-shaped values are enough to recover the local address and
    prefix.  Labels are used only as a hint for the gateway.
    """
    if os.name != "nt":
        return None
    kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "timeout": 10.0,
        "creationflags": _CREATE_NO_WINDOW,
    }
    try:
        completed = subprocess.run(["ipconfig"], **kwargs)  # type: ignore[arg-type]
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.warning("ipconfig fallback failed: %s", exc)
        return None
    if completed.returncode != 0:
        LOGGER.warning("ipconfig exited with code %d", completed.returncode)
        return None
    text = _decode_console(completed.stdout)

    # Adapter sections begin with an unindented header ending in a colon
    # ("Wireless LAN adapter WiFi:"), followed by an optional blank line and
    # indented fields.  Splitting on blank lines would mistake the first
    # field (often the DNS suffix) for the adapter name.
    sections: list[tuple[str, list[str]]] = []
    header = ""
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not line[:1].isspace() and stripped.endswith(":"):
            if header or body:
                sections.append((header, body))
            header = stripped.rstrip(":")
            body = []
        else:
            body.append(line)
    if header or body:
        sections.append((header, body))

    candidates: list[AdapterInfo] = []
    for header, body in sections:
        lines = [line for line in body if line.strip()]
        if not header or not lines:
            continue
        block = "\n".join(body)
        addresses = [addr for addr in _IPV4_RE.findall(block) if addr != "0.0.0.0"]
        if not addresses:
            continue

        local: str | None = None
        prefix: int | None = None
        for address in addresses:
            if _is_netmask(address):
                prefix = _prefix_from_mask(address)
                break
            local = address
        if local is None or prefix is None or local.startswith("169.254."):
            continue

        gateway: str | None = None
        for line in lines:
            lowered = line.lower()
            if any(
                hint in lowered
                for hint in (
                    "gateway",
                    "passerelle",
                    "standardgateway",
                    "puerta de enlace",
                    "网关",
                    "ゲートウェイ",
                )
            ):
                found = [addr for addr in _IPV4_RE.findall(line) if addr != "0.0.0.0"]
                if found:
                    gateway = found[0]
                    break
        if gateway is None:
            seen_mask = False
            for address in addresses:
                if _is_netmask(address):
                    seen_mask = True
                    continue
                if seen_mask and address != local:
                    gateway = address
                    break
        if gateway is not None:
            try:
                if ipaddress.IPv4Address(gateway) not in ipaddress.IPv4Network(
                    f"{local}/{prefix}", strict=False
                ):
                    gateway = None
            except ValueError:
                gateway = None

        candidates.append(
            AdapterInfo(
                if_index=0,
                name=header,
                description=header,
                ip=local,
                prefix_length=prefix,
                gateway=gateway,
                mac=None,
                if_type=0,
                is_up=True,
            )
        )
    if not candidates:
        return None
    return max(candidates, key=_adapter_score)


def _adapter_score(adapter: AdapterInfo) -> tuple[int, int, int, int]:
    try:
        private = int(ipaddress.IPv4Address(adapter.ip).is_private)
    except ipaddress.AddressValueError:
        private = 0
    physical = int(adapter.if_type in (_IF_TYPE_ETHERNET, _IF_TYPE_WIFI))
    return (int(adapter.gateway is not None), physical, private, -adapter.if_index)


def _select_adapter(adapters: list[AdapterInfo]) -> AdapterInfo | None:
    usable = [
        adapter
        for adapter in adapters
        if adapter.is_up
        and adapter.if_type != _IF_TYPE_LOOPBACK
        and adapter.ip
        and not adapter.ip.startswith("127.")
        and not adapter.ip.startswith("169.254.")
    ]
    if not usable:
        return None
    return max(usable, key=_adapter_score)


def detect_network(cidr: str | None = None, *, default_prefix: int = DEFAULT_PREFIX) -> NetworkInfo:
    """Determine the subnet to scan.

    With ``cidr`` the range is taken verbatim (a prefix length is required).
    Otherwise the active adapter with a default gateway is preferred, and
    the scan defaults to a /24 around the local address even when the
    adapter is configured with a larger prefix (for example a /16).
    """
    manual: ipaddress.IPv4Network | None = None
    if cidr is not None:
        if "/" not in cidr:
            raise NetworkScopeError(
                f"--cidr {cidr!r} needs a prefix length, e.g. 192.168.1.0/24"
            )
        try:
            parsed = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise NetworkScopeError(f"invalid --cidr {cidr!r}: {exc}") from exc
        if parsed.version != 4:
            raise NetworkScopeError("only IPv4 ranges are supported")
        if parsed.num_addresses > MAX_HOSTS + 2:
            raise NetworkScopeError(
                f"{parsed} contains {parsed.num_addresses} addresses; "
                f"split it into smaller ranges (at most {MAX_HOSTS} hosts)"
            )
        manual = parsed

    adapters = list_ipv4_adapters()
    selected = _select_adapter(adapters)
    source = "auto"
    if selected is None:
        selected = _detect_via_ipconfig()
        if selected is not None:
            source = "ipconfig"
    interfaces = tuple(
        sorted(
            {
                (adapter.if_index, adapter.name)
                for adapter in adapters
                if adapter.if_index > 0 and adapter.name
            }
        )
    )
    LOGGER.debug("IPv4 adapters: %s", adapters)

    if manual is not None:
        gateway = selected.gateway if selected else None
        if gateway is not None:
            try:
                if ipaddress.IPv4Address(gateway) not in manual:
                    LOGGER.info(
                        "default gateway %s is outside the scanned range %s", gateway, manual
                    )
                    gateway = None
            except ipaddress.AddressValueError:
                gateway = None
        return NetworkInfo(
            ip_network=manual,
            local_ip=selected.ip if selected else None,
            prefix_length=selected.prefix_length if selected else None,
            gateway=gateway,
            interface=selected.name if selected else "",
            mac=selected.mac if selected else None,
            source="manual",
            interfaces=interfaces,
        )

    if selected is None:
        raise NetworkDetectionError(
            "could not determine the local IPv4 network. "
            "Connect to a network or pass --cidr explicitly."
        )

    prefix = max(selected.prefix_length, default_prefix)
    try:
        network = ipaddress.IPv4Network(f"{selected.ip}/{prefix}", strict=False)
    except ValueError as exc:
        raise NetworkDetectionError(
            f"could not build a subnet around {selected.ip}/{prefix}"
        ) from exc
    if network.num_addresses > MAX_HOSTS + 2:
        raise NetworkScopeError(
            f"detected range {network} is too large; pass --cidr with a smaller subnet"
        )
    gateway = selected.gateway
    if gateway is not None:
        try:
            if ipaddress.IPv4Address(gateway) not in network:
                gateway = None
        except ipaddress.AddressValueError:
            gateway = None
    LOGGER.info(
        "scanning %s via %s (%s/%d), gateway %s",
        network,
        selected.name,
        selected.ip,
        selected.prefix_length,
        gateway or "unknown",
    )
    return NetworkInfo(
        ip_network=network,
        local_ip=selected.ip,
        prefix_length=prefix,
        gateway=gateway,
        interface=selected.name,
        mac=selected.mac,
        source=source,
        interfaces=interfaces,
    )


# ---------------------------------------------------------------------------
# Name resolution
# ---------------------------------------------------------------------------


def _reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0].strip().rstrip(".")
    except (OSError, UnicodeError):
        return ""
    if not name or name == ip:
        return ""
    return name


def _netbios_lookup(ip: str) -> str:
    if os.name != "nt":
        return ""
    kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "timeout": 3.0,
        "creationflags": _CREATE_NO_WINDOW,
    }
    try:
        completed = subprocess.run(["nbtstat", "-A", ip], **kwargs)  # type: ignore[arg-type]
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    for line in _decode_console(completed.stdout).splitlines():
        match = _NETBIOS_RE.match(line)
        if match:
            name = match.group(1).strip()
            if name and name != "__MSBROWSE__":
                return name
    return ""


def _parallel_names(
    items: list[str],
    function: Callable[[str], str],
    *,
    workers: int,
    timeout: float,
    label: str,
) -> dict[str, str]:
    """Run lookups on daemon threads, returning whatever finished in time."""
    if not items or timeout <= 0:
        return {}
    results: dict[str, str] = {}
    lock = threading.Lock()
    work: queue.Queue[str] = queue.Queue()
    for item in items:
        work.put(item)

    def worker() -> None:
        while True:
            try:
                item = work.get_nowait()
            except queue.Empty:
                return
            try:
                value = function(item)
            except Exception:  # a resolver must never abort the scan
                LOGGER.debug("%s lookup failed for %s", label, item, exc_info=True)
                value = ""
            with lock:
                results[item] = value

    threads = [
        threading.Thread(
            target=worker,
            name=f"netscan-{label.lower()}-{index}",
            daemon=True,
        )
        for index in range(min(workers, len(items)))
    ]
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.start()
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)
    with lock:
        return dict(results)


def resolve_names(
    ips: list[str],
    *,
    use_dns: bool = True,
    use_netbios: bool = False,
    dns_timeout: float = 3.0,
    netbios_timeout: float = 5.0,
) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve reverse DNS and optional NetBIOS names concurrently.

    ``socket.gethostbyaddr`` has no timeout parameter, so each lookup runs
    on a daemon thread and the aggregate wait is bounded.  A slow resolver
    therefore delays the scan by at most a few seconds, and its threads
    cannot keep the interpreter alive.
    """
    unique = list(dict.fromkeys(ips))
    dns = (
        _parallel_names(unique, _reverse_dns, workers=48, timeout=dns_timeout, label="DNS")
        if use_dns
        else {}
    )
    netbios: dict[str, str] = {}
    if use_netbios:
        missing = [ip for ip in unique if not dns.get(ip)]
        netbios = _parallel_names(
            missing,
            _netbios_lookup,
            workers=16,
            timeout=netbios_timeout,
            label="NetBIOS",
        )
    return dns, netbios


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Run one ICMP + ARP sweep over a :class:`NetworkInfo`."""

    def __init__(
        self,
        network: NetworkInfo,
        *,
        timeout_ms: int = 1000,
        workers: int = 64,
        resolve_names_flag: bool = True,
        netbios: bool = False,
        pinger: IcmpPinger | None = None,
    ) -> None:
        if not 1 <= workers <= 512:
            raise ValueError("workers must be between 1 and 512")
        if not 1 <= timeout_ms <= 60_000:
            raise ValueError("timeout_ms must be between 1 and 60000")
        self.network = network
        self.timeout_ms = timeout_ms
        self.workers = workers
        self.resolve_names_flag = resolve_names_flag
        self.netbios = netbios
        self._pinger = pinger
        self._local_hostname = ""
        try:
            self._local_hostname = socket.gethostname()
        except OSError:
            pass

    def scan(
        self,
        on_progress: Callable[[ScanProgress], None] | None = None,
    ) -> ScanResult:
        """Scan every host address in the configured subnet.

        The sweep is bounded by an internal time budget derived from the
        address count, worker count and per-host timeout, so a filtered or
        unreachable network cannot hang the process indefinitely.
        """
        started_at = datetime.now(timezone.utc)
        start = time.monotonic()
        network = self.network.ip_network
        allowed = {str(address) for address in network.hosts()}
        if len(allowed) > MAX_HOSTS:
            raise NetworkScopeError(
                f"{network} contains more than {MAX_HOSTS} hosts; use a narrower --cidr"
            )
        interfaces = dict(self.network.interfaces)

        arp_before_table = read_arp_table(interfaces)
        arp_before = self._filter_arp(arp_before_table.entries, allowed)
        LOGGER.info(
            "ARP cache before sweep: %d usable entries in %s (method: %s)",
            len(arp_before),
            network,
            arp_before_table.method,
        )

        pinger = self._pinger or IcmpPinger(self.timeout_ms)
        owns_pinger = self._pinger is None
        try:
            ping_method = pinger.method
            ips = sorted(allowed, key=ipaddress.IPv4Address)
            total = len(ips)
            waves = math.ceil(total / self.workers) if total else 0
            budget = min(
                _MAX_SCAN_SECONDS,
                max(30.0, waves * (self.timeout_ms / 1000.0) * 2.0 + 10.0),
            )
            deadline = start + budget
            LOGGER.debug(
                "sweeping %d addresses with %d workers, %.1fs budget",
                total,
                self.workers,
                budget,
            )

            alive: dict[str, PingResult] = {}
            arp_live = arp_before
            scanned = 0
            timed_out = False
            last_emit = 0.0
            last_arp = start

            def snapshot(phase: str) -> ScanProgress:
                return ScanProgress(
                    scanned=scanned,
                    total=total,
                    hosts=self._merge(alive, arp_live, allowed),
                    elapsed_seconds=time.monotonic() - start,
                    phase=phase,
                )

            def emit(phase: str = "scanning") -> None:
                nonlocal last_emit
                if on_progress is not None:
                    try:
                        on_progress(snapshot(phase))
                    except Exception:  # rendering trouble must not stop the scan
                        LOGGER.debug("progress callback failed", exc_info=True)
                last_emit = time.monotonic()

            emit()
            executor = ThreadPoolExecutor(
                max_workers=self.workers, thread_name_prefix="netscan-ping"
            )
            futures = {executor.submit(pinger.ping, ip): ip for ip in ips}
            try:
                for future in as_completed(
                    futures, timeout=max(0.001, deadline - time.monotonic())
                ):
                    ip = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:  # defensive: a worker must not break the scan
                        result = PingResult(ip, False, detail=f"worker error: {exc}")
                    scanned += 1
                    if result.alive:
                        alive[ip] = result
                    now = time.monotonic()
                    if now - last_arp >= 0.45:
                        live_table = read_arp_table(interfaces)
                        if live_table.method != "unavailable":
                            arp_live = self._filter_arp(live_table.entries, allowed)
                        last_arp = now
                    if on_progress is not None and (
                        now - last_emit >= 0.12 or scanned == total
                    ):
                        emit()
            except TimeoutError:
                timed_out = True
                LOGGER.warning(
                    "scan budget of %.0f seconds reached; reporting partial results",
                    budget,
                )
            finally:
                # Always join the workers: an in-flight IcmpSendEcho must
                # finish before its handle can safely be closed.
                executor.shutdown(wait=True, cancel_futures=True)

            after_table = read_arp_table(interfaces)
            if after_table.method == "unavailable":
                arp_after = arp_live
                arp_method = arp_before_table.method
            else:
                arp_after = self._filter_arp(after_table.entries, allowed)
                arp_method = after_table.method
            LOGGER.info(
                "ARP cache after sweep: %d usable entries in %s (method: %s)",
                len(arp_after),
                network,
                arp_method,
            )

            # The cache is refreshed while the sweep runs, but entries seen
            # only in the "before" snapshot are still valid observations.
            arp_combined = dict(arp_before)
            arp_combined.update(arp_after)
            hosts = self._merge(alive, arp_combined, allowed)

            if on_progress is not None and (self.resolve_names_flag or self.netbios):
                try:
                    on_progress(
                        ScanProgress(
                            scanned=scanned,
                            total=total,
                            hosts=hosts,
                            elapsed_seconds=time.monotonic() - start,
                            phase="resolving",
                        )
                    )
                except Exception:
                    LOGGER.debug("progress callback failed", exc_info=True)

            if self.resolve_names_flag or self.netbios:
                targets = [host.ip for host in hosts if host.ip != self.network.local_ip]
                dns_names, netbios_names = resolve_names(
                    targets,
                    use_dns=self.resolve_names_flag,
                    use_netbios=self.netbios,
                )
                for host in hosts:
                    if host.ip in dns_names:
                        host.hostname = dns_names[host.ip]
                    if host.ip in netbios_names:
                        host.netbios = netbios_names[host.ip]

            return ScanResult(
                network=self.network,
                hosts=hosts,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                scanned=scanned,
                total=total,
                timeout_ms=self.timeout_ms,
                workers=self.workers,
                ping_method=ping_method,
                arp_method=arp_method,
                arp_before=len(arp_before),
                arp_after=len(arp_after),
                timed_out=timed_out,
            )
        finally:
            if owns_pinger:
                pinger.close()

    @staticmethod
    def _filter_arp(
        entries: Mapping[str, ArpEntry], allowed: set[str]
    ) -> dict[str, ArpEntry]:
        return {ip: entry for ip, entry in entries.items() if ip in allowed}

    def _merge(
        self,
        ping_results: Mapping[str, PingResult],
        arp_entries: Mapping[str, ArpEntry],
        allowed: set[str],
    ) -> list[Host]:
        """Combine ICMP responses and ARP observations into host records."""
        hosts: dict[str, Host] = {}
        for ip, result in ping_results.items():
            if result.alive:
                hosts[ip] = Host(ip=ip, rtt_ms=result.rtt_ms, state="up")

        for ip, entry in arp_entries.items():
            if ip not in allowed:
                continue
            host = hosts.get(ip)
            if host is None:
                hosts[ip] = Host(
                    ip=ip,
                    mac=entry.mac,
                    vendor=vendor_for_mac(entry.mac),
                    interface=entry.interface,
                    state="arp-only",
                )
            else:
                host.mac = entry.mac
                host.vendor = vendor_for_mac(entry.mac)
                if entry.interface:
                    host.interface = entry.interface

        local_ip = self.network.local_ip
        if local_ip and local_ip in allowed:
            host = hosts.get(local_ip)
            local_mac = self.network.mac
            if host is None:
                hosts[local_ip] = Host(
                    ip=local_ip,
                    mac=local_mac,
                    vendor=vendor_for_mac(local_mac),
                    hostname=self._local_hostname,
                    state="self",
                    interface=self.network.interface,
                )
            else:
                host.state = "self"
                host.hostname = host.hostname or self._local_hostname
                if not host.mac and local_mac:
                    host.mac = local_mac
                    host.vendor = vendor_for_mac(local_mac)
                if self.network.interface:
                    host.interface = self.network.interface

        gateway = self.network.gateway
        for host in hosts.values():
            host.gateway = bool(gateway and host.ip == gateway)
        return sorted(hosts.values(), key=lambda item: ipaddress.IPv4Address(item.ip))


__all__ = [
    "AdapterInfo",
    "Host",
    "MAX_HOSTS",
    "NetworkDetectionError",
    "NetworkInfo",
    "NetworkScopeError",
    "ScanError",
    "ScanProgress",
    "ScanResult",
    "Scanner",
    "detect_network",
    "list_ipv4_adapters",
    "resolve_names",
]
