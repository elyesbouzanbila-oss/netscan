"""ICMP echo probing for the local network scanner.

On Windows the preferred path calls ``IcmpSendEcho`` from ``iphlpapi.dll``
through :mod:`ctypes`.  That needs no administrator rights (unlike raw
sockets) and avoids spawning a ``ping.exe`` process for every address.
If the DLL call cannot be used, the module falls back to the platform's
``ping`` command and still reports a usable result.

Only IPv4 is supported, matching the rest of the tool.
"""

from __future__ import annotations

import atexit
import ctypes
import functools
import ipaddress
import logging
import math
import os
import re
import struct
import subprocess
import threading
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)

_IS_WINDOWS = os.name == "nt"
_CREATE_NO_WINDOW = 0x0800_0000
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_REQUEST_SIZE = 32
_REPLY_BUFFER_SIZE = 512
_PAYLOAD = b"netscan" + b"\x00" * (_REQUEST_SIZE - len(b"netscan"))
_RTT_RE = re.compile(r"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)

# A few ICMP status values returned by IcmpSendEcho.
_STATUS_NAMES = {
    11001: "buffer too small",
    11002: "destination network unreachable",
    11003: "destination host unreachable",
    11004: "destination protocol unreachable",
    11005: "destination port unreachable",
    11006: "no route to destination",
    11007: "bad destination address",
    11008: "bad destination",
    11009: "bad option",
    11010: "request timed out",
    11011: "bad buffer",
    11012: "destination unreachable",
    11013: "time-to-live exceeded",
    11014: "bad TOS",
    11015: "bad IP header",
}


@dataclass(frozen=True, slots=True)
class PingResult:
    """Outcome of one ICMP echo request."""

    ip: str
    alive: bool
    rtt_ms: float | None = None
    detail: str = ""


class _IPOptionInformation(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMPEchoReply(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IPOptionInformation),
    ]


class _WinIcmp:
    """Thin ctypes wrapper around the Windows ICMP helper API."""

    def __init__(self) -> None:
        self.available = False
        self._create = None
        self._close = None
        self._send = None
        if not _IS_WINDOWS:
            return
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return
        try:
            dll = win_dll("iphlpapi.dll", use_last_error=True)
            create = dll.IcmpCreateFile
            create.argtypes = []
            create.restype = ctypes.c_void_p
            close = dll.IcmpCloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            send = dll.IcmpSendEcho
            send.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_ushort,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            send.restype = ctypes.c_uint32

            probe = create()
            if not probe or probe == _INVALID_HANDLE:
                raise OSError("IcmpCreateFile returned an invalid handle")
            close(probe)

            self._create = create
            self._close = close
            self._send = send
            self.available = True
        except (AttributeError, OSError, ValueError) as exc:
            LOGGER.warning("Windows ICMP API unavailable: %s", exc)

    def create_handle(self) -> int | None:
        """Create an ICMP handle for one worker thread."""
        if not self.available or self._create is None:
            return None
        try:
            handle = self._create()
        except OSError as exc:
            LOGGER.warning("IcmpCreateFile failed: %s", exc)
            return None
        if not handle or handle == _INVALID_HANDLE:
            return None
        return int(handle)

    def close_handle(self, handle: int) -> None:
        if not self.available or self._close is None:
            return
        try:
            self._close(ctypes.c_void_p(handle))
        except OSError:  # pragma: no cover - best effort during shutdown
            LOGGER.debug("IcmpCloseHandle failed", exc_info=True)

    def send_echo(self, handle: int, address: int, timeout_ms: int) -> tuple[bool, float | None, str]:
        """Send one echo request and return ``(alive, rtt_ms, detail)``."""
        if self._send is None:
            return False, None, "ICMP API unavailable"
        request = ctypes.create_string_buffer(_PAYLOAD)
        reply = ctypes.create_string_buffer(_REPLY_BUFFER_SIZE)
        try:
            count = self._send(
                ctypes.c_void_p(handle),
                ctypes.c_uint32(address),
                ctypes.cast(request, ctypes.c_void_p),
                _REQUEST_SIZE,
                None,
                ctypes.cast(reply, ctypes.c_void_p),
                _REPLY_BUFFER_SIZE,
                timeout_ms,
            )
        except OSError as exc:
            return False, None, f"IcmpSendEcho failed: {exc}"
        if not count:
            error = ctypes.get_last_error()
            return False, None, _STATUS_NAMES.get(error, f"no reply (error {error})")
        echo = ctypes.cast(reply, ctypes.POINTER(_ICMPEchoReply)).contents
        status = int(echo.Status)
        if status == 0:
            return True, float(echo.RoundTripTime), ""
        return False, None, _STATUS_NAMES.get(status, f"ICMP status {status}")


@functools.lru_cache(maxsize=1)
def _win_icmp() -> _WinIcmp:
    return _WinIcmp()


_HANDLES: set[int] = set()
_HANDLES_LOCK = threading.Lock()


def _register_handle(handle: int) -> None:
    with _HANDLES_LOCK:
        _HANDLES.add(handle)


def _unregister_handle(handle: int) -> None:
    with _HANDLES_LOCK:
        _HANDLES.discard(handle)


def _close_all_handles() -> None:
    with _HANDLES_LOCK:
        handles = list(_HANDLES)
        _HANDLES.clear()
    api = _win_icmp()
    for handle in handles:
        api.close_handle(handle)


atexit.register(_close_all_handles)


class IcmpPinger:
    """Ping IPv4 addresses using the ICMP helper API, or ``ping`` as fallback."""

    def __init__(self, timeout_ms: int = 1000) -> None:
        if not 1 <= timeout_ms <= 60_000:
            raise ValueError("timeout_ms must be between 1 and 60000")
        self.timeout_ms = timeout_ms
        self._api = _win_icmp()
        self.method = "icmp-dll" if self._api.available else "ping"
        self._local = threading.local()
        self._handles: set[int] = set()
        self._handles_lock = threading.Lock()
        LOGGER.debug("ICMP probe method: %s", self.method)

    def ping(self, ip: str) -> PingResult:
        """Probe a single IPv4 address.

        Every failure mode (filtered host, missing DLL, timeout) is returned
        as an unsuccessful :class:`PingResult` instead of an exception.
        """
        try:
            # IcmpSendEcho expects IPAddr in network byte order.  On the
            # little-endian platforms Windows runs on, that is the byte-swapped
            # integer, just as inet_addr() would produce.
            address = struct.unpack("<I", ipaddress.IPv4Address(ip).packed)[0]
        except ipaddress.AddressValueError as exc:
            return PingResult(ip, False, detail=f"invalid address: {exc}")

        if self.method == "icmp-dll":
            handle = self._thread_handle()
            if handle is not None:
                alive, rtt, detail = self._api.send_echo(handle, address, self.timeout_ms)
                return PingResult(ip, alive, rtt, detail)
            # Handle creation can fail when the process is out of resources;
            # fall through to the command based probe for this address.
        return self._ping_command(ip)

    def _thread_handle(self) -> int | None:
        handle = getattr(self._local, "handle", None)
        if handle is not None:
            return handle
        if getattr(self._local, "failed", False):
            return None
        handle = self._api.create_handle()
        if handle is None:
            self._local.failed = True
            LOGGER.warning("Could not create a per-thread ICMP handle; using ping.exe")
            return None
        self._local.handle = handle
        with self._handles_lock:
            self._handles.add(handle)
        _register_handle(handle)
        return handle

    def close(self) -> None:
        """Close every ICMP handle this pinger created.

        Call only after all worker threads have finished.  The process-level
        ``atexit`` hook covers handles whose pinger was never closed.
        """
        with self._handles_lock:
            handles = list(self._handles)
            self._handles.clear()
        for handle in handles:
            self._api.close_handle(handle)
            _unregister_handle(handle)

    def _ping_command(self, ip: str) -> PingResult:
        timeout_s = self.timeout_ms / 1000.0
        if _IS_WINDOWS:
            command = ["ping", "-n", "1", "-w", str(self.timeout_ms), ip]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_s))), ip]
        kwargs: dict[str, object] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": timeout_s + 2.0,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if _IS_WINDOWS:
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        else:
            kwargs["env"] = {**os.environ, "LC_ALL": "C"}
        try:
            completed = subprocess.run(command, **kwargs)  # type: ignore[arg-type]
        except (OSError, subprocess.SubprocessError) as exc:
            return PingResult(ip, False, detail=f"ping command failed: {exc}")
        if completed.returncode != 0:
            return PingResult(ip, False, detail="no reply")
        match = _RTT_RE.search(completed.stdout)
        rtt: float | None = None
        if match:
            try:
                rtt = float(match.group(2).replace(",", "."))
            except ValueError:
                rtt = None
            if rtt is not None and match.group(1) == "<":
                rtt = min(rtt, 0.5)
        return PingResult(ip, True, rtt, "ping command")


__all__ = ["IcmpPinger", "PingResult"]
