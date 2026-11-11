"""Terminal presentation for the scanner.

Interactive terminals get a live, ANSI-updated table while the sweep runs;
pipes and files get one line per discovered host followed by the final
inventory.  All table output is ASCII so it works with redirected streams
and legacy console code pages.
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import sys
from datetime import datetime
from typing import TextIO

from .scanner import Host, NetworkInfo, ScanProgress, ScanResult

LOGGER = logging.getLogger(__name__)

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_CYAN = "\x1b[36m"

_HEADERS = ("IP", "MAC", "Vendor", "Hostname", "RTT", "State")
_CAPS = (17, 17, 20, 30, 8, 9)
_MINS = (15, 17, 6, 8, 5, 9)
_STATE_LABELS = {"up": "up", "self": "self", "arp-only": "ARP only"}
_STATE_COLORS = {"up": (_GREEN,), "self": (_CYAN,), "arp-only": (_YELLOW,)}


class Style:
    """Apply ANSI attributes only when color output is enabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def apply(self, text: str, *codes: str) -> str:
        if not self.enabled or not text or not codes:
            return text
        return f"{''.join(codes)}{text}{_RESET}"


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _enable_windows_ansi() -> bool:
    """Turn on virtual-terminal processing for the Windows console."""
    if os.name != "nt":
        return True
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return False
    try:
        kernel32 = win_dll("kernel32.dll", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [ctypes.c_int32]
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetConsoleMode.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel32.GetConsoleMode.restype = ctypes.c_int
        kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.SetConsoleMode.restype = ctypes.c_int

        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if not handle or handle == ctypes.c_void_p(-1).value:
            return False
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except (AttributeError, OSError):
        return False


def _fit(text: str, width: int) -> str:
    if width <= 0 or len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 2] + ".."


def _safe_text(text: str) -> str:
    """Keep network-supplied names from injecting terminal control codes."""
    return "".join(char if char.isprintable() else "?" for char in text)


def _format_rtt(rtt: float | None) -> str:
    if rtt is None:
        return "-"
    if rtt < 1:
        return "<1 ms"
    if rtt < 10:
        return f"{rtt:.1f} ms"
    return f"{rtt:.0f} ms"


def _state_label(state: str) -> str:
    return _STATE_LABELS.get(state, state)


def _format_elapsed(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    return f"{minutes}m{int(seconds % 60):02d}s"


def render_inventory(
    hosts: list[Host], style: Style, max_width: int = 110
) -> list[str]:
    """Render the inventory rows as an ASCII table."""
    rows: list[list[str]] = []
    for host in hosts:
        ip_text = host.ip + (" *" if host.gateway else "")
        name = _safe_text(host.hostname or host.netbios or "-")
        rows.append(
            [
                ip_text,
                host.mac or "-",
                host.vendor or "-",
                name,
                _format_rtt(host.rtt_ms),
                _state_label(host.state),
            ]
        )

    widths: list[int] = []
    for index, header in enumerate(_HEADERS):
        natural = max([len(header)] + [len(row[index]) for row in rows])
        widths.append(max(_MINS[index], min(_CAPS[index], natural)))

    total = sum(widths) + 3 * len(widths) + 1
    while total > max_width:
        adjustable = [
            (widths[index] - _MINS[index], index) for index in (3, 2)
        ]
        adjustable = [item for item in adjustable if item[0] > 0]
        if not adjustable:
            break
        _, index = max(adjustable)
        widths[index] -= 1
        total -= 1

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def make_row(cells: list[str], *, align_right: int | None = None) -> str:
        rendered: list[str] = []
        for index, cell in enumerate(cells):
            fitted = _fit(cell, widths[index])
            if align_right == index:
                rendered.append(f" {fitted:>{widths[index]}} ")
            else:
                rendered.append(f" {fitted:<{widths[index]}} ")
        return "|" + "|".join(rendered) + "|"

    header = make_row(list(_HEADERS))
    lines = [border, style.apply(header, _BOLD), border]

    for host, row in zip(hosts, rows):
        line_cells = list(row)
        state_text = f" {_fit(line_cells[5], widths[5]):<{widths[5]}} "
        state_text = style.apply(state_text, *_STATE_COLORS.get(host.state, ()))
        line = make_row(line_cells, align_right=4)
        # Replace the plain state cell with its coloured equivalent.
        plain_state = f" {_fit(row[5], widths[5]):<{widths[5]}} "
        if state_text != plain_state:
            line = line[: line.rfind(plain_state)] + state_text + "|"
        lines.append(line)

    if rows:
        lines.append(border)
    return lines


class LiveDisplay:
    """Render scan progress, the live table and final reports."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stdout
        is_tty = _is_tty(self.stream)
        ansi = _enable_windows_ansi() if is_tty else False
        try:
            size = os.get_terminal_size(self.stream.fileno())
        except (OSError, ValueError, AttributeError):
            size = shutil.get_terminal_size(fallback=(110, 30))
        self.width = max(60, size.columns)
        self.height = max(15, size.lines)
        self.tty = is_tty and ansi and self.width >= 80
        no_color = "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb"
        self.style = Style(self.tty and not no_color)
        self._network: NetworkInfo | None = None
        self._progress: ScanProgress | None = None
        self._rendered_lines = 0
        self._seen: set[str] = set()
        self._cycle: int | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self, network: NetworkInfo, *, watch_cycle: int | None = None) -> None:
        """Start a display cycle for one scan."""
        self._network = network
        self._cycle = watch_cycle
        if self.tty:
            self._render()
        elif watch_cycle is not None:
            stamp = datetime.now().strftime("%H:%M:%S")
            self.stream.write(f"\n--- scan #{watch_cycle} at {stamp} ---\n")
            self.stream.flush()

    def update(self, progress: ScanProgress) -> None:
        """Consume live scan state."""
        self._progress = progress
        if self.tty:
            self._render()
            return
        # The initial snapshot contains cached ARP rows whose ICMP probes have
        # not run yet; printing those as "ARP only" would be misleading.  Only
        # emit hosts whose ICMP (or self) status is already known, and leave
        # ARP-only devices to the final inventory table.
        if progress.scanned == 0 and progress.phase == "scanning":
            return
        for host in progress.hosts:
            if host.state == "arp-only" or host.ip in self._seen:
                continue
            self._seen.add(host.ip)
            self.stream.write(self._discovery_line(host) + "\n")
        self.stream.flush()

    def finish(self) -> None:
        """Clear the live area, leaving the cursor where it started."""
        if self.tty and self._rendered_lines:
            self.stream.write(f"\x1b[{self._rendered_lines}A\x1b[J")
            self.stream.flush()
        self._rendered_lines = 0

    # -- live rendering ----------------------------------------------------

    def _render(self) -> None:
        if self._network is None:
            return
        lines = self._compose()
        if self._rendered_lines:
            self.stream.write(f"\x1b[{self._rendered_lines}A")
        self.stream.write("\x1b[J")
        for line in lines:
            self.stream.write(line + "\n")
        self.stream.flush()
        self._rendered_lines = len(lines)

    def _compose(self) -> list[str]:
        assert self._network is not None
        network = self._network
        progress = self._progress
        if self._cycle is None:
            title = f"netscan  {network.ip_network}"
        else:
            title = (
                f"scan #{self._cycle}  {datetime.now():%H:%M:%S}  {network.ip_network}"
            )
        if network.local_ip:
            if network.prefix_length:
                title += f"   local {network.local_ip}/{network.prefix_length}"
            else:
                title += f"   local {network.local_ip}"
        lines = [self.style.apply(_fit(title, self.width), _BOLD)]

        if progress is not None:
            lines.append(self.style.apply(_fit(self._progress_line(progress), self.width), _DIM))
            max_rows = max(1, self.height - 7)
            shown = progress.hosts[:max_rows]
            lines.extend(render_inventory(shown, self.style, self.width))
            if len(progress.hosts) > len(shown):
                lines.append(
                    f"  ... {len(progress.hosts) - len(shown)} more host(s); "
                    "the final table lists all."
                )
        return lines[: self.height]

    def _progress_line(self, progress: ScanProgress) -> str:
        if progress.phase == "resolving":
            return (
                f"Resolving names...  {progress.scanned}/{progress.total} scanned  "
                f"{len(progress.hosts)} found  {_format_elapsed(progress.elapsed_seconds)}"
            )
        ratio = progress.scanned / progress.total if progress.total else 1.0
        width = 20
        filled = max(0, min(width, int(ratio * width)))
        bar = "#" * filled + "-" * (width - filled)
        return (
            f"[{bar}] {progress.scanned}/{progress.total}  "
            f"{len(progress.hosts)} found  {_format_elapsed(progress.elapsed_seconds)}"
        )

    @staticmethod
    def _discovery_line(host: Host) -> str:
        name = _safe_text(host.hostname or host.netbios)
        fields = [
            f"+ {host.ip:<15}",
            f"{host.mac or '-':<17}",
            f"{_state_label(host.state):<8}",
            f"{_format_rtt(host.rtt_ms):>7}",
        ]
        if host.vendor:
            fields.append(host.vendor)
        if name:
            fields.append(name)
        return "  ".join(fields)

    # -- reports -----------------------------------------------------------

    def print_inventory(self, result: ScanResult) -> None:
        """Print the complete final inventory and a short summary."""
        self.finish()
        network = result.network
        stamp = result.finished_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        title = (
            f"Inventory: {network.ip_network}  "
            f"({len(result.hosts)} active, {stamp})"
        )
        title_width = self.width if self.tty else max(self.width, 110)
        self.stream.write("\n" + self.style.apply(_fit(title, title_width), _BOLD) + "\n")
        max_width = title_width
        for line in render_inventory(result.hosts, self.style, max_width):
            self.stream.write(line + "\n")

        local = network.local_ip or "unknown"
        if network.local_ip and network.prefix_length:
            local = f"{network.local_ip}/{network.prefix_length}"
        interface = network.interface or "unknown interface"
        gateway = network.gateway or "not detected"
        summary = (
            f"{len(result.hosts)} active: {result.icmp_count} responding, "
            f"{result.arp_only_count} ARP only (ICMP filtered)."
        )
        self.stream.write(self.style.apply(summary, _BOLD) + "\n")
        self.stream.write(f"Local {local} on {interface} | gateway {gateway}\n")
        self.stream.write(
            f"Scanned {result.scanned}/{result.total} addresses in "
            f"{result.duration_seconds:.1f}s | ping: {result.ping_method} | "
            f"arp: {result.arp_method}\n"
        )
        if any(host.gateway for host in result.hosts):
            self.stream.write("  * default gateway\n")
        if result.timed_out:
            self.stream.write(
                self.style.apply(
                    "Note: the scan reached its time budget; results may be incomplete.",
                    _YELLOW,
                )
                + "\n"
            )
        self.stream.flush()

    def print_diff(self, new_hosts: list[Host], gone_hosts: list[Host]) -> None:
        """Report devices that appeared or disappeared between scans."""
        self.finish()
        if not new_hosts and not gone_hosts:
            self.stream.write(
                self.style.apply("No changes since the previous scan.", _DIM) + "\n"
            )
            self.stream.flush()
            return
        self.stream.write("\n" + self.style.apply("Changes since the previous scan:", _BOLD) + "\n")
        for host in new_hosts:
            label = self.style.apply("NEW ", _BOLD, _RED)
            detail = self._diff_detail(host)
            self.stream.write(f"  {label} {detail}\n")
        for host in gone_hosts:
            label = self.style.apply("GONE", _YELLOW)
            detail = self._diff_detail(host)
            self.stream.write(f"  {label} {detail}\n")
        self.stream.flush()

    @staticmethod
    def _diff_detail(host: Host) -> str:
        bits = [f"{host.ip:<15}", f"{host.mac or '-':<17}"]
        name = _safe_text(host.hostname or host.netbios)
        if host.vendor:
            bits.append(host.vendor)
        if name:
            bits.append(name)
        return "  ".join(bits).rstrip()


__all__ = ["LiveDisplay", "Style", "render_inventory"]
