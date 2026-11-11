"""Command line interface for netscan."""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

from .display import LiveDisplay
from .scanner import (
    Host,
    NetworkDetectionError,
    NetworkInfo,
    NetworkScopeError,
    ScanResult,
    Scanner,
    detect_network,
)

LOGGER = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_NETWORK = 1
EXIT_USAGE = 2

_LEGAL_NOTICE = (
    "netscan: authorized use only - scan networks you own or have explicit "
    "permission to audit."
)
_UNSUPPORTED_PLATFORM = (
    "netscan: unsupported platform. This tool requires Windows 10 or 11 for "
    "its ICMP/ARP APIs and NetBIOS support. No scan was performed."
)
_CSV_FIELDS = (
    "ip",
    "mac",
    "vendor",
    "hostname",
    "netbios",
    "rtt_ms",
    "state",
    "interface",
    "gateway",
)


def _timeout_ms(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer (milliseconds)") from exc
    if not 50 <= number <= 10_000:
        raise argparse.ArgumentTypeError("timeout must be between 50 and 10000 ms")
    return number


def _workers(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be an integer") from exc
    if not 1 <= number <= 512:
        raise argparse.ArgumentTypeError("workers must be between 1 and 512")
    return number


def _watch_interval(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("watch interval must be a number of seconds") from exc
    if not 1.0 <= number <= 86_400.0:
        raise argparse.ArgumentTypeError("watch interval must be between 1 and 86400 seconds")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser (exposed for tests and documentation)."""
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=(
            "Map active devices on a local IPv4 subnet by combining an ICMP "
            "sweep with ARP cache inspection. No administrator rights required."
        ),
        epilog=(
            "Examples:\n"
            "  netscan --cidr 192.168.1.0/24\n"
            "  netscan --watch 30 --csv inventory.csv --json inventory.json\n\n"
            "Exit codes: 0 success, 1 network/runtime error, 2 bad usage."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cidr",
        metavar="CIDR",
        help="IPv4 subnet to scan, e.g. 192.168.1.0/24 (default: auto-detect, /24).",
    )
    parser.add_argument(
        "--timeout",
        metavar="MS",
        type=_timeout_ms,
        default=1000,
        help="ICMP timeout per host in milliseconds (default: 1000).",
    )
    parser.add_argument(
        "--workers",
        metavar="N",
        type=_workers,
        default=64,
        help="concurrent ping workers (default: 64).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="skip reverse DNS hostname lookups.",
    )
    parser.add_argument(
        "--netbios",
        action="store_true",
        help="also query NetBIOS names with nbtstat -A.",
    )
    parser.add_argument(
        "--watch",
        metavar="SECONDS",
        type=_watch_interval,
        help="rescan every N seconds and report appeared/disappeared devices.",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="write the final inventory to a CSV file.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="write the final inventory to a JSON file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log detection and scan details to stderr.",
    )
    return parser


def _configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )


def _scan(network: NetworkInfo, args: argparse.Namespace, display: LiveDisplay) -> ScanResult:
    scanner = Scanner(
        network,
        timeout_ms=args.timeout,
        workers=args.workers,
        resolve_names_flag=not args.no_resolve,
        netbios=args.netbios,
    )
    return scanner.scan(on_progress=display.update)


def _run_once(args: argparse.Namespace) -> int:
    network = detect_network(args.cidr)
    display = LiveDisplay()
    try:
        display.start(network)
        result = _scan(network, args, display)
    finally:
        display.finish()
    display.print_inventory(result)
    _save_exports(result, args)
    return EXIT_OK


def _run_watch(args: argparse.Namespace) -> int:
    assert args.watch is not None
    display = LiveDisplay()
    previous: dict[str, Host] | None = None
    cycle = 0
    while True:
        cycle += 1
        try:
            network = detect_network(args.cidr)
            display.start(network, watch_cycle=cycle)
            try:
                result = _scan(network, args, display)
            finally:
                display.finish()
        except NetworkDetectionError as exc:
            display.finish()
            print(
                f"netscan: scan #{cycle} failed: {exc}; retrying in {args.watch:g}s",
                file=sys.stderr,
            )
            time.sleep(args.watch)
            continue

        current = {host.ip: host for host in result.hosts}
        if previous is not None:
            new_hosts = [host for ip, host in current.items() if ip not in previous]
            gone_hosts = [host for ip, host in previous.items() if ip not in current]
            display.print_diff(new_hosts, gone_hosts)
            for host in new_hosts:
                LOGGER.warning(
                    "new device (verify it is authorized): %s %s %s",
                    host.ip,
                    host.mac or "-",
                    host.vendor,
                )
            for host in gone_hosts:
                LOGGER.info("device disappeared: %s", host.ip)
        display.print_inventory(result)
        _save_exports(result, args)
        previous = current
        print(
            f"netscan: next scan in {args.watch:g}s (Ctrl+C to stop).",
            file=sys.stderr,
        )
        time.sleep(args.watch)


def _save_exports(result: ScanResult, args: argparse.Namespace) -> None:
    if args.csv:
        _write_atomic(args.csv, _csv_text(result))
        print(
            f"netscan: wrote {args.csv} ({len(result.hosts)} hosts)",
            file=sys.stderr,
        )
    if args.json:
        _write_atomic(args.json, _json_text(result))
        print(
            f"netscan: wrote {args.json} ({len(result.hosts)} hosts)",
            file=sys.stderr,
        )


def _csv_text(result: ScanResult) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_CSV_FIELDS)
    for host in result.hosts:
        writer.writerow(
            [
                host.ip,
                host.mac or "",
                host.vendor,
                host.hostname,
                host.netbios,
                "" if host.rtt_ms is None else round(host.rtt_ms, 3),
                host.state,
                host.interface,
                "true" if host.gateway else "false",
            ]
        )
    return buffer.getvalue()


def _json_text(result: ScanResult) -> str:
    network = result.network
    payload = {
        "tool": "netscan",
        "scanned_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": round(result.duration_seconds, 3),
        "network": {
            "cidr": str(network.ip_network),
            "local_ip": network.local_ip,
            "prefix_length": network.prefix_length,
            "gateway": network.gateway,
            "interface": network.interface,
            "source": network.source,
        },
        "scan": {
            "timeout_ms": result.timeout_ms,
            "workers": result.workers,
            "scanned": result.scanned,
            "total": result.total,
            "ping_method": result.ping_method,
            "arp_method": result.arp_method,
            "arp_entries_before": result.arp_before,
            "arp_entries_after": result.arp_after,
            "timed_out": result.timed_out,
        },
        "summary": {
            "active": len(result.hosts),
            "responding": result.icmp_count,
            "arp_only": result.arp_only_count,
        },
        "hosts": [
            {
                "ip": host.ip,
                "mac": host.mac,
                "vendor": host.vendor,
                "hostname": host.hostname,
                "netbios": host.netbios,
                "rtt_ms": host.rtt_ms,
                "state": host.state,
                "interface": host.interface,
                "gateway": host.gateway,
            }
            for host in result.hosts
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _write_atomic(path: str, text: str) -> None:
    """Write a file via a temporary sibling so a failure leaves no partial file."""
    target = Path(path).expanduser()
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.exists():
        raise OSError(f"output directory does not exist: {parent}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``netscan`` / ``random-bs``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_streams()
    _configure_logging(args.verbose)
    print(_LEGAL_NOTICE, file=sys.stderr)

    if os.name != "nt":
        print(_UNSUPPORTED_PLATFORM, file=sys.stderr)
        return EXIT_NETWORK
    try:
        if args.watch is not None:
            return _run_watch(args)
        return _run_once(args)
    except KeyboardInterrupt:
        print("\nnetscan: interrupted by user.", file=sys.stderr)
        return EXIT_OK
    except NetworkScopeError as exc:
        print(f"netscan: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except NetworkDetectionError as exc:
        print(f"netscan: {exc}", file=sys.stderr)
        return EXIT_NETWORK
    except OSError as exc:
        LOGGER.debug("I/O failure", exc_info=True)
        print(f"netscan: I/O error: {exc}", file=sys.stderr)
        return EXIT_NETWORK
    except Exception as exc:  # keep the CLI from dumping a traceback by default
        LOGGER.debug("unexpected failure", exc_info=True)
        print(f"netscan: error: {exc}", file=sys.stderr)
        return EXIT_NETWORK


if __name__ == "__main__":
    raise SystemExit(main())
