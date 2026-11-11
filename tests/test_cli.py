"""Tests for CLI parsing, export formatting, and atomic writes."""

from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from random_bs import cli
from random_bs.scanner import Host, NetworkInfo, ScanResult


def _fabricated_result() -> ScanResult:
    network = NetworkInfo(
        ip_network=ipaddress.IPv4Network("192.168.1.0/24"),
        local_ip="192.168.1.10",
        prefix_length=24,
        gateway="192.168.1.1",
        interface="WiFi",
        mac="8C:8B:5B:42:B1:53",
        source="manual",
    )
    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    hosts = [
        Host(
            ip="192.168.1.1",
            mac="F0:D4:15:6C:9B:D4",
            hostname="router",
            rtt_ms=1.23456,
            state="up",
            interface="WiFi",
            gateway=True,
        ),
        Host(
            ip="192.168.1.30",
            mac="76:8A:54:7C:7C:B0",
            vendor="randomized",
            netbios="PHONE",
            state="arp-only",
            interface="WiFi",
        ),
        Host(
            ip="192.168.1.10",
            mac="8C:8B:5B:42:B1:53",
            hostname="workstation",
            rtt_ms=0.4,
            state="self",
            interface="WiFi",
        ),
    ]
    return ScanResult(
        network=network,
        hosts=hosts,
        started_at=started,
        finished_at=started + timedelta(seconds=2.5),
        scanned=254,
        total=254,
        timeout_ms=1000,
        workers=64,
        ping_method="icmp-dll",
        arp_method="iphlpapi",
        arp_before=3,
        arp_after=4,
    )


class ParserTests(unittest.TestCase):
    def _assert_rejected(self, argv: list[str]) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.build_parser().parse_args(argv)
        self.assertEqual(caught.exception.code, 2)

    def test_accepts_documented_flags(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "--cidr",
                "192.168.1.0/24",
                "--timeout",
                "50",
                "--workers",
                "1",
                "--no-resolve",
                "--netbios",
                "--watch",
                "1",
                "--csv",
                "inventory.csv",
                "--json",
                "inventory.json",
                "--verbose",
            ]
        )
        self.assertEqual(args.cidr, "192.168.1.0/24")
        self.assertEqual(args.timeout, 50)
        self.assertEqual(args.workers, 1)
        self.assertTrue(args.no_resolve)
        self.assertTrue(args.netbios)
        self.assertEqual(args.watch, 1.0)
        self.assertEqual(args.csv, "inventory.csv")
        self.assertEqual(args.json, "inventory.json")
        self.assertTrue(args.verbose)

    def test_rejects_out_of_range_timeouts(self) -> None:
        for value in ("49", "10001"):
            with self.subTest(value=value):
                self._assert_rejected(["--timeout", value])

    def test_rejects_out_of_range_workers(self) -> None:
        for value in ("0", "513"):
            with self.subTest(value=value):
                self._assert_rejected(["--workers", value])

    def test_rejects_short_watch_interval(self) -> None:
        self._assert_rejected(["--watch", "0.5"])

    def test_rejects_unknown_flag(self) -> None:
        self._assert_rejected(["--not-a-real-option"])


class ExportTests(unittest.TestCase):
    def test_csv_header_and_rows(self) -> None:
        text = cli._csv_text(_fabricated_result())
        rows = list(csv.reader(io.StringIO(text)))

        self.assertEqual(
            rows[0],
            [
                "ip",
                "mac",
                "vendor",
                "hostname",
                "netbios",
                "rtt_ms",
                "state",
                "interface",
                "gateway",
            ],
        )
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[1][0], "192.168.1.1")
        self.assertEqual(rows[1][5], "1.235")
        self.assertEqual(rows[1][8], "true")
        self.assertEqual(rows[2][2], "randomized")
        self.assertEqual(rows[2][5], "")

    def test_json_round_trips_and_preserves_content(self) -> None:
        payload = json.loads(cli._json_text(_fabricated_result()))

        self.assertEqual(payload["network"]["cidr"], "192.168.1.0/24")
        self.assertEqual(payload["summary"]["active"], 3)
        self.assertEqual(payload["summary"]["responding"], 2)
        self.assertEqual(payload["summary"]["arp_only"], 1)
        self.assertEqual(payload["hosts"][1]["vendor"], "randomized")
        self.assertEqual(payload["hosts"][2]["state"], "self")


class AtomicWriteTests(unittest.TestCase):
    def test_creates_file_and_leaves_no_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "inventory.csv")
            cli._write_atomic(target, "hello\n")

            self.assertEqual(Path(target).read_text(encoding="utf-8"), "hello\n")
            self.assertEqual(os.listdir(directory), ["inventory.csv"])

    def test_cleans_up_temporary_on_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "inventory.csv")
            with patch.object(cli.os, "replace", side_effect=OSError("simulated failure")):
                with self.assertRaises(OSError):
                    cli._write_atomic(target, "partial data")

            self.assertFalse(os.path.exists(target))
            self.assertEqual(os.listdir(directory), [])


if __name__ == "__main__":
    unittest.main()
