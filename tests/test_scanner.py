"""Tests for scanner logic that does not touch the network."""

from __future__ import annotations

import ipaddress
import unittest
from unittest.mock import patch

from random_bs import scanner as scanner_module
from random_bs.arp import ArpEntry
from random_bs.icmp import PingResult
from random_bs.scanner import (
    NetworkInfo,
    NetworkScopeError,
    Scanner,
    _is_netmask,
    _prefix_from_mask,
    detect_network,
)


class NetmaskTests(unittest.TestCase):
    def test_accepts_contiguous_masks(self) -> None:
        for mask in ("255.255.255.0", "255.255.0.0", "255.255.255.128", "255.255.255.192"):
            with self.subTest(mask=mask):
                self.assertTrue(_is_netmask(mask))

    def test_rejects_invalid_masks(self) -> None:
        for mask in ("0.0.0.0", "255.0.255.0", "255.255.255.1", "255.255.255.256", "not-a-mask"):
            with self.subTest(mask=mask):
                self.assertFalse(_is_netmask(mask))

    def test_prefix_from_mask(self) -> None:
        self.assertEqual(_prefix_from_mask("255.255.255.0"), 24)
        self.assertEqual(_prefix_from_mask("255.255.255.128"), 25)
        self.assertEqual(_prefix_from_mask("255.255.0.0"), 16)
        self.assertIsNone(_prefix_from_mask("255.0.255.0"))
        self.assertIsNone(_prefix_from_mask("not-a-mask"))


class DetectNetworkTests(unittest.TestCase):
    def test_manual_cidr_is_normalized_without_an_adapter(self) -> None:
        with (
            patch.object(scanner_module, "list_ipv4_adapters", return_value=[]),
            patch.object(scanner_module, "_detect_via_ipconfig", return_value=None),
        ):
            info = detect_network("192.168.1.42/24")

        self.assertEqual(info.ip_network, ipaddress.IPv4Network("192.168.1.0/24"))
        self.assertEqual(info.source, "manual")
        self.assertIsNone(info.local_ip)
        self.assertIsNone(info.gateway)

    def test_missing_prefix_is_rejected(self) -> None:
        with self.assertRaisesRegex(NetworkScopeError, "prefix length"):
            detect_network("192.168.1.0")

    def test_oversized_range_is_rejected(self) -> None:
        with self.assertRaises(NetworkScopeError):
            detect_network("10.0.0.0/8")

    def test_ipv6_is_rejected(self) -> None:
        with self.assertRaisesRegex(NetworkScopeError, "IPv4"):
            detect_network("2001:db8::/64")


class _PingerStub:
    """The merge tests must never perform a real ping."""

    method = "stub"

    def ping(self, ip: str) -> PingResult:
        raise AssertionError(f"_merge must not ping {ip}")

    def close(self) -> None:
        pass


class MergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = NetworkInfo(
            ip_network=ipaddress.IPv4Network("192.168.1.0/24"),
            local_ip="192.168.1.10",
            prefix_length=24,
            gateway="192.168.1.1",
            interface="WiFi",
            mac="8C:8B:5B:42:B1:53",
        )
        self.scanner = Scanner(self.network, pinger=_PingerStub())

    def test_merge_combines_sources_and_forces_local_self(self) -> None:
        pings = {
            "192.168.1.20": PingResult("192.168.1.20", True, 4.5),
            "192.168.1.10": PingResult("192.168.1.10", True, 0.5),
            "192.168.1.3": PingResult("192.168.1.3", True, 2.0),
        }
        arp_entries = {
            "192.168.1.20": ArpEntry("192.168.1.20", "B8:27:EB:11:22:33", "WiFi"),
            "192.168.1.30": ArpEntry("192.168.1.30", "76:8A:54:7C:7C:B0", "WiFi"),
            "192.168.1.1": ArpEntry("192.168.1.1", "F0:D4:15:6C:9B:D4", "WiFi"),
            "192.168.1.10": ArpEntry("192.168.1.10", "8C:8B:5B:42:B1:53", "WiFi"),
            "192.168.1.250": ArpEntry("192.168.1.250", "AA:BB:CC:DD:EE:FF", "WiFi"),
        }
        allowed = {
            "192.168.1.1",
            "192.168.1.3",
            "192.168.1.10",
            "192.168.1.20",
            "192.168.1.30",
        }

        hosts = self.scanner._merge(pings, arp_entries, allowed)
        by_ip = {host.ip: host for host in hosts}

        self.assertEqual(
            [host.ip for host in hosts],
            [
                "192.168.1.1",
                "192.168.1.3",
                "192.168.1.10",
                "192.168.1.20",
                "192.168.1.30",
            ],
        )
        self.assertNotIn("192.168.1.250", by_ip)

        self.assertEqual(by_ip["192.168.1.20"].state, "up")
        self.assertEqual(by_ip["192.168.1.20"].rtt_ms, 4.5)
        self.assertEqual(by_ip["192.168.1.20"].mac, "B8:27:EB:11:22:33")
        self.assertEqual(by_ip["192.168.1.20"].vendor, "Raspberry Pi")

        self.assertEqual(by_ip["192.168.1.30"].state, "arp-only")
        self.assertIsNone(by_ip["192.168.1.30"].rtt_ms)
        self.assertEqual(by_ip["192.168.1.30"].vendor, "randomized")

        self.assertEqual(by_ip["192.168.1.10"].state, "self")
        self.assertEqual(by_ip["192.168.1.10"].hostname, self.scanner._local_hostname)

        self.assertTrue(by_ip["192.168.1.1"].gateway)
        self.assertEqual(by_ip["192.168.1.1"].vendor, "Intel")
        self.assertEqual(
            [host.ip for host in hosts if host.gateway],
            ["192.168.1.1"],
        )

    def test_local_host_is_added_when_sources_do_not_report_it(self) -> None:
        hosts = self.scanner._merge({}, {}, {"192.168.1.10"})

        self.assertEqual([host.ip for host in hosts], ["192.168.1.10"])
        self.assertEqual(hosts[0].state, "self")
        self.assertEqual(hosts[0].mac, self.network.mac)
        self.assertEqual(hosts[0].vendor, "WNC Corporation")


if __name__ == "__main__":
    unittest.main()
