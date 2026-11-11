"""Tests for MAC helpers and the built-in vendor table (no network access)."""

from __future__ import annotations

import unittest

from random_bs.arp import (
    _is_unicast_ip,
    _is_usable_mac,
    _supplemental_oui_vendors,
    format_mac_bytes,
    is_locally_administered,
    normalize_mac,
    vendor_for_mac,
)


class MacFormattingTests(unittest.TestCase):
    def test_format_mac_bytes_six(self) -> None:
        self.assertEqual(
            format_mac_bytes(bytes.fromhex("b827eb112233")),
            "B8:27:EB:11:22:33",
        )

    def test_format_mac_bytes_eight(self) -> None:
        self.assertEqual(
            format_mac_bytes(bytes.fromhex("0011223344556677")),
            "00:11:22:33:44:55:66:77",
        )

    def test_format_mac_bytes_rejects_unsupported_lengths(self) -> None:
        for length in (0, 1, 5, 7, 9):
            with self.subTest(length=length):
                self.assertIsNone(format_mac_bytes(b"\x00" * length))

    def test_normalize_accepts_common_separators(self) -> None:
        expected = "B8:27:EB:11:22:33"
        for text in (
            "B8:27:EB:11:22:33",
            "b8-27-eb-11-22-33",
            "b827.eb11.2233",
            "B827EB112233",
        ):
            with self.subTest(text=text):
                self.assertEqual(normalize_mac(text), expected)

    def test_normalize_rejects_incomplete_or_non_hex(self) -> None:
        for text in ("", "00:11:22:33:44", "00:11:22:33:44:5", "not-a-mac"):
            with self.subTest(text=text):
                self.assertIsNone(normalize_mac(text))


class MacValidityTests(unittest.TestCase):
    def test_rejects_broadcast_zero_and_multicast(self) -> None:
        for mac in (
            "FF:FF:FF:FF:FF:FF",
            "00:00:00:00:00:00",
            "01:00:5E:00:00:01",
            "33:33:00:00:00:01",
        ):
            with self.subTest(mac=mac):
                self.assertFalse(_is_usable_mac(mac))

    def test_accepts_global_and_local_unicast(self) -> None:
        for mac in (
            "B8:27:EB:11:22:33",
            "76:8A:54:7C:7C:B0",
            "A2:9F:7A:6D:2D:C0",
        ):
            with self.subTest(mac=mac):
                self.assertTrue(_is_usable_mac(mac))

    def test_rejects_malformed_values(self) -> None:
        for mac in ("", "not-a-mac", "GG:27:EB:11:22:33"):
            with self.subTest(mac=mac):
                self.assertFalse(_is_usable_mac(mac))


class UnicastIpTests(unittest.TestCase):
    def test_rejects_reserved_and_multicast(self) -> None:
        for ip in ("0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.250"):
            with self.subTest(ip=ip):
                self.assertFalse(_is_unicast_ip(ip))

    def test_accepts_ordinary_hosts(self) -> None:
        for ip in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "169.254.1.1"):
            with self.subTest(ip=ip):
                self.assertTrue(_is_unicast_ip(ip))

    def test_rejects_malformed_ip(self) -> None:
        self.assertFalse(_is_unicast_ip("not-an-ip"))


class LocallyAdministeredTests(unittest.TestCase):
    def test_ul_bit_set(self) -> None:
        for mac in ("76:8A:54:7C:7C:B0", "A2:9F:7A:6D:2D:C0", "CE:CD:50:26:F5:BB"):
            with self.subTest(mac=mac):
                self.assertTrue(is_locally_administered(mac))

    def test_ul_bit_clear(self) -> None:
        for mac in ("F0:D4:15:6C:9B:D4", "B8:27:EB:11:22:33", "8C:8B:5B:42:B1:53"):
            with self.subTest(mac=mac):
                self.assertFalse(is_locally_administered(mac))

    def test_missing_or_malformed(self) -> None:
        for mac in (None, "", "not-a-mac", "76:8A:54"):
            with self.subTest(mac=mac):
                self.assertFalse(is_locally_administered(mac))


class VendorTests(unittest.TestCase):
    def test_known_oui(self) -> None:
        self.assertEqual(vendor_for_mac("B8:27:EB:11:22:33"), "Raspberry Pi")
        self.assertEqual(vendor_for_mac("b8-27-eb-11-22-33"), "Raspberry Pi")
        self.assertEqual(vendor_for_mac("F0:D4:15:6C:9B:D4"), "Intel")
        self.assertEqual(vendor_for_mac("8C:8B:5B:42:B1:53"), "WNC Corporation")

    def test_curated_label_wins_over_bundled_list(self) -> None:
        # mac-vendor.txt calls this prefix "Raspberry Pi Foundation".
        self.assertEqual(vendor_for_mac("B8:27:EB:11:22:33"), "Raspberry Pi")

    def test_bundled_list_resolves_an_uncurated_prefix(self) -> None:
        self.assertEqual(vendor_for_mac("00:00:0D:00:00:01"), "FIBRONICS LTD.")
        self.assertGreater(len(_supplemental_oui_vendors()), 20_000)

    def test_bundled_list_skips_placeholder_vendors(self) -> None:
        vendors = _supplemental_oui_vendors()
        self.assertTrue(vendors)
        self.assertNotIn("IEEE Registration Authority", vendors.values())
        self.assertNotIn("Private", vendors.values())

    def test_bundled_list_matches_the_longest_prefix(self) -> None:
        cases = {
            "C8:5C:E2:70:00:01": "SYNERGY SYSTEMS AND SOLUTIONS",  # 28-bit IAB
            "40:D8:55:0D:70:01": "Avant Technologies",  # 36-bit OUI36
        }
        for mac, vendor in cases.items():
            with self.subTest(mac=mac):
                self.assertEqual(vendor_for_mac(mac), vendor)

    def test_global_oui_missing_from_table_is_blank(self) -> None:
        self.assertEqual(vendor_for_mac("F8:FF:FF:00:00:01"), "")

    def test_randomized_mac_is_labeled(self) -> None:
        for mac in ("76:8A:54:7C:7C:B0", "A2:9F:7A:6D:2D:C0"):
            with self.subTest(mac=mac):
                self.assertEqual(vendor_for_mac(mac), "randomized")

    def test_malformed_returns_empty(self) -> None:
        for mac in (None, "", "not-a-mac", "00:11:22:33:44"):
            with self.subTest(mac=mac):
                self.assertEqual(vendor_for_mac(mac), "")

    def test_extended_oui_table(self) -> None:
        cases = {
            "00:26:0B": "Cisco",
            "AC:BC:32": "Apple",
            "D4:BE:D9": "Dell",
            "A0:36:9F": "Intel",
            "F0:D4:15": "Intel",
            "8C:8B:5B": "WNC Corporation",
            "AC:22:0B": "ASUS",
            "C0:4A:00": "TP-Link",
            "EC:08:6B": "TP-Link",
            "A0:04:60": "Netgear",
            "F0:9F:C2": "Ubiquiti",
            "00:18:82": "Huawei",
            "7C:9E:BD": "Espressif",
            "DC:4F:22": "Espressif",
        }
        for prefix, vendor in cases.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(vendor_for_mac(f"{prefix}:00:00:01"), vendor)


if __name__ == "__main__":
    unittest.main()
