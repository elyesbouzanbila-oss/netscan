"""Tests for display helpers that do not require a terminal."""

from __future__ import annotations

import unittest

from random_bs.display import Style, _fit, render_inventory
from random_bs.scanner import Host


class FitTests(unittest.TestCase):
    def test_short_text_is_unchanged(self) -> None:
        self.assertEqual(_fit("abc", 10), "abc")
        self.assertEqual(_fit("abcde", 5), "abcde")

    def test_long_text_gets_two_dot_suffix(self) -> None:
        self.assertEqual(_fit("abcdef", 5), "abc..")
        self.assertEqual(_fit("abcdef", 4), "ab..")

    def test_very_narrow_width_is_hard_truncated(self) -> None:
        self.assertEqual(_fit("abcdef", 3), "abc")
        self.assertEqual(_fit("abcdef", 1), "a")


class InventoryRenderTests(unittest.TestCase):
    def test_plain_table_has_markers_labels_and_consistent_width(self) -> None:
        hosts = [
            Host(
                ip="192.168.1.1",
                mac="F0:D4:15:6C:9B:D4",
                hostname="router",
                rtt_ms=2.0,
                state="up",
                gateway=True,
            ),
            Host(
                ip="192.168.1.30",
                mac="76:8A:54:7C:7C:B0",
                vendor="randomized",
                netbios="PHONE",
                rtt_ms=None,
                state="arp-only",
            ),
            Host(
                ip="192.168.1.10",
                mac="8C:8B:5B:42:B1:53",
                hostname="workstation",
                rtt_ms=0.4,
                state="self",
            ),
        ]

        lines = render_inventory(hosts, Style(False))
        joined = "\n".join(lines)

        self.assertEqual(len({len(line) for line in lines}), 1)
        self.assertTrue(lines[0].startswith("+") and lines[0].endswith("+"))
        self.assertTrue(lines[1].startswith("|") and lines[1].endswith("|"))
        self.assertEqual(lines[0], lines[-1])
        self.assertNotIn("\x1b", joined)

        for column in ("IP", "MAC", "Vendor", "Hostname", "RTT", "State"):
            with self.subTest(column=column):
                self.assertIn(column, lines[1])

        self.assertEqual(joined.count(" *"), 1)
        self.assertIn("192.168.1.1 *", joined)
        self.assertIn("ARP only", joined)
        self.assertIn("self", joined)
        self.assertIn("randomized", joined)


if __name__ == "__main__":
    unittest.main()
