"""Blame for a latency rise goes to the segment that added the most itself.

Run with: python -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netprobe
from netprobe import Stats, diagnose, locate, segment_shares


def stat(p50):
    return Stats(sent=100, lost=0, min=p50, p50=p50, p95=p50, p99=p50, max=p50, jitter=0.0)


class SegmentShares(unittest.TestCase):
    def test_hop_rises_are_cumulative(self):
        # Wi-Fi adds 18, the access line 13 more, the rest of the path 5
        shares = segment_shares({'gateway': 18, 'isp': 31}, 36, True)
        self.assertEqual(shares, {'local': 18, 'access': 13, 'beyond': 5})

    def test_isp_probe_overshoot_is_capped_at_the_far_end(self):
        shares = segment_shares({'gateway': 2, 'isp': 90}, 40, True)
        self.assertEqual(shares, {'local': 2, 'access': 38, 'beyond': 0})

    def test_silent_isp_hop_leaves_the_rest_unlocated(self):
        self.assertEqual(segment_shares({'gateway': 5}, 40, True), {'local': 5, 'upstream': 35})
        self.assertEqual(segment_shares({'gateway': 5, 'isp': 30}, 40, False), {'local': 5, 'upstream': 35})


class Locate(unittest.TestCase):
    def test_wifi_blamed_when_it_adds_more_than_the_access_line(self):
        # just under half the rise is on Wi-Fi, but that is still the largest part
        self.assertEqual(locate({'gateway': 18, 'isp': 31}, 36.4, True), 'local')

    def test_access_line_blamed_when_wifi_stays_flat(self):
        self.assertEqual(locate({'gateway': 1, 'isp': 205}, 205, True), 'access')

    def test_beyond_blamed_when_first_two_hops_stay_flat(self):
        self.assertEqual(locate({'gateway': 1, 'isp': 3}, 80, True), 'beyond')

    def test_no_isp_hop(self):
        self.assertEqual(locate({'gateway': 30}, 40, False), 'local')
        self.assertEqual(locate({'gateway': 3}, 40, False), 'upstream')

    def test_loss_with_no_router_reading_is_not_local(self):
        self.assertNotEqual(locate({}, 4.0, True), 'local')


class DiagnoseLoadFinding(unittest.TestCase):
    def finding(self, gateway, isp, internet):
        stats = {('gateway', 'idle'): stat(3.5), ('isp', 'idle'): stat(6.0), ('internet', 'idle'): stat(8.6),
                 ('gateway', 'download'): stat(gateway), ('isp', 'download'): stat(isp),
                 ('internet', 'download'): stat(internet)}
        findings = diagnose(stats, ['idle', 'download'], None, {'download': {'down': 892}}, [], True)
        return next(detail for _, title, detail in findings if title.startswith('Download'))

    def test_split_rise_names_wifi_first_and_the_access_line_second(self):
        detail = self.finding(gateway=21.6, isp=37.0, internet=45.0)
        self.assertIn(netprobe.LOCATIONS['local'], detail.split('Not all of it')[0])
        self.assertIn(netprobe.LOCATIONS['access'], detail.split('Not all of it')[1])

    def test_rise_in_one_segment_names_only_that_segment(self):
        detail = self.finding(gateway=4.0, isp=215.0, internet=220.0)
        self.assertIn(netprobe.LOCATIONS['access'], detail)
        self.assertNotIn('Not all of it', detail)


if __name__ == '__main__':
    unittest.main()
