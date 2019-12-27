import os
import sys
import unittest

from network_analyzer.colors import COLORS

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from unpacker.utilities import format_mac, ipv4, ipv6


class TestUtilities(unittest.TestCase):
    def test_format_ipv4(self):
        self.assertEqual('192.154.43.4', ipv4(b'\xc0\x9a+\x04'))

    def test_format_ipv6(self):
        self.assertEqual(
            'FE80:0000:0000:0000:F4D0:7339:29BA:8A0F',
            ipv6(b'\xfe\x80\x00\x00\x00\x00\x00\x00\xf4\xd0s9)\xba\x8a\x0f'))

    def test_format_mac(self):
        self.assertEqual(
            'F8:63:3F:FC:9B:80', format_mac(b'\xf8c?\xfc\x9b\x80')
        )

    def test_colors(self):
        self.assertTrue(len(COLORS) > 0)
