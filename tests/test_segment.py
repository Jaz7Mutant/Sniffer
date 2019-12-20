import os
import sys
import unittest

from dpkt import hexdump

from segment import UDPSegment, TCPSegment

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))


class TestSegment(unittest.TestCase):
    def test_udp_segment(self):
        segment = UDPSegment(
            b'\xe0.\x005\x00/!$\xa2\x15\x01\x00\x00\x01\x00\x00\x00\x00\x00'
            b'\x00\x03api\x07browser\x06yandex\x02ru\x00\x00\x01\x00\x01'
        )
        self.assertEqual(57390, segment.source_port)
        self.assertEqual(53, segment.target_port)
        self.assertEqual(47, segment.size)
        self.assertEqual(
            hexdump(
                b'\xa2\x15\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api'
                b'\x07browser\x06yandex\x02ru\x00\x00\x01\x00\x01'),
            segment.data
        )

    def test_tcp_segment(self):
        segment = TCPSegment(
            b'\xcfz\x01\xbb+\t:?\xb78\\k\x83\xb78[\x16\xd2xb78[\x16\x88\x01'
            b'\x03\x01\x01\x05\n\xb78[\x16\xb78\\k'
        )
        self.assertEqual(53114, segment.source_port)
        self.assertEqual(443, segment.target_port)
        self.assertEqual(722025023, segment.sequence)
        self.assertEqual(3073924203, segment.acknowledgement)
        self.assertEqual(1, segment.urg)
        self.assertEqual(1, segment.ack)
        self.assertEqual(1, segment.psh)
        self.assertEqual(0, segment.rst)
        self.assertEqual(0, segment.syn)
        self.assertEqual(0, segment.fin)
        self.assertEqual(14427, segment.window_size)
        self.assertEqual(30818, segment.urg_pointer)
