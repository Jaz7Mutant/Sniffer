import os
import sys
import unittest

from unpacker.packet import IPv4Packet

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from network_analyzer.tracking_connection import TrackingConnection


class TestTrackingConnection(unittest.TestCase):
    def test_init(self):
        conn = TrackingConnection('12.34.34.34', '12.21.12.21', True, True)
        self.assertEqual('12.34.34.34', conn.source_ip)
        self.assertEqual('12.21.12.21', conn.target_ip)
        self.assertTrue(True, conn.bidirectional)
        self.assertIsNotNone(conn.pcap_writer)
        self.assertEqual([0], conn.packet_count)
        conn.close()

    def test_broadcast_init(self):
        conn = TrackingConnection('ALL', 'ALL', False, True)
        self.assertEqual('ALL', conn.target_ip)
        self.assertEqual('ALL', conn.source_ip)
        self.assertTrue(conn.broadcast)
        conn.close()

    def test_check_packet(self):
        conn = TrackingConnection(
            '94.140.82.249', '192.168.0.101', False, False
        )
        conn.check_packet(
            b'',
            IPv4Packet(
                b'Ep\x0006G\x00\x00r\x11\x9fs^\x8cR\xf9\xc0\xa8\x00eA\x91\xe7'
                b'\x9e\x00\x1c\x00\xcb!\x00\xf2\x87Q\x96\xff\x0b\x13.|I\x00\r'
                b'\x0e\xa9\xe7\xf1x\xde'
            )
        )
        self.assertEqual([1], conn.get_updated_frame_count())
        self.assertEqual(2, len(conn.packet_count))
        conn.close()
