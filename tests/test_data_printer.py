import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from printer.data_printer import print_ethernet_frame, print_arp_packet
from unpacker.frame import Frame
from unpacker.packet import ARPPacket


class TestDataPrinter(unittest.TestCase):
    def test_print_ethernet(self):
        print_ethernet_frame(
            Frame(b'\n\xfb\xecX\xb7_\xa4\xca\xa0}\xa6}\x08\x00E\x00\x00(\xab'
                  b'\x7f@sdjnfgkl'))
        self.assertIsNotNone(sys.stdout)
        sys.stdout = None

    def test_print_arp(self):
        print_arp_packet(
            ARPPacket(
                b'\x00\x01\x08\x00\n\xfb\xecX\xb7_\xa4\xca\xa0}\x0E\x00\x00(\b'
            )
        )
        self.assertIsNotNone(sys.stdout)
        sys.stdout = None
