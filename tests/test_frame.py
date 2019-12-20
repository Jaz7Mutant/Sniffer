import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from unpacker.frame import Frame


class TestFrame(unittest.TestCase):
    def test_frame(self):
        frame = Frame(
            b'\n\xfb\xecX\xb7_\xa4\xca\xa0}\xa6}\x08\x00E\x00\x00(\xab\x7f@'
            b'\x004\x06o\xce]'
        )
        self.assertEqual('A4:CA:A0:7D:A6:7D', frame.source_mac)
        self.assertEqual('0A:FB:EC:58:B7:5F', frame.destination_mac)
        self.assertEqual('IPv4', frame.ether_type)
        self.assertEqual('45000028ab7f400034066fce5d', frame.data.hex())
