import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from frame_sender.pcap_reader import PCAPReader
from unpacker.frame import Frame


class TestPCAPReader(unittest.TestCase):
    def test_init(self):
        reader = PCAPReader('test')
        self.assertEqual('test', reader.filename)

    def test_parse_pcap(self):
        with open('dump/test.pcap', 'wb') as fh:
            fh.write(
                b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00PF\x00\x00\x00\x00\x00\x00'
                b'\xff\xff\x00\x00\x01\x00\x00\x00\x89t\x08^\x00\x00\x00'
                b'\x007\x00\x00\x007\x00\x00\x00\xac\x84\xc6\x94\xbd\xdc'
                b'.\xf3F\x89\xff\x19\x08\x00E\x00\x00)\xef\xe4@\x00\x80\x06'
            )
        with PCAPReader('dump/test.pcap') as reader:
            for frame in reader:
                self.assertIsNotNone(frame)
                self.assertIsNotNone(Frame(frame))
        self.assertEqual((None, None, None), sys.exc_info())
