import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from printer.pcap_writer import PCAPWriter


class TestPCAPWriter(unittest.TestCase):
    def test_init(self):
        writer = PCAPWriter('fn')
        self.assertEqual('fn', writer.filename)

    def _check_global_pcap_header(self):
        with open('dump/test.pcap', 'rb') as fh:
            self.assertEqual(
                'd4c3b2a1020004005046000000000000ffff000001000000',
                fh.readline().hex())

    def test_context_manager(self):
        with PCAPWriter('test') as writer:
            pass
        self._check_global_pcap_header()

    def test_open(self):
        writer = PCAPWriter('test')
        writer.open()
        writer.close()
        self._check_global_pcap_header()

    def test_dump_frame(self):
        with mock.patch('time.time', lambda: 0):
            writer = PCAPWriter('test')
            writer.open()
            writer.dump_frame_to_pcap(
                b'.\xf3F\x89\xff\x19\xac\x84\xc6\x94\xbd\xdc\x08\x00Ep\x00('
                b'\xb5\xbb@\x005\x06;\xe5\xb2\x8d\xe0$\xc0\xa8\x00e@\x9e\xcf'
                b'\x13\xc5\xca\x86\xda\x1a\xe6\xff\x8cP\x10\xff\xff\xe5J\x00'
            )
            writer.close()
            with open('dump/test.pcap', 'rb') as fh:
                self.assertEqual(
                    'd4c3b2a1020004005046000000000000ffff000001000000000000000'
                    '000000035000000350000002ef34689ff19ac84c694bddc0800457000'
                    '28b5bb400035063be5b28de024c0a80065409ecf13c5ca86da1ae6ff8'
                    'c5010ffffe54a00',
                    fh.readline().hex())
