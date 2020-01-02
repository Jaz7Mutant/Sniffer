import os
import sys
import unittest
from threading import Thread
from unittest import mock

from mock import Mock

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
sys.modules['readchar'] = Mock()
from sniffer import Sniffer
from unpacker.socket_handler import SocketHandler


class TestSniffer(unittest.TestCase):
    def test_sniffing_ipv4(self):
        with mock.patch(
                'unpacker.socket_handler.SocketHandler.get_raw_frame', lambda:
                b'5\x827\xe7\x8f\15T\x92XO&\x10\x07\xb4\x1c\xfbW\xaa\xb7;'
                b'\x84<>\x8d\xc8\xed>\x0e\xd4\xdc\xd1\xd3\xa6k\xc9\xeb2\xd98'
                b'\xc9\xc2\xb8w\x82V\xc2\x94\xf3\x12\x08\x12*N'):
            thread = Thread(
                target=Sniffer.sniff, args=(SocketHandler(0), [], False))
            thread.start()
            Sniffer.finish = True
            thread.join()
            self.assertEqual((None, None, None), sys.exc_info())

    def test_quit_button(self):
        with mock.patch(
                'settings.mode_parser.ModeParser.get_settings',
                lambda *_: (False, False, False, False)):
            with mock.patch(
                    'unpacker.socket_handler.SocketHandler.get_raw_frame',
                    lambda: b' '):
                with mock.patch(
                        'settings.mode_parser.ModeParser.get_socket',
                        lambda *_: SocketHandler(0)):
                    with mock.patch('readchar.readchar', lambda *_: ' '):
                        sniffer = Sniffer()
                        self.assertIsNone(sniffer.wait_for_quit())
                        sniffer.finish = True
                        sniffer.start()
                        self.assertEqual((None, None, None), sys.exc_info())

    def test_init(self):
        with mock.patch(
                'settings.mode_parser.ModeParser.get_settings',
                lambda *_: (True, False, True, True)), \
             mock.patch(
                 'settings.mode_parser.ModeParser.get_socket',
                 lambda *_: None), \
             mock.patch(
                 'settings.mode_parser.ModeParser.get_dump_name',
                 lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.__enter__',
                 lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.get_next_frame',
                 lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.__exit__',
                 lambda *_: None), \
             mock.patch(
                 'builtins.exit',
                 lambda *_: None
             ):
            sniffer = Sniffer()
            self.assertTrue(sniffer.console)
            self.assertFalse(sniffer.plot)
            self.assertTrue(sniffer.dump)
            self.assertTrue(sniffer.send)
