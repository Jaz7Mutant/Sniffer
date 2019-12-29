import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from frame_sender.frame_sender import FrameSender
from unpacker.socket_handler import SocketHandler


class TestFrameSender(unittest.TestCase):
    def test_init_frame_sender(self):
        with mock.patch(
                'frame_sender.pcap_reader.PCAPReader.__init__',
                lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.__enter__',
                 lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.__exit__',
                 lambda *_: None), \
             mock.patch(
                 'frame_sender.pcap_reader.PCAPReader.get_next_frame',
                 lambda *_: None):
            socket = SocketHandler(0)
            frame_sender = FrameSender('test', socket)
            self.assertEqual('test', frame_sender.filename)
            self.assertEqual(socket, frame_sender.sock)
            frame_sender.send_frames()
            self.assertEqual((None, None, None), sys.exc_info())
