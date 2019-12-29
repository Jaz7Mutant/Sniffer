import os
import sys
import unittest
from unpacker.socket_handler import SocketHandler

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from unpacker.windows_socket import WindowsSocket
from unpacker.linux_socket import LinuxSocket


class TestSockets(unittest.TestCase):
    def test_windows_socket(self):
        self.assertTrue(issubclass(WindowsSocket, SocketHandler))

    def test_linux_socket(self):
        self.assertTrue(issubclass(LinuxSocket, SocketHandler))
