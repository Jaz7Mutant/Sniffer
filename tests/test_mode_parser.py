import os
import sys
import unittest
from unittest import mock


sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from settings.mode_parser import ModeParser


class TestModeParser(unittest.TestCase):
    def test_wrong_os(self):
        parser = ModeParser()
        sys.platform = 'gayOS'
        self.assertRaises(NotImplementedError, parser.get_socket)

    def test_get_tracking_connections(self):
        parser = ModeParser()
        with mock.patch('builtins.input', lambda *_: ''):
            self.assertEqual([], parser.get_tracking_connections(True))

    def test_get_dump_name(self):
        with mock.patch('builtins.input', lambda *_: ''):
            parser = ModeParser()
            self.assertRaises(IndexError, parser.get_dump_name)

    def test_get_args(self):
        parser = ModeParser()
        sys.argv = ['prog', '-c', '-d', '-p', '-s']
        self.assertEqual((True, True, True, True), parser.get_settings())
