import unittest

from packet import IPv4Packet


class TestIPv4(unittest.TestCase):
    def test_ipv4_parsing(self):
        packet = IPv4Packet(
            b'E(\x00(\x88\x1e@\x00:\x06\x1e\tW\xf0\x81\x83\xc0\xa8\x00e\x01'
            b'\xbb\xfd\xad\x9c\x8a@\xddD\x05 ZP\x10\x00\xb5\xd3n\x00\x00'
        )
        self.assertEqual(packet.version, 4)
        self.assertEqual(packet.header_len, 20)
        self.assertEqual(packet.id, 34846)
        self.assertEqual(packet.flags, 2)
        self.assertEqual(packet.offset, 0)
        self.assertEqual(packet.ttl, 58)
        self.assertEqual(packet.protocol, 6)
        self.assertEqual(packet.target, '192.168.0.101')
        self.assertEqual(packet.source, '87.240.129.131')


class TestIPv6(unittest.TestCase):
    pass


class TestARP(unittest.TestCase):
    pass
