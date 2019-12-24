import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from unpacker.packet import IPv4Packet, IPv6Packet, ARPPacket


class TestIPv4(unittest.TestCase):
    def test_ipv4_parsing(self):
        packet = IPv4Packet(
            b'E(\x00(\x88\x1e@\x00:\x06\x1e\tW\xf0\x81\x83\xc0\xa8\x00e\x01'
            b'\xbb\xfd\xad\x9c\x8a@\xddD\x05'
        )
        self.assertEqual(packet.version, 4)
        self.assertEqual(packet.header_len, 20)
        self.assertEqual(packet.id, 34846)
        self.assertEqual(packet.flags, 2)
        self.assertEqual(packet.offset, 0)
        self.assertEqual(packet.ttl, 58)
        self.assertEqual(packet.protocol, 6)
        self.assertEqual(packet.target_ip, '192.168.0.101')
        self.assertEqual(packet.source_ip, '87.240.129.131')
        self.assertEqual(packet.data.hex(), '01bbfdad9c8a40dd4405')


class TestIPv6(unittest.TestCase):
    def test_ipv6_parsing(self):
        packet = IPv6Packet(
            b'`\x00\x00\x00\x00 :\xff\xfe\x80\x00\x00\x00\x00\x00\x00i5&{\r'
            b'\x92\x91%\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x01\x88\x00N\x1a \x00\x00'
        )
        self.assertEqual(packet.version, 6)
        self.assertEqual(packet.payload_length, 32)
        self.assertEqual(packet.protocol, 58)
        self.assertEqual(packet.hop_limit, 255)
        self.assertEqual(
            packet.source_ip, 'FE80:0000:0000:0000:6935:267B:0D92:9125')
        self.assertEqual(
            packet.target_ip, 'FF02:0000:0000:0000:0000:0000:0000:0001')
        self.assertEqual(packet.data.hex(), '88004e1a200000')


class TestARP(unittest.TestCase):
    def test_arp_v4ip_packet(self):
        packet = ARPPacket(
            b'\x00\x01\x08\x00\x06\x04\x00\x01\n\xfb\xecX\xb7_\xc0\xc3\xc2'
            b'\xa8+Y\xa4\xca\xa0}\xa6}\xc0\xa8+\x01'
        )
        self.assertEqual(packet.hardware_type, '0001')
        self.assertEqual(packet.protocol_type, '0800')
        self.assertEqual(packet.source_mac, '0A:FB:EC:58:B7:5F')
        self.assertEqual(packet.source_ip, '192.195.194.168')
        self.assertEqual(packet.target_mac, '2B:59:A4:CA:A0:7D')
        self.assertEqual(packet.target_ip, '166.125.192.168')

    def test_arp_v6ip_packet(self):
        packet = ARPPacket(
            b'\x00\x01\x86\xdd\x06\x04\x00\x01\n\xfb\xecX\xb7_\xc0\xa8+Y\xa4'
            b'\xca\xa0}\xa6}\xfb\xecX\xb7_\xc0\xa8\xfb\xecX\xb7_\xc0\xa8\xfb'
            b'\xecX\xb7_\xc0\xa8\xc0\xa8+\x01\x05\xda\x43'
        )
        self.assertEqual(packet.hardware_type, '0001')
        self.assertEqual(packet.protocol_type, '86dd')
        self.assertEqual(packet.source_mac, '0A:FB:EC:58:B7:5F')
        self.assertEqual(
            packet.source_ip, 'C0A8:2B59:A4CA:A07D:A67D:FBEC:58B7:5FC0'
        )
        self.assertEqual(packet.target_mac, 'A8:FB:EC:58:B7:5F')
        self.assertEqual(
            packet.target_ip, 'C0A8:FBEC:58B7:5FC0:A8C0:A82B:0105:DA43'
        )
