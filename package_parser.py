import os
import socket
import struct


class PackageParser:
    @staticmethod
    def parse_packet(raw_packet: bytes):
        pass






class FrameParser:
    @staticmethod
    def parse_frame():
        pass

EtherTypes = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '86dd': 'IPv6',
    '8847': 'MPLS unicast',
    '8848': 'MPLS multicast'
}


class Frame:
    def __init__(self, raw_frame: bytes):
        print(len(raw_frame))
        self.destination_mac = self._format_mac(raw_frame[0:6])
        self.source_mac = self._format_mac(raw_frame[6:12])
        self.ether_type = EtherTypes[raw_frame[12:14].hex()]
        self.data = raw_frame[14:]
        self.packet = None

    def parse_packet(self):
        if self.ether_type == 'IPv4':
            self.packet = IPv4Packet(self.data)
        elif self.ether_type == 'IPv6':
            self.packet = IPv6Packet(self.data)

    def _format_mac(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr


class IPv4Packet:
    def __init__(self, raw_packet: bytes):
        version_header_len = raw_packet[0]
        self.version = version_header_len >> 4
        self.header_len = (version_header_len & 15) * 4
        self.packet_size = int.from_bytes(raw_packet[2:4], byteorder='big')
        self.id = int.from_bytes(raw_packet[4:6], byteorder='big')
        flags_offset = int.from_bytes(raw_packet[6:8], byteorder='big')
        self.flags = flags_offset >> 13
        self.offset = (flags_offset & 127) * 3
        self.ttl, self.protocol = struct.unpack('! B B', raw_packet[8:10])
        self.source = self.ipv4(raw_packet[12:16])
        self.target = self.ipv4(raw_packet[16:20])
        self.data = raw_packet[self.header_len:]

    @staticmethod
    def ipv4(address):
        return '.'.join(map(str, address))


class IPv6Packet:
    def __init__(self, raw_packet: bytes):
        version_header_len = raw_packet[0]
        self.version = version_header_len >> 4
        self.payload_length, self.next_header, self.hop_limit = struct.unpack(
            '! H B B', raw_packet[4:8])
        self.source = self.ipv6(raw_packet[8:24])
        self.target = self.ipv6(raw_packet[24:40])

    @staticmethod
    def ipv6(address):
        bytes_str = map('{:02x}'.format, address)
        return ':'.join(bytes_str).upper()

