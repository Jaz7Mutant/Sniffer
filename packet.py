import struct

from utilities import ipv4, format_mac, ipv6


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
        self.source = ipv4(raw_packet[12:16])
        self.target = ipv4(raw_packet[16:20])
        self.data = raw_packet[self.header_len:]


class IPv6Packet:
    def __init__(self, raw_packet: bytes):
        version_header_len = raw_packet[0]
        self.version = version_header_len >> 4
        self.payload_length, self.next_header, self.hop_limit = struct.unpack(
            '! H B B', raw_packet[4:8])
        self.source = ipv6(raw_packet[8:24])
        self.target = ipv6(raw_packet[24:40])


class ARPPacket:
    def __init__(self, raw_packet: bytes):
        self.hardware_type = raw_packet[:2].hex()
        self.protocol_type = raw_packet[2:4].hex()
        self.source_mac = format_mac(raw_packet[8:14])
        source_ip = raw_packet[14:18]
        self.target_mac = format_mac(raw_packet[18:24])
        target_ip = raw_packet[24:28]
        if self.protocol_type == '0800':
            self.source_ip = ipv4(source_ip)
            self.target_ip = ipv4(target_ip)
        if self.protocol_type == '86dd':
            self.source_ip = ipv6(source_ip)
            self.target_ip = ipv6(target_ip)
