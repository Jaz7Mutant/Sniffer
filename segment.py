import struct

from dpkt import hexdump


class OtherSegment:
    # todo
    pass


# protocol == 1
class ICMPSegment:
    # todo
    pass


# protocol == 17
class UDPSegment:
    def __init__(self, raw_segment: bytes):
        self.source_port, self.target_port, self.size = struct.unpack(
            '! H H H', raw_segment[:6])
        self.data = hexdump(raw_segment[8:])


# protocol == 6
class TCPSegment:
    def __init__(self, raw_segment: bytes):
        self.source_port, self.target_port, self.sequence, \
            self.acknowledgement = struct.unpack('! H H L L', raw_segment[:12])
        flags = raw_segment[14]
        self.urg = (flags & 32) >> 5
        self.ack = (flags & 16) >> 4
        self.psh = (flags & 8) >> 3
        self.rst = (flags & 4) >> 2
        self.syn = (flags & 2) >> 1
        self.fin = (flags & 1)
        self.window_size = int.from_bytes(raw_segment[14:16], byteorder='big')
        self.urg_pointer = int.from_bytes(raw_segment[18:20], byteorder='big')
        self.data = hexdump(raw_segment[24:])
