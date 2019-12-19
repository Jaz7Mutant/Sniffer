from utilities import format_mac


class Frame:
    ether_types = {
        '0800': 'IPv4',
        '0806': 'ARP',
        '86dd': 'IPv6',
        '8847': 'MPLS unicast',
        '8848': 'MPLS multicast'
    }

    def __init__(self, raw_frame: bytes):
        self.destination_mac = format_mac(raw_frame[0:6])
        self.source_mac = format_mac(raw_frame[6:12])
        self.ether_type = self.ether_types[raw_frame[12:14].hex()]
        self.data = raw_frame[14:]
