#! /usr/local/bin/python3.5

from scapy.all import *

from data_printer import print_ethernet_frame, print_ipv4_packet, \
    print_tcp_segment, print_udp_segment, print_ipv6_packet, print_arp_packet
from package_parser import Frame
from packet import IPv4Packet, IPv6Packet, ARPPacket
from pcap_writer import PCAPWriter
from segment import TCPSegment, UDPSegment


def main():

    IFACES.show()  # let’s see what interfaces are available. Windows only
    iface = IFACES.dev_from_index(11)
    socket = conf.L2socket(iface=iface)
    # socket is now an Ethernet socket
    i = 0
    while True:
        packet_raw = socket.recv()  # Raw data
        if not packet_raw:
            continue
        packet_raw = packet_raw.original
        print('----')

        PCAPWriter.dump_frame_to_pcap(packet_raw, str(i))

        frame = Frame(packet_raw)
        print_ethernet_frame(frame)

        parsed_packet = None
        if frame.ether_type == 'IPv4':
            print(frame.data)
            parsed_packet = IPv4Packet(frame.data)
            print_ipv4_packet(parsed_packet)
        elif frame.ether_type == 'IPv6':
            parsed_packet = IPv6Packet(frame.data)
            print_ipv6_packet(parsed_packet)
        elif frame.ether_type == 'ARP':
            parsed_packet = ARPPacket(frame.data)
            print_arp_packet(parsed_packet)

        if parsed_packet is IPv4Packet or parsed_packet is IPv6Packet:
            if parsed_packet.protocol == 6:
                tcp_segment = TCPSegment(parsed_packet.data)
                print_tcp_segment(tcp_segment)
            elif parsed_packet.protocol == 17:
                udp_segment = UDPSegment(parsed_packet.data)
                print_udp_segment(udp_segment)

        i += 1
        # hexdump(packet_raw)


if __name__ == "__main__":
    main()
