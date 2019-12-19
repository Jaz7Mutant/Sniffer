#! /usr/local/bin/python3.5

from scapy.all import IFACES
# import socket # linux
from scapy.config import conf

from data_printer import print_ethernet_frame, print_ipv4_packet, \
    print_tcp_segment, print_udp_segment, print_ipv6_packet, print_arp_packet
from package_parser import Frame
from packet import IPv4Packet, IPv6Packet, ARPPacket
from pcap_writer import PCAPWriter
from segment import TCPSegment, UDPSegment


def main():
    # IFACES.show()
    iface = IFACES.dev_from_index(11)
    sock = conf.L2socket(iface=iface)
    # sock = socket.socket(
    #     socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # linux

    i = 0
    while True:
        packet_raw = sock.recv()
        # packet_raw = sock.recvfrom(65565)[0] # linux
        if not packet_raw:
            continue
        packet_raw = packet_raw.original
        print('-'*20)

        PCAPWriter.dump_frame_to_pcap(packet_raw, 'dump/' +str(i))

        frame = Frame(packet_raw)
        print_ethernet_frame(frame)

        parsed_packet = None
        if frame.ether_type == 'IPv4':
            parsed_packet = IPv4Packet(frame.data)
            print_ipv4_packet(parsed_packet)
        elif frame.ether_type == 'IPv6':
            parsed_packet = IPv6Packet(frame.data)
            print_ipv6_packet(parsed_packet)
        elif frame.ether_type == 'ARP':
            parsed_packet = ARPPacket(frame.data)
            print_arp_packet(parsed_packet)

        if type(parsed_packet) == IPv4Packet or type(parsed_packet) is IPv6Packet:
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
