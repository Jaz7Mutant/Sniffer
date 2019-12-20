#! /usr/local/bin/python3.5
from scapy.all import IFACES
# import socket # linux
from scapy.config import conf

from data_printer import print_ethernet_frame, print_ipv4_packet, \
    print_tcp_segment, print_udp_segment, print_ipv6_packet, print_arp_packet
from frame import Frame
from packet import IPv4Packet, IPv6Packet, ARPPacket
from pcap_writer import PCAPWriter
from segment import TCPSegment, UDPSegment


def main():
    IFACES.show()
    iface_index = input('Choose the interface... ')
    iface = IFACES.dev_from_index(iface_index)
    sock = conf.L2socket(iface=iface)
    # sock = socket.socket(
    #     socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # linux

    with PCAPWriter('dump/dump') as writer:
        try:
            while True:
                raw_data = sock.recv()
                # raw_data = sock.recvfrom(65565)[0] # linux
                if not raw_data:
                    continue
                raw_data = raw_data.original
                print('-'*20)

                # PCAPWriter.dump_frame_to_pcap(raw_data, 'dump/' +str(i))
                writer.dump_frame_to_pcap(raw_data)

                frame = Frame(raw_data)
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

                if (isinstance(parsed_packet, IPv4Packet) or
                        isinstance(parsed_packet, IPv6Packet)):
                    if parsed_packet.protocol == 6:
                        tcp_segment = TCPSegment(parsed_packet.data)
                        print_tcp_segment(tcp_segment)
                    elif parsed_packet.protocol == 17:
                        udp_segment = UDPSegment(parsed_packet.data)
                        print_udp_segment(udp_segment)

                # hexdump(raw_data)
        except KeyboardInterrupt:
            print('Ctrl+C')
            writer.__exit__(None, None, None)


if __name__ == "__main__":
    main()
