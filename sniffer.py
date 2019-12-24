#! /usr/local/bin/python3.5
from threading import Thread
from time import sleep

import pyqtgraph as pg
from scapy.all import IFACES
# import socket # linux
from scapy.config import conf

from network_analyzer.network_load_plot import NetworkLoadPlot
from network_analyzer.tracking_tunnel import TrackingTunnel
from printer.data_printer import print_ethernet_frame, print_ipv4_packet, \
    print_tcp_segment, print_udp_segment, print_ipv6_packet, print_arp_packet
from unpacker.frame import Frame
from unpacker.packet import IPv4Packet, IPv6Packet, ARPPacket
from printer.pcap_writer import PCAPWriter
from unpacker.segment import TCPSegment, UDPSegment


def main():
    IFACES.show()
    iface_index = input('Choose the interface... \n')
    iface = IFACES.dev_from_index(iface_index)
    sock = conf.L2socket(iface=iface)
    # sock = socket.socket(
    #     socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # linux

    tracking_tunnels = list()
    while True:
        print('Write source_ip and target_ip (X.X.X.X X.X.X.X)')
        print('Write empty string to finish')
        raw_string = input()
        if raw_string == '':
            tracking_tunnels.append(TrackingTunnel('', '', True))
            break
        source, target = raw_string.split(' ')
        tracking_tunnels.append(TrackingTunnel(source, target, True))

    network_load_plot = NetworkLoadPlot(tracking_tunnels)
    thread1 = Thread(target=update_plot, args=(network_load_plot,))
    thread2 = Thread(target=sniff, args=(sock, tracking_tunnels))
    thread1.start()
    thread2.start()
    pg.QtGui.QApplication.exec_()
    thread1.join()
    thread2.join()


def update_plot(network_load_plot):
    while True:
        network_load_plot.update(True)
        sleep(5)


def sniff(sock, tracking_tunnels):
    with PCAPWriter('dump/dump') as writer:
        try:
            while True:
                    raw_data = sock.recv()
                    # raw_data = sock.recvfrom(65565)[0] # linux
                    if not raw_data:
                        continue
                    raw_data = raw_data.original
                    print('-'*20)

                    # writer.dump_frame_to_pcap(raw_data)

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

                    for tunnel in tracking_tunnels:
                        tunnel.check_packet(parsed_packet)

                    if (isinstance(parsed_packet, IPv4Packet) or
                            isinstance(parsed_packet, IPv6Packet)):
                        if parsed_packet.protocol == 6:
                            tcp_segment = TCPSegment(parsed_packet.data)
                            print_tcp_segment(tcp_segment)
                        elif parsed_packet.protocol == 17:
                            udp_segment = UDPSegment(parsed_packet.data)
                            print_udp_segment(udp_segment)

        except KeyboardInterrupt:
            print('Ctrl+C')
            writer.__exit__(None, None, None)


if __name__ == "__main__":
    main()
