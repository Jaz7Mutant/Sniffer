#! /usr/local/bin/python3.5
import sys
from threading import Thread

import readchar

from frame_sender.frame_sender import FrameSender
from printer.data_printer import print_ethernet_frame, print_ipv4_packet, \
    print_tcp_segment, print_udp_segment, print_ipv6_packet, print_arp_packet
from settings.mode_parser import ModeParser
from unpacker.frame import Frame
from unpacker.packet import IPv4Packet, IPv6Packet, ARPPacket
from unpacker.segment import TCPSegment, UDPSegment


class Sniffer:
    def __init__(self):
        mode_parser = ModeParser()
        self.console, self.plot, self.dump, self.send = \
            mode_parser.get_settings()
        self.sock = mode_parser.get_socket()
        if self.send:
            filename = mode_parser.get_dump_name()
            frame_sender = FrameSender(filename, self.sock)
            frame_sender.send_frames()
            print('Completed')
            exit(0)
        self.tracking_connections = []
        if self.plot:
            from network_analyzer.plot_handler import PlotHandler
            self.tracking_connections = mode_parser.get_tracking_connections(
                self.dump)
            self.plot_handler = PlotHandler(self.tracking_connections)
        self.sniffer = Thread(target=self.sniff)
        self.quit_handler = Thread(target=self.wait_for_quit)
        self.finish = False

    def start(self):
        self.sniffer.start()
        self.quit_handler.start()
        if self.plot:
            self.plot_handler.start()
        self.sniffer.join()
        self.quit_handler.join()

    def wait_for_quit(self):
        while True:
            a = readchar.readchar()
            if a == ' ' or a == b' ':
                self.finish = True
                if self.plot:
                    self.plot_handler.finish = True
                print("Closing...")
                return

    def sniff(self):
        while not self.finish:
            raw_data = self.sock.get_raw_frame()

            frame = Frame(raw_data)
            if self.console:
                print('-' * 20)
                print_ethernet_frame(frame)

            parsed_packet = None
            if frame.ether_type == 'IPv4':
                parsed_packet = IPv4Packet(frame.data)
                if self.console:
                    print_ipv4_packet(parsed_packet)
            elif frame.ether_type == 'IPv6':
                parsed_packet = IPv6Packet(frame.data)
                if self.console:
                    print_ipv6_packet(parsed_packet)
            elif frame.ether_type == 'ARP':
                parsed_packet = ARPPacket(frame.data)
                if self.console:
                    print_arp_packet(parsed_packet)

            for tunnel in self.tracking_connections:
                tunnel.check_packet(raw_data, parsed_packet)

            if (isinstance(parsed_packet, IPv4Packet) or
                    isinstance(parsed_packet, IPv6Packet)):
                if parsed_packet.protocol == 6:
                    tcp_segment = TCPSegment(parsed_packet.data)
                    if self.console:
                        print_tcp_segment(tcp_segment)
                elif parsed_packet.protocol == 17:
                    udp_segment = UDPSegment(parsed_packet.data)
                    if self.console:
                        print_udp_segment(udp_segment)
        for connection in self.tracking_connections:
            connection.close()


if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.start()
