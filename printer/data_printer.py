from unpacker.frame import Frame
from unpacker.packet import IPv4Packet, IPv6Packet, ARPPacket
from unpacker.segment import TCPSegment, UDPSegment


def print_ethernet_frame(frame: Frame):
    print('Ethernet II frame:')
    print('\tSource MAC: {} \n\tTarget MAC: {}\n\tProtocol: {}'.format(
        frame.source_mac, frame.destination_mac, frame.ether_type))


def print_ipv4_packet(packet: IPv4Packet):
    print(
        '\n\tIPv4 Packet: '
        '\n\t\tVersion: {}'
        '\n\t\tHeader length: {}'
        '\n\t\tId: {}'
        '\n\t\tFlags: {}'
        '\n\t\tOffset: {}'
        '\n\t\tTTL: {}'
        '\n\t\tProtocol: {}'
        '\n\t\tTarget: {}'
        '\n\t\tSource: {}'
        .format(
            packet.version,
            packet.header_len,
            packet.id,
            packet.flags,
            packet.offset,
            packet.ttl,
            packet.protocol,
            packet.target,
            packet.source
        )
    )


def print_ipv6_packet(packet: IPv6Packet):
    print(
        '\n\tIPv6 Packet: '
        '\n\t\tVersion: {}'
        '\n\t\tPayload length: {}'
        '\n\t\tProtocol: {}'
        '\n\t\tHop limit: {}'
        '\n\t\tSource: {}'
        '\n\t\tTarget: {}'
        .format(
            packet.version,
            packet.payload_length,
            packet.protocol,
            packet.hop_limit,
            packet.source,
            packet.target
        )
    )


def print_arp_packet(packet: ARPPacket):
    print(
        '\n\tARP Packet: '
        '\n\t\tHardware type: {}'
        '\n\t\tProtocol Type: {}'
        '\n\t\tSource MAC: {}'
        '\n\t\tSource IP: {}'
        '\n\t\tTarget MAC: {}'
        '\n\t\tTarget IP: {}'
        .format(
            packet.hardware_type,
            packet.protocol_type,
            packet.source_mac,
            packet.source_ip,
            packet.target_mac,
            packet.target_ip
        )
    )


def print_tcp_segment(segment: TCPSegment):
    print(
        '\n\t\tTCP Segment:'
        '\n\t\t\tSource port: {}'
        '\n\t\t\tTarget port: {}'
        '\n\t\t\tSequence: {}'
        '\n\t\t\tAcknowledgement: {}'
        '\n\t\t\tFlags:'
        '\n\t\t\t\tURG: {}'
        '\n\t\t\t\tACK: {}'
        '\n\t\t\t\tPSH: {}'
        '\n\t\t\t\tRST: {}'
        '\n\t\t\t\tSYN: {}'
        '\n\t\t\t\tFIN: {}'
        '\n\t\t\tWindow size: {}'
        '\n\t\t\tURG pointer: {}'
        '\n\t\t\tData: \n{}'
        .format(
            segment.source_port,
            segment.target_port,
            segment.sequence,
            segment.acknowledgement,
            segment.urg,
            segment.ack,
            segment.psh,
            segment.rst,
            segment.syn,
            segment.fin,
            segment.window_size,
            segment.urg_pointer,
            segment.data
        )
    )


def print_udp_segment(segment: UDPSegment):
    print(
        '\n\t\tUDP Segment:'
        '\n\t\t\tSource port: {}'
        '\n\t\t\tTarget port: {}'
        '\n\t\t\tSize: {}\n\t\t\tData: \n{}'
        .format(
            segment.source_port,
            segment.target_port,
            segment.size,
            segment.data
        )
    )
