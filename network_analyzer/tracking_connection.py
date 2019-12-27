import datetime
from copy import deepcopy

from printer.pcap_writer import PCAPWriter


class TrackingConnection:
    def __init__(self, source_ip: str, target_ip: str, write_to_pcap: bool,
                 bidirectional: bool):
        self.broadcast = False
        if source_ip == 'ALL' and target_ip == 'ALL':
            self.broadcast = True
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.bidirectional = bidirectional
        self.packet_count = [0]
        self.write_to_pcap = write_to_pcap
        if write_to_pcap:
            self.pcap_writer = PCAPWriter(
                f'{datetime.datetime.now().strftime("%d.%m.%Y_%H.%M.%S")} '
                f'{self.source_ip} -to- {self.target_ip}'
            ).open()

    def check_packet(self, raw_frame: bytes, packet):
        if (self.broadcast or
                (packet.source_ip == self.source_ip and
                 packet.target_ip == self.target_ip) or
                (self.bidirectional and
                 packet.source_ip == self.target_ip and
                 packet.target_ip == self.source_ip)):
            self._increase_frame_count()
            if self.write_to_pcap:
                self.pcap_writer.dump_frame_to_pcap(raw_frame)

    def get_updated_frame_count(self):
        self.packet_count.append(0)
        return deepcopy(self.packet_count[:-1])

    def _increase_frame_count(self):
        self.packet_count[-1] += 1

    def close(self):
        if self.write_to_pcap:
            self.pcap_writer.close()
