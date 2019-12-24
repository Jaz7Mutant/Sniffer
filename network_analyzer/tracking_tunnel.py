class TrackingTunnel:
    def __init__(self, source_ip: str, target_ip: str, bidirectional: bool):
        self.broadcast = False
        if source_ip == '' and target_ip == '':
            self.broadcast = True
            self.source_ip = 'ALL'
            self.target_ip = 'ALL'
        else:
            self.source_ip = source_ip
            self.target_ip = target_ip
        self.bidirectional = bidirectional
        self.packet_count = [0]

    def check_packet(self, packet):
        if (self.broadcast or
                (packet.source_ip == self.source_ip and
                 packet.target_ip == self.target_ip) or
                (self.bidirectional and
                 packet.source_ip == self.target_ip and
                 packet.target_ip == self.source_ip)):
            self.increase_frame_count()

    def get_updated_frame_count(self):
        self.packet_count.append(0)
        return self.packet_count[:-1]

    def increase_frame_count(self):
        self.packet_count[-1] += 1
