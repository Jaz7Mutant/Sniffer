from unpacker.frame import Frame


class TrackingTunnel:
    def __init__(self, source_mac: str, target_mac: str, bidirectional: bool):
        self.source_mac = source_mac
        self.target_mac = target_mac
        self.bidirectional = bidirectional
        self.frame_count = [0]

    def check_frame(self, frame: Frame):
        if ((frame.source_mac == self.source_mac
                and frame.destination_mac == self.target_mac)
                or (self.bidirectional
                    and frame.source_mac == self.target_mac
                    and frame.destination_mac == self.source_mac)):
            self.increase_frame_count()

    def get_updated_frame_count(self):
        self.frame_count.append(0)
        return self.frame_count[:-1]

    def increase_frame_count(self):
        self.frame_count[-1] += 1
