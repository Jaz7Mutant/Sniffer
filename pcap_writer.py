from dpkt import pcap


class PCAPWriter:
    @staticmethod
    def dump_frame_to_pcap(frame: bytes, filename: str):
        with open(filename + '.pcap', 'wb') as fh:
            writer = pcap.Writer(fh)
            writer.writepkt(frame)
