from dpkt import pcap


class PCAPWriter:
    def __init__(self, filename: str):
        self.filename = filename

    def dump_frame_to_pcap(self, frame: bytes):
        self._writer.writepkt(frame)

    def __enter__(self):
        self._fh = open(self.filename + '.pcap', 'ba')
        self._writer = pcap.Writer(self._fh)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._fh.close()
        if exc_val:
            raise
