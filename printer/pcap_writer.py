from struct import pack
import time


class PCAPWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self._thiszone = 5 * 3600
        self._snaplen = 65535

    def dump_frame_to_pcap(self, frame: bytes):
        self._write_packet_header(frame)
        self._fh.write(frame)

    def open(self):
        return self.__enter__()

    def close(self):
        return self.__exit__(None, None, None)

    def _write_packet_header(self, frame):
        ts_sec = pack("i", int(time.time()))
        ts_usec = pack("i", 0)
        incl_len = pack("i", len(frame) % self._snaplen)
        orig_len = pack("i", len(frame))

        data_to_write = [ts_sec, ts_usec, incl_len, orig_len]

        for x in data_to_write:
            self._fh.write(x)

    def __enter__(self):
        self._fh = open('dump/' + self.filename + '.pcap', 'wb+')  # todo linux
        magic_number = bytes.fromhex("d4c3b2a1")
        major_ver = pack("H", 2)
        minor_ver = pack("H", 4)
        thiszone = pack("i", self._thiszone)
        sigfigs = b"\x00" * 4
        snaplen = pack("i", self._snaplen)
        network = pack("i", 1)

        data_to_write = [magic_number, major_ver,
                         minor_ver, thiszone, sigfigs, snaplen, network]

        for x in data_to_write:
            self._fh.write(x)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._fh.close()
        if exc_val:
            raise
