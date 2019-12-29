from scapy.config import conf

from unpacker.frame import Frame
from unpacker.socket_handler import SocketHandler


class WindowsSocket(SocketHandler):
    def __init__(self, interface):
        self.sock = conf.L2socket(iface=interface)

    def get_raw_frame(self) -> Frame:
        while True:
            raw_data = self.sock.recv()
            if raw_data:
                return raw_data.original

    def send_frame(self, frame: bytes):
        self.sock.send(frame)
