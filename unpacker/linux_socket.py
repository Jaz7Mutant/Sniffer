import socket

from unpacker.socket_handler import SocketHandler


class LinuxSocket(SocketHandler):
    def __init__(self, interface):
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        try:
            if interface != '':
                self.sock.bind((interface, 0))
        except OSError:
            raise OSError("No such device")

    def get_raw_frame(self) -> bytes:
        while True:
            raw_data = self.sock.recvfrom(65565)
            if raw_data:
                return raw_data[0]

    def send_frame(self, frame: bytes):
        self.sock.sendall(frame)
