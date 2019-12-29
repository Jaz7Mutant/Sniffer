from frame_sender.pcap_reader import PCAPReader
from unpacker.socket_handler import SocketHandler


class FrameSender:
    def __init__(self, filename: str, socket: SocketHandler):
        self.filename = filename
        self.sock = socket
        self.pcap_reader = PCAPReader(filename)
        self.pcap_reader.open_file()

    def send_frames(self):
        for frame in self.pcap_reader:
            self.sock.send_frame(frame)
        self.pcap_reader.close_file()
