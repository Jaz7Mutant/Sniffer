class SocketHandler:
    def __init__(self, interface):
        pass

    def get_raw_frame(self) -> bytes:
        raise NotImplementedError

    def send_frame(self, frame: bytes):
        raise NotImplementedError
