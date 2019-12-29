from struct import unpack


class PCAPReader:
    def __init__(self, filename: str):
        self.filename = filename

    def get_next_frame(self):
        self._fh.seek(12, 1)
        raw_len = self._fh.read(4)
        if not raw_len:
            return
        frame_len = unpack('i', raw_len)[0]
        frame = self._fh.read(frame_len)
        return frame

    def open_file(self):
        return self.__enter__()

    def close_file(self):
        self.__exit__(None, None, None)

    def __iter__(self):
        return self

    def __next__(self):
        frame = self.get_next_frame()
        if frame is None:
            raise StopIteration
        return frame

    def __enter__(self):
        self._fh = open(self.filename, 'rb')
        self._fh.seek(24)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._fh.close()
        if exc_val:
            raise
