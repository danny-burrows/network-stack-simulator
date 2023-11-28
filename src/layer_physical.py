from logger import Logger
import os


class PhysicalLayer(Logger):
    PIPE_PATH = "/var/tmp/physical-pipe-"

    communication_index: int

    def __init__(self) -> None:
        super().__init__()
        self.communication_index = 0

    @property
    def pipe_path(self) -> str:
        return PhysicalLayer.PIPE_PATH + str(self.communication_index)

    def send(self, data: bytes) -> None:
        self.logger.debug(f"⌛ Sending data=0x{data.hex()}...")

        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "wb") as f:
            f.write(data)

        if file_owner:
            os.remove(self.pipe_path)

        self.communication_index += 1
        self.logger.debug("✅ Sent.")

    def receive(self) -> bytes:
        self.logger.debug("⌛ Receiving...")

        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "rb") as f:
            data = f.read()

        if file_owner:
            os.remove(self.pipe_path)

        self.logger.debug(f"✅ Received data=0x{data.hex()}")
        self.communication_index += 1
        return data
