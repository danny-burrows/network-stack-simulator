from logger import Logger
import os


class PhysicalLayer(Logger):
    PIPE_PATH = "/var/tmp/physical-pipe"

    def __init__(self) -> None:
        super().__init__()

        try:
            os.rmdir(PhysicalLayer.PIPE_PATH)

        except (FileNotFoundError, NotADirectoryError):
            pass

    def send(self, data: bytes) -> None:
        self.logger.debug(f"⌛ Sending {data=}...")

        file_owner = False
        try:
            os.mkfifo(PhysicalLayer.PIPE_PATH)
            file_owner = True

        except FileExistsError:
            pass

        with open(PhysicalLayer.PIPE_PATH, "wb") as f:
            f.write(data)

        if file_owner:
            os.rmdir(PhysicalLayer.PIPE_PATH)

        self.logger.debug("✅ Sent.")

    def receive(self) -> bytes:
        self.logger.debug("⌛ Receiving...")

        file_owner = False
        try:
            os.mkfifo(PhysicalLayer.PIPE_PATH)
            file_owner = True

        except FileExistsError:
            pass

        with open(PhysicalLayer.PIPE_PATH, "rb") as f:
            data = f.read()

        if file_owner:
            os.rmdir(PhysicalLayer.PIPE_PATH)

        self.logger.debug(f"✅ Received {data=}.")
        return data
