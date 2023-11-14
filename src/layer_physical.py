from logger import Logger


class PhysicalLayer(Logger):
    def __init__(self) -> None:
        super().__init__()

    def send(self, data: bytes) -> None:
        self.logger.info(f"Sending data {data=}")

    def receive(self) -> None:
        self.logger.info("Receiving data...")
        while True:
            pass
