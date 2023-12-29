from logger import Logger
from layer_physical import PhysicalLayer


class LinkLayer(Logger):
    physical: PhysicalLayer

    # The MTU of Ethernet is generally 1500 bytes.
    HARDCODED_MTU = 1500

    def __init__(self):
        super().__init__()
        self.physical = PhysicalLayer()

    def send(self, data: bytes) -> None:
        self.logger.debug(f"⌛ Sending data=0x{data.hex()}...")
        self.logger.debug("⬇️  [Link->Physical]")
        self.physical.send(data)

    def receive(self) -> tuple[bytes, str]:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->Link]")
        self.logger.debug(f"✅ Received data=0x{data.hex()}")
        return data
