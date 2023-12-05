from logger import Logger
from layer_physical import PhysicalLayer


class NetworkLayer(Logger):
    @staticmethod
    def host_to_int(host: str) -> int:
        # Split the IP address into its four bytes and concatenate
        bytes = host.split(".")
        return (int(bytes[0]) << 24) + (int(bytes[1]) << 16) + (int(bytes[2]) << 8) + int(bytes[3])

    physical: PhysicalLayer
    src_host: str
    dest_host: str

    def __init__(self):
        super().__init__()
        self.physical = PhysicalLayer()

    def send(self, data: bytes) -> None:
        self.logger.debug(f"⌛ Sending data=0x{data.hex()}...")
        self.logger.debug("⬇️  [Network->Physical]")
        self.physical.send(data)

    def receive(self) -> tuple[bytes, str]:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->Network]")
        self.logger.debug(f"✅ Received data=0x{data.hex()}")
        return data, NetworkLayer.dest_host
