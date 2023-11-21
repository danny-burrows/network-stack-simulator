from __future__ import annotations
from logger import Logger
from layer_physical import PhysicalLayer


class TcpSocket(Logger):
    transport: TransportLayer

    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport

    def connect(self, addr: str) -> None:
        pass

    def bind(self, addr: str) -> None:
        pass

    def accept(self) -> None:
        pass

    def receive(self) -> bytes:
        return self.transport.receive()

    def send(self, data: bytes) -> None:
        self.transport.send(data)


class TransportLayer(Logger):
    physical: PhysicalLayer

    def __init__(self) -> None:
        super().__init__()
        self.physical = PhysicalLayer()

    def create_socket(self) -> TcpSocket:
        return TcpSocket(self)

    def receive(self) -> bytes:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->TCP]")
        self.logger.info(f"Received {data=}")
        return data

    def send(self, data: bytes) -> None:
        self.logger.info(f"Sending {data=}...")
        self.logger.debug("⬇️  [TCP->Physical]")
        self.physical.send(data)
