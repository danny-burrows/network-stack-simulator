from __future__ import annotations
from logger import Logger
from layer_physical import PhysicalLayer


class ARPTable:
    pass


class Interface:
    name: str
    bound_ip: str
    link: LinkLayer
    # TODO: Add hardcoded src MAC address
    # TODO: Add ARP table that matches dest IP to dest MAC
    arp: ARPTable

    def __init__(self, name: str):
        self.name = name
        self.link = LinkLayer()
        self.arp = ARPTable()

    def bind(self, ip: str):
        self.bound_ip = ip

    def send(self, data: bytes, dest_ip: str) -> None:
        # TODO: Use ARP table to get dest MAC
        # TODO: self.link.send(data, src_mac, dest_mac)
        self.link.send(data)


class LinkLayer(Logger):
    physical: PhysicalLayer

    # The MTU of Ethernet is generally 1500 bytes.
    HARDCODED_MTU = 1500

    def __init__(self):
        super().__init__()
        self.physical = PhysicalLayer()

    def send(self, data: bytes) -> None:
        # TODO: Change to take in src_mac and dest_mac
        self.logger.debug(f"⌛ Sending data=0x{data.hex()}...")
        self.logger.debug("⬇️  [Link->Physical]")
        self.physical.send(data)

    def receive(self) -> tuple[bytes, str]:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->Link]")
        self.logger.debug(f"✅ Received data=0x{data.hex()}")
        return data
