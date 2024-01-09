from __future__ import annotations
from dataclasses import dataclass
import struct

from logger import Logger
from layer_physical import PhysicalLayer


class ARPTable:
    """Simple simulated implementation of an ARP table. Usually this would be stored in, and managed by, the the operating system kernel."""

    def __init__(self):
        self.table = {}

    def add(self, ip: str, mac: int):
        self.table[ip] = mac

    def get(self, ip: str) -> int:
        return self.table[ip]


@dataclass
class EthernetFrame:
    """Representation of a Ethernet frame used by EthernetProtocol."""

    preamble: bytes  # Includes the start of frame delimiter (SFD), see EthernetProtocol for details
    destination_mac: int
    source_mac: int
    ether_type: int  # According to the standard this field indicates the type of protocol used in transmission
    data: bytes
    fcs: int  # Frame check sequence

    def to_string(self) -> str:
        def str_list(lst):
            return [f"{str_list(e)}" if isinstance(e, list) else str(e) for e in lst]

        return "|".join(str_list(self.__dict__.values()))

    def to_bytes(self) -> bytes:
        return (
            self.preamble
            + struct.pack(">Q", self.destination_mac)
            + struct.pack(">Q", self.source_mac)
            + struct.pack(">H", self.ether_type)
            + self.data
            + struct.pack(">I", self.fcs)
        )

    def __str__(self) -> str:
        return self.to_string()


class EthernetProtocol:
    """Implementation of the Ethernet protocol.

    This implementation borrows heavily from the IEEE 802.3 communication standards.
    References can be found here: https://en.wikipedia.org/wiki/IEEE_802.3
    """

    ETHER_SFD = 0b10101011
    ETHER_PREAMBLE = bytes([0b10101010] * 7 + [ETHER_SFD])

    @staticmethod
    def mac_address_to_int(mac_address_string: str) -> int:
        """Converts a MAC address string to an integer."""
        return int(mac_address_string.replace(":", ""), 16)

    @staticmethod
    def int_to_mac_address(mac_address_int: int) -> str:
        """Converts a MAC address integer to a string."""
        return ":".join([f"{(mac_address_int >> (i * 8)) & 0xFF:02X}" for i in range(5, -1, -1)])

    @staticmethod
    def calculate_fcs(frame: EthernetFrame) -> int:
        """Calculates the frame check sequence (FCS) for a given frame using 32 bit CRC."""

        # For purposes of computing the fcs the value of the frame fcs field is zero.
        # Can then get the frame bytes with fcs = 0.
        tmp_fcs = frame.fcs
        frame.fcs = 0
        frame_bytes = frame.to_bytes()

        # perform crc 32 calculation
        # - Data comes in big-endian format
        crc = 0xFFFFFFFF
        polynomial = 0xEDB88320
        for byte in frame_bytes:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc = crc >> 1

        # Invert the bits
        crc = crc ^ 0xFFFFFFFF

        frame.fcs = tmp_fcs
        return crc

    @staticmethod
    def create_ethernet_frame(
        src_mac_address: str,
        dest_mac_address: str,
        data: bytes = bytes(),
    ) -> EthernetFrame:
        ether_type = 0x0800  # IPv4 as stated in https://en.wikipedia.org/wiki/EtherType

        return EthernetFrame(
            preamble=EthernetProtocol.ETHER_PREAMBLE,
            destination_mac=EthernetProtocol.mac_address_to_int(dest_mac_address),
            source_mac=EthernetProtocol.mac_address_to_int(src_mac_address),
            ether_type=ether_type,
            data=data,
            fcs=0,  # CRC calculated outside this function
        )

    @staticmethod
    def parse_ethernet_frame(ethernet_frame_bytes: bytes) -> EthernetFrame:
        preamble = ethernet_frame_bytes[: len(EthernetProtocol.ETHER_PREAMBLE)]
        destination_mac = struct.unpack(">Q", ethernet_frame_bytes[8:16])[0]
        source_mac = struct.unpack(">Q", ethernet_frame_bytes[16:24])[0]
        ether_type = struct.unpack(">H", ethernet_frame_bytes[24:26])[0]
        data = ethernet_frame_bytes[26:-4]
        fcs = struct.unpack(">I", ethernet_frame_bytes[-4:])[0]

        return EthernetFrame(
            preamble=preamble,
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ether_type,
            data=data,
            fcs=fcs,
        )

    @staticmethod
    def get_exam_string(frame: EthernetFrame, note: str = "") -> str:
        def parse_value(field_name, value):
            if field_name == "destination_mac" or field_name == "source_mac":
                return f"{value} ({EthernetProtocol.int_to_mac_address(value)})"
            elif field_name == "ether_type" and value == 2048:
                return f"{value} (IPv4)"
            elif value is not None:
                return str(value)

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(frame).items()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str))

        return "\n".join(
            (
                f"------------{note_str} Link Layer Frame {note_padding}",
                f"RAW DATA: {frame.to_bytes()}",
                "PROTOCOL: Ethernet",
                f"FRAME STRING: {frame.to_string()}",
                "FRAME FIELDS:",
                message_fields,
                "---------- END Link Layer Frame ----------",
            )
        )


class LinkLayerInterface(Logger):
    name: str
    bound_ip: str
    arp: ARPTable

    # Default value for MTU is usualy 1500 but this simulates the MTU of a badly perfoming network.
    HARDCODED_MTU = 750

    def __init__(self, name: str):
        super().__init__()
        self.name = name
        self.arp = ARPTable()
        self.physical_layer = PhysicalLayer()

    def plug_in_and_perform_arp_discovery(self, is_client: bool) -> None:
        """This function simulates the process of plugging in a NIC (Network Interface Card) and performing the initial ARP discovery over the LAN."""

        SERVER_MAC_ADDRESS = "02:00:00:00:00:00"
        SERVER_IP_ADDRESS = "192.168.0.6"
        CLIENT_MAC_ADDRESS = "02:00:00:00:00:01"
        CLIENT_IP_ADDRESS = "192.168.0.4"

        # This mac address would normally be "burned into" the network interface and
        # although it could be spoofed shouldn't be able to change.
        self.MAC_ADDRESS = CLIENT_MAC_ADDRESS if is_client else SERVER_MAC_ADDRESS

        # In a real system this process would involve using the ARP protocol to send
        # requests and discover other hosts on the LAN. In this case we add the required
        # entries to the ARP table to be able to contact the other host in this simulation.
        dest_ip = SERVER_IP_ADDRESS if is_client else CLIENT_IP_ADDRESS
        dest_mac = SERVER_MAC_ADDRESS if is_client else CLIENT_MAC_ADDRESS
        self.arp.add(dest_ip, dest_mac)

    def bind(self, ip: str):
        self.bound_ip = ip

    def send(self, data: bytes, dest_ip: str) -> None:
        dest_mac = self.arp.get(dest_ip)
        frame = EthernetProtocol.create_ethernet_frame(
            src_mac_address=self.MAC_ADDRESS,
            dest_mac_address=dest_mac,
            data=data,
        )

        # Calculate fcs
        frame.fcs = EthernetProtocol.calculate_fcs(frame)

        self.logger.debug(
            f"⌛ Sending Ethernet frame from '{self.MAC_ADDRESS}' to '{dest_mac}' frame={frame.to_string()}..."
        )
        self.logger.debug("⬇️ [Link->Physical]")
        self.exam_logger.info(EthernetProtocol.get_exam_string(frame, note="SENDING"))
        self.physical_layer.send(frame.to_bytes())

    def receive(self) -> bytes:
        data = self.physical_layer.receive()
        self.logger.debug("⬆️ [Physical->Link]")

        frame = EthernetProtocol.parse_ethernet_frame(data)

        # Verify fcs
        calculated_fcs = EthernetProtocol.calculate_fcs(frame)
        if calculated_fcs != frame.fcs:
            raise Exception(f"FCS mismatch! Calculated fcs {calculated_fcs} does not match frame fcs {frame.fcs}")

        self.exam_logger.info(EthernetProtocol.get_exam_string(frame, note="RECEIVED"))
        self.logger.debug(
            f"✅ Received frame from '{EthernetProtocol.int_to_mac_address(frame.source_mac)}' to '{self.MAC_ADDRESS}' packet={frame.to_string()}"
        )
        return frame.data
