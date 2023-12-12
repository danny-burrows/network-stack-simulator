from __future__ import annotations
from dataclasses import dataclass

from logger import Logger
from layer_physical import PhysicalLayer


class DNSResourceRecord:
    # https://tools.ietf.org/html/rfc1035#section-4.1.3
    # Prefixed all with rr_ to avoid name collisions
    rr_name: str
    rr_type: str
    rr_class: str
    rr_ttl: int
    rr_rdata: str

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        self.rr_name = rr_name
        self.rr_ttl = rr_ttl
        self.rr_rdata = rr_rdata

    @property
    def rr_rdlength(self) -> int:
        return len(self.rr_rdata)


class DNSARecord(DNSResourceRecord):
    rr_type: str = "A"
    rr_class: str = "IN"

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, rr_ttl, rr_rdata)


class DNSCNAMERecord(DNSResourceRecord):
    rr_type: str = "CNAME"
    rr_class: str = "IN"

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, rr_ttl, rr_rdata)


class DNSServer:
    _records = set(
        (
            DNSARecord("gollum.mordor", 60, "192.168.0.6"),
            DNSCNAMERecord("www.gollum.mordor", 60, "gollum.mordor"),
            DNSCNAMERecord("rincewind.fourex.disc.atuin", 60, "gollum.mordor"),
        )
    )

    @staticmethod
    def _find_record_from_name(name: str) -> DNSResourceRecord:
        for record in DNSServer._records:
            if record.rr_name == name:
                return record
        raise Exception(f"Record {name} not found")

    @staticmethod
    def resolve(host: str) -> str:
        while potential_record := DNSServer._find_record_from_name(host):
            if potential_record.rr_type == "A":
                return potential_record.rr_rdata
            elif potential_record.rr_type == "CNAME":
                host = potential_record.rr_rdata
        raise Exception(f"Could not resolve host {host}")


#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |Version|  IHL  |Type of Service|          Total Length         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |         Identification        |Flags|      Fragment Offset    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Time to Live |    Protocol   |         Header Checksum       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                       Source Address                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Destination Address                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Options                    |    Padding    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
@dataclass
class IpPacket:
    pass


class IpProtocol:
    @staticmethod
    def create_ip_packet(src_ip: str, dest_ip: str, data: bytes) -> IpPacket:
        pass

    @staticmethod
    def parse_ip_packet(packet_bytes: bytes) -> IpPacket:
        pass

    def get_exam_string(ip_packet: IpPacket, note: str = "") -> str:
        pass


# Kernel IP routing table
# Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
# 0.0.0.0         192.168.1.10    0.0.0.0         UG    600    0        0 eth0
# 192.168.1.0     0.0.0.0         255.0.0.0       U     600    0        0 eth0
class RoutingTable:
    pass


# Create interfaces "eth0" e.t.c. to lookup and send to.
# These interfaces will be a simple class with the physical layer inside
# Interfaces will "contain" ethernet layer.
class Interface:
    # Contains a physical layer
    # Contains config about which IP its bound to...
    # Info simular to the output of `ip a`
    pass


class NetworkLayer(Logger):
    @staticmethod
    def ip_to_int(host: str) -> int:
        # Split the IP address into its four bytes and concatenate
        bytes = host.split(".")
        return (int(bytes[0]) << 24) + (int(bytes[1]) << 16) + (int(bytes[2]) << 8) + int(bytes[3])

    # routing_table: RoutingTable TODO!
    physical: PhysicalLayer
    src_ip: str
    dest_ip: str

    def __init__(self):
        super().__init__()

        # TODO: self.routing_table = RoutingTable()
        self.physical = PhysicalLayer()

    def plug_in_and_perform_dhcp_discovery():
        # TODO: Comment on how this simulates DHCP
        # TODO: Bind my interface (eth0) to a random IP
        # TODO: Construct routing table based on DHCP "response" and hardcoded /8 subset mask
        pass

    def send(self, dest_ip: str, data: bytes) -> None:
        # TODO: Send data via the interface that can reach dest_ip...
        # This is found using a routing table specified above

        # TODO: Calculate checksums

        self.logger.debug(f"⌛ Sending data=0x{data.hex()} from {NetworkLayer.src_ip} to host {dest_ip}...")
        self.logger.debug("⬇️  [Network->Physical]")
        self.physical.send(data)

    def receive(self, src_ip: str) -> tuple[bytes, str]:
        # TODO: Recieve data via the interface bound to src_ip...

        # TODO: Validate checksums

        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->Network]")
        self.logger.debug(f"✅ Received data=0x{data.hex()} to host {src_ip} from {NetworkLayer.dest_ip}")
        return data, NetworkLayer.dest_ip
