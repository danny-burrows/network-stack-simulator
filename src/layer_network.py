from __future__ import annotations
from dataclasses import dataclass
import random
import struct

from logger import Logger
from layer_link import LinkLayer


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
    _records = set()

    def _find_record_from_name(name: str) -> DNSResourceRecord:
        for record in DNSServer._records:
            if record.rr_name == name:
                return record
        raise Exception(f"Record {name} not found")

    def resolve(host: str) -> str:
        while potential_record := DNSServer._find_record_from_name(host):
            if potential_record.rr_type == "A":
                return potential_record.rr_rdata
            elif potential_record.rr_type == "CNAME":
                host = potential_record.rr_rdata
        raise Exception(f"Could not resolve host {host}")

    def add_record(self, record: DNSResourceRecord) -> None:
        self._records.add(record)


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
class IPPacket:
    pass


class IPProtocol:
    @staticmethod
    def ip_to_int(host: str) -> int:
        # Split the IP address into its four bytes and concatenate
        bytes = host.split(".")
        return (int(bytes[0]) << 24) + (int(bytes[1]) << 16) + (int(bytes[2]) << 8) + int(bytes[3])

    def int_to_ip(host_int: int) -> str:
        # Split the int into its four bytes and concatenate
        return f"{(host_int >> 24) & 0xFF}.{(host_int >> 16) & 0xFF}.{(host_int >> 8) & 0xFF}.{host_int & 0xFF}"

    @staticmethod
    def create_ip_packet(src_ip: str, dest_ip: str, data: bytes) -> IPPacket:
        pass

    @staticmethod
    def parse_ip_packet(packet_bytes: bytes) -> IPPacket:
        pass

    def get_exam_string(ip_packet: IPPacket, note: str = "") -> str:
        pass


@dataclass
class Route:
    dest: str
    gateway: str
    genmask: str
    flags: str
    metric: int
    iface: str
    dest_int: int = 0
    genmask_int: int = 0

    def __post_init__(self):
        self.dest_int = IPProtocol.ip_to_int(self.dest)
        self.genmask_int = IPProtocol.ip_to_int(self.genmask)


class RoutingTable:
    table: list[Route] = []

    def add_route(self, dest: str, gateway: str, genmask: str, flags: str, metric: int, iface: str) -> None:
        self.table.append(Route(dest, gateway, genmask, flags, metric, iface))

    def match_route(self, dest_ip: str) -> Route:
        dest_ip_int = IPProtocol.ip_to_int(dest_ip)
        best_match = None
        for route in self.table:
            # Check if the destination IP is in the subnet of the route
            if (route.dest_int & route.genmask_int) == (dest_ip_int & route.genmask_int):
                # The best match is the one with the most 1s in the genmask or the lowest metric
                if (
                    (best_match is None)
                    or (route.genmask_int > best_match.genmask_int)
                    or (route.metric < best_match.metric)
                ):
                    best_match = route

        return best_match


class Interface:
    name: str
    bound_ip: str
    link: LinkLayer

    def __init__(self, name: str):
        self.name = name
        self.link = LinkLayer()

    def bind(self, ip: str):
        self.bound_ip = ip


class NetworkLayer(Logger):
    dns_server: DNSServer
    routing_table: RoutingTable
    interfaces: dict[str, Interface]

    @property
    def local_ip(self) -> str:
        return self.interfaces["eth0"].bound_ip

    def __init__(self):
        super().__init__()

        self.dns_server = DNSServer()
        self.routing_table = RoutingTable()
        self.interfaces = {}

        self._add_interface("eth0")

    def _add_interface(self, name: str):
        self.interfaces[name] = Interface(name)

    def plug_in_and_perform_dhcp_discovery(self, client: bool = False) -> None:
        # Function to generate an IP in range specified by exam spec
        # Exam specified IP Range (CIDR): 192.168.1.0/8 == (192.0.0.0/8)
        subnet_ip = "192.0.0.0"
        subnet_mask = "255.0.0.0"

        def generate_ip_in_range() -> str:
            subnet_mask_int = IPProtocol.ip_to_int(subnet_mask)
            subnet_ip_int = IPProtocol.ip_to_int(subnet_ip)
            ip_int = random.randint(subnet_ip_int, subnet_ip_int + (2**32 - subnet_mask_int))
            return IPProtocol.int_to_ip(ip_int)

        # Find default gateway  (hardcoded for our simulation)
        # TODO: Comment about how we would actually find the gateway
        default_gateway_ip = "192.168.1.20"
        self.logger.debug(f"Discovered default gateway '{default_gateway_ip}'")

        # Add default gateway to routing table
        self.routing_table.add_route("0.0.0.0", default_gateway_ip, subnet_mask, "UG", 600, "eth0")

        # Add local subnet to routing table
        self.routing_table.add_route(subnet_ip, "0.0.0.0", subnet_mask, "U", 600, "eth0")

        # Using DHCP discover IP address (hardcoded for our simulation)
        # TODO: Comment on how this would really happen with  DHCP
        eth0_ip = generate_ip_in_range()
        self.logger.debug(f"Discovered IP address '{eth0_ip}' for interface eth0")

        # Bind interface to discovered IP and update routing table accordingly
        self.interfaces["eth0"].bind(eth0_ip)

        # For our simulation we need to communicate the servers IP over to client
        # TODO: Comment on how this would really happen with DHCP
        # TODO: There may be a better way to do this in this simulation
        # TODO: Ensure exam logging is doing what we expect
        # If client then populate DNS server with records
        if client:
            ip = IPProtocol.int_to_ip(struct.unpack(">I", self.interfaces["eth0"].link.receive())[0])
            self.logger.debug(f"Received IP from server '{ip}'.")
            self.dns_server.add_record(DNSARecord("gollum.mordor", 60, ip))
            self.dns_server.add_record(DNSCNAMERecord("www.gollum.mordor", 60, "gollum.mordor"))
            self.dns_server.add_record(DNSCNAMERecord("rincewind.fourex.disc.atuin", 60, "gollum.mordor"))
        # If server then send IP to client
        else:
            self.logger.debug(f"Sending IP to client '{self.local_ip}'...")
            self.interfaces["eth0"].link.send(struct.pack(">I", IPProtocol.ip_to_int(self.local_ip)))

    def send(self, dest_ip: str, data: bytes) -> None:
        # TODO: Calculate checksums

        # Resolve the route for dest IP
        route = self.routing_table.match_route(dest_ip)
        if not route:
            raise Exception(f"No route found for destination {dest_ip}")

        # Get the interface for the route
        assert route.iface in self.interfaces
        interface = self.interfaces[route.iface]

        # TODO: Create packet with data

        # Send message down the interface
        self.logger.debug(
            f"⌛ Sending data on '{interface.name}' from '{interface.bound_ip}' to '{dest_ip}' data=0x{data.hex()}..."
        )
        self.logger.debug("⬇️ [Network->Link]")
        interface.link.send(data)

    def receive(self, src_ip: str) -> tuple[bytes, str]:
        # Get the interface for the source IP
        interface = None
        for interface in self.interfaces.values():
            if interface.bound_ip == src_ip:
                break

        # Receive message from the interface
        data = interface.link.receive()
        self.logger.debug("⬆️ [Link->Network]")

        # TODO: Parse packet from data and get src IP
        packet_src_ip = "100.100.100.100"

        # TODO: Validate checksums

        # Return final packet and IP
        self.logger.debug(
            f"✅ Received data on '{interface.name}' from '{packet_src_ip}' to '{interface.bound_ip}' data=0x{data.hex()}"
        )
        return data, packet_src_ip
