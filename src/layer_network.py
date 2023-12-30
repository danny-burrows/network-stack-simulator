from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
import struct

from logger import Logger
from layer_link import LinkLayerInterface


class DNSResourceRecord:
    """A DNS resource record.
    https://tools.ietf.org/html/rfc1035#section-4.1.3"""

    # Prefixed all with rr_ to avoid name collisions
    rr_name: str
    rr_type: str
    rr_class: str
    rr_ttl: int
    rr_rdata: str

    def __init__(self, rr_name: str, rr_type: str, rr_class: str, rr_ttl: int, rr_rdata: str):
        self.rr_name = rr_name
        self.rr_type = rr_type
        self.rr_class = rr_class
        self.rr_ttl = rr_ttl
        self.rr_rdata = rr_rdata

    @property
    def rr_rdlength(self) -> int:
        return len(self.rr_rdata)


class DNSARecord(DNSResourceRecord):
    """A DNS A record.
    https://tools.ietf.org/html/rfc1035#section-3.4.1"""

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, "A", "IN", rr_ttl, rr_rdata)


class DNSCNAMERecord(DNSResourceRecord):
    """A DNS CNAME record.
    https://tools.ietf.org/html/rfc1035#section-3.3.1"""

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, "CNAME", "IN", rr_ttl, rr_rdata)


class DNSServer:
    _records = set()

    def _find_record_from_name(name: str) -> DNSResourceRecord:
        # Find the first record with the given name
        for record in DNSServer._records:
            if record.rr_name == name:
                return record
        raise Exception(f"Record {name} not found")

    def resolve(host: str) -> str:
        # Resolve the host by following CNAME records until an A record is found.
        # This is a naive implementation that does not handle loops nor aims to replicate
        # the complexity of a real DNS server, which would need to handle things like caching and TTLs.
        # A top level overview can be seen here RFC 1034: https://tools.ietf.org/html/rfc1034#section-5.3.3
        while potential_record := DNSServer._find_record_from_name(host):
            if potential_record.rr_type == "A":
                return potential_record.rr_rdata
            elif potential_record.rr_type == "CNAME":
                host = potential_record.rr_rdata

        raise Exception(f"Could not resolve host {host}")

    def add_record(self, record: DNSResourceRecord) -> None:
        self._records.add(record)


@dataclass
class IPFlags:
    """Internal of IPPacket.
    IP flags are 3-bits packed into a single byte."""

    zero: bool = False  # Always False as specifed in RFC 791
    dont_fragment: bool = True  # Hardcoded to True as data fragmenting is not implemented
    more_fragments: bool = False

    @classmethod
    def from_bytes(cls, flags_bytes: bytes) -> IPFlags:
        # Unpack packed bytes as unsigned char bitmask then construct
        flags_bitmask = struct.unpack(">B", flags_bytes)[0]
        return cls.from_bitmask(flags_bitmask)

    @classmethod
    def from_bitmask(cls, flags_bitmask: int) -> IPFlags:
        # Extract first 3 bits into bools and construct
        return cls(
            zero=bool(flags_bitmask & (2**2)),
            dont_fragment=bool(flags_bitmask & (2**1)),
            more_fragments=bool(flags_bitmask & (2**0)),
        )

    def to_bytes(self) -> bytes:
        # Convert to bitmask then directly to bytes
        return bytes([self.to_bitmask()])

    def to_bitmask_list(self) -> [int]:
        # Convert to list of flags as bits
        return [int(v) for v in [self.zero, self.dont_fragment, self.more_fragments]]

    def to_bitmask(self) -> int:
        # Convert to bitmask for flags
        return sum(v * 2**i for i, v in enumerate(self.to_bitmask_list()[::-1]))

    def to_string(self) -> str:
        return "".join(str(i) for i in self.to_bitmask_list())

    def to_nice_string(self) -> str:
        return f"({', '.join(flag_name.upper() for flag_name, flag_value in vars(self).items() if flag_value)})"

    def __int__(self) -> int:
        return self.to_bitmask()

    def __str__(self) -> str:
        return self.to_string()

    def __eq__(self, __value: IPFlags) -> bool:
        return self.to_bitmask() == __value.to_bitmask()


@dataclass
class IPOption:
    """Internal of IPPacket.
    IP options are variable length, packed into words."""

    class Kind(IntEnum):
        END_OF_OPTION_LIST = 0
        NO_OPERATION = 1
        SECURITY = 2
        LOOSE_SOURCE_ROUTING = 3
        STRICT_SOURCE_ROUTING = 4
        RECORD_ROUTE = 5
        STREAM_ID = 6
        INTERNET_TIMESTAMP = 7

    SINGLE_BYTE_KINDS = set((Kind.END_OF_OPTION_LIST, Kind.NO_OPERATION))
    ALL_KINDS = set(
        (
            Kind.END_OF_OPTION_LIST,
            Kind.NO_OPERATION,
            Kind.SECURITY,
            Kind.LOOSE_SOURCE_ROUTING,
            Kind.STRICT_SOURCE_ROUTING,
            Kind.RECORD_ROUTE,
            Kind.STREAM_ID,
            Kind.INTERNET_TIMESTAMP,
        )
    )

    @staticmethod
    def from_bytes(option_bytes: bytes) -> IPOption:
        (
            option,
            _remaining_bytes,
        ) = IPOption.from_bytes_with_remainder(option_bytes)

        return option

    @staticmethod
    def from_bytes_with_remainder(option_bytes: bytes) -> tuple[IPOption, bytes]:
        # Extract option kind from front of option_bytes, and return along with the remainder.

        # Byte 1: Option kind
        option_kind = option_bytes[0]

        if option_kind in IPOption.SINGLE_BYTE_KINDS:
            return IPOption(kind=option_kind), option_bytes[1:]

        if option_kind not in IPOption.ALL_KINDS:
            raise NotImplementedError(f"Unsupported option kind: {option_kind}")

        if len(option_bytes) <= 1:
            raise ValueError("Option kind requires length field but no length was specified!")

        # Byte 2: Length of data
        option_length = option_bytes[1]

        # Byte 3+: Option data
        option_data = option_bytes[2:option_length]

        return IPOption(kind=option_kind, data=option_data), option_bytes[option_length:]

    kind: Kind
    data: bytes = bytes()
    len: int = field(init=False)

    def __post_init__(self):
        self.len = 1 if self.kind in IPOption.SINGLE_BYTE_KINDS else 2 + len(self.data)

    def to_string(self) -> str:
        if self.kind in IPOption.SINGLE_BYTE_KINDS:
            return f"kind={IPOption.Kind(self.kind).name}"
        else:
            return f"kind={IPOption.Kind(self.kind).name} len={self.len} data=0x{self.data.hex()}"

    def to_bytes(self) -> bytes:
        if self.kind in IPOption.SINGLE_BYTE_KINDS:
            return bytes([self.kind])
        else:
            return bytes([self.kind, self.len]) + self.data

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return self.to_string()


@dataclass
class IPPacket:
    """Representation of a IP packet used by IPProtocol."""

    version: int
    ihl: int
    type_of_service: int
    total_length: int
    identification: int
    flags: IPFlags
    fragment_offset: int
    time_to_live: int
    protocol: int
    header_checksum: int
    source_address: int
    destination_address: int
    options: IPOption
    data: bytes

    def to_string(self) -> str:
        def str_list(lst):
            return [f"{str_list(e)}" if isinstance(e, list) else str(e) for e in lst]

        return "|".join(str_list(self.__dict__.values()))

    def to_bytes(self) -> bytes:
        # Pack version, ihl, and type of service
        version_ihl_tos_bytes = struct.pack(
            ">BBH",
            (self.version << 4) + self.ihl,
            self.type_of_service,
            self.total_length,
        )

        # Pack identification, flags, and fragment offset
        identification_flags_fragment_bytes = struct.pack(
            ">HH",
            self.identification,
            self.flags.to_bitmask() << 13 + self.fragment_offset,
        )

        # Pack time to live, protocol, and header checksum
        ttl_protocol_checksum_bytes = struct.pack(
            ">BBH",
            self.time_to_live,
            self.protocol,
            self.header_checksum,
        )

        # Pack source and destination address
        source_dest_bytes = struct.pack(
            ">II",
            self.source_address,
            self.destination_address,
        )

        # Pack options bytes up
        options_bytes = [o.to_bytes() for o in self.options]

        # Calc padding needed to ensure options are padded to the nearest 4-byte word
        length_of_options_bytes = sum(len(o) for o in options_bytes)

        # Get the nearest number of 4-byte words needed to hold all options
        options_space_bytes = -4 * (length_of_options_bytes // -4)
        options_padding = bytes(options_space_bytes - length_of_options_bytes)

        # Construct header with all packed bits, including options and options padding
        header = (
            version_ihl_tos_bytes
            + identification_flags_fragment_bytes
            + ttl_protocol_checksum_bytes
            + source_dest_bytes
        )
        for option_bytes in options_bytes:
            header += option_bytes
        header += options_padding

        # Return final packed header + data bytes
        return header + self.data

    def __str__(self) -> str:
        return self.to_string()


class IPProtocol:
    """Implementation of the IP protocol as specified in RFC 791.

    This implementation is limited to IPv4 and does not support data fragmenting.

    RFC 791: https://datatracker.ietf.org/doc/html/rfc791
    """

    @staticmethod
    def ip_to_int(host: str) -> int:
        # Split the IP address into its four bytes and concatenate
        bytes = host.split(".")
        return (int(bytes[0]) << 24) + (int(bytes[1]) << 16) + (int(bytes[2]) << 8) + int(bytes[3])

    @staticmethod
    def int_to_ip(host_int: int) -> str:
        # Split the int into its four bytes and concatenate
        return f"{(host_int >> 24) & 0xFF}.{(host_int >> 16) & 0xFF}.{(host_int >> 8) & 0xFF}.{host_int & 0xFF}"

    @staticmethod
    def calculate_checksum(packet: IPPacket) -> int:
        # Calculate checksum using method described in RFC

        # For purposes of computing the checksum, the value of the packet checksum field is zero.
        tmp_checksum = packet.header_checksum
        packet.header_checksum = 0

        # Calculate checksum.
        # The checksum field is the 16 bit one's complement of the one's
        # complement sum of all 16 bit words in the header.
        checksum = 0
        packet_bytes = packet.to_bytes()
        for i in range(0, len(packet_bytes), 2):
            if i + 2 <= len(packet_bytes):
                checksum += struct.unpack(">H", packet_bytes[i : i + 2])[0]
            else:
                # Handle the case where there's only one byte left
                checksum += packet_bytes[i]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Restore checksum
        packet.header_checksum = tmp_checksum

        return checksum

    @staticmethod
    def create_ip_packet(
        src_ip: str,
        dest_ip: str,
        data: bytes = bytes(),
        options: list[IPOption] = [],
    ) -> IPPacket:
        # Calculate the number of bytes in the header
        MIN_IP_HEADER_BYTES = 20
        length_of_options_bytes = sum(len(o) for o in options)

        # Check options are valid and align to the nearest 4 byte word.
        if options != [] and length_of_options_bytes % 4 != 0 and options[-1].kind != IPOption.Kind.END_OF_OPTION_LIST:
            raise Exception(
                "If options do not align to the nearest 4 byte word they must contain an END_OF_OPTION_LIST option!"
            )

        # Get the nearest number of 4-byte words needed to hold all options
        options_space_bytes = -4 * (length_of_options_bytes // -4)

        # Get the data offset in 4-byte words
        ihl = (MIN_IP_HEADER_BYTES + options_space_bytes) // 4

        return IPPacket(
            version=4,  # Hardcoded to IPv4 for this simulation (also this is the version covered by RFC 791)
            ihl=ihl,
            type_of_service=0,  # Hardcoded to 0 (Routine) as described in RFC 791
            total_length=20 + length_of_options_bytes + len(data),
            identification=0,  # Hardcoded to 0 as unused as data fragmenting is not implemented
            flags=IPFlags(),  # See IPFlags for default values - hardcoded for this simulation
            fragment_offset=0,  # Hardcoded to 0 as unused as data fragmenting is not implemented
            time_to_live=64,
            protocol=6,  # Hardcoded to TCP (6)for this simulation more details on Assigned number: https://datatracker.ietf.org/doc/html/rfc790
            header_checksum=0,  # Checksum calculated outside this function to accomodate potential changes to header state such as TTL
            source_address=IPProtocol.ip_to_int(src_ip),
            destination_address=IPProtocol.ip_to_int(dest_ip),
            options=options,
            data=data,
        )

    @staticmethod
    def parse_ip_packet(packet_bytes: bytes) -> IPPacket:
        # View first 20 bytes for header and parse variables
        (
            version_ihl,
            type_of_service,
            total_length,
            identification,
            flags_fragment_offset,
            time_to_live,
            protocol,
            header_checksum,
            source_address,
            destination_address,
        ) = struct.unpack(">BBHHHBBHII", packet_bytes[:20])

        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        flags = IPFlags.from_bytes(bytes([flags_fragment_offset >> 13]))
        fragment_offset = flags_fragment_offset & 0x1FFF

        options_bytes = packet_bytes[20 : ihl * 4]
        options: list[IPOption] = []
        while options_bytes:
            option, options_bytes = IPOption.from_bytes_with_remainder(options_bytes)
            options.append(option)

            # Stop parsing options when reached END_OF_OPTION_LIST
            if option.kind == IPOption.Kind.END_OF_OPTION_LIST:
                break

        data = packet_bytes[ihl * 4 :]

        return IPPacket(
            version=version,
            ihl=ihl,
            type_of_service=type_of_service,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            time_to_live=time_to_live,
            protocol=protocol,
            header_checksum=header_checksum,
            source_address=source_address,
            destination_address=destination_address,
            options=options,
            data=data,
        )

    @staticmethod
    def get_exam_string(packet: IPPacket, note: str = "") -> str:
        def parse_value(field_name, value):
            if field_name == "flags":
                return f"{value.to_string()} {value.to_nice_string()}"
            elif field_name == "source_address" or field_name == "destination_address":
                return f"{value} ({IPProtocol.int_to_ip(value)})"
            elif field_name == "options" and value:
                return "".join(f"\n     |- {option.to_string()}" for option in value)
            elif field_name == "version" and value == 4:
                return "4 (IPv4)"
            elif field_name == "protocol" and value == 6:
                return "6 (TCP)"
            elif value is not None:
                return str(value)

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(packet).items()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str))

        return "\n".join(
            (
                f"------------{note_str} Network Layer Packet {note_padding}",
                f"RAW DATA: {packet.to_bytes()}",
                "PROTOCOL: IP",
                f"PACKET STRING: {packet.to_string()}",
                "PACKET FIELDS:",
                message_fields,
                "---------- END Network Layer Packet ----------",
            )
        )


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


class NetworkLayer(Logger):
    dns_server: DNSServer
    routing_table: RoutingTable
    interfaces: dict[str, LinkLayerInterface]

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
        self.interfaces[name] = LinkLayerInterface(name)

    def plug_in_and_perform_dhcp_discovery(self, is_client: bool = False) -> None:
        # Exam specified IP Range (CIDR): 192.168.1.0/8 == (192.0.0.0/8)
        SUBNET_IP = "192.0.0.0"
        SUBNET_MASK = "255.0.0.0"
        SERVER_IP_ADDRESS = "192.168.0.6"
        CLIENT_IP_ADDRESS = "192.168.0.4"

        # Simulates plugging in the physical cables and performing ARP discovery to find the MAC address of the other host
        self.interfaces["eth0"].plug_in_and_perform_arp_discovery(is_client)

        # Function to generate an IP in range specified by exam spec
        # def generate_ip_in_range() -> str:
        #     subnet_mask_int = IPProtocol.ip_to_int(subnet_mask)
        #     subnet_ip_int = IPProtocol.ip_to_int(subnet_ip)
        #     ip_int = random.randint(subnet_ip_int, subnet_ip_int + (2**32 - subnet_mask_int))
        #     return IPProtocol.int_to_ip(ip_int)

        # Find default gateway (hardcoded for our simulation)
        # In a real network, the default gateway IP Address would be found using ARP at the link layer
        default_gateway_ip = "192.168.1.20"
        self.logger.debug(f"Discovered default gateway '{default_gateway_ip}'")

        # Add default gateway to routing table
        self.routing_table.add_route("0.0.0.0", default_gateway_ip, SUBNET_MASK, "UG", 600, "eth0")

        # Add local subnet to routing table
        self.routing_table.add_route(SUBNET_IP, "0.0.0.0", SUBNET_MASK, "U", 600, "eth0")

        # In a real scenario the DHCP server would be found using various methods and
        # the DHCP server would assign an IP address to the client.
        # For our simulation we hardcode it based on whether client or server.
        eth0_ip = CLIENT_IP_ADDRESS if is_client else SERVER_IP_ADDRESS
        self.logger.debug(f"Discovered IP address '{eth0_ip}' for interface eth0")

        # Bind interface to discovered IP
        self.interfaces["eth0"].bind(eth0_ip)

        # For our simulation we need to populate the DNS server with records manually.
        # In a real scenario the DNS server would be found using various methods and
        # the DNS server would be populated with records.
        if is_client:
            self.dns_server.add_record(DNSARecord("gollum.mordor", 60, SERVER_IP_ADDRESS))
            self.dns_server.add_record(DNSCNAMERecord("www.gollum.mordor", 60, "gollum.mordor"))
            self.dns_server.add_record(DNSCNAMERecord("rincewind.fourex.disc.atuin", 60, "gollum.mordor"))

    def send(self, dest_ip: str, data: bytes) -> None:
        # Resolve the route for dest IP
        route = self.routing_table.match_route(dest_ip)
        if not route:
            raise Exception(f"No route found for destination {dest_ip}")

        # Get the interface for the route
        assert route.iface in self.interfaces
        interface = self.interfaces[route.iface]

        packet = IPProtocol.create_ip_packet(interface.bound_ip, dest_ip, data)

        # Calculate checksum
        packet.header_checksum = IPProtocol.calculate_checksum(packet)

        # Send message down the interface
        self.logger.debug(
            f"⌛ Sending IP packet on '{interface.name}' from '{interface.bound_ip}' to '{dest_ip}' packet={packet.to_string()}..."
        )
        self.logger.debug("⬇️ [Network->Link]")
        self.exam_logger.info(IPProtocol.get_exam_string(packet, note="SENDING"))
        interface.send(packet.to_bytes(), dest_ip)

    def receive(self, src_ip: str) -> tuple[bytes, str]:
        # Get the interface for the source IP
        interface = None
        for interface in self.interfaces.values():
            if interface.bound_ip == src_ip:
                break

        # Receive message from the interface
        data = interface.receive()
        self.logger.debug("⬆️ [Link->Network]")

        packet = IPProtocol.parse_ip_packet(data)
        packet_src_ip = IPProtocol.int_to_ip(packet.source_address)
        self.exam_logger.info(IPProtocol.get_exam_string(packet, note="RECEIVED"))

        # Verify checksum
        calculated_checksum = IPProtocol.calculate_checksum(packet)
        if calculated_checksum != packet.header_checksum:
            raise Exception(
                f"Checksum mismatch! Calculated checksum {calculated_checksum} does not match packet checksum {packet.header_checksum}"
            )

        # Simulates the packet being dropped if the TTL is 0
        packet.time_to_live -= 1
        if packet.time_to_live == 0:
            self.logger.debug(
                f"❌ Dropped packet on '{interface.name}' from '{packet_src_ip}' to '{interface.bound_ip}' due to TTL being 0 packet={packet.to_string()}"
            )
            raise Exception("Simulation Error: Packet dropped due to TTL being 0")

        # Return final packet and IP
        self.logger.debug(
            f"✅ Received packet on '{interface.name}' from '{packet_src_ip}' to '{interface.bound_ip}' packet={packet.to_string()}"
        )
        return packet.data, packet_src_ip
