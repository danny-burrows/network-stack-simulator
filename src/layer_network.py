from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
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
        # Extract first 6 bits into bools and construct
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
        return self.__str__()

    def to_nice_string(self) -> str:
        return f"({', '.join(flag_name.upper() for flag_name, flag_value in vars(self).items() if flag_value)})"

    def __int__(self) -> int:
        return self.to_bitmask()

    def __str__(self) -> str:
        return "".join(str(i) for i in self.to_bitmask_list())

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
        return self.__str__()

    def to_bytes(self) -> bytes:
        if self.kind in IPOption.SINGLE_BYTE_KINDS:
            return bytes([self.kind])
        else:
            return bytes([self.kind, self.len]) + self.data

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        if self.kind in IPOption.SINGLE_BYTE_KINDS:
            return f"kind={IPOption.Kind(self.kind).name}"
        else:
            return f"kind={IPOption.Kind(self.kind).name} len={self.len} data=0x{self.data.hex()}"


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
        return self.__str__()

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
        def str_list(lst):
            return [f"{str_list(e)}" if isinstance(e, list) else str(e) for e in lst]

        return "|".join(str_list(self.__dict__.values()))


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
    def calculate_checksum(packet: IPPacket) -> int:
        # Calculate checksum using method described in RFC

        # Set checksum to 0 for calculation
        tmp_checksum = packet.header_checksum
        packet.header_checksum = 0

        # Calculate checksum
        # The checksum field is the 16 bit one's complement of the one's
        # complement sum of all 16 bit words in the header.  For purposes of
        # computing the checksum, the value of the checksum field is zero.
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

        # Find default gateway (hardcoded for our simulation)
        # In a real network, the default gateway IP Address would be found using ARP at the link layer
        default_gateway_ip = "192.168.1.20"
        self.logger.debug(f"Discovered default gateway '{default_gateway_ip}'")

        # Add default gateway to routing table
        self.routing_table.add_route("0.0.0.0", default_gateway_ip, subnet_mask, "UG", 600, "eth0")

        # Add local subnet to routing table
        self.routing_table.add_route(subnet_ip, "0.0.0.0", subnet_mask, "U", 600, "eth0")

        # In a real scenario the DHCP server would be found using various methods and
        # the DHCP server would assign an IP address to the client. For our simulation
        # we will just generate an IP address in the subnet range.
        eth0_ip = generate_ip_in_range()
        self.logger.debug(f"Discovered IP address '{eth0_ip}' for interface eth0")

        # Bind interface to discovered IP and update routing table accordingly
        self.interfaces["eth0"].bind(eth0_ip)

        # For our simulation we need to communicate the servers IP over to client
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
        interface.link.send(packet.to_bytes())

    def receive(self, src_ip: str) -> tuple[bytes, str]:
        # Get the interface for the source IP
        interface = None
        for interface in self.interfaces.values():
            if interface.bound_ip == src_ip:
                break

        # Receive message from the interface
        data = interface.link.receive()
        self.logger.debug("⬆️ [Link->Network]")

        packet = IPProtocol.parse_ip_packet(data)
        packet_src_ip = IPProtocol.int_to_ip(packet.source_address)

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
