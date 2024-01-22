from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

import random
import struct
import os
import sys


class PhysicalLayer:
    PIPE_PATH = "/var/tmp/physical-pipe-"

    communication_index: int

    def __init__(self) -> None:
        self.communication_index = 0

    @property
    def pipe_path(self) -> str:
        return PhysicalLayer.PIPE_PATH + str(self.communication_index)

    def send(self, data: bytes) -> None:
        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "wb") as f:
            f.write(data)

        if file_owner:
            os.remove(self.pipe_path)

        self.communication_index += 1

    def receive(self) -> bytes:
        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "rb") as f:
            data = f.read()

        if file_owner:
            os.remove(self.pipe_path)

        self.communication_index += 1
        return data


# --------------------------------


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

    def to_string_fields(self) -> list[tuple[str, str]]:
        def handle(field_name, value):
            if isinstance(value, list):
                return "[{}]".format(", ".join(handle("", v) for i, v in enumerate(value)))
            elif field_name == "data":
                return "0x" + value.hex() if value else "<NONE>"
            elif value is not None:
                return str(value)

        return [(field_name, handle(field_name, value)) for (field_name, value) in vars(self).items()]

    def to_string(self) -> str:
        return "|".join(v for _, v in self.to_string_fields())

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
        def format_value(field_name, value):
            if field_name == "flags":
                return f"{packet.flags.to_string()} {packet.flags.to_nice_string()}"
            elif field_name == "source_address" or field_name == "destination_address":
                return f"{value} ({IPProtocol.int_to_ip(int(value))})"
            elif field_name == "options" and packet.options:
                return "".join(f"\n     |- {option.to_string()}" for option in packet.options)
            elif field_name == "options" and not packet.options:
                return "[]"
            elif field_name == "version" and value == "4":
                return "4 (IPv4)"
            elif field_name == "protocol" and value == "6":
                return "6 (TCP)"
            return value

        message_fields = "\n".join(
            f"  |- {field_name}: {format_value(field_name, value)}" for field_name, value in packet.to_string_fields()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str))

        return "\n".join(
            (
                f"------------{note_str} Network Layer Packet {note_padding}",
                f"RAW DATA: 0x{packet.to_bytes().hex()}",
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


class Interface:
    HARDCODED_MTU = 1500

    physical: PhysicalLayer
    name: str
    bound_ip: str

    def __init__(self, name: str):
        self.physical = PhysicalLayer()
        self.name = name
        self.bound_ip = None

    def bind(self, ip: str) -> None:
        self.bound_ip = ip

    def send(self, data: bytes, dest_ip: str) -> None:
        self.physical.send(data)

    def receive(self) -> bytes:
        return self.physical.receive()


class NetworkLayer:
    dns_server: DNSServer
    routing_table: RoutingTable
    interfaces: dict[str, Interface]

    @property
    def local_ip(self) -> str:
        return self.interfaces["eth0"].bound_ip

    def __init__(self):
        self.dns_server = DNSServer()
        self.routing_table = RoutingTable()
        self.interfaces = {}

        self._add_interface("eth0")

    def _add_interface(self, name: str):
        self.interfaces[name] = Interface(name)

    def plug_in_and_perform_dhcp_discovery(self) -> None:
        # Exam specified IP Range (CIDR): 192.168.1.0/8 == (192.0.0.0/8)
        SUBNET_IP = "192.0.0.0"
        SUBNET_MASK = "255.0.0.0"
        CLIENT_IP_ADDRESS = "192.168.0.4"
        SERVER_IP_ADDRESS = "192.168.0.6"

        # Function to generate an IP in range specified by exam spec
        # def generate_ip_in_range() -> str:
        #     subnet_mask_int = IPProtocol.ip_to_int(subnet_mask)
        #     subnet_ip_int = IPProtocol.ip_to_int(subnet_ip)
        #     ip_int = random.randint(subnet_ip_int, subnet_ip_int + (2**32 - subnet_mask_int))
        #     return IPProtocol.int_to_ip(ip_int)

        # Find default gateway (hardcoded for our simulation)
        # In a real network, the default gateway IP Address would be found using ARP at the link layer
        default_gateway_ip = "192.168.1.20"

        # Add default gateway to routing table
        self.routing_table.add_route("0.0.0.0", default_gateway_ip, SUBNET_MASK, "UG", 600, "eth0")

        # Add local subnet to routing table
        self.routing_table.add_route(SUBNET_IP, "0.0.0.0", SUBNET_MASK, "U", 600, "eth0")

        # In a real scenario the DHCP server would be found using various methods and
        # the DHCP server would assign an IP address to the client.
        # For our simulation we hardcode it based on whether client or server.
        eth0_ip = SERVER_IP_ADDRESS

        # Bind interface to discovered IP
        self.interfaces["eth0"].bind(eth0_ip)

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
        print(IPProtocol.get_exam_string(packet, note="SENDING"))
        interface.send(packet.to_bytes(), dest_ip)

    def receive(self, src_ip: str) -> tuple[bytes, str]:
        # Get the interface for the source IP
        interface = None
        for interface in self.interfaces.values():
            if interface.bound_ip == src_ip:
                break

        # Receive message from the interface
        data = interface.receive()

        packet = IPProtocol.parse_ip_packet(data)
        packet_src_ip = IPProtocol.int_to_ip(packet.source_address)
        print(IPProtocol.get_exam_string(packet, note="RECEIVED"))

        # Verify checksum
        calculated_checksum = IPProtocol.calculate_checksum(packet)
        if calculated_checksum != packet.header_checksum:
            raise Exception(
                f"Checksum mismatch! Calculated checksum {calculated_checksum} does not match packet checksum {packet.header_checksum}"
            )

        # Simulates the packet being dropped if the TTL is 0
        packet.time_to_live -= 1
        if packet.time_to_live == 0:
            raise Exception("Simulation Error: Packet dropped due to TTL being 0")

        # Return final packet and IP
        return packet.data, packet_src_ip


# --------------------------------


@dataclass
class TCPFlags:
    """Internal of TCPSegment.
    TCP flags are 6-bits packed into a single byte."""

    urg: bool = False
    ack: bool = False
    psh: bool = False
    rst: bool = False
    syn: bool = False
    fin: bool = False

    @classmethod
    def from_bytes(cls, flags_bytes: bytes) -> TCPFlags:
        # Unpack packed bytes as unsigned char bitmask then construct
        flags_bitmask = struct.unpack(">B", flags_bytes)[0]
        return cls.from_bitmask(flags_bitmask)

    @classmethod
    def from_bitmask(cls, flags_bitmask: int) -> TCPFlags:
        # Extract first 6 bits into bools and construct
        return cls(
            urg=bool(flags_bitmask & (2**5)),
            ack=bool(flags_bitmask & (2**4)),
            psh=bool(flags_bitmask & (2**3)),
            rst=bool(flags_bitmask & (2**2)),
            syn=bool(flags_bitmask & (2**1)),
            fin=bool(flags_bitmask & (2**0)),
        )

    def to_bytes(self) -> bytes:
        # Convert to bitmask then directly to bytes
        return bytes([self.to_bitmask()])

    def to_bitmask_list(self) -> [int]:
        # Convert to list of flags as bits
        return [int(v) for v in [self.urg, self.ack, self.psh, self.rst, self.syn, self.fin]]

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

    def __eq__(self, __value: TCPFlags) -> bool:
        return self.to_bitmask() == __value.to_bitmask()


@dataclass
class TCPOption:
    """Internal of TCPSegment.
    TCP options are variable length, packed into words."""

    class Kind(IntEnum):
        END_OF_OPTION_LIST = 0
        NO_OPERATION = 1
        MAXIMUM_SEGMENT_SIZE = 2
        WINDOW_SCALING = 3

    SINGLE_BYTE_KINDS = set((Kind.END_OF_OPTION_LIST, Kind.NO_OPERATION))
    ALL_KINDS = set((Kind.END_OF_OPTION_LIST, Kind.NO_OPERATION, Kind.MAXIMUM_SEGMENT_SIZE, Kind.WINDOW_SCALING))

    @staticmethod
    def from_bytes(option_bytes: bytes) -> TCPOption:
        (
            option,
            _remaining_bytes,
        ) = TCPOption.from_bytes_with_remainder(option_bytes)

        return option

    @staticmethod
    def from_bytes_with_remainder(option_bytes: bytes) -> tuple[TCPOption, bytes]:
        # Extract option kind from front of option_bytes, and return along with the remainder.

        # Byte 1: Option kind
        option_kind = option_bytes[0]

        if option_kind in TCPOption.SINGLE_BYTE_KINDS:
            return TCPOption(kind=option_kind), option_bytes[1:]

        if option_kind not in TCPOption.ALL_KINDS:
            raise NotImplementedError(f"Unsupported option kind: {option_kind}")

        if len(option_bytes) <= 1:
            raise ValueError("Option kind requires length field but no length was specified!")

        # Byte 2: Length of data
        option_length = option_bytes[1]

        # Byte 3+: Option data
        option_data = option_bytes[2:option_length]

        return TCPOption(kind=option_kind, data=option_data), option_bytes[option_length:]

    kind: Kind
    data: bytes = bytes()
    len: int = field(init=False)

    def __post_init__(self):
        self.len = 1 if self.kind in TCPOption.SINGLE_BYTE_KINDS else 2 + len(self.data)

    def to_string(self) -> str:
        if self.kind in TCPOption.SINGLE_BYTE_KINDS:
            return f"kind={TCPOption.Kind(self.kind).name}"
        else:
            return f"kind={TCPOption.Kind(self.kind).name} len={self.len} data=0x{self.data.hex()}"

    def to_bytes(self) -> bytes:
        if self.kind in TCPOption.SINGLE_BYTE_KINDS:
            return bytes([self.kind])
        else:
            return bytes([self.kind, self.len]) + self.data

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return self.to_string()


@dataclass
class TCPSegment:
    """Internal of TCPProtocol.
    Representation of a TCP segment used by TCPProtocol."""

    src_port: int
    dest_port: int
    seq_number: int
    ack_number: int
    data_offset: int
    flags: TCPFlags
    window: bytes
    checksum: int
    urgent_pointer: bytes
    options: list[TCPOption]
    data: bytes

    @property
    def seg_len(self) -> int:
        # RFC defines seg_len as length of data + 1 if FIN or SYN flags are set.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.1
        return len(self.data) + (self.flags.fin or self.flags.syn)

    @property
    def seg_seq(self) -> int:
        # RFC defines seg_seq as seq_number.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.1
        return self.seq_number

    @property
    def seg_ack(self) -> int:
        # RFC defines seg_ack as ack_number.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.1
        return self.ack_number

    def to_string_fields(self) -> list[tuple[str, str]]:
        def handle(field_name, value):
            if isinstance(value, list):
                return "[{}]".format(", ".join(handle("", v) for i, v in enumerate(value)))
            elif field_name == "data":
                return "0x" + value.hex() if value else "<NONE>"
            elif value is not None:
                return str(value)

        return [(field_name, handle(field_name, value)) for (field_name, value) in vars(self).items()]

    def to_string(self) -> str:
        return "|".join(v for _, v in self.to_string_fields())

    def to_bytes(self) -> bytes:
        # Pack ports, seq, and ack number
        src_dest_seq_ack_bytes = struct.pack(
            ">HHII",
            self.src_port,
            self.dest_port,
            self.seq_number,
            self.ack_number,
        )

        # Calculate data offset (4) + reserved (6) + flags (6) bytes = 16 bits

        # Data offset must fit into 4 bits
        assert self.data_offset < 2**4

        # Pad data offset to the right with 4 / 6 reserved bits
        data_offset_padded = self.data_offset << 4

        # Flags already left padded remaining 2 / 6 reserved bits
        flags_bitmask = self.flags.to_bitmask()

        # Pack all of the above into 16 bits
        flags_data_offset = struct.pack(
            ">BB",
            data_offset_padded,
            flags_bitmask,
        )

        # Pack some remaining variables
        window_checksum_urg = struct.pack(
            ">HHH",
            self.window,
            self.checksum,
            self.urgent_pointer,
        )

        # Pack options bytes up
        options_bytes = [o.to_bytes() for o in self.options]

        # Calc padding needed to ensure options are padded to the nearest 4-byte word
        length_of_options_bytes = sum(len(o) for o in options_bytes)

        # Get the nearest number of 4-byte words needed to hold all options
        options_space_bytes = -4 * (length_of_options_bytes // -4)
        options_padding = bytes(options_space_bytes - length_of_options_bytes)

        # Construct header with all packed bits, including options and options padding
        header = src_dest_seq_ack_bytes + flags_data_offset + window_checksum_urg
        for option_bytes in options_bytes:
            header += option_bytes
        header += options_padding

        # Return final packed header + data bytes
        return header + self.data

    def __str__(self) -> str:
        return self.to_string()


class TCPProtocol:
    """This class represents a TCP simulation based on RFC 793.

    The class itself allows for parsing and creating TCP frames or "segments".

    RFC 793 has been referenced heavily throughout to verify this implementation
    is correct.

    - RFC 793: https://datatracker.ietf.org/doc/html/rfc793
    """

    # The MSS is usually the link MTU size minus the 40 bytes of the TCP and IP headers,
    # but many implementations use segments of 512 or 536 bytes. We will use 512 bytes.

    # The Maximum Segment Size of a TCP Segment is calculated based on the MTU defined by the
    # link layer - the size of the IP header (20 bytes) and the TCP header (20 bytes).
    HARDCODED_MSS = Interface.HARDCODED_MTU - 40

    # The receive window is the amount of data that can be sent before the receiver must ACK.
    # We will use the maximum 16-bit size (65535 bytes):
    WINDOW_SIZE = 2**16 - 1

    @staticmethod
    def create_tcp_segment(
        src_port: int,
        dest_port: int,
        seq_number: int,
        ack_number: int,
        window: int,
        flags: TCPFlags,
        data: bytes = bytes(),
        options: list[TCPOption] = [],
    ) -> TCPSegment:
        # Calculate the number of bytes in the header
        MIN_TCP_HEADER_BYTES = 20
        length_of_options_bytes = sum(len(o) for o in options)

        # Check options are valid and align to the nearest 4 byte word.
        if options != [] and length_of_options_bytes % 4 != 0 and options[-1].kind != TCPOption.Kind.END_OF_OPTION_LIST:
            raise Exception(
                "If options do not align to the nearest 4 byte word they must contain an END_OF_OPTION_LIST option!"
            )

        # Get the nearest number of 4-byte words needed to hold all options
        options_space_bytes = -4 * (length_of_options_bytes // -4)

        # Get the data offset in 4-byte words
        data_offset = (MIN_TCP_HEADER_BYTES + options_space_bytes) // 4

        # Put all into final struct and return
        return TCPSegment(
            src_port=src_port,
            dest_port=dest_port,
            seq_number=seq_number,
            ack_number=ack_number,
            data_offset=data_offset,
            flags=flags,
            window=window,
            # Checksum calculated outside this function using pseudo header.
            checksum=0,
            # Unused urgent pointer set to 0.
            urgent_pointer=0,
            options=options,
            data=data,
        )

    @staticmethod
    def parse_tcp_segment(segment_bytes: bytes) -> TCPSegment:
        # View first 20 bytes for header and parse variables
        (
            src_port,
            dest_port,
            seq_number,
            ack_number,
            data_offset_padded,
            flags_bitmask,
            window,
            checksum,
            urgent_pointer,
        ) = struct.unpack(">HHIIBBHHH", segment_bytes[:20])

        # Calculate data starting location
        data_offset = data_offset_padded >> 4
        data_offset_bytes = data_offset * 4

        # Parse flags bitmask into nice struct
        flags = TCPFlags.from_bitmask(flags_bitmask)

        # View calculated options bytes and parse options
        options_bytes = segment_bytes[20:data_offset_bytes]
        options: list[TCPOption] = []
        while options_bytes:
            option, options_bytes = TCPOption.from_bytes_with_remainder(options_bytes)
            options.append(option)

            # Stop parsing options when reached END_OF_OPTION_LIST
            if option.kind == TCPOption.Kind.END_OF_OPTION_LIST:
                break

        # View calculated data bytes
        data = segment_bytes[data_offset_bytes:]

        # Put all into final struct and return
        return TCPSegment(
            src_port=src_port,
            dest_port=dest_port,
            seq_number=seq_number,
            ack_number=ack_number,
            data_offset=data_offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=options,
            data=data,
        )

    @staticmethod
    def calculate_checksum(segment: TCPSegment, src_ip: str, dest_ip: str) -> int:
        # Set checksum to 0 for calculation
        tmp_checksum = segment.checksum
        segment.checksum = 0

        # 16-bit one's complement of the one's complement sum of all 16-bit words in the pseudo header + tcp header + text
        words_to_sum = []

        # --- Pseudo header ---
        # Split 32-bit src_ip + dest_ip into 16-bit words
        src_ip_bytes = struct.pack(">I", IPProtocol.ip_to_int(src_ip))
        dest_ip_bytes = struct.pack(">I", IPProtocol.ip_to_int(dest_ip))
        words_to_sum.append(src_ip_bytes[:2])
        words_to_sum.append(src_ip_bytes[2:])
        words_to_sum.append(dest_ip_bytes[:2])
        words_to_sum.append(dest_ip_bytes[2:])

        # Reserved + Protocol and TCP Length
        words_to_sum.append(struct.pack(">BB", 0x00, 0x06))
        words_to_sum.append(struct.pack(">H", len(segment.to_bytes())))

        # Ensure pseudo header is 96 bits (12 bytes)
        assert sum(len(w) for w in words_to_sum) == 96 // 8

        # --- TCP Segment ---
        # Split header into 16-bit words and optionally pad to 16-bits
        segment_bytes = segment.to_bytes()
        for i in range(0, len(segment_bytes), 2):
            word = segment_bytes[i : i + 2]
            word += bytes(2 - len(word))
            words_to_sum.append(word)

        # --- Perform calculation ---
        # 1's complement sum all 16-bit words
        checksum = 0
        for word in words_to_sum:
            checksum += struct.unpack(">H", word)[0]

        # 1's complement the sum and return
        checksum = ~checksum & 0xFFFF

        # Restore checksum
        segment.checksum = tmp_checksum
        return checksum

    @staticmethod
    def get_exam_string(segment: TCPSegment, init_seq: int, init_ack: int, note: str = "") -> str:
        def format_values(field_name, value):
            if field_name == "flags":
                return f"{segment.flags.to_string()} {segment.flags.to_nice_string()}"
            elif field_name == "options" and segment.options:
                return "".join(f"\n     |- {option.to_string()}" for option in segment.options)
            elif field_name == "options" and not segment.options:
                return "[]"
            elif field_name == "seq_number":
                return f"{value} (rel={0 if (value == '0' or init_seq == 0) else (int(value) - init_seq)})"
            elif field_name == "ack_number":
                return f"{value} (rel={0 if (value == '0' or init_ack == 0) else (int(value) - init_ack)})"
            elif value is not None:
                return str(value)

        message_fields = "\n".join(
            f"  |- {field_name}: {format_values(field_name, value)}" for field_name, value in segment.to_string_fields()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str))

        return "\n".join(
            (
                f"------------{note_str} Transport Layer Segment {note_padding}",
                f"RAW DATA: 0x{segment.to_bytes().hex()}",
                "PROTOCOL: TCP",
                f"SEGMENT STRING: {segment.to_string()}",
                "SEGMENT FIELDS:",
                message_fields,
                "---------- END Transport Layer Frame ----------",
            )
        )


class TransportControlBlock:
    """Struct for maintaining state for a TCP connection."""

    class State(IntEnum):
        CLOSED = 0  # CLOSED is a defined but "fictional" state in RFC 793, however it is useful for the simulation.
        LISTEN = 1
        SYN_SENT = 2
        SYN_RECEIVED = 3
        ESTABLISHED = 4
        FIN_WAIT_1 = 5
        FIN_WAIT_2 = 6
        CLOSE_WAIT = 7
        CLOSING = 8
        LAST_ACK = 9
        TIME_WAIT = 10

    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    src_mss: int
    dest_mss: int
    send_buffer: bytes = bytes()
    recv_buffer: bytes = bytes()
    state: State = State.CLOSED

    # Send Sequence Variables
    snd_una: int = 0
    snd_nxt: int = 0
    snd_wnd: int = 0
    snd_wl1: int = 0
    snd_wl2: int = 0
    iss: int = 0

    # Receive Sequence Variables
    rcv_nxt: int = 0
    rcv_wnd: int = 0
    irs: int = 0


class TCPIPSocket:
    """Very small mock socket that imitates the real interface
    used to interact with the transport layer."""

    transport: TransportLayer
    bound_src_ip: str
    bound_src_port: int
    tcb: TransportControlBlock = None

    def __init__(self, transport: TransportLayer) -> None:
        self.transport = transport

    def _resolve_ip_from_host(self, host: str) -> str:
        """Resolve an IP address from a host.
        A host could be a hostname in domain notation or an IPv4 address.
        """
        host = host.lstrip("https://").lstrip("http://")

        # Host is local IP address.
        if host == "localhost" or host == "0.0.0.0":
            return self.transport.network.local_ip

        # Host is already an IP address.
        if host.count(".") == 3 and all(s.isdigit() for s in host.split(".")):
            return host

        # Host is a hostname, resolve it.
        else:
            return DNSServer.resolve(host)

    def connect(self, addr: tuple(str, int)) -> None:
        # Configure socket with bound ip.
        self.bound_src_ip = self._resolve_ip_from_host("0.0.0.0")

        # Assign a random dynamic port for the client to use.
        # Dynamic ports are in the range 49152 to 65535.
        self.bound_src_port = random.randint(49152, 65535)

        # Calculate destination ip and port from addr.
        dest_host, dest_port = addr
        dest_ip = self._resolve_ip_from_host(dest_host)

        # Tell transport layer to perform active open procedure.
        self.tcb = self.transport.active_open_connection(self.bound_src_ip, self.bound_src_port, dest_ip, dest_port)

    def bind(self, addr: tuple(str, int)) -> None:
        # Passive open procedure prerequisite.

        # Calculate destination ip and port from addr then configure.
        host, port = addr
        ip = self._resolve_ip_from_host(host)
        self.bound_src_ip, self.bound_src_port = (ip, port)

    def accept(self) -> None:
        # Step 1 and 2 of passive open procedure.

        # Ensure socket is not currently connected.
        if self.tcb and self.tcb.state != TransportControlBlock.State.CLOSED:
            raise Exception(f"Simulation Error: TCB is not in CLOSED state: {self.tcb.state}")

        # Create a TCB and set it to the LISTEN state.
        self.tcb = TransportControlBlock()
        self.tcb.src_ip = self.bound_src_ip
        self.tcb.src_port = self.bound_src_port
        self.tcb.state = TransportControlBlock.State.LISTEN

        # Tell transport layer to receive segments into the listening TCB.
        self.transport.passive_open_connection(self.tcb)

    def receive(self, bufsize: int) -> bytes:
        # Receive 'bufsize' bytes of application data.
        return self.transport.receive(self.tcb, bufsize)

    def send(self, data: bytes) -> None:
        # Send application layer bytes.
        return self.transport.send(self.tcb, data)

    def close(self) -> None:
        # Close the connection.
        self.transport.active_close_connection(self.tcb)

    def wait_close(self) -> None:
        # Wait for the connection to close.
        self.transport.passive_close_connection(self.tcb)


class TransportLayer:
    """Simulated transport layer capable of opening / communicating with
    TCPConnections a between a source ip+port (ourselves) and some destination ip+port."""

    network: NetworkLayer

    def __init__(self) -> None:
        self.network = NetworkLayer()

    def create_socket(self) -> TCPIPSocket:
        return TCPIPSocket(self)

    def active_open_connection(self, src_ip: str, src_port: str, dest_ip: str, dest_port: str) -> TransportControlBlock:
        # Active open connection using TCP RFC 793 state diagram fig 6:
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.4

        # Create a TCB and set it to the fictional CLOSED state.
        tcb = TransportControlBlock()
        tcb.src_ip = src_ip
        tcb.src_port = src_port
        tcb.dest_ip = dest_ip
        tcb.dest_port = dest_port
        tcb.src_mss = TCPProtocol.HARDCODED_MSS
        tcb.state = TransportControlBlock.State.CLOSED

        # Initialize send sequence variables.
        tcb.iss = random.randint(0, 2**32 - 1)
        tcb.snd_una = tcb.iss
        tcb.snd_nxt = tcb.iss
        tcb.snd_wnd = TCPProtocol.WINDOW_SIZE
        tcb.snd_wl1 = 0
        tcb.snd_wl2 = 0

        # Initialize receive sequence variables.
        tcb.irs = 0
        tcb.rcv_nxt = 0
        tcb.rcv_wnd = TCPProtocol.WINDOW_SIZE

        # ACTIVE 1. Create and send a SYN segment, set TCB state to SYN_SENT.
        syn_options = [TCPOption(kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE, data=struct.pack(">H", tcb.src_mss))]
        syn_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(syn=True),
            options=syn_options,
        )
        tcb.snd_una = syn_segment.seg_seq
        tcb.snd_nxt += syn_segment.seg_len
        self._send_tcp_segment(tcb, syn_segment)
        tcb.state = TransportControlBlock.State.SYN_SENT

        # NOTE: Can now either receive SYN, SYNACK, client close, or timeout.
        # we handle receiving SYNACK, proceed to ACTIVE open step 2.
        # We do not handle SYN, normally would proceed to SYN_RECEIVED state with simultaneous open.
        # We do not handle client calling close or handle timeout.

        # ACTIVE 2. Wait for SYNACK segment.
        recv_segment, _ = self._receive_tcp_segment(tcb)
        if recv_segment.flags != TCPFlags(syn=True, ack=True):
            raise Exception(f"Simulation Error: Server responded with invalid segment: {recv_segment.to_string()}")

        # Check they sent an acceptable ACK for our SYN.
        # In a real system we would retransmit the SYN segment if not.
        # In this simulation we will just raise an exception.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.3
        if not (tcb.snd_una < recv_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {recv_segment.to_string()}")

        # Update sequence numbers.
        tcb.irs = recv_segment.seg_seq
        tcb.rcv_nxt = recv_segment.seg_seq + recv_segment.seg_len
        tcb.snd_wnd = recv_segment.window
        tcb.snd_wl1 = recv_segment.seg_seq
        tcb.snd_wl2 = recv_segment.seg_ack

        # If found MSS option in segment update TCB with dest MSS.
        if mss_option := next((o for o in recv_segment.options if o.kind == TCPOption.Kind.MAXIMUM_SEGMENT_SIZE), None):
            tcb.dest_mss = struct.unpack(">H", mss_option.data)[0]

        # ACTIVE 3. Send a final response ACK segment, then set TCB state to ESTABLISHED.
        ack_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(ack=True),
        )
        tcb.snd_una = ack_segment.seg_seq
        tcb.snd_nxt += ack_segment.seg_len
        self._send_tcp_segment(tcb, ack_segment)

        # Return final established TCB in established state
        tcb.state = TransportControlBlock.State.ESTABLISHED
        return tcb

    def passive_open_connection(self, tcb: TransportControlBlock) -> None:
        # Passive open connection using TCP RFC 793 state diagram fig 6:
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.4

        # Ensure connection is in LISTEN state.
        if tcb.state != TransportControlBlock.State.LISTEN:
            raise Exception(f"Simulation Error: TCB is not in LISTEN state: {tcb.state}")

        # Perform passive open on a connection on bound TCB using the three-way handshake procedure.

        # Initialize send sequence variables.
        tcb.iss = random.randint(0, 2**32 - 1)
        tcb.snd_una = tcb.iss
        tcb.snd_nxt = tcb.iss
        tcb.snd_wnd = TCPProtocol.WINDOW_SIZE
        tcb.snd_wl1 = 0
        tcb.snd_wl2 = 0

        # Initialize receive sequence variables.
        tcb.irs = 0
        tcb.rcv_nxt = 0
        tcb.rcv_wnd = TCPProtocol.WINDOW_SIZE

        # PASSIVE 1. Wait to receive first applicable SYN segment.
        recv_segment, segment_src_ip = self._receive_tcp_segment(tcb)
        if not recv_segment.flags == TCPFlags(syn=True):
            raise Exception(f"Simulation Error: Client responded with non SYN segment: {recv_segment.to_string()}")

        # Update sequence numbers.
        tcb.irs = recv_segment.seg_seq
        tcb.rcv_nxt = recv_segment.seg_seq + recv_segment.seg_len
        tcb.snd_wnd = recv_segment.window
        tcb.snd_wl1 = recv_segment.seg_seq
        tcb.snd_wl2 = recv_segment.seg_ack

        # Update TCB with ip and port of received segment.
        tcb.dest_ip = segment_src_ip
        tcb.dest_port = recv_segment.src_port

        # If found MSS option in segment update TCB with dest MSS.
        if mss_option := next((o for o in recv_segment.options if o.kind == TCPOption.Kind.MAXIMUM_SEGMENT_SIZE), None):
            tcb.dest_mss = struct.unpack(">H", mss_option.data)[0]

        # PASSIVE 2. Create and send a SYNACK segment, set TCB state to SYN_RCVD.
        syn_ack_options = [
            TCPOption(kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE, data=struct.pack(">H", TCPProtocol.HARDCODED_MSS))
        ]
        syn_ack_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(syn=True, ack=True),
            options=syn_ack_options,
        )
        tcb.snd_una = syn_ack_segment.seg_seq
        tcb.snd_nxt += syn_ack_segment.seg_len
        self._send_tcp_segment(tcb, syn_ack_segment)
        tcb.state = TransportControlBlock.State.SYN_RECEIVED

        # NOTE: We could receive either ACK, client could call close, or timeout.
        # We do not handle client calling close.
        # We do not handle timeout.

        # PASSIVE 3. Wait to receive a final ACK segment.
        recv_segment, segment_src_ip = self._receive_tcp_segment(tcb)
        if not recv_segment.flags == TCPFlags(ack=True):
            raise Exception(f"Simulation Error: Client responded with non ACK segment: {recv_segment.to_string()}")

        # Check they sent an acceptable ACK for our SYNACK.
        # In a real system we would retransmit the SYNACK segment if not.
        # In this simulation we will just raise an exception.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.3
        if not (tcb.snd_una < recv_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {recv_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = recv_segment.seg_seq + recv_segment.seg_len
        tcb.snd_wnd = recv_segment.window
        tcb.snd_wl1 = recv_segment.seg_seq
        tcb.snd_wl2 = recv_segment.seg_ack

        # Return final TCB in established state
        tcb.state = TransportControlBlock.State.ESTABLISHED
        return tcb

    def active_close_connection(self, tcb: TransportControlBlock) -> None:
        # Ensure connection is in ESTABLISHED state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Received application close, perform active close procedure.

        # ACTIVE 1. Send FIN, Enter FIN_WAIT_1.
        fin_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(fin=True),
        )
        tcb.snd_una = fin_segment.seg_seq
        tcb.snd_nxt += fin_segment.seg_len
        self._send_tcp_segment(tcb, fin_segment)
        tcb.state = TransportControlBlock.State.FIN_WAIT_1

        # NOTE: Can now either receive FIN, FINACK, ACK, or timeout.
        # We handle receiving ACK, proceed to FIN_WAIT_2 in ACTIVE 2.
        # We do not handle receiving FINACK, normally send ACK and proceed to TIME_WAIT.
        # We do not handle FIN, normally would proceed to CLOSING with simultaneous close.
        # We do not handle timeout.

        # ACTIVE 2. Wait for ACK segment, wait for FIN, send ACK, proceed to TIME_WAIT.
        ack_segment, _ = self._receive_tcp_segment(tcb)
        if ack_segment.flags != TCPFlags(ack=True):
            raise Exception(f"Simulation Error: Received segment with invalid flags: {ack_segment.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_segment.seg_seq + ack_segment.seg_len
        tcb.snd_wnd = ack_segment.window
        tcb.snd_wl1 = ack_segment.seg_seq
        tcb.snd_wl2 = ack_segment.seg_ack

        # Receive FIN.
        fin_segment, _ = self._receive_tcp_segment(tcb)
        if fin_segment.flags != TCPFlags(fin=True):
            raise Exception(f"Simulation Error: Received segment with invalid flags: {fin_segment.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < fin_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {fin_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = fin_segment.seg_seq + fin_segment.seg_len
        tcb.snd_wnd = fin_segment.window
        tcb.snd_wl1 = fin_segment.seg_seq
        tcb.snd_wl2 = fin_segment.seg_ack

        # Send ACK.
        ack_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(ack=True),
        )
        tcb.snd_una = ack_segment.seg_seq
        tcb.snd_nxt += ack_segment.seg_len
        self._send_tcp_segment(tcb, ack_segment)
        tcb.state = TransportControlBlock.State.TIME_WAIT

        # ACTIVE 3. Wait for 2MSL timeout, Enter CLOSED.
        # time.sleep(2 * 60) # Not waiting for timeout in simulation.
        tcb.state = TransportControlBlock.State.CLOSED

    def passive_close_connection(self, tcb: TransportControlBlock) -> None:
        # Ensure connection is in ESTABLISHED state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Awaiting active close, perform passive close procedure.

        # PASSIVE 1. Receive FIN, Send ACK, Enter CLOSE_WAIT.
        fin_segment, _ = self._receive_tcp_segment(tcb)
        if fin_segment.flags != TCPFlags(fin=True):
            raise Exception(f"Simulation Error: Received segment with invalid flags: {fin_segment.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < fin_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {fin_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = fin_segment.seg_seq + fin_segment.seg_len
        tcb.snd_wnd = fin_segment.window
        tcb.snd_wl1 = fin_segment.seg_seq
        tcb.snd_wl2 = fin_segment.seg_ack

        # Send ACK.
        ack_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(ack=True),
        )
        tcb.snd_una = ack_segment.seg_seq
        tcb.snd_nxt += ack_segment.seg_len
        self._send_tcp_segment(tcb, ack_segment)
        tcb.state = TransportControlBlock.State.CLOSE_WAIT

        # PASSIVE 2. Wait for application close, Send FIN, Enter LAST_ACK.
        # continue # Not waiting for application close in simulation.

        # Send FIN.
        fin_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TCPFlags(fin=True),
        )
        tcb.snd_una = fin_segment.seg_seq
        tcb.snd_nxt += fin_segment.seg_len
        self._send_tcp_segment(tcb, fin_segment)
        tcb.state = TransportControlBlock.State.LAST_ACK

        # PASSIVE 3. Receive ACK, send nothing, Enter CLOSED.
        ack_segment, _ = self._receive_tcp_segment(tcb)
        if ack_segment.flags != TCPFlags(ack=True):
            raise Exception(f"Simulation Error: Received segment with invalid flags: {ack_segment.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_segment.seg_seq + ack_segment.seg_len
        tcb.snd_wnd = ack_segment.window
        tcb.snd_wl1 = ack_segment.seg_seq
        tcb.snd_wl2 = ack_segment.seg_ack

        # Close and finish
        tcb.state = TransportControlBlock.State.CLOSED

    def receive(self, tcb: TransportControlBlock, bufsize: int) -> bytes:
        # Ensure connection is in a valid state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Receive segments if have no ready data.
        if len(tcb.recv_buffer) == 0:
            # Receive first PSHACK segment.
            segment, _ = self._receive_tcp_segment(tcb)
            if segment.flags != TCPFlags(psh=True, ack=True):
                raise Exception(f"Simulation Error: Received segment with invalid flags: {segment.to_string()}")

            # Check they sent an acceptable ACK for the current communication.
            if not (tcb.snd_una < segment.seg_ack <= tcb.snd_nxt):
                raise Exception(f"Simulation Error: Client responded with invalid ACK number: {segment.to_string()}")

            # Update sequence numbers.
            tcb.rcv_nxt = segment.seg_seq + segment.seg_len
            tcb.snd_wnd = segment.window
            tcb.snd_wl1 = segment.seg_seq
            tcb.snd_wl2 = segment.seg_ack

            # Respond with ACK.
            ack_segment = TCPProtocol.create_tcp_segment(
                src_port=tcb.src_port,
                dest_port=tcb.dest_port,
                seq_number=tcb.snd_nxt,
                ack_number=tcb.rcv_nxt,
                window=tcb.rcv_wnd,
                flags=TCPFlags(ack=True),
            )
            tcb.snd_una = ack_segment.seg_seq
            tcb.snd_nxt += ack_segment.seg_len
            self._send_tcp_segment(tcb, ack_segment)

            # Receive data into the recv_buffer.
            tcb.recv_buffer += segment.data

        # Receive 'bufsize' bytes of application data.
        data = tcb.recv_buffer[:bufsize]
        tcb.recv_buffer = tcb.recv_buffer[bufsize:]
        return data

    def send(self, tcb: TransportControlBlock, data: bytes) -> None:
        # Ensure connection is in a valid state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Ensure segment is less than dest MSS.
        # In a real system we would split the data into multiple segments.
        # In this simulation we will just raise an exception.
        if len(data) > tcb.dest_mss:
            raise Exception(f"Simulation Error: Segment size {len(data)} exceeds dest MSS {tcb.dest_mss}.")

        # Create single segment with all application data.
        pshack_flags = TCPFlags(psh=True, ack=True)
        pshack_segment = TCPProtocol.create_tcp_segment(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=pshack_flags,
            data=data,
        )
        tcb.snd_una = pshack_segment.seg_seq
        tcb.snd_nxt += pshack_segment.seg_len
        self._send_tcp_segment(tcb, pshack_segment)

        # Receive responding ACK segment.
        ack_segment, _ = self._receive_tcp_segment(tcb)
        if ack_segment.flags != TCPFlags(ack=True):
            raise Exception(f"Simulation Error: Received segment with invalid flags: {ack_segment.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_segment.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_segment.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_segment.seg_seq + ack_segment.seg_len
        tcb.snd_wnd = ack_segment.window
        tcb.snd_wl1 = ack_segment.seg_seq
        tcb.snd_wl2 = ack_segment.seg_ack

    def _receive_tcp_segment(self, tcb: TransportControlBlock) -> tuple[TCPSegment, str]:
        # Explictly does not check TCB state or SEQ / ACK numbers.
        # This responsibility is left to the caller.

        # Receive and parse the latest segment.
        # Guaranteed to be fully received due if communicated MSS.
        segment_data, segment_src_ip = self.network.receive(tcb.src_ip)
        segment = TCPProtocol.parse_tcp_segment(segment_data)
        print(TCPProtocol.get_exam_string(segment, tcb.irs, tcb.iss, note="RECEIVED"))

        # Check segment ip and port is for this connection.
        if segment.dest_port != tcb.src_port:
            raise Exception(
                f"Server waiting to accept connections received segment for incorrect port: {segment.to_string()}"
            )

        # Check segment checksum is correct
        checksum = TCPProtocol.calculate_checksum(segment, segment_src_ip, tcb.src_ip)
        if checksum != segment.checksum:
            raise Exception(
                f"Server waiting to accept connections received segment with incorrect checksum: {segment.to_string()}"
            )

        # Log and return segment
        return segment, segment_src_ip

    def _send_tcp_segment(self, tcb: TransportControlBlock, segment: TCPSegment) -> None:
        # Explictly does not check TCB state or SEQ / ACK numbers.
        # This responsibility is left to the caller.

        # Set checksum on the segment using pseudo header info.
        segment.checksum = TCPProtocol.calculate_checksum(segment, tcb.src_ip, tcb.dest_ip)

        # Log and send segment
        print(TCPProtocol.get_exam_string(segment, tcb.iss, tcb.irs, note="SENDING"))
        self.network.send(tcb.dest_ip, segment.to_bytes())


# --------------------------------


class HTTPProtocol:
    """This class represents a HTTP simulation based on RFC 2616.

    The class itself allows for parsing and creating HTTP Messages (Requests and Responses).

    RFC 2616 has been referenced heavily throughout to verify this implementation
    is correct.

    - RFC 2616: https://datatracker.ietf.org/doc/html/rfc2616
    - Summary of RFC 2616, used in places for clarification: https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html
    """

    # HTTP Version for this simulation.
    VERSION = "HTTP/1.1"

    # A subset of all HTTP/1.1 methods representing those implemented
    # for this simulation. Used as a check when decoding messages.
    VALID_METHODS = ["HEAD", "GET"]

    # A subset of all HTTP/1.1 statuses representing those implemented
    # for this simulatioin. Used to randomly select a response in th
    # 300's range, for a given request.
    STATUS_PHRASES = {
        "300": "Multiple Choices",
        "301": "Moved Permanently",
        "302": "Found",
        "303": "See Other",
        "304": "Not Modified",
    }

    # Helper constants used when parsing HTTP Messages.
    SP = " "
    CRLF = "\n"  # For the sake of simplicity we set CRLF (usually \r\n) to \n.

    @dataclass
    class HTTPRequestStruct:
        method: str
        uri: str
        version: str
        headers: dict
        body: str

        def to_string(self) -> str:
            req_str = f"{self.method}{HTTPProtocol.SP}{self.uri}{HTTPProtocol.SP}{self.version}{HTTPProtocol.CRLF}"
            for header in self.headers:
                req_str += f"{header}:{HTTPProtocol.SP}{self.headers[header]}{HTTPProtocol.CRLF}"
            req_str += HTTPProtocol.CRLF
            req_str += self.body

            return req_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @dataclass
    class HTTPResponseStruct:
        version: str
        status_code: str
        headers: dict[str, str]
        body: str

        def to_string(self) -> str:
            phrase = HTTPProtocol.STATUS_PHRASES[self.status_code]
            res_str = f"{self.version}{HTTPProtocol.SP}{self.status_code}{HTTPProtocol.SP}{phrase}{HTTPProtocol.CRLF}"
            for header in self.headers:
                res_str += f"{header}:{HTTPProtocol.SP}{self.headers[header]}{HTTPProtocol.CRLF}"
            res_str += HTTPProtocol.CRLF
            res_str += self.body

            return res_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @staticmethod
    def parse_request(req_bytes: bytes) -> HTTPRequestStruct:
        # Requests are parsed according to "Section 5: Request" of RFC 2616
        # Some steps are taken to ensure correctness of the req_bytes
        # according to the specification.

        start, headers, body = HTTPProtocol._parse_message(req_bytes)

        start_elements = start.split(HTTPProtocol.SP)
        if len(start_elements) != 3:
            raise ValueError(
                f"HTTP Request Parse Error: Invalid start line of length '{len(start_elements)}': {req_bytes}!"
            )

        method, uri, version = start_elements

        if method not in HTTPProtocol.VALID_METHODS:
            raise ValueError(f"HTTP Request Parse Error: Unsupported method '{method}': {req_bytes}!")

        if version != HTTPProtocol.VERSION:
            raise ValueError(f"HTTP Request Parse Error: Unsupported version '{version}': {req_bytes}!")

        return HTTPProtocol.HTTPRequestStruct(method, uri, version, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        # Responses are parsed according to "Section 6: Response" of RFC 2616
        # Some steps are taken to ensure correctness of the res_bytes
        # according to the specification.

        start, headers, body = HTTPProtocol._parse_message(res_bytes)

        start_elements = start.split(HTTPProtocol.SP)
        if len(start_elements) < 3:
            raise ValueError(
                f"HTTP Response Parse Error: Invalid start line of length '{len(start_elements)}': {res_bytes}!"
            )

        version, status_code, status_msg = start_elements[0], start_elements[1], " ".join(start_elements[2:])

        if version != HTTPProtocol.VERSION:
            raise ValueError(f"HTTP Response Parse Error: Unsupported version '{version}': {res_bytes}!")

        if status_code not in HTTPProtocol.STATUS_PHRASES:
            raise ValueError(f"HTTP Response Parse Error: Unsupported status code '{status_code}': {res_bytes}!")

        if status_msg != HTTPProtocol.STATUS_PHRASES[status_code]:
            raise ValueError(
                f"HTTP Response Parse Error: Incorrect phrase '{status_msg}!={HTTPProtocol.STATUS_PHRASES[status_code]}': {res_bytes}!"
            )

        return HTTPProtocol.HTTPResponseStruct(version, status_code, headers, body)

    @staticmethod
    def _parse_message(msg_bytes: bytes) -> list[list[str], dict[str, str], str]:
        # RFC 2616 specifies a HTTP message with two possible types: Request/Response.
        # This function parses the generic funtionality from both.

        msg_str = msg_bytes.decode("utf-8")

        try:
            header, body = msg_str.split(f"{HTTPProtocol.CRLF}{HTTPProtocol.CRLF}")
        except ValueError as e:
            raise ValueError(f"HTTP Message Parse Error: Could not split headers / body! ({msg_str})\n{e}")

        # header_lines contains both start-line and header-lines
        header_lines = header.split(HTTPProtocol.CRLF)
        if len(header_lines) < 0:
            raise ValueError(f"HTTP Message Parse Error: Headers expect at least 1 line! ({msg_str})")

        # RFC 2616 specifies some start-line which can be a request-line or a status-line, hence the naming chosen here.
        # start = header_lines.pop(0).split(HTTPProtocol.SP)
        start = header_lines.pop(0)

        headers = {}
        for header_line in header_lines:
            try:
                key, value = header_line.split(f":{HTTPProtocol.SP}")
            except ValueError as e:
                raise ValueError(f"HTTP Message Parse Error: Headers expect 'key: value'! ({msg_str})\n{e}")
            headers[key.lower()] = value

        return start, headers, body

    @staticmethod
    def create_request(method: str, uri: str, *, headers: dict[str, str], body: str = "") -> HTTPRequestStruct:
        method = method.upper()
        for key in headers:
            headers[key] = headers[key].lower()

        if method not in HTTPProtocol.VALID_METHODS:
            raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

        if method == "HEAD" and body:
            # According to RFC 2616 HEAD requests should not have a body
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HTTPProtocol.HTTPRequestStruct(method, uri, HTTPProtocol.VERSION, headers, body)

    @staticmethod
    def create_response(status_code: str, *, headers: dict[str, str] = {}, body="") -> HTTPResponseStruct:
        if status_code not in HTTPProtocol.STATUS_PHRASES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")

        return HTTPProtocol.HTTPResponseStruct(HTTPProtocol.VERSION, status_code, headers, body)

    @staticmethod
    def get_exam_string(message: HTTPRequestStruct | HTTPRequestStruct, note: str = "") -> None:
        message_type = "request" if type(message) is HTTPProtocol.HTTPRequestStruct else "response"
        message_string = "\n".join(f"  | {line}" for line in message.to_string().split("\n"))

        def parse_value(field_name, value):
            if value and field_name == "body":
                return value.encode("utf-8")
            elif value:
                return str(value)
            else:
                return "<NONE>"

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(message).items()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str) - 1)

        return "\n".join(
            (
                f"------------{note_str} Application Layer Message {note_padding}",
                f"RAW DATA: 0x{message.to_bytes().hex()}",
                "PROTOCOL: HTTP",
                f"MESSAGE TYPE: {message_type}",
                "MESSAGE STRING:",
                message_string,
                "FIELDS:",
                message_fields,
                "---------- END Application Layer Message ----------",
            )
        )


class ApplicationLayer:
    transport: TransportLayer

    def __init__(self) -> None:
        self.transport = TransportLayer()

    def execute(self) -> None:
        # Plugin and setup network layer
        self.transport.network.plug_in_and_perform_dhcp_discovery()

        # Initialize mock TCP socket that holds a config and talks to self.transport
        sock = self.transport.create_socket()
        sock.bind(("0.0.0.0", 80))

        # Passive open socket and accept connections on local ip:80
        sock.accept()

        # Receive HEAD request and send random 300 response
        req_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        req = HTTPProtocol.parse_request(req_bytes)
        print(HTTPProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HTTPProtocol.STATUS_PHRASES.keys()))
        res = HTTPProtocol.create_response(status)
        print(HTTPProtocol.get_exam_string(res, note="SENDING"))
        sock.send(res.to_bytes())

        sock.wait_close()

        # Passive open socket again and accept connections on local ip:80
        sock.accept()

        # Receive GET request and send random 300 response
        req_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        req = HTTPProtocol.parse_request(req_bytes)
        print(HTTPProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HTTPProtocol.STATUS_PHRASES.keys()))
        res = HTTPProtocol.create_response(status)
        print(HTTPProtocol.get_exam_string(res, note="SENDING"))
        sock.send(res.to_bytes())

        sock.wait_close()


if __name__ == "__main__":
    ApplicationLayer().execute()
