from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from logger import Logger
from layer_network import NetworkLayer, DNSServer


@dataclass
class TcpFlags:
    """Internal of TcpPacket.
    TCP flags are 6-bits packed into a single byte."""

    urg: bool = False
    ack: bool = False
    psh: bool = False
    rst: bool = False
    syn: bool = False
    fin: bool = False

    @classmethod
    def from_bytes(cls, flags_bytes: bytes) -> TcpFlags:
        # Unpack packed bytes as unsigned char bitmask then construct
        flags_bitmask = struct.unpack(">B", flags_bytes)[0]
        return cls.from_bitmask(flags_bitmask)

    @classmethod
    def from_bitmask(cls, flags_bitmask: int) -> TcpFlags:
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
        return self.__str__()

    def to_nice_string(self) -> str:
        return f"({', '.join(flag_name.upper() for flag_name, flag_value in vars(self).items() if flag_value)})"

    def __int__(self) -> int:
        return self.to_bitmask()

    def __str__(self) -> str:
        return "".join(str(i) for i in self.to_bitmask_list())

    def __eq__(self, __value: TcpFlags) -> bool:
        return self.to_bitmask() == __value.to_bitmask()


@dataclass
class TcpOption(Logger):
    """Internal of TcpPacket.
    TCP options are variable length, packed into words."""

    class Kind(IntEnum):
        END_OF_OPTION_LIST = 0
        NO_OPERATION = 1
        MAXIMUM_SEGMENT_SIZE = 2
        WINDOW_SCALING = 3

    SINGLE_BYTE_KINDS = set((Kind.END_OF_OPTION_LIST, Kind.NO_OPERATION))
    ALL_KINDS = set((Kind.END_OF_OPTION_LIST, Kind.NO_OPERATION, Kind.MAXIMUM_SEGMENT_SIZE, Kind.WINDOW_SCALING))

    @staticmethod
    def from_bytes(option_bytes: bytes) -> TcpOption:
        (
            option,
            _remaining_bytes,
        ) = TcpOption.from_bytes_with_remainder(option_bytes)

        return option

    @staticmethod
    def from_bytes_with_remainder(option_bytes: bytes) -> tuple[TcpOption, bytes]:
        # Extract option kind from front of option_bytes, and return along with the remainder.

        # Byte 1: Option kind
        option_kind = option_bytes[0]

        if option_kind in TcpOption.SINGLE_BYTE_KINDS:
            return TcpOption(kind=option_kind), option_bytes[1:]

        if option_kind not in TcpOption.ALL_KINDS:
            raise NotImplementedError(f"Unsupported option kind: {option_kind}")

        if len(option_bytes) <= 1:
            raise ValueError("Option kind requires length field but no length was specified!")

        # Byte 2: Length of data
        option_length = option_bytes[1]

        # Byte 3+: Option data
        option_data = option_bytes[2:option_length]

        return TcpOption(kind=option_kind, data=option_data), option_bytes[option_length:]

    kind: Kind
    data: bytes = bytes()
    len: int = field(init=False)

    def __post_init__(self):
        super().__init__()
        self.len = 1 if self.kind in TcpOption.SINGLE_BYTE_KINDS else 2 + len(self.data)

    def to_string(self) -> str:
        return self.__str__()

    def to_bytes(self) -> bytes:
        if self.kind in TcpOption.SINGLE_BYTE_KINDS:
            return bytes([self.kind])
        else:
            return bytes([self.kind, self.len]) + self.data

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        if self.kind in TcpOption.SINGLE_BYTE_KINDS:
            return f"kind={TcpOption.Kind(self.kind).name}"
        else:
            return f"kind={TcpOption.Kind(self.kind).name} len={self.len} data=0x{self.data.hex()}"


@dataclass
class TcpPacket:
    """Internal of TcpProtocol.
    Representation of a TCP packet used by TcpProtocol."""

    src_port: int
    dest_port: int
    seq_number: int
    ack_number: int
    data_offset: int
    flags: TcpFlags
    window: bytes
    checksum: int
    urgent_pointer: bytes
    options: list[TcpOption]
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

    def to_string(self) -> str:
        return self.__str__()

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
        def str_list(lst):
            return [f"{str_list(e)}" if isinstance(e, list) else str(e) for e in lst]

        return "|".join(str_list(self.__dict__.values()))


class TcpProtocol:
    """This class represents a TCP simulation based on RFC 793.

    The class itself allows for parsing and creating TCP frames or "packets".

    RFC 793 has been referenced heavily throughout to verify this implementation
    is correct.

    - RFC 793: https://datatracker.ietf.org/doc/html/rfc793
    """

    # The MSS is usually the link MTU size minus the 40 bytes of the TCP and IP headers,
    # but many implementations use segments of 512 or 536 bytes. We will use 512 bytes.
    HARDCODED_MSS = 512

    # The receive window is the amount of data that can be sent before the receiver must ACK.
    # We will use the maximum 16-bit window size of.
    WINDOW_SIZE = 2**16 - 1  # 16-bit window size

    @staticmethod
    def create_packet(
        src_port: int,
        dest_port: int,
        seq_number: int,
        ack_number: int,
        window: int,
        flags: TcpFlags,
        data: bytes = bytes(),
        options: list[TcpOption] = [],
    ) -> TcpPacket:
        # Calculate the number of bytes in the header
        MIN_TCP_HEADER_BYTES = 20
        length_of_options_bytes = sum(len(o) for o in options)

        # Check options are valid and align to the nearest 4 byte word.
        if options != [] and length_of_options_bytes % 4 != 0 and options[-1].kind != TcpOption.Kind.END_OF_OPTION_LIST:
            raise Exception(
                "If options do not align to the nearest 4 byte word they must contain an END_OF_OPTION_LIST option!"
            )

        # Get the nearest number of 4-byte words needed to hold all options
        options_space_bytes = -4 * (length_of_options_bytes // -4)

        # Get the data offset in 4-byte words
        data_offset = (MIN_TCP_HEADER_BYTES + options_space_bytes) // 4

        # Put all into final struct and return
        return TcpPacket(
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
    def parse_packet(packet_bytes: bytes) -> TcpPacket:
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
        ) = struct.unpack(">HHIIBBHHH", packet_bytes[:20])

        # Calculate data starting location
        data_offset = data_offset_padded >> 4
        data_offset_bytes = data_offset * 4

        # Parse flags bitmask into nice struct
        flags = TcpFlags.from_bitmask(flags_bitmask)

        # View calculated options bytes and parse options
        options_bytes = packet_bytes[20:data_offset_bytes]
        options: list[TcpOption] = []
        while options_bytes:
            option, options_bytes = TcpOption.from_bytes_with_remainder(options_bytes)
            options.append(option)

            # Stop parsing options when reached END_OF_OPTION_LIST
            if option.kind == TcpOption.Kind.END_OF_OPTION_LIST:
                break

        # View calculated data bytes
        data = packet_bytes[data_offset_bytes:]

        # Put all into final struct and return
        return TcpPacket(
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
    def calculate_checksum(packet: TcpPacket, src_ip: str, dest_ip: str) -> int:
        # Set checksum to 0 for calculation
        tmp_checksum = packet.checksum
        packet.checksum = 0

        # 16-bit one's complement of the one's complement sum of all 16-bit words in the pseudo header + tcp header + text
        words_to_sum = []

        # --- Pseudo header ---
        # Split 32-bit src_ip + dest_ip into 16-bit words
        src_ip_bytes = struct.pack(">I", NetworkLayer.ip_to_int(src_ip))
        dest_ip_bytes = struct.pack(">I", NetworkLayer.ip_to_int(dest_ip))
        words_to_sum.append(src_ip_bytes[:2])
        words_to_sum.append(src_ip_bytes[2:])
        words_to_sum.append(dest_ip_bytes[:2])
        words_to_sum.append(dest_ip_bytes[2:])

        # Reserved + Protocol and TCP Length
        words_to_sum.append(struct.pack(">BB", 0x00, 0x06))
        words_to_sum.append(struct.pack(">H", len(packet.to_bytes())))

        # Ensure pseudo header is 96 bits (12 bytes)
        assert sum(len(w) for w in words_to_sum) == 96 // 8

        # --- TCP Packet ---
        # Split header into 16-bit words and optionally pad to 16-bits
        packet_bytes = packet.to_bytes()
        for i in range(0, len(packet_bytes), 2):
            word = packet_bytes[i : i + 2]
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
        packet.checksum = tmp_checksum
        return checksum

    @staticmethod
    def get_exam_string(packet: TcpPacket, init_seq: int, init_ack: int, note: str = "") -> str:
        def parse_value(field_name, value):
            if field_name == "flags":
                return f"{value.to_string()} {value.to_nice_string()}"
            elif field_name == "options" and value:
                return "".join(f"\n     |- {option.to_string()}" for option in value)
            elif field_name == "seq_number":
                return f"{value} (rel={0 if (value == 0 or init_seq == 0) else (value - init_seq)})"
            elif field_name == "ack_number":
                return f"{value} (rel={0 if (value == 0 or init_ack == 0) else (value - init_ack)})"
            elif value is not None:
                return str(value)

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(packet).items()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str))

        return "\n".join(
            (
                f"------------{note_str} Transport Layer Frame {note_padding}",
                f"RAW DATA: {packet.to_bytes()}",
                "PROTOCOL: TCP",
                f"PACKET STRING: {packet.to_string()}",
                "PACKET FIELDS:",
                message_fields,
                "---------- END Transport Layer Frame ----------",
            )
        )


class TransportControlBlock(Logger):
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

    def __init__(self) -> None:
        super().__init__()

    def __setattr__(self, __name: str, __value: Any) -> None:
        if __name == "state" and self.logger:
            self.logger.debug(f"Setting TCB state to {TransportControlBlock.State(__value).name}.")

        super().__setattr__(__name, __value)


class TcpIpSocket(Logger):
    """Very small mock socket that imitates the real interface
    used to interact with the transport layer."""

    transport: TransportLayer
    bound_src_ip: str
    bound_src_port: int
    tcb: TransportControlBlock = None

    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport

    @staticmethod
    def _resolve_ip_from_host(host: str) -> str:
        """Resolve an IP address from a host.
        A host could be a hostname in domain notation or an IPv4 address.
        """
        host = host.lstrip("https://").lstrip("http://")

        if host.count(".") == 3 and all(s.isdigit() for s in host.split(".")):
            # Host is already an IP address.
            return host
        else:
            # Host is a hostname, resolve it.
            return DNSServer.resolve(host)

    def connect(self, addr: tuple(str, int)) -> None:
        # Configure socket with bound ip.
        self.bound_src_ip = NetworkLayer.src_ip

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
        # Unpack addr then update socket configuration.

        # Calculate destination ip and port from addr.
        host, port = addr
        ip = self._resolve_ip_from_host(host)
        self.bound_src_ip, self.bound_src_port = (ip, port)

    def accept(self) -> None:
        # Step 1 and 2 of passive open procedure.

        if self.tcb and self.tcb.state != TransportControlBlock.State.CLOSED:
            raise Exception(f"Simulation Error: TCB is not in CLOSED state: {self.tcb.state}")

        # Create a TCB and set it to the LISTEN state.
        self.tcb = TransportControlBlock()
        self.tcb.src_ip = self.bound_src_ip
        self.tcb.src_port = self.bound_src_port
        self.tcb.state = TransportControlBlock.State.LISTEN

        # Tell transport layer to receive packets into the listening TCB.
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


class TransportLayer(Logger):
    """Simulated transport layer capable of opening / communicating with
    TcpConnections a between a source ip+port (ourselves) and some destination ip+port."""

    network: NetworkLayer

    def __init__(self) -> None:
        super().__init__()
        self.network = NetworkLayer()

    def create_socket(self) -> TcpIpSocket:
        return TcpIpSocket(self)

    def active_open_connection(self, src_ip: str, src_port: str, dest_ip: str, dest_port: str) -> TransportControlBlock:
        # Active open connection using TCP RFC 793 state diagram fig 6:
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.4
        self.logger.info(f"Initiating open active on {src_port}->{dest_port}, performing handshake.")

        # Create a TCB and set it to the fictional CLOSED state.
        tcb = TransportControlBlock()
        tcb.src_ip = src_ip
        tcb.src_port = src_port
        tcb.dest_ip = dest_ip
        tcb.dest_port = dest_port
        tcb.src_mss = TcpProtocol.HARDCODED_MSS
        tcb.state = TransportControlBlock.State.CLOSED

        # Initialize send sequence variables.
        tcb.iss = random.randint(0, 2**32 - 1)
        tcb.snd_una = tcb.iss
        tcb.snd_nxt = tcb.iss
        tcb.snd_wnd = TcpProtocol.WINDOW_SIZE
        tcb.snd_wl1 = 0
        tcb.snd_wl2 = 0

        # Initialize receive sequence variables.
        tcb.irs = 0
        tcb.rcv_nxt = 0
        tcb.rcv_wnd = TcpProtocol.WINDOW_SIZE

        # ACTIVE 1. Create and send a SYN packet, set TCB state to SYN_SENT.
        self.logger.info("Sending handshake SYN...")
        syn_options = [TcpOption(kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE, data=struct.pack(">H", tcb.src_mss))]
        syn_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(syn=True),
            options=syn_options,
        )
        tcb.snd_una = syn_packet.seg_seq
        tcb.snd_nxt += syn_packet.seg_len
        self._send_tcp_packet(tcb, syn_packet)
        tcb.state = TransportControlBlock.State.SYN_SENT

        # NOTE: Can now either receive SYN, SYNACK, client close, or timeout.
        # we handle receiving SYNACK, proceed to ACTIVE open step 2.
        # We do not handle SYN, normally would proceed to SYN_RECEIVED state with simultaneous open.
        # We do not handle client calling close or handle timeout.

        # ACTIVE 2. Wait for SYNACK packet.
        self.logger.info("Receiving handshake SYNACK...")
        recv_packet, _ = self._receive_tcp_packet(tcb)
        if recv_packet.flags != TcpFlags(syn=True, ack=True):
            raise Exception(f"Simulation Error: Server responded with invalid packet: {recv_packet.to_string()}")

        # Check they sent an acceptable ACK for our SYN.
        # In a real system we would retransmit the SYN packet if not.
        # In this simulation we will just raise an exception.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.3
        if not (tcb.snd_una < recv_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {recv_packet.to_string()}")

        # Update sequence numbers.
        tcb.irs = recv_packet.seg_seq
        tcb.rcv_nxt = recv_packet.seg_seq + recv_packet.seg_len
        tcb.snd_wnd = recv_packet.window
        tcb.snd_wl1 = recv_packet.seg_seq
        tcb.snd_wl2 = recv_packet.seg_ack

        # If found MSS option in packet update TCB with dest MSS.
        if mss_option := next((o for o in recv_packet.options if o.kind == TcpOption.Kind.MAXIMUM_SEGMENT_SIZE), None):
            tcb.dest_mss = struct.unpack(">H", mss_option.data)[0]
            self.logger.debug(f"Received dest MSS: {tcb.dest_mss}.")

        # ACTIVE 3. Send a final response ACK packet, then set TCB state to ESTABLISHED.
        self.logger.info("Sending handshake ACK...")
        ack_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(ack=True),
        )
        tcb.snd_una = ack_packet.seg_seq
        tcb.snd_nxt += ack_packet.seg_len
        self._send_tcp_packet(tcb, ack_packet)

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
        self.logger.info(f"Initiating passive open on {tcb.src_port}, performing handshake.")

        # Initialize send sequence variables.
        tcb.iss = random.randint(0, 2**32 - 1)
        tcb.snd_una = tcb.iss
        tcb.snd_nxt = tcb.iss
        tcb.snd_wnd = TcpProtocol.WINDOW_SIZE
        tcb.snd_wl1 = 0
        tcb.snd_wl2 = 0

        # Initialize receive sequence variables.
        tcb.irs = 0
        tcb.rcv_nxt = 0
        tcb.rcv_wnd = TcpProtocol.WINDOW_SIZE

        # PASSIVE 1. Wait to receive first applicable SYN packet.
        self.logger.info("Handshake SYN...")
        recv_packet, packet_src_ip = self._receive_tcp_packet(tcb)
        if not recv_packet.flags == TcpFlags(syn=True):
            raise Exception(f"Simulation Error: Client responded with non SYN packet: {recv_packet.to_string()}")

        # Update sequence numbers.
        tcb.irs = recv_packet.seg_seq
        tcb.rcv_nxt = recv_packet.seg_seq + recv_packet.seg_len
        tcb.snd_wnd = recv_packet.window
        tcb.snd_wl1 = recv_packet.seg_seq
        tcb.snd_wl2 = recv_packet.seg_ack

        # Update TCB with ip and port of received packet.
        tcb.dest_ip = packet_src_ip
        tcb.dest_port = recv_packet.src_port

        # If found MSS option in packet update TCB with dest MSS.
        if mss_option := next((o for o in recv_packet.options if o.kind == TcpOption.Kind.MAXIMUM_SEGMENT_SIZE), None):
            tcb.dest_mss = struct.unpack(">H", mss_option.data)[0]
            self.logger.debug(f"Received dest MSS: {tcb.dest_mss}.")

        # PASSIVE 2. Create and send a SYNACK packet, set TCB state to SYN_RCVD.
        self.logger.info("Handshake SYNACK...")
        syn_ack_options = [
            TcpOption(kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE, data=struct.pack(">H", TcpProtocol.HARDCODED_MSS))
        ]
        syn_ack_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(syn=True, ack=True),
            options=syn_ack_options,
        )
        tcb.snd_una = syn_ack_packet.seg_seq
        tcb.snd_nxt += syn_ack_packet.seg_len
        self._send_tcp_packet(tcb, syn_ack_packet)
        tcb.state = TransportControlBlock.State.SYN_RECEIVED

        # NOTE: We could receive either ACK, client could call close, or timeout.
        # We do not handle client calling close.
        # We do not handle timeout.

        # PASSIVE 3. Wait to receive a final ACK packet.
        self.logger.info("Handshake ACK...")
        recv_packet, packet_src_ip = self._receive_tcp_packet(tcb)
        if not recv_packet.flags == TcpFlags(ack=True):
            raise Exception(f"Simulation Error: Client responded with non ACK packet: {recv_packet.to_string()}")

        # Check they sent an acceptable ACK for our SYNACK.
        # In a real system we would retransmit the SYNACK packet if not.
        # In this simulation we will just raise an exception.
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.3
        if not (tcb.snd_una < recv_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {recv_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = recv_packet.seg_seq + recv_packet.seg_len
        tcb.snd_wnd = recv_packet.window
        tcb.snd_wl1 = recv_packet.seg_seq
        tcb.snd_wl2 = recv_packet.seg_ack

        # Return final TCB in established state
        tcb.state = TransportControlBlock.State.ESTABLISHED
        return tcb

    def active_close_connection(self, tcb: TransportControlBlock) -> None:
        # Ensure connection is in ESTABLISHED state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Received application close, perform active close procedure.
        self.logger.info("Initiating active close.")

        # ACTIVE 1. Send FIN, Enter FIN_WAIT_1.
        self.logger.info("Sending FIN...")
        fin_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(fin=True),
        )
        tcb.snd_una = fin_packet.seg_seq
        tcb.snd_nxt += fin_packet.seg_len
        self._send_tcp_packet(tcb, fin_packet)
        tcb.state = TransportControlBlock.State.FIN_WAIT_1

        # NOTE: Can now either receive FIN, FINACK, ACK, or timeout.
        # We handle receiving ACK, proceed to FIN_WAIT_2 in ACTIVE 2.
        # We do not handle receiving FINACK, normally send ACK and proceed to TIME_WAIT.
        # We do not handle FIN, normally would proceed to CLOSING with simultaneous close.
        # We do not handle timeout.

        # ACTIVE 2. Wait for ACK packet, wait for FIN, send ACK, proceed to TIME_WAIT.
        self.logger.info("Receiving ACK...")
        ack_packet, _ = self._receive_tcp_packet(tcb)
        if ack_packet.flags != TcpFlags(ack=True):
            raise Exception(f"Simulation Error: Received packet with invalid flags: {ack_packet.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_packet.seg_seq + ack_packet.seg_len
        tcb.snd_wnd = ack_packet.window
        tcb.snd_wl1 = ack_packet.seg_seq
        tcb.snd_wl2 = ack_packet.seg_ack

        # Receive FIN.
        self.logger.info("Receiving FIN...")
        fin_packet, _ = self._receive_tcp_packet(tcb)
        if fin_packet.flags != TcpFlags(fin=True):
            raise Exception(f"Simulation Error: Received packet with invalid flags: {fin_packet.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < fin_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {fin_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = fin_packet.seg_seq + fin_packet.seg_len
        tcb.snd_wnd = fin_packet.window
        tcb.snd_wl1 = fin_packet.seg_seq
        tcb.snd_wl2 = fin_packet.seg_ack

        # Send ACK.
        self.logger.info("Sending ACK...")
        ack_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(ack=True),
        )
        tcb.snd_una = ack_packet.seg_seq
        tcb.snd_nxt += ack_packet.seg_len
        self._send_tcp_packet(tcb, ack_packet)
        tcb.state = TransportControlBlock.State.TIME_WAIT

        # ACTIVE 3. Wait for 2MSL timeout, Enter CLOSED.
        self.logger.info("Waiting for 2MSL timeout...")
        # time.sleep(2 * 60) # Not waiting for timeout in simulation.
        tcb.state = TransportControlBlock.State.CLOSED

    def passive_close_connection(self, tcb: TransportControlBlock) -> None:
        # Ensure connection is in ESTABLISHED state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Awaiting active close, perform passive close procedure.
        self.logger.info("Initiating passive close.")

        # PASSIVE 1. Receive FIN, Send ACK, Enter CLOSE_WAIT.
        self.logger.info("Receiving FIN...")
        fin_packet, _ = self._receive_tcp_packet(tcb)
        if fin_packet.flags != TcpFlags(fin=True):
            raise Exception(f"Simulation Error: Received packet with invalid flags: {fin_packet.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < fin_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {fin_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = fin_packet.seg_seq + fin_packet.seg_len
        tcb.snd_wnd = fin_packet.window
        tcb.snd_wl1 = fin_packet.seg_seq
        tcb.snd_wl2 = fin_packet.seg_ack

        # Send ACK.
        self.logger.info("Sending ACK...")
        ack_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(ack=True),
        )
        tcb.snd_una = ack_packet.seg_seq
        tcb.snd_nxt += ack_packet.seg_len
        self._send_tcp_packet(tcb, ack_packet)
        tcb.state = TransportControlBlock.State.CLOSE_WAIT

        # PASSIVE 2. Wait for application close, Send FIN, Enter LAST_ACK.
        self.logger.info("Waiting for application close...")
        # continue # Not waiting for application close in simulation.

        # Send FIN.
        self.logger.info("Sending FIN...")
        fin_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=TcpFlags(fin=True),
        )
        tcb.snd_una = fin_packet.seg_seq
        tcb.snd_nxt += fin_packet.seg_len
        self._send_tcp_packet(tcb, fin_packet)
        tcb.state = TransportControlBlock.State.LAST_ACK

        # PASSIVE 3. Receive ACK, send nothing, Enter CLOSED.
        self.logger.info("Receiving ACK...")
        ack_packet, _ = self._receive_tcp_packet(tcb)
        if ack_packet.flags != TcpFlags(ack=True):
            raise Exception(f"Simulation Error: Received packet with invalid flags: {ack_packet.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_packet.seg_seq + ack_packet.seg_len
        tcb.snd_wnd = ack_packet.window
        tcb.snd_wl1 = ack_packet.seg_seq
        tcb.snd_wl2 = ack_packet.seg_ack

        # Close and finish
        tcb.state = TransportControlBlock.State.CLOSED

    def receive(self, tcb: TransportControlBlock, bufsize: int) -> bytes:
        # Ensure connection is in a valid state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Receive packets if have no ready data.
        if len(tcb.recv_buffer) == 0:
            # Receive first PSHACK packet.
            packet, _ = self._receive_tcp_packet(tcb)
            if packet.flags != TcpFlags(psh=True, ack=True):
                raise Exception(f"Simulation Error: Received packet with invalid flags: {packet.to_string()}")

            # Check they sent an acceptable ACK for the current communication.
            if not (tcb.snd_una < packet.seg_ack <= tcb.snd_nxt):
                raise Exception(f"Simulation Error: Client responded with invalid ACK number: {packet.to_string()}")

            # Update sequence numbers.
            tcb.rcv_nxt = packet.seg_seq + packet.seg_len
            tcb.snd_wnd = packet.window
            tcb.snd_wl1 = packet.seg_seq
            tcb.snd_wl2 = packet.seg_ack

            # Respond with ACK.
            ack_packet = TcpProtocol.create_packet(
                src_port=tcb.src_port,
                dest_port=tcb.dest_port,
                seq_number=tcb.snd_nxt,
                ack_number=tcb.rcv_nxt,
                window=tcb.rcv_wnd,
                flags=TcpFlags(ack=True),
            )
            tcb.snd_una = ack_packet.seg_seq
            tcb.snd_nxt += ack_packet.seg_len
            self._send_tcp_packet(tcb, ack_packet)

            # Receive data into the recv_buffer.
            tcb.recv_buffer += packet.data

        # Receive 'bufsize' bytes of application data.
        data = tcb.recv_buffer[:bufsize]
        tcb.recv_buffer = tcb.recv_buffer[bufsize:]
        return data

    def send(self, tcb: TransportControlBlock, data: bytes) -> None:
        # Ensure connection is in a valid state.
        if tcb.state != TransportControlBlock.State.ESTABLISHED:
            raise Exception(f"Simulation Error: TCB is not in ESTABLISHED state: {tcb.state}")

        # Ensure packet is less than dest MSS.
        # In a real system we would split the data into multiple packets.
        # In this simulation we will just raise an exception.
        if len(data) > tcb.dest_mss:
            raise Exception(f"Simulation Error: Packet size {len(data)} exceeds dest MSS {tcb.dest_mss}.")

        # Create single packet with all application data.
        pshack_flags = TcpFlags(psh=True, ack=True)
        pshack_packet = TcpProtocol.create_packet(
            src_port=tcb.src_port,
            dest_port=tcb.dest_port,
            seq_number=tcb.snd_nxt,
            ack_number=tcb.rcv_nxt,
            window=tcb.rcv_wnd,
            flags=pshack_flags,
            data=data,
        )
        tcb.snd_una = pshack_packet.seg_seq
        tcb.snd_nxt += pshack_packet.seg_len
        self._send_tcp_packet(tcb, pshack_packet)

        # Receive responding ACK packet.
        ack_packet, _ = self._receive_tcp_packet(tcb)
        if ack_packet.flags != TcpFlags(ack=True):
            raise Exception(f"Simulation Error: Received packet with invalid flags: {ack_packet.to_string()}")

        # Check they sent an acceptable ACK for the current communication.
        if not (tcb.snd_una < ack_packet.seg_ack <= tcb.snd_nxt):
            raise Exception(f"Simulation Error: Client responded with invalid ACK number: {ack_packet.to_string()}")

        # Update sequence numbers.
        tcb.rcv_nxt = ack_packet.seg_seq + ack_packet.seg_len
        tcb.snd_wnd = ack_packet.window
        tcb.snd_wl1 = ack_packet.seg_seq
        tcb.snd_wl2 = ack_packet.seg_ack

    def _receive_tcp_packet(self, tcb: TransportControlBlock) -> tuple[TcpPacket, str]:
        # Explictly does not check TCB state or SEQ / ACK numbers.
        # This responsibility is left to the caller.

        # Receive and parse the latest packet.
        # Guaranteed to be fully received due if communicated MSS.
        packet_data, packet_src_ip = self.network.receive(tcb.src_ip)
        packet = TcpProtocol.parse_packet(packet_data)
        self.logger.debug("⬆️  [Network->TCP]")
        self.logger.info(f"Received {packet.to_string()=}")
        self.exam_logger.info(TcpProtocol.get_exam_string(packet, tcb.irs, tcb.iss, note="RECEIVED"))

        # Check packet ip and port is for this connection.
        if packet.dest_port != tcb.src_port:
            raise Exception(
                f"Server waiting to accept connections received packet for incorrect port: {packet.to_string()}"
            )

        # Check packet checksum is correct
        checksum = TcpProtocol.calculate_checksum(packet, packet_src_ip, tcb.src_ip)
        if checksum != packet.checksum:
            raise Exception(
                f"Server waiting to accept connections received packet with incorrect checksum: {packet.to_string()}"
            )

        # Log and return packet
        return packet, packet_src_ip

    def _send_tcp_packet(self, tcb: TransportControlBlock, packet: TcpPacket) -> None:
        # Explictly does not check TCB state or SEQ / ACK numbers.
        # This responsibility is left to the caller.

        # Set checksum on the packet using pseudo header info.
        packet.checksum = TcpProtocol.calculate_checksum(packet, tcb.src_ip, tcb.dest_ip)

        # Log and send packet
        self.logger.info(f"Sending {packet.to_string()=}...")
        self.network.send(tcb.dest_ip, packet.to_bytes())
        self.logger.debug("⬇️  [TCP->Network]")
        self.exam_logger.info(TcpProtocol.get_exam_string(packet, tcb.iss, tcb.irs, note="SENDING"))
