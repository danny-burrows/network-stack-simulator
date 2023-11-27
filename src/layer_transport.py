from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from enum import IntEnum

from logger import Logger
from layer_physical import PhysicalLayer


class TcpProtocol:
    # TODO: Make sure this BUFSIZE is correct.
    BUFSIZE = 800

    @dataclass
    class TcpFlags:
        urg: bool = False
        ack: bool = False
        psh: bool = False
        rst: bool = False
        syn: bool = False
        fin: bool = False

        @classmethod
        def from_bytes(cls, flags_bytes: bytes) -> TcpProtocol.TcpFlags:
            # Unpack packed bytes as unsigned char bitmask then construct
            flags_bitmask = struct.unpack("=B", flags_bytes)[0]
            return cls.from_bitmask(flags_bitmask)

        @classmethod
        def from_bitmask(cls, flags_bitmask: int) -> TcpProtocol.TcpFlags:
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
            return bytes([ self.to_bitmask() ])
        
        def to_bitmask_list(self) -> [int]:
            # Convert to list of flags as bits
            return [int(v) for v in [self.urg, self.ack, self.psh, self.rst, self.syn, self.fin]]
        
        def to_bitmask(self) -> int:
            # Convert to bitmask for flags
            return sum(v * 2**i for i, v in enumerate(self.to_bitmask_list()[::-1]))

        def to_string(self) -> str:
            # Stringify as bits from bitmask
            return "".join(str(i) for i in self.to_bitmask_list())
    
        def __int__(self) -> int:
            return self.to_bitmask()

    class TcpOptionKind(IntEnum):
        END_OF_OPTION_LIST = 0
        NO_OPERATION = 1
        MAXIMUM_SEGMENT_SIZE = 2

    OPTIONS_SINGLE_BYTE_KINDS = set((TcpOptionKind.END_OF_OPTION_LIST, TcpOptionKind.NO_OPERATION))
    OPTIONS_ALL_KINDS = set((TcpOptionKind.END_OF_OPTION_LIST, TcpOptionKind.NO_OPERATION, TcpOptionKind.MAXIMUM_SEGMENT_SIZE))

    @dataclass
    class TcpOption(Logger):
        @staticmethod
        def from_bytes(option_bytes: bytes) -> TcpProtocol.TcpOption:
            (option, _remaining_bytes) = TcpProtocol.TcpOption.from_bytes_with_remainder(option_bytes)
            return option

        @staticmethod
        def from_bytes_with_remainder(option_bytes: bytes) -> tuple[TcpProtocol.TcpOption, bytes]:
            # Byte 1: Option kind
            option_kind = option_bytes[0]

            if option_kind in TcpProtocol.OPTIONS_SINGLE_BYTE_KINDS:
                return TcpProtocol.TcpOption(kind=option_kind), option_bytes[1:]

            if option_kind not in TcpProtocol.OPTIONS_ALL_KINDS:
                raise NotImplementedError(f"Unsupported option kind: {option_kind}")

            if len(option_bytes) <= 1:
                raise ValueError("Option kind requires length field but no length was specified!")

            # Byte 2: Length of data
            option_length = option_bytes[1]

            # Byte 3+: Option data
            option_data = option_bytes[2:option_length]

            return TcpProtocol.TcpOption(kind=option_kind, data=option_data), option_bytes[option_length:]

        kind: TcpProtocol.TcpOptionKind
        data: bytes = bytes()

        def __len__(self):
            return 1 if self.kind in TcpProtocol.OPTIONS_SINGLE_BYTE_KINDS else 2 + len(self.data)
        
        def to_string(self) -> str:
            if self.kind in TcpProtocol.OPTIONS_SINGLE_BYTE_KINDS:
                return str(self.kind)
            else:
                return f"{self.kind}{self.length}{self.data if self.data else ''}"

        def to_bytes(self) -> bytes:
            if self.kind in TcpProtocol.OPTIONS_SINGLE_BYTE_KINDS:
                return bytes([ self.kind ])
            else:
                return bytes([ self.kind, self.length ]) + self.data

    @dataclass
    class TcpPacket:
        src_port: int
        dest_port: int
        seq_number: int
        ack_number: int
        data_offset: int
        flags: TcpProtocol.TcpFlags
        recv_window: bytes
        checksum: int
        urgent_pointer: bytes
        options: list[TcpProtocol.TcpOption]
        data: bytes

        def to_string(self) -> str:
            # TODO: Implement nice to_string()
            return self.__str__()

        def to_bytes(self) -> bytes:
            # Pack ports, seq, and ack number
            src_dest_seq_ack_bytes = struct.pack(
                "=HHII",
                self.src_port,
                self.dest_port,
                self.seq_number,
                self.ack_number,
            )

            # Calculate data offset (4) + reserved (6) + flags (6) bytes = 16 bits

            # Data offset must fit into 4 bits
            assert self.data_offset < 2**4

            # Pad right of data offset right 4 / 6 reserved bits
            data_offset_padded = self.data_offset << 4

            # Left of flags contains last 2 / 6 reserved bits
            flags_bitmask = self.flags.to_bitmask()

            # Pack all of the above into 16 bits
            flags_data_offset = struct.pack(
                "=BB",
                data_offset_padded,
                flags_bitmask,
            )
            
            # Pack some remaining variables
            window_checksum_urg = struct.pack(
                "=HHH",
                self.recv_window,
                self.checksum,
                self.urgent_pointer,
            )

            # Pack options bytes up
            options_bytes = [ o.to_bytes() for o in self.options ]

            # Calc padding needed to ensure options are padded to the nearest 4-byte word
            length_of_options = sum(len(o) for o in options_bytes)
            options_padding = bytes(4 - (length_of_options % 4))

            # Construct header with all packed bits, including options and options padding
            header = src_dest_seq_ack_bytes + flags_data_offset + window_checksum_urg
            for option_bytes in options_bytes:
                header += option_bytes
            header += options_padding

            # Return final packed header + data bytes
            return header + self.data

    @staticmethod
    def create_packet(
        src_port: int, dest_port: int, flags: TcpFlags, data: bytes = bytes(), options: list[TcpOption] = []
    ) -> TcpPacket:
        # TODO: Look at why there needs to be a single options.
        #       Related code in to_bytes() with length_of_options.
        # There must be at least one option...
        if options == []:
            # Add a single terminating option
            options = [TcpProtocol.TcpOption(kind=TcpProtocol.TcpOptionKind.END_OF_OPTION_LIST)]

        # Calculate the number of 32 bit words in the header
        MIN_TCP_HEADER_WORDS = 5
        length_of_options_in_bytes = sum(len(o) for o in options)
        data_offset = MIN_TCP_HEADER_WORDS + ((-4 * (length_of_options_in_bytes // -4)) // 4)

        # TODO: Calculate checksum using "psudo packet" mentioned in lectures...

        packet = TcpProtocol.TcpPacket(
            src_port=src_port,
            dest_port=dest_port,
            # Initialise SEQ and ACK numbers to 0
            seq_number=0,
            ack_number=0,
            data_offset=data_offset,
            # TODO: Need to find better values for the following or justify them being hardcoded...
            flags=flags,
            recv_window=0,
            checksum=1,
            urgent_pointer=0,
            options=options,
            data=data,
        )
        return packet

    @staticmethod
    def parse_packet(packet_bytes: bytes) -> TcpPacket:
        # View first 20 bytes for header and parse variables
        (
            src_port,
            dest_port,
            seq_number,
            ack_number,
            data_offset,
            flags_bitmask,
            recv_window,
            checksum,
            urgent_pointer,
        ) = struct.unpack("=HHIIBBHHH", packet_bytes[:20])

        # Calculate data starting location
        data_offset = data_offset >> 4
        data_offset = data_offset * 4

        # Parse flags bitmask into nice struct
        flags = TcpProtocol.TcpFlags.from_bitmask(flags_bitmask)

        # View calculated options bytes and parse options
        options_data = packet_bytes[20:data_offset]
        options: list[TcpProtocol.TcpOption] = []
        while options_data:
            option, options_data = TcpProtocol.TcpOption.from_bytes_with_remainder(options_data)
            options.append(option)

            # Stop parsing options when reached END_OF_OPTION_LIST
            if option.kind == TcpProtocol.TcpOptionKind.END_OF_OPTION_LIST:
                break

        # View calculated data bytes
        data = packet_bytes[data_offset:]

        # Put all into final struct and return
        return TcpProtocol.TcpPacket(
            src_port=src_port,
            dest_port=dest_port,
            seq_number=seq_number,
            ack_number=ack_number,
            data_offset=data_offset,
            flags=flags,
            recv_window=recv_window,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=options,
            data=data,
        )

    @staticmethod
    def get_exam_string(packet: TcpPacket) -> str:
        # TODO
        pass


class TcpConnection:
    src_host: str
    src_port: str
    dest_host: str
    dest_port: str
    send_buffer: bytes = bytes()
    recv_buffer: bytes = bytes()
    is_handshaking: bool = False
    has_handshaked: bool = False


class TcpSocket(Logger):
    """Very small mock socket that imitates the real interface
    used to interact with TCP Streams.
    """

    @staticmethod
    def _parse_addr(addr: str) -> (str, int):
        # TODO: Some validation for ip/domain correctness?
        host, port = addr.split(":")
        return host, int(port)

    transport: TransportLayer
    conn: TcpConnection

    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport
        self.conn = TcpConnection()

    def connect(self, addr: str) -> None:
        # Hardcode the client IP address
        src_host = "192.168.1.6"

        # Assign a random dynamic port for the client to use.
        # Dynamic ports are in the range 49152 to 65535.
        src_port = random.randint(49152, 65535)

        # Configure connection with src info.
        self.conn.src_host = src_host
        self.conn.src_port = src_port

        # Calculate destination host and port then configure connection.
        dest_host, dest_port = self._parse_addr(addr)
        self.conn.dest_host = dest_host
        self.conn.dest_port = dest_port

        # Tell transport layer to initiate handshake procedure on connection
        self.transport.initiate_tcp_handshake(self.conn)

    def bind(self, addr: str) -> None:
        # Unpack addr then update configuration.
        host, port = self._parse_addr(addr)
        self.conn.src_host = host
        self.conn.src_port = port

    def accept(self) -> None:
        # Tell transport layer to wait for a handshake procedure.
        self.transport.accept_incoming_tcp_handshake(self.conn)

    def receive(self, bufsize: int) -> bytes:
        # Receive 'bufsize' bytes of application data
        return self.transport.receive(self.conn, bufsize)

    def send(self, data: bytes) -> None:
        # Send application layer bytes.
        return self.transport.send(self.conn, data)


class TransportLayer(Logger):
    """Simulated transport layer capable of handling a single connection
    between a source host/port (ourselves) and some destination host/port.
    """

    physical: PhysicalLayer

    def __init__(self) -> None:
        super().__init__()
        self.physical = PhysicalLayer()

    def create_socket(self) -> TcpSocket:
        return TcpSocket(self)
    
    def initiate_tcp_handshake(self, conn: TcpConnection) -> int:
        # Perform three-way handshake to initiate a connection with addr.
        self.logger.info(f"Initiating handshake on {conn.src_port}->{conn.dest_port}.")
        conn.is_handshaking = True

        # 1. Create and send a SYN packet.
        self.logger.debug("Handshake SYN.")
        syn_packet = TcpProtocol.create_packet(conn.src_port, conn.dest_port, TcpProtocol.TcpFlags(syn=True))
        self._send_tcp_packet(syn_packet)

        # 2. Wait to receive a SYNACK packet.
        self.logger.debug("Handshake SYNACK.")
        recv_packet = self._receive_tcp_packet()

        # Check recv packet has is SYNACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not (recv_packet.flags.syn and recv_packet.flags.ack):
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

        # 3. Send a final response ACK packet.
        self.logger.debug("Handshake ACK.")
        ack_packet = TcpProtocol.create_packet(conn.src_port, conn.dest_port, TcpProtocol.TcpFlags(ack=True))
        self._send_tcp_packet(ack_packet)

        # Update connection state
        conn.is_handshaking = False
        conn.has_handshaked = True

    def accept_incoming_tcp_handshake(self, conn: TcpConnection) -> int:
        # Receiving end of three-way handshake to initiate a connection with any request.
        self.logger.info(f"Accepting handshake on {conn.src_port}.")
        conn.is_handshaking = True

        # 1. Wait to receive a SYN packet.
        self.logger.debug("Handshake SYN.")
        while True:

            # Wait to receive a packet.
            recv_packet = self._receive_tcp_packet()

            # Check packet has SYN set.
            if not recv_packet.flags.syn:
                self.logger.warn(f"Server waiting to accept connections received non-SYN packet: {recv_packet.to_string()}")

            # Check packet has correct dest port.
            elif recv_packet.dest_port != conn.src_port:
                self.logger.warn(f"Server waiting to accept connections received packet for incorrect port: {recv_packet.to_string()}")
            
            # Found a valid packet so perform handshake.
            else:
                break

        # Update connection with current connection.
        conn.dest_port = recv_packet.src_port

        # 2. Create and send a SYNACK packet.
        self.logger.debug("Handshake SYNACK.")
        syn_ack_packet = TcpProtocol.create_packet(conn.src_port, conn.dest_port, TcpProtocol.TcpFlags(syn=True, ack=True))
        self._send_tcp_packet(syn_ack_packet)

        # 3. Wait to receive a FINAL ACK packet.
        self.logger.debug("Handshake ACK.")
        recv_packet = self._receive_tcp_packet()

        # Check recv packet has is ACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not recv_packet.flags.ack:
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

        # Update connection state
        conn.is_handshaking = False
        conn.has_handshaked = True

    def _receive_tcp_packet(self) -> TcpProtocol.TcpPacket:
        packet = TcpProtocol.parse_packet(self.physical.receive())
        self.logger.debug("⬆️  [Physical->TCP]")
        self.logger.info(f"Received {packet.to_string()=}")
        return packet

    def _send_tcp_packet(self, packet: TcpProtocol.TcpPacket) -> None:
        self.logger.info(f"Sending {packet.to_string()=}...")
        self.logger.debug("⬇️  [TCP->Physical]")
        self.physical.send(packet.to_bytes())

    def receive(self, conn: TcpConnection, bufsize: int) -> bytes:
        # Ensure connection is in a valid state.
        assert(conn.has_handshaked)

        # Receive packets if have no ready data.
        if len(conn.recv_buffer) == 0:

            # Receive first incoming packet.
            packet = self._receive_tcp_packet()
            
            # Check packet is coming for the solitary connection.
            assert(packet.dest_port == conn.src_port and packet.src_port == conn.dest_port)

            # TODO: Check packet has correct flags.
            # TODO: Handle ACK then PSH.

            # Receive data into the recv_buffer.
            conn.recv_buffer += packet.data

        # Receive 'bufsize' bytes of application data
        data = conn.recv_buffer[:bufsize]
        conn.recv_buffer = conn.recv_buffer[bufsize:]
        return data

    def send(self, conn: TcpConnection, data: bytes) -> None:
        # Ensure connection is in a valid state.
        assert(conn.has_handshaked)

        # TODO: Split data up into packets.

        # Create single packet with all application data.
        packet = TcpProtocol.create_packet(conn.src_port, conn.dest_port, TcpProtocol.TcpFlags(ack=True), data=data)

        # Send single packet.
        self._send_tcp_packet(packet)
