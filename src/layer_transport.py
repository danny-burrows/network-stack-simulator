from __future__ import annotations

import random
import struct
from dataclasses import dataclass

from logger import Logger
from layer_physical import PhysicalLayer


class TcpSocket(Logger):
    """Very small mock socket that imitates the real interface
    used to interact with TCP Streams.
    """

    transport: TransportLayer

    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport

    @staticmethod
    def _parse_addr(addr: str) -> (str, int):
        # TODO: Some validation for ip/domain correctness?
        host, port = addr.split(":")
        return host, int(port)

    def connect(self, addr: str) -> None:
        # Hardcode the client IP address
        host = "192.168.1.6"

        # Assign a random dynamic port for the client to use.
        # Dynamic ports are in the range 49152 to 65535.
        port = random.randint(49152, 65535)

        self._bind(host, port)

        # Calculate destination host and port.
        dest_host, dest_port = self._parse_addr(addr)

        # Initiate handshake by sending SYN packet to destination.
        self.transport.initiate_handshake(self.port, dest_port)

    def _bind(self, host: str, port: int) -> None:
        self.host, self.port = host, port

    def bind(self, addr: str) -> None:
        self._bind(*self._parse_addr(addr))

    def accept(self) -> None:
        # Open file and wait for some SYN packet...
        self.transport.accept_incoming_handshake(self.port)
        pass

    def receive(self) -> bytes:
        return self.transport.receive()

    def send(self, data: bytes) -> None:
        self.transport.send(data)


class TcpProtocol:
    @dataclass
    class TcpFlags:
        urg: bool = False
        ack: bool = False
        psh: bool = False
        rst: bool = False
        syn: bool = False
        fin: bool = False

        @classmethod
        def from_bytes(cls, flag_bytes: bytes):
            assert len(flag_bytes) == 1, "Size of flags should be 1 byte (6 bits with 2 left-padding)"
            flags_int = struct.unpack("=B", flag_bytes)[0]
            return cls.from_int(flags_int)

        @classmethod
        def from_int(cls, flags_int: int):
            return cls(
                urg=bool(flags_int & (2**5)),
                ack=bool(flags_int & (2**4)),
                psh=bool(flags_int & (2**3)),
                rst=bool(flags_int & (2**2)),
                syn=bool(flags_int & (2**1)),
                fin=bool(flags_int & (2**0)),
            )

        def __int__(self) -> int:
            flags_int = 0
            for i, b in enumerate(self._to_int_list()[::-1]):
                flags_int += b * (2**i)
            return flags_int

        def _to_int_list(self) -> [bool]:
            flag_list = [int(self.urg), int(self.ack), int(self.psh), int(self.rst), int(self.syn), int(self.fin)]
            assert len(flag_list) == len(vars(self))
            return flag_list

        def to_string(self) -> str:
            return "".join(str(i) for i in self._to_int_list())

        def to_bytes(self) -> bytes:
            return bytes([int(self)])

    @dataclass
    class TcpOption:
        KIND_END_OF_OPTION_LIST = 0
        KIND_NO_OPERATION = 1
        KIND_MAXIMUM_SEGMENT_SIZE = 2

        kind: int
        length: int = 1
        data: bytes = bytes()

        @classmethod
        def from_bytes(cls, option_bytes: bytes):
            return cls.from_bytes_with_remainder(option_bytes)[0]

        @classmethod
        def from_bytes_with_remainder(cls, option_bytes: bytes) -> (TcpProtocol.TcpOption, bytes):
            option_kind = option_bytes[0]

            if option_kind in (cls.KIND_END_OF_OPTION_LIST, cls.KIND_NO_OPERATION):
                return cls(kind=option_kind), option_bytes[1:]

            assert len(option_bytes) > 1, "Option is of kind with size > 1 but has no length or data!"

            option_length = option_bytes[1]
            option_data = struct.unpack(f"={option_length - 2}s", option_bytes[2:option_length])[0]

            return cls(kind=option_kind, length=option_length, data=option_data), option_bytes[option_length:]

        def __len__(self):
            return self.length

        def to_string(self) -> str:
            return f"{self.kind}{self.length}{self.data if self.data else ''}"

        def to_bytes(self) -> bytes:
            # If option is "End of Option List" or "No-Operation" then no length needed
            if self.kind in (self.KIND_END_OF_OPTION_LIST, self.KIND_NO_OPERATION):
                option_bytes = bytes([self.kind])
            else:
                option_bytes = bytes([self.kind, self.length]) + self.data

            # Ensure result is the correct length
            assert len(option_bytes) == self.length
            return option_bytes

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
        options: [TcpProtocol.TcpOption]
        data: bytes

        def to_string(self) -> str:
            pass

        def to_bytes(self) -> bytes:
            src_dest_seq_ack_bytes = struct.pack(
                "=HHII",
                self.src_port,
                self.dest_port,
                self.seq_number,
                self.ack_number,
            )

            # Calculate data offset + reserved + flags (4) bytes
            # NB: There are a total of 6 reserved bits

            # Data offset must fit into 4 bits
            assert self.data_offset < 2**4

            # Pad-right with 4 of the 6 reserved bits
            data_offset_padded = self.data_offset << 4

            # The remaining 2 reserve bits are left-padded onto the flags
            flags_int = int(self.flags)

            flags_data_offset = struct.pack(
                "=BB",
                data_offset_padded,
                flags_int,
            )

            window_checksum_urg = struct.pack(
                "=HHH",
                self.recv_window,
                self.checksum,
                self.urgent_pointer,
            )

            options_bytes = [o.to_bytes() for o in self.options]

            # Calc padding needed to ensure options are padded to the nearest 4-byte word
            length_of_options = sum(len(o) for o in options_bytes)
            options_padding = bytes(4 - (length_of_options % 4))

            header = src_dest_seq_ack_bytes + flags_data_offset + window_checksum_urg

            for option_bytes in options_bytes:
                header += option_bytes
            header += options_padding

            return header + self.data

    @staticmethod
    def create_packet(
        src_port: int, dest_port: int, flags: TcpFlags, data: bytes = bytes(), options: [TcpOption] = []
    ) -> TcpPacket:
        # There must be at least one option...
        if options == []:
            # Add a single terminating option
            options = [TcpProtocol.TcpOption(kind=TcpProtocol.TcpOption.KIND_END_OF_OPTION_LIST)]

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
    def parse_packet(packet_data: bytes) -> TcpPacket:
        (
            src_port,
            dest_port,
            seq_number,
            ack_number,
            padded_data_offset,
            padded_flags,
            recv_window,
            checksum,
            urgent_pointer,
        ) = struct.unpack("=HHIIBBHHH", packet_data[:20])

        data_offset = padded_data_offset >> 4
        data_offset_bytes = data_offset * 4

        flags = TcpProtocol.TcpFlags.from_int(padded_flags)

        options_data = packet_data[20:data_offset_bytes]
        options = []
        while options_data:
            option, options_data = TcpProtocol.TcpOption.from_bytes_with_remainder(options_data)
            options.append(option)

            # If option is of type options terminate then break
            if option.kind == TcpProtocol.TcpOption.KIND_END_OF_OPTION_LIST:
                break

        data = packet_data[data_offset_bytes:]

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


class TransportLayer(Logger):
    """Simulated transport layer capable of handling a single connection
    between a source host/port (ourselves) and some destination host/port.
    """

    physical: PhysicalLayer

    src_port: int
    dest_port: int

    def __init__(self) -> None:
        super().__init__()
        self.physical = PhysicalLayer()

    def create_socket(self) -> TcpSocket:
        return TcpSocket(self)

    def initiate_handshake(self, src_port, dest_port):
        # Perform three-way handshake to initiate a connection with addr.

        # Create and send a SYN packet.
        syn_packet = TcpProtocol.create_packet(src_port, dest_port, TcpProtocol.TcpFlags(syn=True))
        self._send_packet(syn_packet)

        # Wait to recive a SYNACK.
        recv_packet = self._receive_packet()

        # Check recv packet has is SYNACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not (recv_packet.flags.syn and recv_packet.flags.ack):
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

        # 3. Send an ACK.
        ack_packet = TcpProtocol.create_packet(src_port, dest_port, TcpProtocol.TcpFlags(ack=True))
        self._send_packet(ack_packet)

        self.src_port = src_port
        self.dest_port = dest_port

    def accept_incoming_handshake(self, src_port) -> int:
        while True:
            # Wait to receive a packet.
            recv_packet = self._receive_packet()

            # Check recv packet has is SYN flag set.
            if recv_packet.flags.syn:
                break

            self.logger.warn(f"Server waiting to accept connections recived NON-SYN packet: {recv_packet.to_string()}")

        self.src_port = src_port
        self.dest_port = recv_packet.src_port

        # Create and send a SYNACK packet.
        syn_ack_packet = TcpProtocol.create_packet(
            src_port, recv_packet.src_port, TcpProtocol.TcpFlags(syn=True, ack=True)
        )
        self._send_packet(syn_ack_packet)

        # Wait to receive a ACK packet.
        recv_packet = self._receive_packet()

        # Check recv packet has is ACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not recv_packet.flags.ack:
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

    def close_connection(target_addr):
        # Send FIN packet to target_addr to close the connection.
        pass

    def _receive_packet(self) -> TcpProtocol.TcpPacket:
        packet = TcpProtocol.parse_packet(self.physical.receive())
        self.logger.debug("⬆️  [Physical->TCP]")
        self.logger.info(f"Received {packet=}")
        return packet

    def _send_packet(self, packet: TcpProtocol.TcpPacket) -> None:
        self.logger.info(f"Sending {packet=}...")
        self.logger.debug("⬇️  [TCP->Physical]")
        self.physical.send(packet.to_bytes())

    def receive(self) -> bytes:
        packet = self._receive_packet()
        return packet.data

    def send(self, data: bytes) -> None:
        # TODO: Ensure connection has been established and fill out flags and options
        packet = TcpProtocol.create_packet(
            self.src_port, self.dest_port, TcpProtocol.TcpFlags(ack=True), data=data, options=[]
        )
        self._send_packet(packet)
