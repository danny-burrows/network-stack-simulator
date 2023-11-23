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

        self._bind((host, port))

        # Calculate destination host and port.
        dest_host, dest_port = self._parse_addr(addr)

        # Initiate handshake by sending SYN packet to destination.
        self.transport.initiate_handshake(self.port, dest_port)

    def _bind(self, host: str, port: int) -> None:
        self.host, self.port = host, port

    def bind(self, addr: str) -> None:
        self._bind(self._parse_addr(addr))

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
            return cls(
                urg=bool(flags_int & (2**0)),
                ack=bool(flags_int & (2**1)),
                psh=bool(flags_int & (2**2)),
                rst=bool(flags_int & (2**3)),
                syn=bool(flags_int & (2**4)),
                fin=bool(flags_int & (2**5)),
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
        # TODO: Could probably do with checking certain "kinds" arent given any data...

        kind: int
        length: int = 1
        data: bytes = bytes()

        def __len__(self):
            return self.length

        def to_string(self) -> str:
            return f"{self.kind}{self.length}{self.data if self.data else ''}"

        def to_bytes(self) -> bytes:
            # If option is "End of Option List" or "No-Operation" then no length needed
            if self.kind in (0, 1):
                option_bytes = bytes([self.kind])
            else:
                option_bytes = bytes([self.kind, self.length]) + self.data

            print(option_bytes)

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
        unused: int
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
            options = [TcpProtocol.TcpOption(kind=0)]

        # Calculate the number of 32 bit words in the header
        MIN_TCP_HEADER_WORDS = 5
        length_of_options = sum(len(o) for o in options)
        data_offset = MIN_TCP_HEADER_WORDS + -(length_of_options // -32)

        # TODO: Calculate checksum using "psudo packet" mentioned in lectures...

        packet = TcpProtocol.TcpPacket(
            src_port=src_port,
            dest_port=dest_port,
            # Initialise SEQ and ACK numbers to 0
            seq_number=0,
            ack_number=0,
            data_offset=data_offset,
            # TODO: Need to find better values for the following or justify them being hardcoded...
            unused=0,
            flags=flags,
            recv_window=0,
            checksum=1,
            urgent_pointer=0,
            options=options,
            data=data,
        )
        return packet

    @staticmethod
    def parse_packet(data: bytes) -> TcpPacket:
        # TODO
        pass

    @staticmethod
    def get_exam_string(packet: TcpPacket) -> str:
        # TODO
        pass


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

    def initiate_handshake(self, src_port, dest_port):
        # Perform three-way handshake to initiate a connection with addr.

        # Create and send a SYN packet.
        syn_packet = TcpProtocol.create_packet(src_port, dest_port, TcpProtocol.TcpFlags(syn=True))
        self.send(syn_packet.to_bytes())

        # Wait to recive a SYNACK.
        recv_packet_bytes = self.receive()
        recv_packet = TcpProtocol.parse_packet(recv_packet_bytes)

        # Check recv packet has is SYNACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not (recv_packet.flags.syn and recv_packet.flags.ack):
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

        # 3. Send an ACK.
        ack_packet = TcpProtocol.create_packet(src_port, dest_port, TcpProtocol.TcpFlags(ack=True))
        self.send(ack_packet.to_bytes())

    def accept_incoming_handshake(self, src_port) -> int:
        while True:
            # Wait to recieve a packet.
            recv_packet_bytes = self.receive()
            recv_packet = TcpProtocol.parse_packet(recv_packet_bytes)

            # Check recv packet has is SYN flag set.
            if recv_packet.flags.syn:
                break

            self.logger.warn(f"Server waiting to accept connections recived NON-SYN packet: {recv_packet.to_string()}")

        # Create and send a SYNACK packet.
        syn_ack_packet = TcpProtocol.create_packet(
            src_port, recv_packet.src_port, TcpProtocol.TcpFlags(syn=True, ack=True)
        )
        self.send(syn_ack_packet.to_bytes())

        # Wait to recieve a ACK packet.
        recv_packet_bytes = self.receive()
        recv_packet = TcpProtocol.parse_packet(recv_packet_bytes)

        # Check recv packet has is ACK flags set.
        # TODO: More error handling? Probably better error handling...
        if not recv_packet.flags.ack:
            raise Exception("Simulation Error: Server responded with unrecognised packet in sequence!")

    def close_connection(target_addr):
        # Send FIN packet to target_addr to close the connection.
        pass

    def receive(self) -> bytes:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->TCP]")
        self.logger.info(f"Received {data=}")
        return data

    def send(self, data: bytes) -> None:
        self.logger.info(f"Sending {data=}...")
        self.logger.debug("⬇️  [TCP->Physical]")
        self.physical.send(data)
