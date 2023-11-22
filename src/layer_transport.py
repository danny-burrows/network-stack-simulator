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
        dest_port = self.transport.accept_incoming_handshake(self.port)
        pass

    def receive(self) -> bytes:
        return self.transport.receive()

    def send(self, data: bytes) -> None:
        self.transport.send(data)


class TcpProtocol:

    @dataclass
    class TcpFlags:
        # NOTE: Flags are left-padded to also accomodate the "reserved" portion
        
        urg: bool = False
        ack: bool = False
        psh: bool = False
        rst: bool = False
        syn: bool = False
        fin: bool = False

        def to_string(self) -> str:
            return "Flags: " + "".join("1" if i else "0" for i in vars(self))

        def to_bytes(self) -> bytes:
            flags_int = int(urg)*32 + int(ack)*16 + int(psh)*8 + int(rst)*4 + int(syn)*2 + int(fin)
            return bytes([flags_int])

    @dataclass
    class TcpOption:
        kind: int
        length: int | None
        data: bytes | None

        def __len__(self):
            len(self.to_bytes())

        def to_string(self) -> str:
            pass

        def to_bytes(self) -> bytes:
            pass
    
    @dataclass
    class TcpPacket:
        src_port: int
        dest_port: int
        seq_number: int
        ack_number: int
        length: int
        unused: int
        flags: bytes
        recv_window: bytes
        checksum: int
        urgent_pointer: bytes
        options: [TcpOption]
        data: bytes

        def to_string(self) -> str:
            pass

        def to_bytes(self) -> bytes:
            pass

    @staticmethod
    def create_packet(src_port: int, dest_port: int, flags: TcpFlags, data: bytes = bytes(), options: [TcpOption] = []) -> TcpPacket:
        # Calculate the number of 32 bit words in the header
        MIN_TCP_HEADER_WORDS = 5
        length_of_options = sum(len(o) for o in options)
        data_offset = MIN_TCP_HEADER_WORDS + -(length_of_options // -32)

        # TODO: Calculate checksum using "psudo packet" mentioned in lectures...
        
        packet = TcpPacket(
            src_port=src_port,
            dest_port=dest_port,

            # Initialise SEQ and ACK numbers to 0
            seq_number=0,
            ack_number=0,

            # TODO: Need to find better values for the following or justify them being hardcoded...
            unused=0,
            flags=bytes(),
            recv_window=0,
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

    def initiate_handshake(src_port, dest_port):
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

    def accept_incoming_handshake(src_port) -> int:
        while True:
            # Wait to recieve a packet.
            recv_packet_bytes = self.receive()
            recv_packet = TcpProtocol.parse_packet(recv_packet_bytes)

            # Check recv packet has is SYN flag set.
            if recv_packet.flags.syn:
                break
            
            self.logger.warn(f"Server waiting to accept connections recived NON-SYN packet: {recv_packet.to_string()}")
        
        # Create and send a SYNACK packet.
        syn_ack_packet = TcpProtocol.create_packet(src_port, dest_port, TcpProtocol.TcpFlags(syn=True, ack=True))
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
