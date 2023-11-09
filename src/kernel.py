from __future__ import annotations
import threading
import os
import time

from dataclasses import dataclass
from logger import Logger
from io import TextIOWrapper
from typing import Callable
from protocols import TCPConnection, TCPPacketStruct, TCPProtocol


def named_pipe_from_addr_port(addr, port):
    return f"/var/tmp/{addr}:{port}"


class NamedPipe(Logger):
    pipe_path: str
    is_listening: bool
    listener_interupt: bool
    listener_thread: threading.Thread
    listener_read_file: TextIOWrapper

    def __init__(self, pipe_path: str) -> None:
        Logger.__init__(self)
        self.pipe_path = pipe_path
        self.is_listening = False
        self.listener_interupt = False
        self.listener_thread = None
        self.listener_read_file = None
        self.create_pipe_file()

    def close(self) -> None:
        if self.is_listening:
            self.stop_listening()

    def create_pipe_file(self) -> None:
        try:
            self.logger.debug(f"Creating pipe file {self.pipe_path=}...")
            os.mkfifo(self.pipe_path)
        except FileExistsError:
            self.logger.debug(f"File '{self.pipe_path}' already exists so cannot be created")

    def delete_pipe_file(self) -> None:
        try:
            os.remove(self.pipe_path)
        except FileNotFoundError:
            self.logger.debug(f"File '{self.pipe_path}' doesn't exist so cannot be deleted")

    def send(self, frame: bytes) -> None:
        self.logger.debug(f"Opening pipe file for writing '{self.pipe_path}'")

        with open(self.pipe_path, "wb") as send_file:
            self.logger.debug(f"Writing {frame=}")
            send_file.write(frame)

        self.logger.debug(f"Finished writing, closing pipe file '{self.pipe_path}'")

    def start_listening(self, callback: Callable[[str], None]) -> None:
        if self.is_listening:
            return
        self.listener_interupt = False
        self.listener_thread = threading.Thread(target=self._listen, args=(callback,))
        self.listener_thread.daemon = True
        self.listener_thread.start()
        self.is_listening = True

    def stop_listening(self) -> None:
        if not self.is_listening:
            return
        self.listener_interupt = True
        self.listener_thread.join()
        self.is_listening = False

    def _listen(self, callback: Callable[[str], None]) -> None:
        self.logger.debug(f"Opening pipe file for reading '{self.pipe_path}'")
        self.listener_read_file = open(self.pipe_path, "rb")
        # Alternative option... can cause weird behavior but prevents the block
        # self.listener_read_file = os.fdopen(os.open(self.pipe_path, os.O_RDONLY | os.O_NONBLOCK))
        self.logger.debug(f"Pipe read file '{self.pipe_path}' opened!")

        while not self.listener_interupt:
            frame = self.listener_read_file.read()
            if len(frame) > 0:
                self.logger.debug(f"Received {frame=}")
                callback(frame)

            time.sleep(0.1)

        self.logger.debug(f"Finished reading, closing pipe file '{self.pipe_path}'")
        self.listener_read_file.close()


class TCPConnectionStruct:
    src_port: int
    dest_port: int
    recv_data: [TCPPacketStruct]
    send_data: [TCPPacketStruct]
    is_physically_connected: bool
    is_handshake_complete: bool
    is_handshaking: bool
    handshake_complete_event: threading.Event

    def __init__(self, src_port: str, dest_port: str) -> None:
        self.src_port = src_port
        self.dest_port = dest_port
        self.recv_data = []
        self.send_data = []
        self.is_physically_connected = False
        self.is_handshake_complete = False
        self.is_handshaking = False
        self.handshake_complete_event = threading.Event()


class Kernel(Logger):
    tcp_connection_structs_mutex: threading.Lock
    tcp_connection_structs: dict[tuple[int, int], TCPConnectionStruct]
    incoming_data_mutex: threading.Lock
    incoming_data: bytes
    named_pipes: dict[str, NamedPipe]

    def __init__(self) -> None:
        Logger.__init__(self)
        self.tcp_connection_structs_mutex = threading.Lock()
        self.tcp_connection_structs = {}
        self.incoming_data_mutex = threading.Lock()
        self.incoming_data = bytes()
        self.named_pipes = {}

    def wait_tcp_connection(self, src_addr: int, src_port: int) -> TCPConnection:
        self.logger.info(f"Waiting TCP Connection: {src_addr}:{src_port}")
        self.ensure_wire_exists(src_addr, src_port, True)
        
        with self.tcp_connection_structs_mutex:
            tcp_connection_key = (src_port, None)
            if tcp_connection_key not in self.tcp_connection_structs:
                self.logger.info(f"Creating connection {src_port}-None")
                tcp_connection_struct = TCPConnectionStruct(src_port, None)
                self.tcp_connection_structs[tcp_connection_key] = tcp_connection_struct

            else:
                raise Exception("BAD")
        
        tcp_connection_struct.handshake_complete_event.wait()
        return tcp_connection_struct

    def create_tcp_connection(self, src_addr: str, src_port: int, dest_addr: str, dest_port: int) -> TCPConnection:
        self.logger.info(f"Creating TCP Connection: {src_addr}:{src_port} -> {dest_addr}:{dest_port}")
        self.ensure_wire_exists(src_addr, src_port, True)
        self.ensure_wire_exists(dest_addr, dest_port, False)

        with self.tcp_connection_structs_mutex:
            tcp_connection_key = (src_port, dest_port)
            if tcp_connection_key not in self.tcp_connection_structs:
                self.logger.info(f"Creating connection {src_port}-{dest_port}")
                tcp_connection_struct = TCPConnectionStruct(src_port, dest_port)
                self.tcp_connection_structs[tcp_connection_key] = tcp_connection_struct

            else:
                tcp_connection_struct = self.tcp_connection_structs[(src_port, dest_port)]

        tcp_connection_struct.handshake_complete_event.wait()
        return tcp_connection_struct

    def ensure_wire_exists(self, addr: str, port: str, to_listen: bool) -> None:
        self.logger.info(f"Ensuring wire exists {addr}:{port}")
        pipe_path = named_pipe_from_addr_port(addr, port)
        if pipe_path in self.named_pipes:
            return
        
        pipe = NamedPipe(pipe_path)
        self.named_pipes[port] = pipe
        
        if to_listen:
            pipe.start_listening(self._recv_data)
    
    def _recv_data(self, data: bytes):
        with self.incoming_data_mutex:
            self.incoming_data += data

    def _process_tcp_packet(self, packet: TCPPacketStruct) -> None:
        self.logger.info(f"Processing packet: {packet.src_port}:{packet.dest_port}")
        # key = (packet.src_port, packet.dest_port)

        full_key = (packet.dest_port,packet.src_port)
        accept_key = (packet.dest_port,None)

        if full_key in self.tcp_connection_structs:
            self.logger.info(f"Passing packet to conn {full_key}")
            self.tcp_connection_structs[full_key].recv_data.append(packet)
        
        elif accept_key in self.tcp_connection_structs:
            self.logger.info(f"Passing packet to conn {accept_key}")
            self.tcp_connection_structs[accept_key].recv_data.append(packet)
        

    def _process_tcp_connection(self, conn: TCPConnectionStruct) -> None:
        if not conn.is_physically_connected:
            if conn.src_port and conn.dest_port:
                self.logger.info(f"Connection physically connected: {conn.src_port}-{conn.dest_port}")
                conn.is_physically_connected = True

            if len(conn.recv_data) > 0:
                packet: TCPPacketStruct = conn.recv_data[0]
                conn.recv_data = conn.recv_data[1:]
                self.logger.info(f"Connection received data {packet.src_port}-{packet.dest_port}")
        ''
        if conn.is_physically_connected:
            if not conn.is_handshake_complete and not conn.is_handshaking:
                first_packet = TCPProtocol.create_packet(conn.src_port, conn.dest_port)
                self.logger.info(f"Sending packet {first_packet} to file port {conn.dest_port}")
                self.named_pipes[conn.dest_port].send(first_packet)
                conn.is_handshaking = True


    def run(self) -> None:
        # Running in a thread
        while True:

            # Parse packets from buffer
            tcp_packets: TCPPacketStruct = []
            with self.incoming_data_mutex:
                while len(self.incoming_data) > 0:
                    self.logger.info("Parsing data!")
                    tcp_packet, remaining_data = TCPProtocol.parse_packet(self.incoming_data)
                    self.incoming_data = remaining_data
                    tcp_packets.append(tcp_packet)

            # Route packets to connections
            for tcp_packet in tcp_packets:
                self._process_tcp_packet(tcp_packet)

            # Process connections
            for key in self.tcp_connection_structs:
                self._process_tcp_connection(self.tcp_connection_structs[key])
            
            time.sleep(0.2)
