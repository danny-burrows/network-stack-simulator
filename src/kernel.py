import threading
import os
import threading
import time

from dataclasses import dataclass
from logger import Logger
from io import TextIOWrapper
from typing import Callable
from protocols import TCPConnection, TCPPacketStruct, TCPProtocol


def named_pipe_from_address(address):
    pipe_name = "".join([c for c in address if c.isalpha() or c.isdigit() or c==' ']).rstrip()
    return f"/var/tmp/{pipe_name}"


class NamedPipe(Logger):

    pipe_path: str
    is_listening: bool
    listener_interupt: bool
    listener_thread: threading.Thread
    listener_read_file: TextIOWrapper

    def __init__(self, pipe_path: str) -> None:
        super().__init__()
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


@dataclass
class TCPConnectionStruct:

    src_port: str
    dest_port: str
    recv_data: list[TCPPacketStruct] = []
    send_data: list[TCPPacketStruct] = []
    is_physically_connected: bool = False
    is_handshake_complete: bool = False
    handshake_complete_event: threading.Event = threading.Event()


class Kernel:
    
    tcp_connection_structs_mutex: threading.Lock
    tcp_connection_structs: dict[tuple[str, str], TCPConnectionStruct]
    incoming_data_mutex: threading.Lock
    incoming_data: bytearray
    
    def __init__(self) -> None:
        self.tcp_connection_structs_mutex = threading.Lock()
        self.tcp_connection_structs = set()
        self.incoming_data_mutex = threading.Lock()
        self.incoming_data = bytearray()

    def wait_tcp_connection(self, src_addr, src_port) -> TCPConnection:
        while len(wires := self._find_new_wires(src_addr, src_port)) == 0:
            time.sleep(0.2)

        dest_addr, dest_port = wires[0]
        return self.create_tcp_connection(src_addr, src_port, dest_addr, dest_port)
        
    def create_tcp_connection(self, src_addr, src_port, dest_addr, dest_port) -> TCPConnection:
        self._connect_wires(src_addr, src_port, dest_addr, dest_port)

        with self.tcp_connection_structs_mutex:
            if (src_port, dest_port) not in self.tcp_connection_structs:
                tcp_connection_struct = TCPConnectionStruct(src_port, dest_port)
                self.tcp_connection_structs[(src_port, dest_port)] = tcp_connection_struct
            
            else:
                tcp_connection_struct = self.tcp_connection_structs[(src_port, dest_port)]

        tcp_connection_struct.handshake_complete_event.wait()
        return tcp_connection_struct

    def _find_new_wires(dest_addr, dest_port) -> bool:
        pass

    def _connect_wires(src_addr, src_port, dest_addr, dest_port) -> None:
        pass

    def _recv_data(self, data):
        with self.incoming_data_mutex:
            self.incoming_data.append(data)
    
    def run(self) -> None:
        # Running in a thread...        
        while True:

            # Parse packets from buffer
            tcp_packets: TCPPacketStruct = []
            with self.incoming_data_mutex:
                while len(self.incoming_data) > 0:
                    tcp_packet, remaining_data = TCPProtocol.parse_packet(self.incoming_data)
                    self.incoming_data = remaining_data
                    tcp_packets.append(tcp_packet)
                    
            # Route packets to connections
            for tcp_packet in tcp_packets:
                key = (tcp_packet.src_port, tcp_packet.dest_port)
                self.tcp_connection_structs[key].recv_data.append(tcp_packet)

            # Process connections
            for conn in self.tcp_connection_structs:
                TCPProtocol.process_connection(conn)
