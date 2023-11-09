import threading
import os
import threading
import time

from dataclasses import dataclass
from queue import Queue
from logger import Logger
from io import TextIOWrapper
from typing import Callable


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


class PhysicalConnection(Logger):
    send_pipe: NamedPipe
    recv_pipe: NamedPipe
    recv_buffer: list[str]
    recv_event: threading.Event

    def __init__(self, send_pipe_path, recv_pipe_path) -> None:
        super().__init__()
        self.is_connected = False
        self.send_pipe = NamedPipe(send_pipe_path)
        self.recv_pipe = NamedPipe(recv_pipe_path)
        self.recv_thread = None
        self.recv_buffer = []
        self.recv_event = threading.Event()

    def connect(self) -> None:
        if self.is_connected:
            return
        self.logger.debug("Connecting...")
        self.recv_pipe.start_listening(self._receive)
        self.is_connected = True
        self.logger.debug("Connected!")

    def _receive(self, frame: str) -> None:
        self.recv_buffer.append(frame)
        self.recv_event.set()

    def disconnect(self) -> None:
        if not self.is_connected:
            return
        self.logger.debug("Disconnecting...")
        self.recv_pipe.close()
        self.is_connected = False
        self.logger.debug("Disconnected!")

    def send(self, frame: bytes) -> None:
        if not self.is_connected:
            return
        self.send_pipe.send(frame)

    def recv(self, count: int = 1, timeout: int = 60) -> bytes:
        if not self.is_connected:
            return
        while len(self.recv_buffer) < count:
            self.recv_event.wait(timeout)
        frame = self.recv_buffer[:count]
        self.recv_buffer = self.recv_buffer[count:]
        if count == 1:
            frame = frame[0]
        return frame


class TCPSocket:

    def __init__(self, kernel) -> None:
        self.kernel = kernel

    def bind(self, host: str, port: str) -> None:
        self.transport.bind(self, host, port)

    def connect(self, host: str, port: str) -> None:
        self.bind(host, port)
        self.kernel.create_tcp_connection()

    def recv(self, size: int) -> bytes:
        pass
    
    def recv(self, size: int) -> bytes:
        pass
    
    
    def listen(self) -> None:
        pass

    def accept(self) -> None:
        pass

    def close(self) -> None:
        pass


class TCPConnectionInterface:    
    def __init__(self, connection_data_ref):
        self.connection_data_ref = connection_data_ref
    
    def recv(self, bufsize: int) -> bytes:
        if not self.is_physically_connected or not self.is_handshake_complete:
            raise Exception("TCP Connection not established!")
        
        while len(self.recv_buffer) < bufsize:
            self.recv_event.wait()
        frame = self.recv_buffer[:bufsize]
        self.recv_buffer = self.recv_buffer[bufsize:]
        if bufsize == 1:
            frame = frame[0]
        return frame
    
    def recv_all(self):
        res_bytes = bytearray()
        while True:
            bytes = self.recv(1024)
            res_bytes.append(bytes)
            if len(bytes) < 1024:
                break
        
    def send(self, data):
        if not self.is_physically_connected or not self.is_handshake_complete:
            raise Exception("TCP Connection not established!")

        self.send_data.queue(data)

class TCPConnectionStruct:
    src_address: str
    dest_address: str
    recv_data: bytes
    send_data: bytes
    
    is_physically_connected: bool
    is_handshake_complete: bool
    
    handshake_complete_event: threading.Event

class TCPPacketStruct:
    src_port: str
    dest_port: str
    seq_number: str
    ack_number: str
    
    len_unused: str
    flags: str
    
    recv_window: str
    checksum: str
    urgent_pointer: str
    
    options: str
    data: str

class Kernel:
    tcp_connection_structs: set[TCPConnectionStruct]
    physical_connections: set[PhysicalConnection]
    
    incoming_data_mutex: threading.Lock
    incoming_data: bytearray
    
    def __init__(self) -> None:
        self.tcp_connection_structs = set()
        self.physical_connections = set()
        
        self.incoming_data_mutex = threading.Lock()
        self.incoming_data = bytearray()
        
    def create_tcp_connection(self, dest_address) -> TCPConnectionInterface:
        tcp_connection_struct = TCPConnectionStruct()
        tcp_connection_struct.src_address = 0  # TODO 
        tcp_connection_struct.dest_address = dest_address
        tcp_connection_struct.is_physically_connected = False
        tcp_connection_struct.is_handshake_complete = False
        tcp_connection_struct.handshake_complete_event = threading.Event()
        tcp_connection_struct.recv_data = bytes()
        tcp_connection_struct.send_data = bytes()
        
        self.tcp_connection_structs.add(tcp_connection_struct)

        tcp_connection_struct.handshake_complete_event.wait()
        return TCPConnectionInterface(tcp_connection_struct)        
    
    def _recv_data(self, data):
        with self.incoming_data_mutex:
            self.incoming_data.append(data)
    
    def _read_incoming_data(self, byte_count) -> bytearray:
        data_to_read = self.incoming_data[:byte_count]
        self.incoming_data = self.incoming_data[byte_count:]
        return data_to_read
    
    def _parse_tcp_packets(self) -> list[TCPPacketStruct]:        
        with self.incoming_data_mutex:
            tcp_packets = []
            
            while len(self.incoming_data) > 0:
                # Read TCP header...
                
                src_port = self._read_incoming_data(2)
                dest_port = self._read_incoming_data(2)
                seq_number = self._read_incoming_data(4)
                ack_number = self._read_incoming_data(4)
                
                len_unused = self._read_incoming_data(1)
                flags = self._read_incoming_data(1)
                
                recv_window = self._read_incoming_data(2)
                checksum = self._read_incoming_data(2)
                urgent_pointer = self._read_incoming_data(2)
                
                options = None # TODO: Variable size
                data = None # TODO: Variable size
                
                tcp_packets.append(TCPPacketStruct(src_port,dest_port,seq_number,ack_number,len_unused,flags,recv_window,checksum,urgent_pointer,options,data))
                
            return tcp_packets   
                
            
    
    def run(self) -> None:
        # Running in a thread...        
        
        while True:
            # Process connections
            # - State management
            # - Outgoing data
        
            # Process incoming data
            tcp_packets = self._parse_tcp_packets()
            for tcp_packet in tcp_packets:
                pass
            
            # Process incoming connections
            while not self.partial_connections.empty():
                partial_connection = self.partial_connections.get()
                self._establish_physical_connection(partial_connection)
            
            
            for connection...

                
            
            # - Created the named pipes etc
            # - Create partial connection threads
            #   until both ends are live.
            
            # Process incoming messages for connections
            # - Queue them in their respective incoming_data
            
            # Handle closed connections
