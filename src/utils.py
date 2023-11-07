import os
import threading
import time

from logger import Logger
from io import TextIOWrapper
from typing import Callable

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

class NetworkInterface(Logger):
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
    
    def recv(self, count: int=1, timeout: int=60) -> bytes:
        if not self.is_connected:
            return
        while len(self.recv_buffer) < count:
            self.recv_event.wait(timeout)
        frame = self.recv_buffer[:count]
        self.recv_buffer = self.recv_buffer[count:]
        if count == 1:
            frame = frame[0]
        return frame
