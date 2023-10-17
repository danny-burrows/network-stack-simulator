
import os
import threading
from io import TextIOWrapper
from typing import Callable


class NamedPipe:
    pipe_path: str
    is_open: bool
    recv_pipe: TextIOWrapper
    send_pipe: TextIOWrapper

    def __init__(self, pipe_path: str) -> None:
        self.pipe_path = pipe_path
        self.is_open = False
        self.recv_pipe = None
        self.send_pipe = None

    def open_recv_pipe(self) -> None:
        if self.is_open: return
        if not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)
        print(f"(Pipe) Opening recv_pipe in {self.pipe_path}...\n")
        self.recv_pipe = open(self.pipe_path, "r")
        print(f"(Pipe) recv_pipe opened!\n")
        self.is_open = True

    def open_send_pipe(self) -> None:
        if self.is_open: return
        if not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)
        print(f"(Pipe) Opening send_pipe in {self.pipe_path}...\n")
        self.send_pipe = open(self.pipe_path, "w")
        print(f"(Pipe) send_pipe opened!\n")
        self.is_open = True
    
    def close_pipe(self) -> None:
        if not self.is_open: return
        if self.send_pipe:
            self.send_pipe.close()
        if self.recv_pipe:
            self.recv_pipe.close()
        self.is_open = False

    def delete_pipe(self) -> None:
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)

    def send(self, data: str) -> None:
        if not self.is_open or not self.send_pipe:
            print(f"(Pipe) Cannot send data to {self.pipe_path}, not an open send_pipe\n")
            print(self.send_pipe, self.recv_pipe)
            return
            
        print(f"(Pipe) Sending data to {self.pipe_path}: {data=}\n")
        self.send_pipe.write(data)
        self.send_pipe.flush()

    def listen(self, callback: Callable[[str], None]) -> None:
        if not self.is_open or not self.recv_pipe:
            print(f"(Pipe) Cannot listen for data from {self.pipe_path}, not an open recv_pipe\n")
            print(self.send_pipe, self.recv_pipe)
            return
    
        print(f"(Pipe) Listening for data from {self.pipe_path}\n")
        while self.is_open and self.recv_pipe:
            print("(Pipe) Reading...")
            data = self.recv_pipe.read()
            print(f"(Pipe) Received data on {self.pipe_path}: {data=}\n")
            callback(data)


class NetworkInterface:
    send_pipe: NamedPipe
    recv_pipe: NamedPipe
    recv_thread: threading.Thread
    recv_buffer: list[str]
    recv_event: threading.Event

    def __init__(self, send_pipe_path, recv_pipe_path) -> None:
        self.is_connected = False
        self.send_pipe = NamedPipe(send_pipe_path)
        self.recv_pipe = NamedPipe(recv_pipe_path)
        self.recv_thread = None
        self.recv_buffer = []
        self.recv_event = threading.Event()
        
    def connect(self) -> None:
        if self.is_connected: return
        print(f"(Network Interface) Connecting...\n")
        (p_send := threading.Thread(target=self.send_pipe.open_send_pipe)).start()
        (p_recv := threading.Thread(target=self.recv_pipe.open_recv_pipe)).start()
        p_send.join()
        p_recv.join()
        self.recv_thread = threading.Thread(
            target=self.recv_pipe.listen, args=(self._receive,))
        self.recv_thread.start()
        self.is_connected = True
        print(f"(Network Interface) Connected!\n")
    
    def _receive(self, data: str) -> None:
        self.recv_buffer.append(data)
        self.recv_event.set()

    def disconnect(self) -> None:
        if not self.is_connected: return
        print(f"(Network Interface) Disconnecting...\n")
        self.send_pipe.close_pipe()
        self.recv_pipe.close_pipe()
        self.recv_thread.join()
        self.is_connected = False
        print(f"(Network Interface) Disconnected!\n")
            
    def send(self, data: str) -> None:
        if not self.is_connected: return
        self.send_pipe.send(data)
    
    def receive(self, count: int=1, timeout: int=60) -> str:
        if not self.is_connected: return
        while len(self.recv_buffer) < count:
            self.recv_event.wait(timeout)
        data = self.recv_buffer[:count]
        self.recv_buffer = self.recv_buffer[count:]
        if count == 1:
            data = data[0]
        return data
