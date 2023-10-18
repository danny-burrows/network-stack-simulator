
import os
import threading
from io import TextIOWrapper
from typing import Callable
import time


class NamedPipe:
    pipe_path: str
    is_listening: bool
    listener_interupt: bool
    listener_thread: threading.Thread
    listener_read_file: TextIOWrapper

    def __init__(self, pipe_path: str) -> None:
        self.pipe_path = pipe_path
        self.is_listening = False
        self.listener_interupt = False
        self.listener_thread = None
        self.listener_read_file = None
    
    def close(self) -> None:
        if self.is_listening:
            self.stop_listening()

    def create_pipe_file(self) -> None:
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)

    def delete_pipe_file(self) -> None:
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)

    def send(self, data: str) -> None:
        print(f"---(Pipe) Opening pipe write file ({self.pipe_path})...")

        with open(self.pipe_path, "w") as send_file:
            print(f"---(Pipe) Writing {data=}")
            send_file.write(data)

        print(f"---(Pipe) Finished write, closing file ({self.pipe_path})")

    def start_listening(self, callback: Callable[[str], None]) -> None:
        if self.is_listening:
            return
        self.listener_interupt = False
        self.listener_thread = threading.Thread(target=self._listen, args=(callback,))
        self.listener_thread.start()
        self.is_listening = True
    
    def stop_listening(self) -> None:
        if not self.is_listening:
            return
        self.listener_interupt = True
        self.listener_thread.join()
        self.is_listening = False

    def _listen(self, callback: Callable[[str], None]) -> None:
        print(f"---(Pipe) Opening pipe read file ({self.pipe_path})...")
        self.listener_read_file = open(self.pipe_path, "r")
        print(f"---(Pipe) Pipe read file opened!")

        print(f"---(Pipe) Listening for data...")
        while not self.listener_interupt:
            
            # TODO: Potential for a bug where self.kill_listen is set
            # ---> here <---
            # and missed by the loop conditional...
            # This is mitigated by the time.sleep() but we should fix
            
            data = self.listener_read_file.read()
            if len(data) > 0:
                print(f"---(Pipe) Received {data=}")
                callback(data)
            time.sleep(0.2)
        
        print(f"---(Pipe) Finished read, closing file ({self.pipe_path})")
        self.listener_read_file.close()


class NetworkInterface:
    send_pipe: NamedPipe
    recv_pipe: NamedPipe
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
        if self.is_connected:
            return
        print("--(Network Interface) Connecting...")
        self.recv_pipe.start_listening(self._receive)
        self.is_connected = True
        print("--(Network Interface) Connected!")
    
    def _receive(self, data: str) -> None:
        self.recv_buffer.append(data)
        self.recv_event.set()

    def disconnect(self) -> None:
        if not self.is_connected:
            return
        print("--(Network Interface) Disconnecting...")
        self.recv_pipe.close()
        self.is_connected = False
        print("--(Network Interface) Disconnected!")
            
    def send(self, data: str) -> None:
        if not self.is_connected: 
            return
        self.send_pipe.send(data)
    
    def receive(self, count: int=1, timeout: int=60) -> str:
        if not self.is_connected:
            return
        while len(self.recv_buffer) < count:
            self.recv_event.wait(timeout)
        data = self.recv_buffer[:count]
        self.recv_buffer = self.recv_buffer[count:]
        if count == 1:
            data = data[0]
        return data
