import os
import threading

class NetworkInterface:

    def __init__(self, send_pipe_path, recv_pipe_path):
        self.send_pipe = NamedPipe(send_pipe_path)
        self.recv_pipe = NamedPipe(recv_pipe_path)
        
        self.recv_buffer = []
        self.recv_thread = None
    
    @property
    def is_listening(self):
        return self.recv_thread is not None

    def _recv_data(self, data):
        self.recv_buffer.append(data)
            
    def _listen(self):
        self.recv_pipe.listen(self._recv_data)
        
    def connect(self):
        self.recv_thread = threading.Thread(target=self._listen)
        self.recv_thread.start()
        
        # launch thread and listen for stuff... puts it in recv_buffer
        
        # except this is in a thread
        self.recv_pipe.listen()
        
        pass        
            
    def send(self, payload):
        # Non-blocking send
        
        self.send_pipe.send(payload)
    
    def recv_data():
        # blocks until buffer has some data available
        pass
    
    def disconnect(self):
        # kill the connection thread
        self.recv_thread.kill()
    
    
class NamedPipe:
    CODE_PACKET_DELIM="PIPE_PACKET_DELIM\n"
    CODE_CLOSE_SERVER="PIPE_CODE_CLOSE_SERVER\n"

    def __init__(self, pipe_path):
        self.pipe_path = pipe_path
        self.open_pipe()

    def open_pipe(self):
        if not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)

    def delete_pipe(self):
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)

    def send(self, payload):
        print(f"(Pipe) Sending packet to {self.pipe_path}\n============\n{payload}============")
        with open(self.pipe_path, "w") as pipe:
            pipe.write(payload)            
        print("(Pipe) Sent\n")

    def listen(self, callback):
        print(f"(Pipe) Listening for packets from {self.pipe_path}\n")        
        with open(self.pipe_path, 'r') as pipe_in:        
            while True:
                pipe_data = pipe_in.read()
                callback(pipe_data)

    def stop_listening(self):
        self.run_server = False



pipe = NamedPipe("/var/tmp/testpipe")
pipe.listen(lambda x: print("Callback"))



