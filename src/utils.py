import os

DEFAULT_PIPE_PATH="/var/tmp/physical-pipe"


class PhysicalLayer:
    CODE_PACKET_DELIM="PIPE_PACKET_DELIM\n"
    CODE_CLOSE_SERVER="PIPE_CODE_CLOSE_SERVER\n"

    def __init__(self, pipe_path=DEFAULT_PIPE_PATH):
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
        pipe_out = os.open(self.pipe_path, os.O_WRONLY)
        os.write(pipe_out, payload.encode())
        os.write(pipe_out, self.CODE_PACKET_DELIM.encode())
        os.close(pipe_out)
        print("(Pipe) Sent\n")

    def listen(self, callback):
        print(f"(Pipe) Listening for packets from {self.pipe_path}\n")
        
        with open(self.pipe_path, 'r') as pipe_in:        
            run_server = True
            while run_server:
                pipe_data = pipe_in.read()
                packet_end = pipe_data.find(self.CODE_PACKET_DELIM)
                while packet_end != -1:
                    payload = pipe_data[:packet_end]
                    print(f"(Pipe) Received payload\n============\n{payload}============\n")
                    if payload == self.CODE_CLOSE_SERVER:
                        run_server = False
                    callback(payload)
                    pipe_data = pipe_data[packet_end+len(self.CODE_PACKET_DELIM):]
                    packet_end = pipe_data.find(self.CODE_PACKET_DELIM)
