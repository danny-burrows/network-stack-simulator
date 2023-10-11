
import os
import time
import threading


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
        pipe_out = os.open(self.pipe_path, os.O_WRONLY)
        os.write(pipe_out, payload.encode())
        os.write(pipe_out, NamedPipe.CODE_PACKET_DELIM.encode())
        os.close(pipe_out)
        print("(Pipe) Sent\n")

    def listen(self, callback):
        print(f"(Pipe) Listening for packets from {self.pipe_path}\n")
        run_server = True
        while run_server:
            with open(self.pipe_path, 'r') as pipe_in:
                pipe_data = pipe_in.read()
                packet_end = pipe_data.find(NamedPipe.CODE_PACKET_DELIM)
                while packet_end != -1:
                    payload = pipe_data[:packet_end]
                    print(f"(Pipe) Received payload\n============\n{payload}============\n")
                    if payload == NamedPipe.CODE_CLOSE_SERVER:
                        run_server = False
                    callback(payload)
                    pipe_data = pipe_data[packet_end+len(NamedPipe.CODE_PACKET_DELIM):]
                    packet_end = pipe_data.find(NamedPipe.CODE_PACKET_DELIM)


class DNSProtocol:
    def resolve_ip(self, url):
        return "0.0.0.0"


class HTTPProtocol:
    def create_request(self, method, ip, body=None):
        req = None
        match method:
            case "HEAD":
                req = "A"
                req = f"{method} / HTTP/1.1\n"
                req += f"Host: {ip}\n"
                req += "\n"
                if body:
                    req += f"{body}\n"
        return req
    

class PhysicalLayer:
    def __init__(self, pipe_path):
        self.named_pipe = NamedPipe(pipe_path)

    def send(self, packet):
        self.named_pipe.send(packet)

    def listen(self, callback):
        self.named_pipe.listen(callback)


class ClientApplicationLayer:
    def __init__(self, physical_layer):
        self.physical_layer = physical_layer
        self.dns_protocol = DNSProtocol()
        self.http_protocol = HTTPProtocol()
    
    def send_http_request(self, method, url):
        print(f"(Client App) Sending HTTP Request ({method}, {url})\n")

        ip = self.dns_protocol.resolve_ip(url)
        print(f"(Client App) Resolved IP {url} => {ip}\n")

        req1 = self.http_protocol.create_request(method, ip, body="1")
        self.physical_layer.send(req1)
        req2 = self.http_protocol.create_request(method, ip, body="2")
        self.physical_layer.send(req2)

        self.physical_layer.send(NamedPipe.CODE_CLOSE_SERVER)


class ServerApplicationLayer:
    def __init__(self, physical_layer):
        self.http_protocol = HTTPProtocol()
        self.physical_layer = physical_layer

    def listen_http(self):
        print(f"(Server App) Listening for HTTP\n")
        self.physical_layer.listen(self.receive_http)

    def receive_http(self, packet):
        pass


def client(pipe_path):
    physical = PhysicalLayer(pipe_path)
    application = ClientApplicationLayer(physical)
    
    application.send_http_request("HEAD", "google.com")


def server(pipe_path):
    physical = PhysicalLayer(pipe_path)
    application = ServerApplicationLayer(physical)
    
    application.listen_http()


def main():
    pipe_path = "/var/tmp/physical-pipe"
    server_thread = threading.Thread(target=server, args=(pipe_path,))
    server_thread.start()
    time.sleep(0.2)
    client(pipe_path)
    server_thread.join()


if __name__ == "__main__":
    main()
