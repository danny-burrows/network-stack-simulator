import sys
from logger import Logger
from protocols import HTTPProtocol
from main_server import ServerApp
from kernel import Kernel, TCPSocket

root_logger = Logger()


class ClientApp(Logger):
    sock: TCPSocket
    kernel: Kernel

    def __init__(self, kernel: Kernel) -> None:
        super().__init__()
        self.kernel = kernel

    def execute(self) -> None:
        self.sock = TCPSocket(self.kernel)
        
        self.sock.connect("127.0.0.1", 3000)

        self.send_http_request("HEAD", "google.com")
        self.send_http_request("GET", "google.com")
        self.send_server_kill()

        self.sock.close()

    def send_http_request(self, method: str, url: str) -> HTTPProtocol.HTTPResponse:
        self.logger.info(f"Sending HTTP Request: ({method}, {url})")

        req = HTTPProtocol.try_create_request(method, {"host": url})
        req_str = req.to_string()
        req_bytes = req_str.encode()
        self.logger.debug(f"Created HTTP Request String: {req_str=}")

        self.logger.debug("Sending Payload...")
        self.sock.send(req_bytes)

        self.logger.debug("Awaiting Response...")
        
        res_bytes = bytearray()
        while True:
            bytes = self.sock.recv(1024)
            res_bytes.append(bytes)
            if len(bytes) < 1024:
                break
            
        
        res_str = res_bytes.decode()

        res = HTTPProtocol.try_parse_response(res_str)
        self.logger.info(f"Received HTTP Response: {res_str=}")

        return res

    def send_server_kill(self) -> None:
        self.logger.debug("Sending Server Kill")
        self.sock.send(ServerApp.CODE_SERVER_KILL.encode())


def client() -> None:
    try:
        root_logger.logger.info("Client Start")

        kernel = Kernel()
        kernel.run()
        
        app = ClientApp(kernel)
        app.execute()

        kernel.close()
        
        root_logger.logger.info("Client End")

    except KeyboardInterrupt:
        kernel.close()
        sys.exit(0)


if __name__ == "__main__":
    client()
