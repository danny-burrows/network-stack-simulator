import sys
from logger import Logger
from utils import NetworkInterface
from protocols import HTTPProtocol, TCPSocket, TransportLayer
from main_server import ServerApplicationLayer

class ClientApplicationLayer(Logger):
    transport: TransportLayer
    socket: TCPSocket

    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport
        
    def execute(self) -> None:
        self.sock = self.transport.create_socket()
        self.sock.connect("127.0.0.1", 3000)

        res_1 = self.send_http_request("HEAD", "google.com")
        res_2 = self.send_http_request("GET", "google.com")
        self.send_server_kill()

        self.sock.close()

    def send_http_request(self, method: str, url: str) -> HTTPProtocol.HTTPResponse:
        self.logger.info(f"Sending HTTP Request: ({method}, {url})")
        
        req = HTTPProtocol.try_create_request(method, { "host": url })
        req_str = req.to_string()
        req_bytes = req_str.encode()
        self.logger.debug(f"Created HTTP Request String: {req_str=}")

        self.logger.debug(f"Sending Payload...")
        self.sock.send(req_bytes)

        self.logger.debug("Awaiting Response...")
        res_bytes = self.sock.recv()
        res_str = res_bytes.decode()

        res = HTTPProtocol.try_parse_response(res_str)
        self.logger.info(f"Received HTTP Response: {res_str=}")

        return res

    def send_server_kill(self) -> None:
        self.logger.debug("Sending Server Kill")
        self.sock.send(ServerApplicationLayer.CODE_SERVER_KILL.encode())

def client() -> None:
    try:
        client_logger = Logger()
        client_logger.logger.info("Client Start")

        transport = TransportLayer()
        application = ClientApplicationLayer(transport)
        
        application.execute()

        client_logger.logger.info("Client End")

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    client()
