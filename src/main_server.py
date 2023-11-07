import sys
from logger import Logger
from utils import NetworkInterface
from protocols import HTTPProtocol, TCPSocket, TransportLayer

class ServerApplicationLayer(Logger):    
    CODE_SERVER_KILL="PIPE_CODE_SERVER_KILL"

    net_if: NetworkInterface
    
    def __init__(self, transport: TransportLayer) -> None:
        super().__init__()
        self.transport = transport
    
    def execute(self) -> None:
        # TODO: Socket stuff
        self.sock = self.transport.create_socket()
        self.accept()
        # self.sock.bind("127.0.0.1", 3000)

        self.start_http_server()

        self.sock.close()

    def start_http_server(self) -> None:
        self.logger.debug("Listening for HTTP...")
        req_bytes = None
        while req_bytes := self.sock.recv():
            req_str = req_bytes.decode()

            if req_str == ServerApplicationLayer.CODE_SERVER_KILL:
                self.logger.debug("Received Server Kill")
                self.sock.close()
                return None

            self.logger.info(f"Received HTTP Request: {req_str=}")
            
            req = HTTPProtocol.try_parse_request(req_str)
            res = HTTPProtocol.try_create_response("302")
            res_str = res.to_string()
            res_bytes = res_str.encode()
            
            self.logger.info(f"Sending HTTP Response: {res_str=}")
            
            self.net_if.send(res_bytes)

def server() -> None:
    try:
        logger = Logger()
        
        logger.logger.info("Server Start")

        transport = TransportLayer()
        application = ServerApplicationLayer(transport)

        application.execute()

        logger.logger.info("Server End")

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    server()
