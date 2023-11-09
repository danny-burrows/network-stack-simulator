import sys
from logger import Logger
from utils import NetworkInterface
from protocols import HTTPProtocol
from kernel import Socket, Kernel

class ServerApp(Logger):
    CODE_SERVER_KILL = "PIPE_CODE_SERVER_KILL"

    kernel: Kernel

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        super().__init__()

    def execute(self) -> None:
        # TODO: Socket stuff
        self.sock = Socket(self.kernel)
        self.accept()
        # self.sock.bind("127.0.0.1", 3000)

        self.start_http_server()

        self.sock.close()

    def start_http_server(self) -> None:
        self.logger.debug("Listening for HTTP...")
        req_bytes = None
        while req_bytes := self.sock.recv():
            req_str = req_bytes.decode()

            if req_str == ServerApp.CODE_SERVER_KILL:
                self.logger.debug("Received Server Kill")
                self.sock.close()
                return None

            self.logger.info(f"Received HTTP Request: {req_str=}")

            HTTPProtocol.try_parse_request(req_str)
            res = HTTPProtocol.try_create_response("302")
            res_str = res.to_string()
            res_bytes = res_str.encode()

            self.logger.info(f"Sending HTTP Response: {res_str=}")

            self.net_if.send(res_bytes)


def server() -> None:
    try:
        logger = Logger()
        logger.logger.info("Server Start")

        kernel = Kernel()
        
        app = ServerApp(kernel)
        app.execute()

        logger.logger.info("Server End")

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    server()
