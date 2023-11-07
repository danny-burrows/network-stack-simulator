import sys
from logger import Logger
from utils import NetworkInterface
from protocols import HTTPProtocol


class ApplicationLayer(Logger):
    CODE_SERVER_KILL = "PIPE_CODE_SERVER_KILL"

    net_if: NetworkInterface

    def __init__(self, net_if: NetworkInterface) -> None:
        super().__init__()
        self.net_if = net_if

    def listen_http(self) -> None:
        self.logger.debug("Listening for HTTP...")
        req_str = None
        while (self.net_if.is_connected) and (req_str := self.net_if.receive()):
            if req_str == ApplicationLayer.CODE_SERVER_KILL:
                self.logger.debug("Received Server Kill")
                return None

            self.logger.info(f"Received HTTP Request: {req_str=}")

            HTTPProtocol.try_parse_request(req_str)
            res = HTTPProtocol.try_create_response("302")
            res_str = res.to_string()

            self.logger.info(f"Sending HTTP Response: {res_str=}")

            self.net_if.send(res_str)


def server() -> None:
    try:
        logger = Logger()

        logger.logger.info("Server Start")

        net_if = NetworkInterface("/var/tmp/client-eth0", "/var/tmp/server-eth0")
        application = ApplicationLayer(net_if)

        net_if.connect()
        application.listen_http()
        net_if.disconnect()

        logger.logger.info("Server End")

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    server()
