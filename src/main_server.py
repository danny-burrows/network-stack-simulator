import logging

from logger import Logger
from utils import NetworkInterface


class ApplicationLayer(Logger):    
    CODE_SERVER_KILL="PIPE_CODE_SERVER_KILL"

    net_if: NetworkInterface
    
    def __init__(self, net_if: NetworkInterface) -> None:
        super().__init__()
        self.net_if = net_if

    def listen_http(self) -> None:
        self.log.debug("(Server App) Listening for HTTP...")
        req = None
        while (self.net_if.is_connected) and (req := self.net_if.receive()):
            if req == ApplicationLayer.CODE_SERVER_KILL:
                self.log.debug("(Server App) Received Server Kill")
                return None

            self.log.info(f"(Server App) Received Request: {req=}")

            res = "Response\n"
            self.log.info(f"(Server App) Sending Response: {res=}")
            self.net_if.send(res)


def server() -> None:
    logging.info("(Server Main) Start")

    net_if = NetworkInterface("/var/tmp/client-eth0", "/var/tmp/server-eth0")
    application = ApplicationLayer(net_if)

    net_if.connect()
    application.listen_http()
    net_if.disconnect()

    logging.info("(Server Main) End")


if __name__ == "__main__":
    server()
