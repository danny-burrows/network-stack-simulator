from logger import Logger
from utils import NetworkInterface


class ApplicationLayer(Logger):    
    CODE_SERVER_KILL="PIPE_CODE_SERVER_KILL"

    net_if: NetworkInterface
    
    def __init__(self, net_if: NetworkInterface) -> None:
        super().__init__()
        self.net_if = net_if

    def listen_http(self) -> None:
        self.log.debug("Listening for HTTP...")
        req = None
        while (self.net_if.is_connected) and (req := self.net_if.receive()):
            if req == ApplicationLayer.CODE_SERVER_KILL:
                self.log.debug("Received Server Kill")
                return None

            self.log.info(f"Received Request: {req=}")

            res = "Response\n"
            self.log.info(f"Sending Response: {res=}")
            self.net_if.send(res)


def server() -> None:
    logger = Logger()
    
    logger.log.info("Start")

    net_if = NetworkInterface("/var/tmp/client-eth0", "/var/tmp/server-eth0")
    application = ApplicationLayer(net_if)

    net_if.connect()
    application.listen_http()
    net_if.disconnect()

    logger.log.info("End")


if __name__ == "__main__":
    server()
