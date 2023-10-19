import logging

from logger import Logger
from utils import NetworkInterface
from protocols import DNSProtocol, HTTPProtocol
from main_server import ApplicationLayer as ServerApplicationLayer


class ApplicationLayer(Logger):
    net_if: NetworkInterface

    def __init__(self, net_if: NetworkInterface) -> None:
        super().__init__()
        self.net_if = net_if
        
    def send_http_request(self, method: str, url: str) -> str:
        self.log.info(f"Sending HTTP Request: ({method}, {url})")

        ip = DNSProtocol.resolve_ip(url)
        self.log.info(f"Resolved IP {url} => {ip}")
        
        req = HTTPProtocol.create_request(method, ip)
        self.log.info(f"Sending Request: {req=}")
        self.net_if.send(req)

        self.log.debug("Awaiting Response...")
        data = self.net_if.receive()
        self.log.info(f"Received Response: {data=}")

        return data

    def send_server_kill(self) -> None:
        self.log.debug("Sending Server Kill")
        self.net_if.send(ServerApplicationLayer.CODE_SERVER_KILL)


def client() -> None:
    logging.info("Start")

    net_if = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
    application = ApplicationLayer(net_if)
    
    net_if.connect()
    res_1 = application.send_http_request("HEAD", "google.com")
    res_2 = application.send_http_request("GET", "google.com")
    logging.info(f"{res_1=}")
    logging.info(f"{res_2=}")
    application.send_server_kill()
    net_if.disconnect()

    logging.info("End")


if __name__ == "__main__":
    client()
