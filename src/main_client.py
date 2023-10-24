import sys
from logger import Logger
from utils import NetworkInterface
from protocols import DNSProtocol, HTTPProtocol
from main_server import ApplicationLayer as ServerApplicationLayer


class ApplicationLayer(Logger):
    net_if: NetworkInterface

    def __init__(self, net_if: NetworkInterface) -> None:
        super().__init__()
        self.net_if = net_if
        
    def send_http_request(self, method: str, url: str) -> HTTPProtocol.HTTPResponse:
        self.logger.info(f"Sending HTTP Request: ({method}, {url})")
        
        req = HTTPProtocol.try_create_request(method, { "host": url })
        req_str = req.to_string()
        self.logger.debug(f"Created HTTP Request String: {req_str=}")

        ip = DNSProtocol.resolve_ip(url)
        self.logger.debug(f"Resolved IP {url} => {ip}")

        self.logger.debug(f"Sending Payload...")
        self.net_if.send(req_str)

        self.logger.debug("Awaiting Response...")
        res_str = self.net_if.receive()
        
        res = HTTPProtocol.try_parse_response(res_str)
        self.logger.info(f"Received HTTP Response: {res_str=}")

        return res

    def send_server_kill(self) -> None:
        self.logger.debug("Sending Server Kill")
        self.net_if.send(ServerApplicationLayer.CODE_SERVER_KILL)


def client() -> None:
    try:
        client_logger = Logger()
        
        client_logger.logger.info("Client Start")

        net_if = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
        application = ApplicationLayer(net_if)
        
        net_if.connect()
        res_1 = application.send_http_request("HEAD", "google.com")
        res_2 = application.send_http_request("GET", "google.com")
        client_logger.logger.info(f"{res_1.to_string()=}")
        client_logger.logger.info(f"{res_2.to_string()=}")
        application.send_server_kill()
        net_if.disconnect()

        client_logger.logger.info("Client End")

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    client()
