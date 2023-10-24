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
        self.log.info(f"Sending HTTP Request: ({method}, {url})")

        ip = DNSProtocol.resolve_ip(url)
        self.log.debug(f"Resolved IP {url} => {ip}")
        
        req = HTTPProtocol.try_create_request(method, { "host": ip })
        req_str = req.to_string()
        self.log.debug(f"Sending HTTP Request String: {req_str=}")
        self.net_if.send(req_str)

        self.log.debug("Awaiting Response...")
        res_str = self.net_if.receive()
        res = HTTPProtocol.try_parse_response_str(res_str)
        self.log.info(f"Received HTTP Response: {res_str=}")

        return res

    def send_server_kill(self) -> None:
        self.log.debug("Sending Server Kill")
        self.net_if.send(ServerApplicationLayer.CODE_SERVER_KILL)


def client() -> None:
    logger = Logger()
    
    logger.log.info("Client Start")

    net_if = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
    application = ApplicationLayer(net_if)
    
    net_if.connect()
    res_1 = application.send_http_request("HEAD", "google.com")
    res_2 = application.send_http_request("GET", "google.com")
    logger.log.info(f"{res_1.to_string()=}")
    logger.log.info(f"{res_2.to_string()=}")
    application.send_server_kill()
    net_if.disconnect()

    logger.log.info("Client End")


if __name__ == "__main__":
    client()
