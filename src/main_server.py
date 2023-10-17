
from utils import NetworkInterface
from protocols import HTTPProtocol, DNSProtocol


class ApplicationLayer:    
    CODE_SERVER_KILL="PIPE_CODE_SERVER_KILL\n"

    net_if: NetworkInterface
    dns_protocol: DNSProtocol
    http_protocol: HTTPProtocol
    
    def __init__(self, net_if: NetworkInterface) -> None:
        self.net_if = net_if
        self.dns_protocol = DNSProtocol()
        self.http_protocol = HTTPProtocol()

    def listen_http(self) -> None:
        print("(Server App) Listening for HTTP\n")
        req = None
        while (self.net_if.is_connected) and (req := self.net_if.receive()):
            if req == ApplicationLayer.CODE_SERVER_KILL:
                print(f"(Client App) Received Server Kill\n")
                return None

            print(f"(Client App) Received Request: {req=}\n")

            res = "Response\n"
            print(f"(Client App) Sending Response: {res=}\n")
            self.net_if.send(res)


def server() -> None:
    net_if = NetworkInterface("/var/tmp/client-eth0", "/var/tmp/server-eth0")
    application = ApplicationLayer(net_if)

    net_if.connect()
    application.listen_http()
    net_if.disconnect()


if __name__ == "__main__":
    server()
