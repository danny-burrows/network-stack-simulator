
from utils import NetworkInterface
from protocols import DNSProtocol, HTTPProtocol
from main_server import ApplicationLayer as ServerApplicationLayer


class ApplicationLayer:
    net_if: NetworkInterface
    dns_protocol: DNSProtocol
    http_protocol: HTTPProtocol

    def __init__(self, net_if: NetworkInterface) -> None:
        self.net_if = net_if
        self.dns_protocol = DNSProtocol()
        self.http_protocol = HTTPProtocol()
        
    def send_http_request(self, method: str, url: str) -> str:
        print(f"(Client App) Sending HTTP Request: ({method}, {url})\n")

        ip = self.dns_protocol.resolve_ip(url)
        print(f"(Client App) Resolved IP {url} => {ip}\n")
        
        req = self.http_protocol.create_request(method, ip)
        print(f"(Client App) Sending Request: {req=}\n")
        self.net_if.send(req)

        data = self.net_if.receive()
        print(f"(Client App) Received Response: {data=}\n")

        return data

    def send_server_kill(self) -> None:
        print("(Client App) Sending Server Kill\n")
        self.net_if.send(ServerApplicationLayer.CODE_SERVER_KILL)


def client() -> None:
    net_if = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
    application = ApplicationLayer(net_if)
    
    net_if.connect()
    res_1 = application.send_http_request("HEAD", "google.com")
    res_2 = application.send_http_request("GET", "google.com")
    print(f"(Client Main) {res_1=}\n")
    print(f"(Client Main) {res_2=}\n")
    application.send_server_kill()
    net_if.disconnect()


if __name__ == "__main__":
    client()
