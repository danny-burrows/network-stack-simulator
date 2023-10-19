
from utils import NetworkInterface
from protocols import DNSProtocol, HTTPProtocol
from main_server import ApplicationLayer as ServerApplicationLayer


class ApplicationLayer:
    net_if: NetworkInterface

    def __init__(self, net_if: NetworkInterface) -> None:
        self.net_if = net_if
        
    def send_http_request(self, method: str, url: str) -> str:
        print(f"-(Client App) Sending HTTP Request: ({method}, {url})")

        ip = DNSProtocol.resolve_ip(url)
        print(f"-(Client App) Resolved IP {url} => {ip}")
        
        req = HTTPProtocol.create_request(method, ip)
        print(f"-(Client App) Sending Request: {req=}")
        self.net_if.send(req)

        print("-(Client App) Awaiting Response...")
        data = self.net_if.receive()
        print(f"-(Client App) Received Response: {data=}")

        return data

    def send_server_kill(self) -> None:
        print("-(Client App) Sending Server Kill")
        self.net_if.send(ServerApplicationLayer.CODE_SERVER_KILL)


def client() -> None:
    print("\n(Client Main) Start\n")

    net_if = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
    application = ApplicationLayer(net_if)
    
    net_if.connect()
    res_1 = application.send_http_request("HEAD", "google.com")
    res_2 = application.send_http_request("GET", "google.com")
    print(f"(Client Main) {res_1=}")
    print(f"(Client Main) {res_2=}")
    application.send_server_kill()
    net_if.disconnect()

    print("\n(Client Main) End\n")


if __name__ == "__main__":
    client()
