from utils import PhysicalLayer
from protocols import DNSProtocol, HTTPProtocol


class ClientApplicationLayer:
    def __init__(self, physical_layer):
        self.physical_layer = physical_layer
        self.dns_protocol = DNSProtocol()
        self.http_protocol = HTTPProtocol()
    
    def send_http_request(self, method, url):
        print(f"(Client App) Sending HTTP Request ({method}, {url})\n")

        ip = self.dns_protocol.resolve_ip(url)
        print(f"(Client App) Resolved IP {url} => {ip}\n")

        req1 = self.http_protocol.create_request(method, ip, body="1")
        self.physical_layer.send(req1)
        req2 = self.http_protocol.create_request(method, ip, body="2")
        self.physical_layer.send(req2)

        self.physical_layer.send(PhysicalLayer.CODE_CLOSE_SERVER)


def client():
    physical = PhysicalLayer()
    application = ClientApplicationLayer(physical)
    
    application.send_http_request("HEAD", "google.com")


if __name__ == "__main__":
    client()
