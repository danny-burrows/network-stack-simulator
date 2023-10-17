from utils import NetworkInterface
from protocols import DNSProtocol, HTTPProtocol


class ApplicationLayer:
    def __init__(self, physical_layer):
        self.physical_layer = physical_layer
        self.dns_protocol = DNSProtocol()
        self.http_protocol = HTTPProtocol()

    def resolve_ip(self, url):
        ip = self.dns_protocol.resolve_ip(url)
        print(f"(Client App) Resolved IP {url} => {ip}\n")
        return ip
    
    def send_http_request(self, method, url):
        # blocking send implemeted with NetworkInterface
        
        print(f"(Client App) Sending HTTP Request ({method}, {url})\n")
        ip = self.resolve_ip(url)
        
        req1 = self.http_protocol.create_request(method, ip)
        self.physical_layer.send(req1)

    def send_server_kill(self):
        print("(Client App) Sending Server Kill\n")
        self.physical_layer.send(NetworkInterface.CODE_CLOSE_SERVER)
        


def client():
    physical = NetworkInterface("/var/tmp/server-eth0", "/var/tmp/client-eth0")
    
    application = ApplicationLayer(physical)
    
    response = application.send_http_request("HEAD", "google.com")
    
    application.send_http_request("GET", "google.com")
    
    application.send_server_kill()


if __name__ == "__main__":
    client()
