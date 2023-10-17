from utils import PhysicalLayer
from protocols import HTTPProtocol


class ServerApplicationLayer:
    def __init__(self, physical_layer):
        self.http_protocol = HTTPProtocol()
        self.physical_layer = physical_layer

    def listen_http(self):
        print("(Server App) Listening for HTTP\n")
        self.physical_layer.listen(self.receive_http)

    def receive_http(self, packet):
        pass


def server():
    physical = PhysicalLayer()
    application = ServerApplicationLayer(physical)
    
    application.listen_http()



if __name__ == "__main__":
    server()
