
class DNSProtocol:
    def resolve_ip(self, url):
        return "0.0.0.0"


class HTTPProtocol:
    def create_request(self, method, ip, body=None):
        req = None
        match method:
            case "HEAD":
                req = "A"
                req = f"{method} / HTTP/1.1\n"
                req += f"Host: {ip}\n"
                req += "\n"
                if body:
                    req += f"{body}\n"
        return req
    
