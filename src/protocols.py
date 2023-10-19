
class DNSProtocol:
    
    @staticmethod
    def resolve_ip(url: str) -> str:
        return "0.0.0.0"


class HTTPProtocol:
    
    @staticmethod
    def create_request(method: str, ip: str, body: str=None) -> str:
        match method.upper():

            case "HEAD":
                req = (f"{method} / HTTP/1.1\n"
                       f"Host: {ip}\n\n")

            case "GET":
                req = (f"{method} / HTTP/1.1\n"
                       f"Host: {ip}\n\n")
                if body:
                    req += f"{body}\n"
                    
            case unsupported_method:
                raise NotImplementedError(f"HTTP method '{unsupported_method}' is not implemented!")

        return req
