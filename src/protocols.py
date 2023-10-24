from logger import Logger


class DNSProtocol:
    
    @staticmethod
    def resolve_ip(url: str) -> str:
        return "0.0.0.0"


class HTTPProtocol:
    VERSION="HTTP/1.1"

    class HTTPRequest(Logger):
        method: str
        headers: dict
        body: str

        def __init__(self, method: str, headers: dict[str,str], body: str=None):
            Logger.__init__(self)

            self.headers = {}
            for header in headers:
                self.headers[header.lower()] = headers[header]

            if "host" not in headers:
                raise ValueError(f"HTTPRequest requires 'host' in headers")

            match method.upper():
                case "HEAD":
                    self.method = method
                    self.body = None
                    if body:
                        self.log.warn(f"Method HEAD should not receive {body=}")

                case "GET":
                    self.method = method
                    self.body = body

                case unsupported_method:
                    raise NotImplementedError(f"HTTP method '{unsupported_method}' is not implemented!")

        @classmethod
        def try_parse(cls, req_str: str):
            status, headers, body = HTTPProtocol._try_parse_http_message(req_str)
            method = status[0]
            version = status[2]
            return cls(method, headers, body)

        def to_string(self) -> str:
            req_str = f"{self.method} / {HTTPProtocol.VERSION}\n"
            for header in self.headers:
                req_str += f"{header}: {self.headers[header]}\n"
            req_str += "\n"
            
            if self.body:
                req_str += f"{self.body}\n"

            return req_str

    class HTTPResponse(Logger):
        VERSION="HTTP/1.1"
        res_code: str
        headers: dict[str,str]
        body: str

        def __init__(self, err_code: str, headers: dict[str,str]={}, body=None):
            Logger.__init__(self)
            self.res_code = err_code
            self.headers = headers
            self.body = body

        @classmethod
        def try_parse(cls, res_str):
            status, headers, body = HTTPProtocol._try_parse_http_message(res_str)
            version = status[0]
            res_code = status[1]
            return cls(res_code, headers, body)

        def to_string(self) -> str:
            res_msg = "OK"
            res_str = f"{HTTPProtocol.VERSION} {self.res_code} {res_msg}\n"
            for header in self.headers:
                res_str += f"{header}: {self.headers[header]}\n"
            res_str += "\n"
            
            if self.body:
                res_str += f"{self.body}\n"

            return res_str

    @staticmethod
    def _try_parse_http_message(str: str) -> list[list[str], dict[str,str], str]:
        meta_content, body_content = str.split("\n\n")
        meta_lines = meta_content.split("\n")

        status = meta_lines[0].split(" ")

        headers = {}
        for i in range(1, len(meta_lines)):
            line = meta_lines[i]
            line = line.split(": ")
            headers[line[0].lower()] = line[1]

        return status, headers, body_content

    @staticmethod
    def try_parse_request_str(req_str: str) -> HTTPRequest:
        return HTTPProtocol.HTTPRequest.try_parse(req_str)

    @staticmethod
    def try_parse_response_str(res_str: str) -> HTTPResponse:
        return HTTPProtocol.HTTPResponse.try_parse(res_str)

    @staticmethod
    def try_create_request(method: str, headers: dict[str,str], body: str=None) -> HTTPRequest:
        return HTTPProtocol.HTTPRequest(method, headers, body)

    @staticmethod
    def try_create_response(err_code: str) -> HTTPResponse:
        return HTTPProtocol.HTTPResponse(err_code)
