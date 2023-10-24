from logger import Logger


class DNSProtocol:
    
    @staticmethod
    def resolve_ip(url: str) -> str:
        return "0.0.0.0"


class HTTPProtocol:
    VERSION="HTTP/1.1"
    VALID_METHODS = [ "HEAD", "GET" ]
    VALID_RES_CODES = [ "302" ]
    RES_MSG_MAP = { "302": "Found" }

    class HTTPRequest(Logger):
        method: str
        headers: dict
        body: str

        def __init__(self, method: str, headers: dict[str,str], body: str=None):
            Logger.__init__(self)

            self.headers = {}
            for header in headers:
                self.headers[header.lower()] = headers[header]

            method = method.upper()
            if method not in HTTPProtocol.VALID_METHODS:
                raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

            match method:
                case "HEAD":
                    self.method = method
                    self.body = None
                    if body:
                        self.log.warn(f"HTTPRequest method HEAD should not receive {body=}")

                case "GET":
                    self.method = method
                    self.body = body

        @classmethod
        def try_parse(cls, req_str: str):
            status, headers, body = HTTPProtocol._try_parse_http_message(req_str)

            if len(status) != 3:
                raise ValueError(f"HTTPRequest parse has invalid status line of length '{len(status)}': {req_str}!")
            
            method = status[0]
            version = status[2]

            if method not in HTTPProtocol.VALID_METHODS:
                raise ValueError(f"HTTPRequest parsed unsupported method '{method}': {req_str}!")
            
            if status[1] != "/":
                raise ValueError(f"HTTPRequest parsed invalid status line '{status}': {req_str}!")

            if version != HTTPProtocol.VERSION:
                raise ValueError(f"HTTPRequest parsed unsupported version '{version}': {req_str}!")
            
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

        def __init__(self, res_code: str, headers: dict[str,str]={}, body=None):
            Logger.__init__(self)
            self.res_code = res_code
            self.headers = headers
            self.body = body

        @classmethod
        def try_parse(cls, res_str):
            status, headers, body = HTTPProtocol._try_parse_http_message(res_str)

            if len(status) != 3:
                raise ValueError(f"HTTPResponse parse has invalid status line of length '{len(status)}': {res_str}!")
            
            version = status[0]
            res_code = status[1]
            res_msg = status[2]

            if version != HTTPProtocol.VERSION:
                raise ValueError(f"HTTPResponse parsed unsupported version '{version}': {res_str}!")

            if res_code not in HTTPProtocol.VALID_RES_CODES:
                raise ValueError(f"HTTPResponse parsed unsupported response code '{res_code}': {res_str}!")

            if res_msg != HTTPProtocol.RES_MSG_MAP[res_code]:
                raise ValueError(f"HTTPResponse parsed incorrect response message '{res_msg}!={HTTPProtocol.RES_MSG_MAP[res_code]}': {res_str}!")

            return cls(res_code, headers, body)

        def to_string(self) -> str:
            res_msg = HTTPProtocol.RES_MSG_MAP[self.res_code]
            res_str = f"{HTTPProtocol.VERSION} {self.res_code} {res_msg}\n"

            for header in self.headers:
                res_str += f"{header}: {self.headers[header]}\n"
            res_str += "\n"

            if self.body:
                res_str += f"{self.body}\n"

            return res_str

    @staticmethod
    def _try_parse_http_message(msg_str: str) -> list[list[str], dict[str,str], str]:
        split_content = msg_str.split("\n\n")

        if len(split_content) != 2:
            raise ValueError(f"HTTP message content split incorrect count '{len(split_content)}': {msg_str}!")

        meta_content, body_content = split_content

        meta_lines = meta_content.split("\n")

        if len(meta_lines) < 1:
            raise ValueError(f"HTTP message meta contains less than 1 line '{meta_lines}': {msg_str}!")

        status = meta_lines[0].split(" ")

        headers = {}
        for i in range(1, len(meta_lines)):
            line = meta_lines[i]
            line = line.split(": ")
            if len(line) != 2:
                raise ValueError(f"HTTP message header line split incorrect count '{line}': {msg_str}!")
            headers[line[0].lower()] = line[1]

        return status, headers, body_content

    @staticmethod
    def try_parse_request(req_str: str) -> HTTPRequest:
        return HTTPProtocol.HTTPRequest.try_parse(req_str)

    @staticmethod
    def try_parse_response(res_str: str) -> HTTPResponse:
        return HTTPProtocol.HTTPResponse.try_parse(res_str)

    @staticmethod
    def try_create_request(method: str, headers: dict[str,str], body: str=None) -> HTTPRequest:
        return HTTPProtocol.HTTPRequest(method, headers, body)

    @staticmethod
    def try_create_response(res_code: str) -> HTTPResponse:
        return HTTPProtocol.HTTPResponse(res_code)
