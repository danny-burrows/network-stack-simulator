from logger import Logger
from layer_transport import TcpProtocol, TransportLayer
from layer_network import NetworkLayer
from dataclasses import dataclass
import random


class HttpProtocol:
    # https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5

    VERSION = "HTTP/1.1"
    VALID_METHODS = ["HEAD", "GET"]
    STATUS_PHRASES = {"302": "Found"}

    SP = " "
    CRLF = "\n"

    @dataclass
    class HTTPRequestStruct:
        method: str
        uri: str
        version: str
        headers: dict
        body: str

        def to_string(self) -> str:
            req_str = f"{self.method}{HttpProtocol.SP}{self.uri}{HttpProtocol.SP}{self.version}{HttpProtocol.CRLF}"
            for header in self.headers:
                req_str += f"{header}:{HttpProtocol.SP}{self.headers[header]}{HttpProtocol.CRLF}"
            req_str += HttpProtocol.CRLF
            req_str += self.body

            return req_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @dataclass
    class HTTPResponseStruct:
        version: str
        status_code: str
        headers: dict[str, str]
        body: str

        def to_string(self) -> str:
            phrase = HttpProtocol.STATUS_PHRASES[self.status_code]
            res_str = f"{self.version}{HttpProtocol.SP}{self.status_code}{HttpProtocol.SP}{phrase}{HttpProtocol.CRLF}"
            for header in self.headers:
                res_str += f"{header}:{HttpProtocol.SP}{self.headers[header]}{HttpProtocol.CRLF}"
            res_str += HttpProtocol.CRLF
            res_str += self.body

            return res_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @staticmethod
    def parse_request(req_bytes: bytes) -> HTTPRequestStruct:
        start, headers, body = HttpProtocol._parse_message(req_bytes)

        if len(start) != 3:
            raise ValueError(f"HTTP Request Parse Error: Invalid start line of length '{len(start)}': {req_bytes}!")

        (method, uri, version) = start

        if method not in HttpProtocol.VALID_METHODS:
            raise ValueError(f"HTTP Request Parse Error: Unsupported method '{method}': {req_bytes}!")

        if version != HttpProtocol.VERSION:
            raise ValueError(f"HTTP Request Parse Error: Unsupported version '{version}': {req_bytes}!")

        return HttpProtocol.HTTPRequestStruct(method, uri, version, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        start, headers, body = HttpProtocol._parse_message(res_bytes)

        if len(start) != 3:
            raise ValueError(f"HTTP Response Parse Error: Invalid start line of length '{len(start)}': {res_bytes}!")

        version, status_code, status_msg = start

        if version != HttpProtocol.VERSION:
            raise ValueError(f"HTTP Response Parse Error: Unsupported version '{version}': {res_bytes}!")

        if status_code not in HttpProtocol.STATUS_PHRASES:
            raise ValueError(f"HTTP Response Parse Error: Unsupported status code '{status_code}': {res_bytes}!")

        if status_msg != HttpProtocol.STATUS_PHRASES[status_code]:
            raise ValueError(
                f"HTTP Response Parse Error: Incorrect phrase '{status_msg}!={HttpProtocol.STATUS_PHRASES[status_code]}': {res_bytes}!"
            )

        return HttpProtocol.HTTPResponseStruct(version, status_code, headers, body)

    @staticmethod
    def _parse_message(msg_bytes: bytes) -> list[list[str], dict[str, str], str]:
        msg_str = msg_bytes.decode("utf-8")

        try:
            header, body = msg_str.split(f"{HttpProtocol.CRLF}{HttpProtocol.CRLF}")
        except ValueError as e:
            raise ValueError(f"HTTP Message Parse Error: Could not split headers / body! ({msg_str})\n{e}")

        # header_lines contains both start-line and header-lines
        header_lines = header.split(HttpProtocol.CRLF)
        if len(header_lines) < 0:
            raise ValueError(f"HTTP Message Parse Error: Headers expect at least 1 line! ({msg_str})")

        # Spec specifies start-line as request-line or status-line
        start = header_lines.pop(0).split(HttpProtocol.SP)

        headers = {}
        for header_line in header_lines:
            try:
                key, value = header_line.split(f":{HttpProtocol.SP}")
            except ValueError as e:
                raise ValueError(f"HTTP Message Parse Error: Headers expect 'key: value'! ({msg_str})\n{e}")
            headers[key.lower()] = value

        return start, headers, body

    @staticmethod
    def create_request(method: str, uri: str, *, headers: dict[str, str], body: str = "") -> HTTPRequestStruct:
        method = method.upper()
        for key in headers:
            headers[key] = headers[key].lower()

        if method not in HttpProtocol.VALID_METHODS:
            raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

        if method == "HEAD" and body:
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HttpProtocol.HTTPRequestStruct(method, uri, HttpProtocol.VERSION, headers, body)

    @staticmethod
    def create_response(status_code: str, *, headers: dict[str, str] = {}, body="") -> HTTPResponseStruct:
        if status_code not in HttpProtocol.STATUS_PHRASES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")

        return HttpProtocol.HTTPResponseStruct(HttpProtocol.VERSION, status_code, headers, body)

    @staticmethod
    def get_exam_string(message: HTTPRequestStruct | HTTPRequestStruct) -> None:
        message_type = "request" if type(message) is HttpProtocol.HTTPRequestStruct else "response"
        message_string = "\n".join(f"  | {line}" for line in message.to_string().split("\n"))

        def parse_value(field_name, value):
            if value and field_name == "body":
                return value.encode("utf-8")
            elif value:
                return str(value)
            else:
                return "<None>"

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(message).items()
        )

        return "\n".join(
            (
                "------------ HTTP Layer ------------",
                f"RAW DATA: {message.to_bytes()}",
                f"MESSAGE TYPE: {message_type}",
                "MESSAGE STRING:",
                message_string,
                "FIELDS:",
                message_fields,
                "---------- END HTTP Layer ----------",
            )
        )


class ApplicationLayer(Logger):
    transport: TransportLayer

    def __init__(self) -> None:
        super().__init__()
        self.transport = TransportLayer()

    def execute_client(self) -> None:
        # Hardcoded source IP for client
        # SRC host is hardcoded as we have no DNS mechanism
        NetworkLayer.src_host = "192.168.0.4"
        NetworkLayer.dest_host = "192.168.0.6"

        # Initialize mock TCP socket that holds a config and talks to self.transport
        sock = self.transport.create_socket()

        # Active open socket and connect to server ip:80
        hostname, port = "192.168.0.6", "80"
        addr = f"{hostname}:{port}"
        sock.connect(addr)

        # Send HEAD request and receive response
        req = HttpProtocol.create_request("HEAD", "/", headers={"host": hostname})
        self.logger.info(f"Sending {req.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(req))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(req.to_bytes())

        res_bytes = sock.receive(TcpProtocol.BUFSIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        res = HttpProtocol.parse_response(res_bytes)
        self.logger.info(f"Received {res.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(res))

        # Send GET request and receive response
        req = HttpProtocol.create_request("GET", "/", headers={"host": hostname})
        self.logger.info(f"Sending {req.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(req))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(req.to_bytes())

        res_bytes = sock.receive(TcpProtocol.BUFSIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        res = HttpProtocol.parse_response(res_bytes)
        self.logger.info(f"Received {res.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(res))

    def execute_server(self) -> None:
        # Hardcoded source IP for server
        NetworkLayer.src_host = "192.168.0.6"
        NetworkLayer.dest_host = "192.168.0.4"

        # Initialize mock TCP socket that holds a config and talks to self.transport
        sock = self.transport.create_socket()

        # Passive open socket and accept connections on local ip:80
        hostname, port = NetworkLayer.src_host, "80"
        addr = f"{hostname}:{port}"
        sock.bind(addr)
        sock.listen()
        sock.accept()

        # Receive HEAD request and send random 300 response
        req_bytes = sock.receive(TcpProtocol.BUFSIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        req = HttpProtocol.parse_request(req_bytes)
        self.logger.info(f"Received {req.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(req))

        status = random.choice(list(HttpProtocol.STATUS_PHRASES.keys()))
        res = HttpProtocol.create_response(status)
        self.logger.info(f"Sending {res.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(res))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(res.to_bytes())

        # Receive GET request and send random 300 response
        req_bytes = sock.receive(TcpProtocol.BUFSIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        req = HttpProtocol.parse_request(req_bytes)
        self.logger.info(f"Received {req.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(req))

        status = random.choice(list(HttpProtocol.STATUS_PHRASES.keys()))
        res = HttpProtocol.create_response(status)
        self.logger.info(f"Sending {res.to_string()=}")
        self.exam_logger.info(HttpProtocol.get_exam_string(res))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(res.to_bytes())
