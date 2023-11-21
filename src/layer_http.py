from logger import Logger
from layer_physical import PhysicalLayer
from dataclasses import dataclass
import random


class HttpLayer(Logger):
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
            req_str = f"{self.method}{HttpLayer.SP}{self.uri}{HttpLayer.SP}{self.version}{HttpLayer.CRLF}"
            for header in self.headers:
                req_str += f"{header}:{HttpLayer.SP}{self.headers[header]}{HttpLayer.CRLF}"
            req_str += HttpLayer.CRLF
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
            phrase = HttpLayer.STATUS_PHRASES[self.status_code]
            res_str = f"{self.version}{HttpLayer.SP}{self.status_code}{HttpLayer.SP}{phrase}{HttpLayer.CRLF}"
            for header in self.headers:
                res_str += f"{header}:{HttpLayer.SP}{self.headers[header]}{HttpLayer.CRLF}"
            res_str += HttpLayer.CRLF
            res_str += self.body

            return res_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @staticmethod
    def parse_request(req_bytes: bytes) -> HTTPRequestStruct:
        start, headers, body = HttpLayer._parse_message(req_bytes)

        if len(start) != 3:
            raise ValueError(f"HTTP Request Parse Error: Invalid start line of length '{len(start)}': {req_bytes}!")

        (method, uri, version) = start

        if method not in HttpLayer.VALID_METHODS:
            raise ValueError(f"HTTP Request Parse Error: Unsupported method '{method}': {req_bytes}!")

        if version != HttpLayer.VERSION:
            raise ValueError(f"HTTP Request Parse Error: Unsupported version '{version}': {req_bytes}!")

        return HttpLayer.HTTPRequestStruct(method, uri, version, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        start, headers, body = HttpLayer._parse_message(res_bytes)

        if len(start) != 3:
            raise ValueError(f"HTTP Response Parse Error: Invalid start line of length '{len(start)}': {res_bytes}!")

        version, status_code, status_msg = start

        if version != HttpLayer.VERSION:
            raise ValueError(f"HTTP Response Parse Error: Unsupported version '{version}': {res_bytes}!")

        if status_code not in HttpLayer.STATUS_PHRASES:
            raise ValueError(f"HTTP Response Parse Error: Unsupported status code '{status_code}': {res_bytes}!")

        if status_msg != HttpLayer.STATUS_PHRASES[status_code]:
            raise ValueError(
                f"HTTP Response Parse Error: Incorrect phrase '{status_msg}!={HttpLayer.STATUS_PHRASES[status_code]}': {res_bytes}!"
            )

        return HttpLayer.HTTPResponseStruct(version, status_code, headers, body)

    @staticmethod
    def _parse_message(msg_bytes: bytes) -> list[list[str], dict[str, str], str]:
        msg_str = msg_bytes.decode("utf-8")

        try:
            header, body = msg_str.split(f"{HttpLayer.CRLF}{HttpLayer.CRLF}")
        except ValueError as e:
            raise ValueError(f"HTTP Message Parse Error: Could not split headers / body! ({msg_str})\n{e}")

        # header_lines contains both start-line and header-lines
        header_lines = header.split(HttpLayer.CRLF)
        if len(header_lines) < 0:
            raise ValueError(f"HTTP Message Parse Error: Headers expect at least 1 line! ({msg_str})")

        # Spec specifies start-line as request-line or status-line
        start = header_lines.pop(0).split(HttpLayer.SP)

        headers = {}
        for header_line in header_lines:
            try:
                key, value = header_line.split(f":{HttpLayer.SP}")
            except ValueError as e:
                raise ValueError(f"HTTP Message Parse Error: Headers expect 'key: value'! ({msg_str})\n{e}")
            headers[key.lower()] = value

        return start, headers, body

    @staticmethod
    def create_request(method: str, uri: str, *, headers: dict[str, str], body: str = "") -> HTTPRequestStruct:
        method = method.upper()
        for key in headers:
            headers[key] = headers[key].lower()

        if method not in HttpLayer.VALID_METHODS:
            raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

        if method == "HEAD" and body:
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HttpLayer.HTTPRequestStruct(method, uri, HttpLayer.VERSION, headers, body)

    @staticmethod
    def create_response(status_code: str, *, headers: dict[str, str] = {}, body = "") -> HTTPResponseStruct:
        if status_code not in HttpLayer.STATUS_PHRASES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")

        return HttpLayer.HTTPResponseStruct(HttpLayer.VERSION, status_code, headers, body)

    physical: PhysicalLayer

    @staticmethod
    def get_exam_string(message: HTTPRequestStruct | HTTPRequestStruct) -> None:
        message_type = "request" if type(message) is HttpLayer.HTTPRequestStruct else "response"
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

    def __init__(self, physical: PhysicalLayer) -> None:
        super().__init__()
        self.physical = physical

    def receive_request(self) -> HTTPRequestStruct:
        req_bytes = self.physical.receive()
        self.logger.debug("⬆️  [PHYSICAL->HTTP]")
        req = self.parse_request(req_bytes)
        self.logger.info(f"Received {req.to_string()=}")
        self.exam_logger.info(self.get_exam_string(req))

    def receive_response(self) -> HTTPResponseStruct:
        res_bytes = self.physical.receive()
        self.logger.debug("⬆️  [PHYSICAL->HTTP]")
        res = self.parse_response(res_bytes)
        self.logger.info(f"Received {res.to_string()=}")
        self.exam_logger.info(self.get_exam_string(res))

    def send_message(self, msg: HTTPResponseStruct | HTTPRequestStruct) -> None:
        self.logger.info(f"Sending {msg.to_string()=}")
        self.exam_logger.info(self.get_exam_string(msg))
        self.logger.debug("⬇️  [HTTP->PHYSICAL]")
        self.physical.send(msg.to_bytes())

    def execute_client(self) -> None:
        # Send HEAD request and receive response
        req = self.create_request("HEAD", "/", headers={"host": "exam.com"})
        self.send_message(req)
        res = self.receive_response()

        # Send GET request and receive response
        req = self.create_request("GET", "/", headers={"host": "exam.com"})
        self.send_message(req)
        res = self.receive_response()

    def execute_server(self) -> None:
        # Receive HEAD request and send random 300 response
        req = self.receive_request()
        status = random.choice(list(HttpLayer.STATUS_PHRASES.keys()))
        res = self.create_response(status)
        self.send_message(res)

        # Receive GET request and send random 300 response
        req = self.receive_request()
        status = random.choice(list(HttpLayer.STATUS_PHRASES.keys()))
        res = self.create_response(status)
        self.send_message(res)
