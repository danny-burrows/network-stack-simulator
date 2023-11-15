from logger import Logger
from layer_physical import PhysicalLayer
from dataclasses import dataclass


class HttpLayer(Logger):
    VERSION = "HTTP/1.1"
    VALID_STATUS_CODES = ["302"]
    VALID_METHODS = ["HEAD", "GET"]
    STATUS_CODE_MAP = {"302": "Found"}

    @dataclass
    class HTTPRequestStruct:
        method: str
        headers: dict
        body: str

        def to_string(self) -> str:
            req_str = f"{self.method} / {HttpLayer.VERSION}\n"

            for header in self.headers:
                req_str += f"{header}: {self.headers[header]}\n"
            req_str += "\n"

            if self.body:
                req_str += f"{self.body}"

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
            status_msg = HttpLayer.STATUS_CODE_MAP[self.status_code]
            res_str = f"{HttpLayer.VERSION} {self.status_code} {status_msg}\n"

            for header in self.headers:
                res_str += f"{header}: {self.headers[header]}\n"
            res_str += "\n"

            if self.body:
                res_str += f"{self.body}"

            return res_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @staticmethod
    def parse_request(req_bytes: bytes) -> HTTPRequestStruct:
        status, headers, body = HttpLayer._parse_message(req_bytes)

        if len(status) != 3:
            raise ValueError(f"HTTPRequest parse has invalid status line of length '{len(status)}': {req_bytes}!")

        method = status[0]
        version = status[2]

        if method not in HttpLayer.VALID_METHODS:
            raise ValueError(f"HTTPRequest parsed unsupported method '{method}': {req_bytes}!")

        if status[1] != "/":
            raise ValueError(f"HTTPRequest parsed invalid status line '{status}': {req_bytes}!")

        if version != HttpLayer.VERSION:
            raise ValueError(f"HTTPRequest parsed unsupported version '{version}': {req_bytes}!")

        # Ensure body is None rather than '' if empty
        if not body:
            body = None

        return HttpLayer.HTTPRequestStruct(method, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        status, headers, body = HttpLayer._parse_message(res_bytes)

        if len(status) != 3:
            raise ValueError(f"HTTPResponse parse has invalid status line of length '{len(status)}': {res_bytes}!")

        version = status[0]
        status_code = status[1]
        status_msg = status[2]

        if version != HttpLayer.VERSION:
            raise ValueError(f"HTTPResponse parsed unsupported version '{version}': {res_bytes}!")

        if status_code not in HttpLayer.VALID_STATUS_CODES:
            raise ValueError(f"HTTPResponse parsed unsupported response code '{status_code}': {res_bytes}!")

        if status_msg != HttpLayer.STATUS_CODE_MAP[status_code]:
            raise ValueError(
                f"HTTPResponse parsed incorrect response message '{status_msg}!={HttpLayer.STATUS_CODE_MAP[status_code]}': {res_bytes}!"
            )

        return HttpLayer.HTTPResponseStruct(version, status_code, headers, body)

    @staticmethod
    def _parse_message(msg_bytes: bytes) -> list[list[str], dict[str, str], str]:
        msg_str = msg_bytes.decode("utf-8")

        split_content = msg_str.split("\n\n")

        if len(split_content) != 2:
            raise ValueError(f"HTTP message content split incorrect count '{len(split_content)}': {msg_str}!")

        meta_content, body_content = split_content

        meta_lines = meta_content.split("\n")

        if len(meta_lines) < 1:
            raise ValueError(f"HTTP message meta contains 0 lines: {msg_str}!")

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
    def create_request(method: str, headers: dict[str, str], body: str = None) -> HTTPRequestStruct:
        method = method.upper()
        for header in headers:
            headers[header] = headers[header].lower()

        if method not in HttpLayer.VALID_METHODS:
            raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

        if method == "HEAD" and body:
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HttpLayer.HTTPRequestStruct(method, headers, body)

    @staticmethod
    def create_response(status_code: str, headers: dict[str, str] = {}, body=None) -> HTTPResponseStruct:
        if status_code not in HttpLayer.VALID_STATUS_CODES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")
        return HttpLayer.HTTPResponseStruct(HttpLayer.VERSION, status_code, headers, body)

    physical: PhysicalLayer

    @staticmethod
    def get_exam_string(message_type, message_data: bytes) -> None:
        message_obj = None
        if message_type == "request":
            message_obj = HttpLayer.parse_request(message_data)
        elif message_type == "response":
            message_obj = HttpLayer.parse_response(message_data)
        else:
            raise ValueError(f"get_exam_string called with invalid message_type '{message_type}'!")

        message_string = "\n".join(f"  | {line}" for line in message_obj.to_string().split("\n"))

        def parse_value(field_name, value):
            if value and field_name == "body":
                return value.encode("utf-8")
            elif value:
                return str(value)
            else:
                return "<None>"

        message_obj_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(message_obj).items()
        )

        return "\n".join(
            (
                "------------ HTTP Layer ------------",
                f"RAW DATA: {message_data}",
                f"MESSAGE TYPE: {message_type}",
                "MESSAGE STRING:",
                message_string,
                "FIELDS:",
                message_obj_fields,
                "---------- END HTTP Layer ----------",
            )
        )

    def __init__(self, physical: PhysicalLayer) -> None:
        super().__init__()
        self.physical = physical

    def execute_client(self) -> None:
        req = self.create_request("HEAD", {})
        self.logger.info(f"{req.to_string()=}")
        self.exam_logger.info(self.get_exam_string("request", req.to_bytes()))
        self.physical.send(req.to_bytes())

    def execute_server(self) -> None:
        req_bytes = self.physical.receive()
        req = self.parse_request(req_bytes)
        self.logger.info(f"{req.to_string()=}")
