from __future__ import annotations

from dataclasses import dataclass

import random
import os
import sys


class PhysicalLayer:
    PIPE_PATH = "/var/tmp/physical-pipe-"

    communication_index: int

    def __init__(self) -> None:
        self.communication_index = 0

    @property
    def pipe_path(self) -> str:
        return PhysicalLayer.PIPE_PATH + str(self.communication_index)

    def send(self, data: bytes) -> None:
        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "wb") as f:
            f.write(data)

        if file_owner:
            os.remove(self.pipe_path)

        self.communication_index += 1

    def receive(self) -> bytes:
        file_owner = False
        try:
            os.mkfifo(self.pipe_path)
            file_owner = True

        except FileExistsError:
            pass

        with open(self.pipe_path, "rb") as f:
            data = f.read()

        if file_owner:
            os.remove(self.pipe_path)

        self.communication_index += 1
        return data


# --------------------------------


class HttpProtocol:
    """This class represents a HTTP simulation based on RFC 2616.

    The class itself allows for parsing and creating HTTP Messages (Requests and Responses).

    RFC 2616 has been referenced heavily throughout to verify this implementation
    is correct.

    - RFC 2616: https://datatracker.ietf.org/doc/html/rfc2616
    - Summary of RFC 2616, used in places for clarification: https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html
    """

    # HTTP Version for this simulation.
    VERSION = "HTTP/1.1"

    # A subset of all HTTP/1.1 methods representing those implemented
    # for this simulation. Used as a check when decoding messages.
    VALID_METHODS = ["HEAD", "GET"]

    # A subset of all HTTP/1.1 statuses representing those implemented
    # for this simulatioin. Used to randomly select a response in th
    # 300's range, for a given request.
    STATUS_PHRASES = {
        "300": "Multiple Choices",
        "301": "Moved Permanently",
        "302": "Found",
        "303": "See Other",
        "304": "Not Modified",
    }

    # Helper constants used when parsing HTTP Messages.
    SP = " "
    CRLF = "\n"  # For the sake of simplicity we set CRLF (usually \r\n) to \n.

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
        # Requests are parsed according to "Section 5: Request" of RFC 2616
        # Some steps are taken to ensure correctness of the req_bytes
        # according to the specification.

        start, headers, body = HttpProtocol._parse_message(req_bytes)

        start_elements = start.split(HttpProtocol.SP)
        if len(start_elements) != 3:
            raise ValueError(
                f"HTTP Request Parse Error: Invalid start line of length '{len(start_elements)}': {req_bytes}!"
            )

        method, uri, version = start_elements

        if method not in HttpProtocol.VALID_METHODS:
            raise ValueError(f"HTTP Request Parse Error: Unsupported method '{method}': {req_bytes}!")

        if version != HttpProtocol.VERSION:
            raise ValueError(f"HTTP Request Parse Error: Unsupported version '{version}': {req_bytes}!")

        return HttpProtocol.HTTPRequestStruct(method, uri, version, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        # Responses are parsed according to "Section 6: Response" of RFC 2616
        # Some steps are taken to ensure correctness of the res_bytes
        # according to the specification.

        start, headers, body = HttpProtocol._parse_message(res_bytes)

        start_elements = start.split(HttpProtocol.SP)
        if len(start_elements) < 3:
            raise ValueError(
                f"HTTP Response Parse Error: Invalid start line of length '{len(start_elements)}': {res_bytes}!"
            )

        version, status_code, status_msg = start_elements[0], start_elements[1], " ".join(start_elements[2:])

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
        # RFC 2616 specifies a HTTP message with two possible types: Request/Response.
        # This function parses the generic funtionality from both.

        msg_str = msg_bytes.decode("utf-8")

        try:
            header, body = msg_str.split(f"{HttpProtocol.CRLF}{HttpProtocol.CRLF}")
        except ValueError as e:
            raise ValueError(f"HTTP Message Parse Error: Could not split headers / body! ({msg_str})\n{e}")

        # header_lines contains both start-line and header-lines
        header_lines = header.split(HttpProtocol.CRLF)
        if len(header_lines) < 0:
            raise ValueError(f"HTTP Message Parse Error: Headers expect at least 1 line! ({msg_str})")

        # RFC 2616 specifies some start-line which can be a request-line or a status-line, hence the naming chosen here.
        # start = header_lines.pop(0).split(HttpProtocol.SP)
        start = header_lines.pop(0)

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
            # According to RFC 2616 HEAD requests should not have a body
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HttpProtocol.HTTPRequestStruct(method, uri, HttpProtocol.VERSION, headers, body)

    @staticmethod
    def create_response(status_code: str, *, headers: dict[str, str] = {}, body="") -> HTTPResponseStruct:
        if status_code not in HttpProtocol.STATUS_PHRASES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")

        return HttpProtocol.HTTPResponseStruct(HttpProtocol.VERSION, status_code, headers, body)

    @staticmethod
    def get_exam_string(message: HTTPRequestStruct | HTTPRequestStruct, note: str = "") -> None:
        message_type = "request" if type(message) is HttpProtocol.HTTPRequestStruct else "response"
        message_string = "\n".join(f"  | {line}" for line in message.to_string().split("\n"))

        def parse_value(field_name, value):
            if value and field_name == "body":
                return value.encode("utf-8")
            elif value:
                return str(value)
            else:
                return "<NONE>"

        message_fields = "\n".join(
            f"  |- {field_name}: {parse_value(field_name, value)}" for field_name, value in vars(message).items()
        )

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str) - 1)

        return "\n".join(
            (
                f"------------{note_str} Application Layer Message {note_padding}",
                f"RAW DATA: 0x{message.to_bytes().hex()}",
                "PROTOCOL: HTTP",
                f"MESSAGE TYPE: {message_type}",
                "MESSAGE STRING:",
                message_string,
                "FIELDS:",
                message_fields,
                "---------- END Application Layer Message ----------",
            )
        )


class ApplicationLayer:
    physical: PhysicalLayer

    def __init__(self) -> None:
        self.physical = PhysicalLayer()

    def execute(self) -> None:
        # Receive GET request and send random 300 response
        req_bytes = self.physical.receive()
        req = HttpProtocol.parse_request(req_bytes)
        print(HttpProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HttpProtocol.STATUS_PHRASES.keys()))
        res = HttpProtocol.create_response(status)
        print(HttpProtocol.get_exam_string(res, note="SENDING"))
        self.physical.send(res.to_bytes())

        # Receive HEAD request and send random 300 response
        req_bytes = self.physical.receive()
        req = HttpProtocol.parse_request(req_bytes)
        print(HttpProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HttpProtocol.STATUS_PHRASES.keys()))
        res = HttpProtocol.create_response(status)
        print(HttpProtocol.get_exam_string(res, note="SENDING"))
        self.physical.send(res.to_bytes())


if __name__ == "__main__":
    ApplicationLayer().execute()
