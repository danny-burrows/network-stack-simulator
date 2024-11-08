from logger import Logger
from layer_transport import TCPProtocol, TransportLayer
from dataclasses import dataclass
import random


class HTTPProtocol:
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
            req_str = f"{self.method}{HTTPProtocol.SP}{self.uri}{HTTPProtocol.SP}{self.version}{HTTPProtocol.CRLF}"
            for header in self.headers:
                req_str += f"{header}:{HTTPProtocol.SP}{self.headers[header]}{HTTPProtocol.CRLF}"
            req_str += HTTPProtocol.CRLF
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
            phrase = HTTPProtocol.STATUS_PHRASES[self.status_code]
            res_str = f"{self.version}{HTTPProtocol.SP}{self.status_code}{HTTPProtocol.SP}{phrase}{HTTPProtocol.CRLF}"
            for header in self.headers:
                res_str += f"{header}:{HTTPProtocol.SP}{self.headers[header]}{HTTPProtocol.CRLF}"
            res_str += HTTPProtocol.CRLF
            res_str += self.body

            return res_str

        def to_bytes(self) -> bytes:
            return self.to_string().encode("utf-8")

    @staticmethod
    def parse_request(req_bytes: bytes) -> HTTPRequestStruct:
        # Requests are parsed according to "Section 5: Request" of RFC 2616
        # Some steps are taken to ensure correctness of the req_bytes
        # according to the specification.

        start, headers, body = HTTPProtocol._parse_message(req_bytes)

        start_elements = start.split(HTTPProtocol.SP)
        if len(start_elements) != 3:
            raise ValueError(
                f"HTTP Request Parse Error: Invalid start line of length '{len(start_elements)}': {req_bytes}!"
            )

        method, uri, version = start_elements

        if method not in HTTPProtocol.VALID_METHODS:
            raise ValueError(f"HTTP Request Parse Error: Unsupported method '{method}': {req_bytes}!")

        if version != HTTPProtocol.VERSION:
            raise ValueError(f"HTTP Request Parse Error: Unsupported version '{version}': {req_bytes}!")

        return HTTPProtocol.HTTPRequestStruct(method, uri, version, headers, body)

    @staticmethod
    def parse_response(res_bytes: bytes) -> HTTPResponseStruct:
        # Responses are parsed according to "Section 6: Response" of RFC 2616
        # Some steps are taken to ensure correctness of the res_bytes
        # according to the specification.

        start, headers, body = HTTPProtocol._parse_message(res_bytes)

        start_elements = start.split(HTTPProtocol.SP)
        if len(start_elements) < 3:
            raise ValueError(
                f"HTTP Response Parse Error: Invalid start line of length '{len(start_elements)}': {res_bytes}!"
            )

        version, status_code, status_msg = start_elements[0], start_elements[1], " ".join(start_elements[2:])

        if version != HTTPProtocol.VERSION:
            raise ValueError(f"HTTP Response Parse Error: Unsupported version '{version}': {res_bytes}!")

        if status_code not in HTTPProtocol.STATUS_PHRASES:
            raise ValueError(f"HTTP Response Parse Error: Unsupported status code '{status_code}': {res_bytes}!")

        if status_msg != HTTPProtocol.STATUS_PHRASES[status_code]:
            raise ValueError(
                f"HTTP Response Parse Error: Incorrect phrase '{status_msg}!={HTTPProtocol.STATUS_PHRASES[status_code]}': {res_bytes}!"
            )

        return HTTPProtocol.HTTPResponseStruct(version, status_code, headers, body)

    @staticmethod
    def _parse_message(msg_bytes: bytes) -> list[list[str], dict[str, str], str]:
        # RFC 2616 specifies a HTTP message with two possible types: Request/Response.
        # This function parses the generic funtionality from both.

        msg_str = msg_bytes.decode("utf-8")

        try:
            header, body = msg_str.split(f"{HTTPProtocol.CRLF}{HTTPProtocol.CRLF}")
        except ValueError as e:
            raise ValueError(f"HTTP Message Parse Error: Could not split headers / body! ({msg_str})\n{e}")

        # header_lines contains both start-line and header-lines
        header_lines = header.split(HTTPProtocol.CRLF)
        if len(header_lines) < 0:
            raise ValueError(f"HTTP Message Parse Error: Headers expect at least 1 line! ({msg_str})")

        # RFC 2616 specifies some start-line which can be a request-line or a status-line, hence the naming chosen here.
        # start = header_lines.pop(0).split(HTTPProtocol.SP)
        start = header_lines.pop(0)

        headers = {}
        for header_line in header_lines:
            try:
                key, value = header_line.split(f":{HTTPProtocol.SP}")
            except ValueError as e:
                raise ValueError(f"HTTP Message Parse Error: Headers expect 'key: value'! ({msg_str})\n{e}")
            headers[key.lower()] = value

        return start, headers, body

    @staticmethod
    def create_request(method: str, uri: str, *, headers: dict[str, str], body: str = "") -> HTTPRequestStruct:
        method = method.upper()
        for key in headers:
            headers[key] = headers[key].lower()

        if method not in HTTPProtocol.VALID_METHODS:
            raise NotImplementedError(f"HTTPRequest initialized with unsupported method '{method}'!")

        if method == "HEAD" and body:
            # According to RFC 2616 HEAD requests should not have a body
            raise NotImplementedError(f"HTTPRequest method HEAD should not receive {body=}")

        return HTTPProtocol.HTTPRequestStruct(method, uri, HTTPProtocol.VERSION, headers, body)

    @staticmethod
    def create_response(status_code: str, *, headers: dict[str, str] = {}, body="") -> HTTPResponseStruct:
        if status_code not in HTTPProtocol.STATUS_PHRASES:
            raise NotImplementedError(f"HTTPResponse initialized with unsupported status code '{status_code}'!")

        return HTTPProtocol.HTTPResponseStruct(HTTPProtocol.VERSION, status_code, headers, body)

    @staticmethod
    def get_exam_string(message: HTTPRequestStruct | HTTPRequestStruct, note: str = "") -> None:
        message_type = "request" if type(message) is HTTPProtocol.HTTPRequestStruct else "response"
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

        note_str = f" {note}" if note else " BEGIN"
        note_padding = "-" * (len("-------------") - len(note_str) - 1)

        return "\n".join(
            (
                f"------------{note_str} Application Layer Message {note_padding}",
                f"RAW DATA: {message.to_bytes()}",
                "PROTOCOL: HTTP",
                f"MESSAGE TYPE: {message_type}",
                "MESSAGE STRING:",
                message_string,
                "FIELDS:",
                message_fields,
                "---------- END Application Layer Message ----------",
            )
        )


class ApplicationLayer(Logger):
    transport: TransportLayer

    def __init__(self) -> None:
        super().__init__()
        self.transport = TransportLayer()

    def execute_client(self) -> None:
        # Plugin and setup network layer
        self.transport.network.plug_in_and_perform_dhcp_discovery(True)

        # Initialize mock TCP socket that holds a config and talks to self.transport
        sock = self.transport.create_socket()

        # Active open socket and connect to server ip:80
        addr = hostname, _port = "https://www.gollum.mordor", 80
        sock.connect(addr)

        # Send GET request for https://www.gollum.mordor/ring.txt and receive response
        req = HTTPProtocol.create_request("GET", "/ring.txt", headers={"host": hostname})
        self.logger.info(f"Sending {req.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(req, note="SENDING"))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(req.to_bytes())

        res_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        res = HTTPProtocol.parse_response(res_bytes)
        self.logger.info(f"Received {res.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(res, note="RECEIVED"))

        sock.close()

        # Active open socket and connect to same server through another domain address
        addr = hostname, _port = "http://rincewind.fourex.disc.atuin", 80
        sock.connect(addr)

        # Send GET request for http://rincewind.fourex.disc.atuin/luggage.jpg and receive response
        req = HTTPProtocol.create_request("GET", "/wizzard.jpg", headers={"host": hostname})
        self.logger.info(f"Sending {req.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(req, note="SENDING"))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(req.to_bytes())

        res_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        res = HTTPProtocol.parse_response(res_bytes)
        self.logger.info(f"Received {res.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(res, note="RECEIVED"))

        sock.close()

    def execute_server(self) -> None:
        # Plugin and setup network layer
        self.transport.network.plug_in_and_perform_dhcp_discovery()

        # Initialize mock TCP socket that holds a config and talks to self.transport
        sock = self.transport.create_socket()
        sock.bind(("0.0.0.0", 80))

        # Passive open socket and accept connections on local ip:80
        sock.accept()

        # Receive HEAD request and send random 300 response
        req_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        req = HTTPProtocol.parse_request(req_bytes)
        self.logger.info(f"Received {req.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HTTPProtocol.STATUS_PHRASES.keys()))
        res = HTTPProtocol.create_response(status)
        self.logger.info(f"Sending {res.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(res, note="SENDING"))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(res.to_bytes())

        sock.wait_close()

        # Passive open socket again and accept connections on local ip:80
        sock.accept()

        # Receive GET request and send random 300 response
        req_bytes = sock.receive(TCPProtocol.WINDOW_SIZE)
        self.logger.debug("⬆️  [TCP->HTTP]")
        req = HTTPProtocol.parse_request(req_bytes)
        self.logger.info(f"Received {req.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(req, note="RECEIVED"))

        status = random.choice(list(HTTPProtocol.STATUS_PHRASES.keys()))
        res = HTTPProtocol.create_response(status)
        self.logger.info(f"Sending {res.to_string()=}")
        self.exam_logger.info(HTTPProtocol.get_exam_string(res, note="SENDING"))
        self.logger.debug("⬇️  [HTTP->TCP]")
        sock.send(res.to_bytes())

        sock.wait_close()
