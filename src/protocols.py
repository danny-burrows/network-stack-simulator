from __future__ import annotations
from logger import Logger
from dataclasses import dataclass
from random import randint
import kernel


def get_random_port() -> int:
    # Temporary / private port range
    return randint(49152, 65653)


class TCPSocket:
    kernel: kernel.Kernel
    host: str
    port: int
    conn: TCPConnection

    @property
    def is_binded(self) -> bool:
        return (self.host is not None) and (self.port is not None)

    def __init__(self, kernel: kernel.Kernel) -> None:
        self.kernel = kernel

    def bind(self, host: str, port: int) -> None:
        self.host = host
        self.port = int(port)

    def accept(self) -> TCPConnection:
        if not self.is_binded:
            raise Exception("Cannot accept() when not binded.")
        return self.kernel.wait_tcp_connection(self.host, self.port)

    def connect(self, host: str, port: str) -> None:
        self.bind("0.0.0.0", get_random_port())
        self.conn = self.kernel.create_tcp_connection(self.host, self.port, host, port)

    def recv(self, size: int) -> bytes:
        return self.conn.recv(size)

    def recv_all(self) -> bytes:
        return self.conn.recv_all()

    def close(self) -> None:
        return self.conn.close()


class TCPConnection:
    def __init__(self, connection_data_ref):
        self.connection_data_ref = connection_data_ref

    def recv(self, bufsize: int) -> bytes:
        pass  # TODO
        # if not self.is_physically_connected or not self.is_handshake_complete:
        #     raise Exception("TCP Connection not established!")

        # while len(self.recv_buffer) < bufsize:
        #     self.recv_event.wait()
        # frame = self.recv_buffer[:bufsize]
        # self.recv_buffer = self.recv_buffer[bufsize:]
        # if bufsize == 1:
        #     frame = frame[0]
        # return frame

    def recv_all(self):
        pass  # TODO
        # res_bytes = bytearray()
        # while True:
        #     bytes = self.recv(1024)
        #     res_bytes.append(bytes)
        #     if len(bytes) < 1024:
        #         break

    def send(self, data):
        pass  # TODO
        # if not self.is_physically_connected or not self.is_handshake_complete:
        #     raise Exception("TCP Connection not established!")

        # self.send_data.queue(data)


@dataclass
class TCPPacketStruct:
    src_port: bytes
    dest_port: bytes
    seq_number: bytes
    ack_number: bytes
    len_unused: bytes
    flags: bytes
    recv_window: bytes
    checksum: bytes
    urgent_pointer: bytes
    options: bytes
    data: bytes


class TCPProtocol:
    @staticmethod
    def parse_packet(packet_data: bytes) -> TCPPacketStruct:
        ptr = 0

        print(f"TCPProtocol parse data {packet_data}")

        def read(count: int):
            nonlocal ptr
            read_data = packet_data[ptr : ptr + count]
            ptr += count
            return read_data

        src_port = int.from_bytes(read(2), byteorder="big")
        dest_port = int.from_bytes(read(2), byteorder="big")
        seq_number = read(4)
        ack_number = read(4)
        len_unused = read(1)
        flags = read(1)
        recv_window = read(2)
        checksum = read(2)
        urgent_pointer = read(2)
        options = None  # TODO: Variable size
        data = None  # TODO: Variable size

        print(f"Ptr incremented to {ptr} leaving {packet_data[ptr:]}")

        packet = TCPPacketStruct(
            src_port,
            dest_port,
            seq_number,
            ack_number,
            len_unused,
            flags,
            recv_window,
            checksum,
            urgent_pointer,
            options,
            data
        )
        
        return packet, packet_data[ptr:]
    
    def create_packet(_src_port: int, _dest_port: int) -> bytes:
        src_port = _src_port.to_bytes(2, "big")
        dest_port = _dest_port.to_bytes(2, "big")
        seq_number = bytes(4)
        ack_number = bytes(4)
        len_unused = bytes(1)
        flags = bytes(1)
        recv_window = bytes(2)
        checksum = bytes(2)
        urgent_pointer = bytes(2)
        options = bytes(0)
        data = bytes(0)

        packet_bytes = src_port + dest_port + seq_number + ack_number + len_unused + flags + recv_window + checksum + urgent_pointer + options + data
        return packet_bytes

    @staticmethod
    def process_connection(conn: kernel.TCPConnectionStruct) -> None:
        pass


class DNSProtocol:
    @staticmethod
    def resolve_ip(url: str) -> str:
        return "0.0.0.0"


class HTTPProtocol:
    VERSION = "HTTP/1.1"
    VALID_METHODS = ["HEAD", "GET"]
    VALID_RES_CODES = ["302"]
    RES_MSG_MAP = {"302": "Found"}

    class HTTPRequest(Logger):
        method: str
        headers: dict
        body: str

        def __init__(self, method: str, headers: dict[str, str], body: str = None):
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
                        self.logger.warn(f"HTTPRequest method HEAD should not receive {body=}")

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
        VERSION = "HTTP/1.1"
        res_code: str
        headers: dict[str, str]
        body: str

        def __init__(self, res_code: str, headers: dict[str, str] = {}, body=None):
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
                raise ValueError(
                    f"HTTPResponse parsed incorrect response message '{res_msg}!={HTTPProtocol.RES_MSG_MAP[res_code]}': {res_str}!"
                )

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
    def _try_parse_http_message(msg_str: str) -> list[list[str], dict[str, str], str]:
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
    def try_create_request(method: str, headers: dict[str, str], body: str = None) -> HTTPRequest:
        return HTTPProtocol.HTTPRequest(method, headers, body)

    @staticmethod
    def try_create_response(res_code: str) -> HTTPResponse:
        return HTTPProtocol.HTTPResponse(res_code)
