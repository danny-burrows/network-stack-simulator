import pytest
import textwrap

from src.protocols import HTTPProtocol


def test_http_protocol_creates_vaild_head_request():
    http_head_request = HTTPProtocol.create_request(method="HEAD", ip="127.0.0.1")

    assert http_head_request == textwrap.dedent(
        """\
        HEAD / HTTP/1.1
        Host: 127.0.0.1

    """
    )


def test_http_protocol_creates_vaild_get_request():
    http_get_request = HTTPProtocol.create_request(method="GET", ip="127.0.0.1", body="some test body")

    assert http_get_request == textwrap.dedent(
        """\
        GET / HTTP/1.1
        Host: 127.0.0.1

        some test body
    """
    )


def test_http_protocol_errors_on_unsupported_method():
    with pytest.raises(NotImplementedError, match="HTTP method 'POST' is not implemented!"):
        HTTPProtocol.create_request(method="POST", ip="127.0.0.1", body="some test body")
