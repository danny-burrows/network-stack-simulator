import pytest
import textwrap

from src.protocols import HTTPProtocol


def test_http_protocol_creates_vaild_head_request():
    http_head_req = HTTPProtocol.try_create_request(method="HEAD", headers={ "host": "127.0.0.1" })
    
    assert http_head_req.to_string() == textwrap.dedent(
        """\
        HEAD / HTTP/1.1
        host: 127.0.0.1

    """
    )


def test_http_protocol_creates_vaild_get_request():
    http_get_req = HTTPProtocol.try_create_request(method="GET", headers={ "host": "127.0.0.1" }, body="some test body")

    assert http_get_req.to_string() == textwrap.dedent(
        """\
        GET / HTTP/1.1
        host: 127.0.0.1

        some test body
    """
    )


def test_http_protocol_errors_on_unsupported_method():
    with pytest.raises(NotImplementedError, match=".*unsupported method 'POST'.*"):
        HTTPProtocol.try_create_request(method="POST", headers={ "host": "127.0.0.1" }, body="some test body")
