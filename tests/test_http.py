import pytest

from layer_http import HttpLayer


def test_create_head_request():
    request = HttpLayer.create_request("HEAD", {"host": "localhost"})
    assert vars(request) == {
        "method": "HEAD",
        "headers": {"host": "localhost"},
        "body": None,
    }


def test_create_get_request():
    request = HttpLayer.create_request("GET", {"host": "localhost"})
    assert vars(request) == {
        "method": "GET",
        "headers": {"host": "localhost"},
        "body": None,
    }


def test_create_head_request_fails_with_body():
    with pytest.raises(NotImplementedError, match="HTTPRequest method HEAD should not receive body='Some body!'"):
        HttpLayer.create_request("HEAD", {"host": "localhost"}, "Some body!")


def test_create_unsupported_method_request_fails():
    with pytest.raises(NotImplementedError, match="HTTPRequest initialized with unsupported method 'POST'!"):
        HttpLayer.create_request("POST", {})


def test_create_response():
    response = HttpLayer.create_response("302", {"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, "Some body!")
    assert vars(response) == {
        "version": "HTTP/1.1",
        "status_code": "302",
        "headers": {"date": "Mon, 01 Jan 1999 00:00:00 GMT"},
        "body": "Some body!",
    }


def test_create_response_fails_on_unsupported_status_code():
    with pytest.raises(NotImplementedError, match="HTTPResponse initialized with unsupported status code '200'!"):
        HttpLayer.create_response("200", {}, "")


def test_head_request_to_string():
    request = HttpLayer.create_request("HEAD", {"host": "localhost"})
    assert request.to_string() == "HEAD / HTTP/1.1\nhost: localhost\n\n"


def test_get_request_to_string():
    request = HttpLayer.create_request("GET", {"host": "localhost"})
    assert request.to_string() == "GET / HTTP/1.1\nhost: localhost\n\n"


def test_response_to_string():
    response = HttpLayer.create_response("302", {"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, "Some body!")
    assert response.to_string() == "HTTP/1.1 302 Found\ndate: Mon, 01 Jan 1999 00:00:00 GMT\n\nSome body!"


def test_parse_response():
    response = HttpLayer.create_response("302", {"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, "Some body!")
    parsed_response = HttpLayer.parse_response(response.to_string().encode("utf-8"))
    assert parsed_response == response


def test_parse_request():
    request = HttpLayer.create_request("GET", {"host": "localhost"})
    parsed_request = HttpLayer.parse_request(request.to_string().encode("utf-8"))
    assert parsed_request == request
