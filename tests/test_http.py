import pytest

from layer_application import HTTPProtocol


def test_create_head_request():
    request = HTTPProtocol.create_request("HEAD", "/", headers={"host": "localhost"})
    assert vars(request) == {
        "version": "HTTP/1.1",
        "method": "HEAD",
        "uri": "/",
        "headers": {"host": "localhost"},
        "body": "",
    }


def test_create_get_request():
    request = HTTPProtocol.create_request("GET", "/", headers={"host": "localhost"})
    assert vars(request) == {
        "version": "HTTP/1.1",
        "method": "GET",
        "uri": "/",
        "headers": {"host": "localhost"},
        "body": "",
    }


def test_create_head_request_fails_with_body():
    with pytest.raises(NotImplementedError, match="HTTPRequest method HEAD should not receive body='Some body!'"):
        HTTPProtocol.create_request("HEAD", "/", headers={"host": "localhost"}, body="Some body!")


def test_create_unsupported_method_request_fails():
    with pytest.raises(NotImplementedError, match="HTTPRequest initialized with unsupported method 'POST'!"):
        HTTPProtocol.create_request("POST", "/", headers={})


def test_create_response():
    response = HTTPProtocol.create_response("302", headers={"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, body="Some body!")
    assert vars(response) == {
        "version": "HTTP/1.1",
        "status_code": "302",
        "headers": {"date": "Mon, 01 Jan 1999 00:00:00 GMT"},
        "body": "Some body!",
    }


def test_create_response_fails_on_unsupported_status_code():
    with pytest.raises(NotImplementedError, match="HTTPResponse initialized with unsupported status code '200'!"):
        HTTPProtocol.create_response("200", headers={}, body="")


def test_head_request_to_string():
    request = HTTPProtocol.create_request("HEAD", "/", headers={"host": "localhost"})
    assert request.to_string() == "HEAD / HTTP/1.1\nhost: localhost\n\n"


def test_get_request_to_string():
    request = HTTPProtocol.create_request("GET", "/", headers={"host": "localhost"})
    assert request.to_string() == "GET / HTTP/1.1\nhost: localhost\n\n"


def test_response_to_string():
    response = HTTPProtocol.create_response("302", headers={"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, body="Some body!")
    assert response.to_string() == "HTTP/1.1 302 Found\ndate: Mon, 01 Jan 1999 00:00:00 GMT\n\nSome body!"


def test_parse_response():
    response = HTTPProtocol.create_response("302", headers={"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, body="Some body!")
    parsed_response = HTTPProtocol.parse_response(response.to_string().encode("utf-8"))
    assert parsed_response == response


def test_parse_request():
    request = HTTPProtocol.create_request("GET", "/", headers={"host": "localhost"})
    parsed_request = HTTPProtocol.parse_request(request.to_string().encode("utf-8"))
    assert parsed_request == request


def test_get_exam_string_is_correct_for_head_request():
    request = HTTPProtocol.create_request("HEAD", "/", headers={})
    actual = HTTPProtocol.get_exam_string(request)
    expected = """\
------------ BEGIN Application Layer Message ------
RAW DATA: b'HEAD / HTTP/1.1\\n\\n'
PROTOCOL: HTTP
MESSAGE TYPE: request
MESSAGE STRING:
  | HEAD / HTTP/1.1
  | 
  | 
FIELDS:
  |- method: HEAD
  |- uri: /
  |- version: HTTP/1.1
  |- headers: <None>
  |- body: <None>
---------- END Application Layer Message ----------"""
    assert actual == expected


def test_get_exam_string_is_correct_for_get_request():
    request = HTTPProtocol.create_request("GET", "/", headers={"host": "127.0.0.1"}, body="Hello, World!")
    actual = HTTPProtocol.get_exam_string(request, note="SENDING")
    expected = """\
------------ SENDING Application Layer Message ----
RAW DATA: b'GET / HTTP/1.1\\nhost: 127.0.0.1\\n\\nHello, World!'
PROTOCOL: HTTP
MESSAGE TYPE: request
MESSAGE STRING:
  | GET / HTTP/1.1
  | host: 127.0.0.1
  | 
  | Hello, World!
FIELDS:
  |- method: GET
  |- uri: /
  |- version: HTTP/1.1
  |- headers: {'host': '127.0.0.1'}
  |- body: b'Hello, World!'
---------- END Application Layer Message ----------"""
    assert actual == expected


def test_get_exam_string_is_correct_for_response():
    response = HTTPProtocol.create_response("302", headers={"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, body="Some body!")
    actual = HTTPProtocol.get_exam_string(response, note="RECIEVED")
    expected = """\
------------ RECIEVED Application Layer Message ---
RAW DATA: b'HTTP/1.1 302 Found\\ndate: Mon, 01 Jan 1999 00:00:00 GMT\\n\\nSome body!'
PROTOCOL: HTTP
MESSAGE TYPE: response
MESSAGE STRING:
  | HTTP/1.1 302 Found
  | date: Mon, 01 Jan 1999 00:00:00 GMT
  | 
  | Some body!
FIELDS:
  |- version: HTTP/1.1
  |- status_code: 302
  |- headers: {'date': 'Mon, 01 Jan 1999 00:00:00 GMT'}
  |- body: b'Some body!'
---------- END Application Layer Message ----------"""
    assert actual == expected
