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


def test_get_exam_string_is_correct_for_head_request():
    request = HttpLayer.create_request("HEAD", {})
    actual = HttpLayer.get_exam_string(request)
    expected = """\
------------ HTTP Layer ------------
RAW DATA: b'HEAD / HTTP/1.1\\n\\n'
MESSAGE TYPE: request
MESSAGE STRING:
  | HEAD / HTTP/1.1
  | 
  | 
FIELDS:
  |- method: HEAD
  |- headers: <None>
  |- body: <None>
---------- END HTTP Layer ----------"""
    assert actual == expected


def test_get_exam_string_is_correct_for_get_request():
    request = HttpLayer.create_request("GET", {"host": "127.0.0.1"}, "Hello, World!")
    actual = HttpLayer.get_exam_string(request)
    expected = """\
------------ HTTP Layer ------------
RAW DATA: b'GET / HTTP/1.1\\nHost: 127.0.0.1\\n\\nHello, World!'
MESSAGE TYPE: request
MESSAGE STRING:
  | GET / HTTP/1.1
  | host: 127.0.0.1
  | 
  | Hello, World!
FIELDS:
  |- method: GET
  |- headers: {'host': '127.0.0.1'}
  |- body: b'Hello, World!'
---------- END HTTP Layer ----------"""
    assert actual == expected


def test_get_exam_string_is_correct_for_response():
    response = HttpLayer.create_response("302", {"date": "Mon, 01 Jan 1999 00:00:00 GMT"}, "Some body!")
    actual = HttpLayer.get_exam_string(response)
    expected = """\
------------ HTTP Layer ------------
RAW DATA: b'HTTP/1.1 302 Found\\ndate: Mon, 01 Jan 1999 00:00:00 GMT\\n\\nSome body!'
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
---------- END HTTP Layer ----------"""
    assert actual == expected
