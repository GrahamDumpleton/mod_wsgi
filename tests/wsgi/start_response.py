"""Test WSGI start_response semantics in Adapter_start_response.

Covers:

  * the legacy write() callable returned by start_response
  * non-tuple exc_info rejected with RuntimeError
  * exc_info supplied after response headers were flushed: the
    supplied exception is re-raised to the caller
  * exc_info supplied before any output: the second call replaces
    the previously-recorded status line and headers
  * a second start_response without exc_info before any output:
    mod_wsgi is deliberately more tolerant than PEP 3333 here and
    lets the second call replace the previously recorded status
    line and headers while nothing has reached the wire yet
  * a second start_response without exc_info after output: must
    raise "headers have already been sent"
  * invalid status-line formats rejected by
    wsgi_validate_status_line (missing code, mixed digits, extra
    digit, missing space, embedded control character)
  * invalid per-header cases rejected by
    wsgi_validate_header_name / wsgi_validate_header_value
    (empty name, space in name, control char in name, CR/LF in
    value, non-string name, non-latin1 value, non-tuple item,
    tuple of wrong length)
  * invalid types for the headers argument itself (string, tuple,
    dict) rejected by PyArg_ParseTuple's list check
"""

import sys
from urllib.parse import parse_qs


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/write": handle_write,
        "/write-before-return": handle_write_before_return,
        "/non-tuple-exc-info": handle_non_tuple_exc_info,
        "/exc-info-after-headers": handle_exc_info_after_headers,
        "/exc-info-before-headers": handle_exc_info_before_headers,
        "/double-no-exc-before-headers": handle_double_no_exc_before_headers,
        "/double-no-exc-after-headers": handle_double_no_exc_after_headers,
        "/invalid-status": handle_invalid_status,
        "/invalid-header": handle_invalid_header,
        "/invalid-headers-type": handle_invalid_headers_type,
    }

    handler = handlers.get(path)
    if handler is None:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    return handler(environ, start_response)


def handle_write(environ, start_response):
    write = start_response("200 OK", [("Content-Type", "text/plain")])
    write(b"via-write-")
    return [b"via-iter"]


def handle_write_before_return(environ, start_response):
    write = start_response("200 OK", [("Content-Type", "text/plain")])
    write(b"pre-")
    write(b"mid-")
    return [b"post1-", b"post2"]


def handle_non_tuple_exc_info(environ, start_response):
    try:
        start_response("200 OK",
                       [("Content-Type", "text/plain")],
                       "not-a-tuple")
    except RuntimeError as e:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [("got:" + str(e)).encode()]
    return [b"no-error-raised"]


def handle_exc_info_after_headers(environ, start_response):
    write = start_response("200 OK", [("Content-Type", "text/plain")])
    write(b"headers-sent-")

    try:
        raise RuntimeError("intentional-exc-info")
    except RuntimeError:
        try:
            start_response("500 Internal Server Error",
                           [("Content-Type", "text/plain")],
                           sys.exc_info())
        except RuntimeError as e:
            write(("reraised:" + str(e)).encode())
            return []

    return []


def handle_exc_info_before_headers(environ, start_response):
    start_response("200 OK",
                   [("Content-Type", "text/plain"),
                    ("X-Before", "first")])

    try:
        raise RuntimeError("before-headers-sent")
    except RuntimeError:
        start_response("418 I'm a teapot",
                       [("Content-Type", "text/plain"),
                        ("X-After", "second")],
                       sys.exc_info())

    return [b"second-headers-win"]


def handle_double_no_exc_before_headers(environ, start_response):
    # mod_wsgi is intentionally more tolerant than PEP 3333: when
    # nothing has been written to the wire yet, a second
    # start_response without exc_info simply replaces the first
    # call's status line and headers.
    start_response("200 OK",
                   [("Content-Type", "text/plain"),
                    ("X-First", "1")])
    start_response("201 Created",
                   [("Content-Type", "text/plain"),
                    ("X-Second", "2")])
    return [b"second-wins"]


def handle_double_no_exc_after_headers(environ, start_response):
    write = start_response("200 OK", [("Content-Type", "text/plain")])
    write(b"pre-")

    try:
        start_response("500 Internal Server Error",
                       [("Content-Type", "text/plain")])
    except RuntimeError as e:
        write(("err:" + str(e)).encode())
        return []

    return []


def _case(environ):
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    return qs.get("case", [""])[0]


def _error_response(start_response, exc):
    start_response("200 OK", [("Content-Type", "text/plain")])
    body = (type(exc).__name__ + ":" + str(exc) + ";end").encode()
    return [body]


# Invalid status lines exercise wsgi_validate_status_line via
# wsgi_convert_status_line_to_bytes.
_INVALID_STATUS_CASES = {
    "no-digits": "OK",
    "mixed": "20X OK",
    "four-digits": "2000 OK",
    "no-space": "200OK",
    "control-char": "200 OK\r\nX-Injected: yes",
}


def handle_invalid_status(environ, start_response):
    case = _case(environ)
    status = _INVALID_STATUS_CASES.get(case)
    if status is None:
        start_response("400 Bad Request", [("Content-Type", "text/plain")])
        return [b"unknown case;end"]

    try:
        start_response(status, [("Content-Type", "text/plain")])
    except (ValueError, TypeError) as e:
        return _error_response(start_response, e)

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"no-error-raised;end"]


# Invalid header tuples exercise wsgi_validate_header_name and
# wsgi_validate_header_value via wsgi_convert_headers_to_bytes.
_INVALID_HEADER_CASES = {
    "empty-name": [("", "value")],
    "space-name": [("X Foo", "value")],
    "control-name": [("X\tFoo", "value")],
    "cr-value": [("X-Foo", "line1\r\nline2")],
    "lf-value": [("X-Foo", "line1\nline2")],
    "non-string-name": [(42, "value")],
    "non-latin1-value": [("X-Foo", "\u65e5\u672c")],
    "not-a-tuple": ["X-Foo:value"],
    "wrong-tuple-size": [("a", "b", "c")],
}


def handle_invalid_header(environ, start_response):
    case = _case(environ)
    extra = _INVALID_HEADER_CASES.get(case)
    if extra is None:
        start_response("400 Bad Request", [("Content-Type", "text/plain")])
        return [b"unknown case;end"]

    headers = [("Content-Type", "text/plain")] + extra
    try:
        start_response("200 OK", headers)
    except (ValueError, TypeError, UnicodeEncodeError) as e:
        return _error_response(start_response, e)

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"no-error-raised;end"]


# Pass the wrong type for the headers argument itself.
_INVALID_HEADERS_TYPE_CASES = {
    "string": "Content-Type: text/plain",
    "tuple": (("Content-Type", "text/plain"),),
    "dict": {"Content-Type": "text/plain"},
}


def handle_invalid_headers_type(environ, start_response):
    case = _case(environ)
    if case not in _INVALID_HEADERS_TYPE_CASES:
        start_response("400 Bad Request", [("Content-Type", "text/plain")])
        return [b"unknown case;end"]

    headers = _INVALID_HEADERS_TYPE_CASES[case]
    try:
        start_response("200 OK", headers)
    except TypeError as e:
        return _error_response(start_response, e)

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"no-error-raised;end"]
