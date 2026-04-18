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
"""

import sys


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
