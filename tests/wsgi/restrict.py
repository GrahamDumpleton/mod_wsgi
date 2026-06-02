"""Test mod_wsgi.Restricted objects on sys.stdin.

The test server is configured with WSGIRestrictStdin On.

Endpoints:

  /test/wsgi/restrict/stdin-type
    Returns the type name of sys.stdin. When restricted, this should
    be mod_wsgi.Restricted.

  /test/wsgi/restrict/stdin-read
    Attempts to access sys.stdin.read. When restricted, any attribute
    access should raise OSError.

  /test/wsgi/restrict/stderr-type
    Returns the type name of sys.stderr. This should never be
    restricted — it is always a log wrapper object.
"""

import sys


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/stdin-type":
        return handle_stdin_type(environ, start_response)
    elif path == "/stdin-read":
        return handle_stdin_read(environ, start_response)
    elif path == "/stderr-type":
        return handle_stderr_type(environ, start_response)
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]


def handle_stdin_type(environ, start_response):
    type_name = type(sys.stdin).__module__ + "." + type(sys.stdin).__name__

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [type_name.encode("utf-8")]


def handle_stdin_read(environ, start_response):
    try:
        sys.stdin.read
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"NOT_RESTRICTED"]
    except OSError as e:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [("RESTRICTED: " + str(e)).encode("utf-8")]


def handle_stderr_type(environ, start_response):
    type_name = type(sys.stderr).__module__ + "." + type(sys.stderr).__name__

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [type_name.encode("utf-8")]
