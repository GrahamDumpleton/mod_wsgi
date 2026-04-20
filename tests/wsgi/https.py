"""Test that HTTPS markers reach the WSGI environ dict correctly.

Endpoints take a ``key`` query parameter (where applicable) and
return a ``;end``-terminated response so the shell test harness
can compare without losing trailing newlines.

  /test/wsgi/https/has?key=X
    Returns ``present=YES`` or ``present=NO``.

  /test/wsgi/https/get?key=X
    Returns ``value=<str(environ[X])>`` or ``value=MISSING``.

  /test/wsgi/https/type?key=X
    Returns ``type=<qualified name>``.
"""

from urllib.parse import parse_qs


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/has": handle_has,
        "/get": handle_get,
        "/type": handle_type,
    }

    handler = handlers.get(path)
    if handler is None:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    return handler(environ, start_response)


def _respond(start_response, body):
    payload = body + b";end"
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


def _key(environ):
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    return qs.get("key", [""])[0]


def handle_has(environ, start_response):
    key = _key(environ)
    present = "YES" if key in environ else "NO"
    return _respond(start_response, ("present=" + present).encode())


def handle_get(environ, start_response):
    key = _key(environ)
    if key in environ:
        body = ("value=" + str(environ[key])).encode("utf-8")
    else:
        body = b"value=MISSING"
    return _respond(start_response, body)


def handle_type(environ, start_response):
    key = _key(environ)
    if key not in environ:
        return _respond(start_response, b"type=MISSING")
    val = environ[key]
    t = type(val)
    qualname = t.__module__ + "." + t.__name__
    return _respond(start_response, ("type=" + qualname).encode())
