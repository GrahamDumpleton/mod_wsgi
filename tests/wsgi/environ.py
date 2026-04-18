"""Test that request metadata reaches the WSGI environ dict.

Endpoints take a ``key`` query parameter (where applicable) and
return a ``;end``-terminated response so the shell test harness
can compare without losing trailing newlines.

  /test/wsgi/environ/has?key=X
    Returns ``present=YES`` or ``present=NO``.

  /test/wsgi/environ/get?key=X
    Returns ``value=<str(environ[X])>`` or ``value=MISSING``.

  /test/wsgi/environ/type?key=X
    Returns ``type=<qualified name>``. For classes stored directly
    (e.g. ``wsgi.file_wrapper``) uses the class's own qualified
    name; for instances uses the qualified name of the instance
    type.

  /test/wsgi/environ/wsgi-version
    Returns ``version=<repr(environ['wsgi.version'])>``.

  /test/wsgi/environ/all-http
    Returns ``keys=<comma-separated sorted list of HTTP_* keys>``.
"""

from urllib.parse import parse_qs


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/has": handle_has,
        "/get": handle_get,
        "/type": handle_type,
        "/wsgi-version": handle_wsgi_version,
        "/all-http": handle_all_http,
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
    if isinstance(val, type):
        qualname = val.__module__ + "." + val.__name__
    else:
        t = type(val)
        qualname = t.__module__ + "." + t.__name__
    return _respond(start_response, ("type=" + qualname).encode())


def handle_wsgi_version(environ, start_response):
    body = ("version=" + repr(environ["wsgi.version"])).encode()
    return _respond(start_response, body)


def handle_all_http(environ, start_response):
    keys = sorted(k for k in environ if k.startswith("HTTP_"))
    body = ("keys=" + ",".join(keys)).encode()
    return _respond(start_response, body)
