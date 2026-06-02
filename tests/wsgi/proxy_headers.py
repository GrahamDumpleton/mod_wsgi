"""Test trusted proxy header processing.

mod_wsgi's ``WSGITrustedProxyHeaders`` directive opts-in to
rewriting selected CGI environ keys based on incoming X-Forwarded-*
style headers sent by a front-end reverse proxy.
``WSGITrustedProxies`` (optional) further gates the rewriting on
the immediate peer IP so a spoofing client can't inject the
headers directly.

Endpoints (every path is mounted at ``/test/wsgi/proxy-headers``,
with a per-test ``<Location>`` sub-path selecting a different
directive combination in ``proxy_headers.conf``):

  /<location>/get?key=X
    Returns ``value=<str(environ[X])>`` or ``value=MISSING``,
    terminated with ``;end``.

  /<location>/has?key=X
    Returns ``present=YES`` or ``present=NO``.

The same handler is used at every location; the <Location>
directives in the .conf file drive the behavioural differences.
"""

from urllib.parse import parse_qs


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    # Strip the per-location prefix so the shared /get and /has
    # dispatch works regardless of which <Location> the request
    # came through.
    for prefix in (
        "/basic",
        "/trusted-client",
        "/untrusted-client",
        "/partial",
    ):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    if path == "/get":
        return handle_get(environ, start_response)
    if path == "/has":
        return handle_has(environ, start_response)

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"Unknown test path"]


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


def handle_get(environ, start_response):
    key = _key(environ)
    if key in environ:
        body = ("value=" + str(environ[key])).encode("utf-8")
    else:
        body = b"value=MISSING"
    return _respond(start_response, body)


def handle_has(environ, start_response):
    key = _key(environ)
    present = "YES" if key in environ else "NO"
    return _respond(start_response, ("present=" + present).encode())
