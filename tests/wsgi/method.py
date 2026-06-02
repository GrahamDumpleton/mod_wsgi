"""Test HTTP method handling in REQUEST_METHOD.

mod_wsgi can translate HEAD requests into GET before dispatching
them to the WSGI application. The WSGIMapHEADToGET directive
controls this:

  * On — always translate HEAD to GET.
  * Off — never translate; app always sees HEAD.
  * Auto (default) — translate only when a content output filter
    (e.g. mod_deflate, mod_include) is in the filter chain so
    that filter processing still sees a real body.

In a plain test setup with no content output filter, the default
leaves HEAD as HEAD. The explicit `On` setting forces the remap;
the explicit `Off` setting matches the default in this setup but
proves the opt-out path.

Endpoints:

  /test/wsgi/method/method
    Default (Auto) mapping. Echoes environ["REQUEST_METHOD"] in
    both the X-Method-Seen response header (so HEAD requests can
    still verify the value) and the body.

  /test/wsgi/method/head-to-get
    Same handler, mounted under a <Location> block with
    `WSGIMapHEADToGET On`; HEAD requests reach the app as GET.

  /test/wsgi/method/head-passthrough
    Same handler, mounted under a <Location> block with
    `WSGIMapHEADToGET Off`; explicit opt-out, HEAD stays as HEAD.
"""


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path in ("/method", "/head-to-get", "/head-passthrough"):
        return handle_method(environ, start_response)

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"Unknown test path"]


def handle_method(environ, start_response):
    method = environ.get("REQUEST_METHOD", "UNKNOWN")
    body = ("method=" + method + ";end").encode()

    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(body))),
        ("X-Method-Seen", method),
    ])
    return [body]
