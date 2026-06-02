"""Test custom response headers via start_response.

Endpoints:

  /test/wsgi/headers/custom
    Returns a single X-Test-Custom header in addition to
    Content-Type to verify arbitrary headers are copied into
    headers_out and reach the client.

  /test/wsgi/headers/multiple-custom
    Returns several distinct X-* headers at once.

  /test/wsgi/headers/repeated-custom
    Returns the same X-Test-Repeated header twice with different
    values to verify that apr_table_add preserves both entries
    rather than overwriting.

  /test/wsgi/headers/www-authenticate
    Returns a 401 with a WWW-Authenticate header which mod_wsgi
    special-cases into err_headers_out.

  /test/wsgi/headers/many
    Returns 25 X-Many-* headers alongside Content-Type to
    exercise the header emission loop with a non-trivial count.

  /test/wsgi/headers/invalid-content-length
    Declares a non-numeric Content-Length which mod_wsgi must
    reject, producing a 500 response.
"""


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/custom": handle_custom,
        "/multiple-custom": handle_multiple_custom,
        "/repeated-custom": handle_repeated_custom,
        "/www-authenticate": handle_www_authenticate,
        "/many": handle_many,
        "/invalid-content-length": handle_invalid_content_length,
    }

    handler = handlers.get(path)
    if handler is None:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    return handler(environ, start_response)


def handle_custom(environ, start_response):
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("X-Test-Custom", "hello-world"),
    ])
    return [b"ok"]


def handle_multiple_custom(environ, start_response):
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("X-Test-First", "one"),
        ("X-Test-Second", "two"),
        ("X-Test-Third", "three"),
    ])
    return [b"ok"]


def handle_repeated_custom(environ, start_response):
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("X-Test-Repeated", "first-value"),
        ("X-Test-Repeated", "second-value"),
    ])
    return [b"ok"]


def handle_www_authenticate(environ, start_response):
    start_response("401 Unauthorized", [
        ("Content-Type", "text/plain"),
        ("WWW-Authenticate", 'Basic realm="test"'),
    ])
    return [b"auth required"]


def handle_many(environ, start_response):
    headers = [("Content-Type", "text/plain")]
    for i in range(1, 26):
        headers.append((f"X-Many-{i:02d}", f"value-{i}"))
    start_response("200 OK", headers)
    return [b"ok"]


def handle_invalid_content_length(environ, start_response):
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", "not-a-number"),
    ])
    return [b"should fail"]
