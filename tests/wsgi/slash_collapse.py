"""Echo SCRIPT_NAME or PATH_INFO to verify mod_wsgi collapses
duplicate ``/`` characters in those environ keys before the
application sees them.

Endpoints take a ``key`` query parameter and return a
``value=<...>;end`` body so the shell harness can compare exact
string values including trailing slashes.
"""

from urllib.parse import parse_qs


def application(environ, start_response):
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    key = qs.get("key", ["PATH_INFO"])[0]
    value = environ.get(key, "")

    body = ("value=" + value + ";end").encode("utf-8")

    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]
