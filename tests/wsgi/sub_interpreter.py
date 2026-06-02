"""Test that requests routed to a named application group execute in
a sub-interpreter.

Every other test in the harness runs in the daemon process group's
main interpreter (the dispatch script returns "" for
application_group, matching the static "%{GLOBAL}" on the
WSGIScriptAlias). For requests under this test's mount,
tests/dispatch.py returns "test-subinterp" so mod_wsgi takes the
Py_NewInterpreter branch in newInterpreterObject on first request
and serves subsequent requests from that sub-interpreter.

Endpoints:

  /test/wsgi/sub-interpreter/application-group
    Returns ``application_group=<value>;end``. Should be
    ``application_group=test-subinterp`` if the dispatch override
    took effect and the sub-interpreter was created.
"""

import mod_wsgi


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/application-group":
        body = ("application_group=" + mod_wsgi.application_group).encode()
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    payload = body + b";end"
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]
