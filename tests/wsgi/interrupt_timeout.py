"""WSGI fixture for the interrupt-timeout / RequestTimeout test.

Three endpoints, dispatched by PATH_INFO under the harness's primary
mount at /test/wsgi/interrupt-timeout:

* /slow  - spins in a pure-Python loop. Injection of
           mod_wsgi.RequestTimeout from the daemon monitor thread
           lands on the next bytecode tick, which unwinds back to
           the adapter and produces a 504 Gateway Timeout. The
           process is not restarted; the worker thread returns to
           the pool to handle further requests.

* /catch - same loop wrapped in try/except mod_wsgi.RequestTimeout
           that re-raises after recording a marker. Exists so the
           test can assert that user code which catches and
           re-raises still produces the 504 path, matching the
           documented contract.

* /fast  - returns 200 immediately. Hit before /slow to confirm
           the daemon is healthy, and after /slow to confirm the
           process did not restart.
"""

from mod_wsgi import RequestTimeout

CATCH_MARKER = "/tmp/mod_wsgi_interrupt_timeout_catch_marker"


def application(environ, start_response):
    path = environ.get("PATH_INFO", "")

    if path == "/slow":
        while True:
            pass

    if path == "/catch":
        try:
            while True:
                pass
        except RequestTimeout:
            with open(CATCH_MARKER, "w") as f:
                f.write("caught\n")
            raise

    if path == "/fast":
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"fast ok"]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"unknown path"]
