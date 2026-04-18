# Benchmark WSGI app modelling a small REST endpoint.
#
# Returns a precomputed ~1 KB body and a handful of response headers,
# so the response path through mod_wsgi exercises a realistic amount
# of header processing and body output without doing real work inside
# the Python callable. Paired with tests/hello.wsgi (12 byte body)
# this lets benchmarks compare raw per-request overhead against a
# more typical response size.
#
# BENCHMARK_DELAY env var (fractional seconds) adds a time.sleep()
# per request to emulate I/O wait on a backend (database / upstream
# service). time.sleep() releases the GIL, so threads within a
# process serve concurrently during the wait.

import os
import time

_BODY = b"A" * 1024

_HEADERS = [
    ("Content-Type", "text/plain"),
    ("Content-Length", str(len(_BODY))),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Benchmark", "1"),
]

_DELAY = float(os.environ.get("BENCHMARK_DELAY", "0") or "0")


if _DELAY > 0:
    def application(environ, start_response):
        time.sleep(_DELAY)
        start_response("200 OK", _HEADERS)
        return [_BODY]
else:
    def application(environ, start_response):
        start_response("200 OK", _HEADERS)
        return [_BODY]
