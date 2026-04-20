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
#
# BENCHMARK_CPU env var (fractional seconds) adds a wall-clock
# timed busy loop per request to emulate Python-level CPU work.
# The loop holds the GIL, so threads within a process serialise
# on CPU work. When combined with BENCHMARK_DELAY the sleep runs
# first, then the CPU work.
#
# BENCHMARK_CHUNKS env var (integer >= 1, default 1) splits a
# mixed BENCHMARK_DELAY + BENCHMARK_CPU workload into N interleaved
# [sleep, cpu] iterations. Threads that sleep concurrently stampede
# onto the GIL for their CPU phase; interleaving with smaller chunks
# scrambles the acquisition timing and reduces that stampede. Only
# has an effect when both DELAY and CPU are positive.
#
# Paths served (all other paths fall through to the benchmark handler):
#
#   /                 Benchmark response (applies delay/cpu, returns body).
#
#   /metrics/reset    Calls mod_wsgi.request_metrics() to seed a fresh
#                     measurement window in this process. Returns the
#                     PID so the collector can track which processes
#                     have been reached.
#
#   /metrics/report   Calls mod_wsgi.request_metrics() again and returns
#                     the accumulated per-process metrics as JSON. The
#                     first call on a given process returns an empty
#                     window, so /metrics/reset must be hit first.

import json
import os
import threading
import time

try:
    import mod_wsgi
except ImportError:
    mod_wsgi = None

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
_CPU = float(os.environ.get("BENCHMARK_CPU", "0") or "0")
_CHUNKS = max(1, int(os.environ.get("BENCHMARK_CHUNKS", "1") or "1"))

_PID = os.getpid()

# Cached report so repeated /metrics/report hits return identical data
# for the same window. request_metrics() resets on every call, so
# without caching a second hit from the collector would clobber the
# accumulated benchmark data with a tiny-window reading.
_metrics_lock = threading.Lock()
_metrics_cache = None


def _cpu_burn(seconds):
    deadline = time.perf_counter() + seconds
    count = 0
    while time.perf_counter() < deadline:
        count += 1
    return count


if _DELAY > 0 and _CPU > 0 and _CHUNKS > 1:
    _DELAY_PER_CHUNK = _DELAY / _CHUNKS
    _CPU_PER_CHUNK = _CPU / _CHUNKS
    _CHUNK_RANGE = range(_CHUNKS)
    def _bench(environ, start_response):
        for _ in _CHUNK_RANGE:
            time.sleep(_DELAY_PER_CHUNK)
            _cpu_burn(_CPU_PER_CHUNK)
        start_response("200 OK", _HEADERS)
        return [_BODY]
elif _DELAY > 0 and _CPU > 0:
    def _bench(environ, start_response):
        time.sleep(_DELAY)
        _cpu_burn(_CPU)
        start_response("200 OK", _HEADERS)
        return [_BODY]
elif _DELAY > 0:
    def _bench(environ, start_response):
        time.sleep(_DELAY)
        start_response("200 OK", _HEADERS)
        return [_BODY]
elif _CPU > 0:
    def _bench(environ, start_response):
        _cpu_burn(_CPU)
        start_response("200 OK", _HEADERS)
        return [_BODY]
else:
    def _bench(environ, start_response):
        start_response("200 OK", _HEADERS)
        return [_BODY]


def _metrics_reset(environ, start_response):
    global _metrics_cache
    with _metrics_lock:
        _metrics_cache = None
        if mod_wsgi is not None:
            mod_wsgi.request_metrics()
    body = str(_PID).encode("ascii")
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def _metrics_report(environ, start_response):
    global _metrics_cache
    with _metrics_lock:
        if _metrics_cache is None:
            data = {}
            if mod_wsgi is not None:
                data = dict(mod_wsgi.request_metrics())
            data["pid"] = _PID
            _metrics_cache = data
        body = json.dumps(_metrics_cache).encode("utf-8")
    start_response("200 OK", [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == "/metrics/reset":
        return _metrics_reset(environ, start_response)
    if path == "/metrics/report":
        return _metrics_report(environ, start_response)
    return _bench(environ, start_response)
