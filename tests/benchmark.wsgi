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
# BENCHMARK_DISTRIBUTION env var selects per-request time sampling:
#
#   "fixed" (default)   Every request uses BENCHMARK_DELAY / BENCHMARK_CPU
#                       verbatim (historical behaviour).
#
#   "lognormal"         Per-request delay (and optionally CPU) is drawn
#                       from a log-normal distribution whose *mean*
#                       equals BENCHMARK_DELAY / BENCHMARK_CPU. Matches
#                       the right-skewed fall-off typical of real HTTP
#                       response time distributions.
#
#   "mixture"           Body + long-tail. 95% of requests draw from the
#                       lognormal body centred on BENCHMARK_DELAY (sharp
#                       peak, sigma = BENCHMARK_IO_SIGMA). The remaining
#                       5% draw from a slow lognormal centred on 2 s,
#                       capped at 5 s (thin but real long tail). Models
#                       fast happy path + rare slow path (DB retries,
#                       cache misses, GC pauses) — how real HTTP latency
#                       decomposes in production. CPU side uses the
#                       plain lognormal (no tail branch) to avoid
#                       pathological stalls on rare CPU outliers.
#
# BENCHMARK_IO_SIGMA env var (float, default 0.6) is the log-normal
# sigma parameter for the I/O delay when distribution is "lognormal".
# Larger sigma => heavier tail. sigma ~ 0.6 gives roughly
# P95 = 2.7 * P50, P99 = 4 * P50.
#
# BENCHMARK_CPU_SIGMA env var (float, default 0.0) is the log-normal
# sigma for the CPU portion. Defaulting to zero keeps per-request CPU
# constant so the test host is not overwhelmed by pathological tail
# samples; set > 0 to also vary CPU.
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
import math
import os
import random
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
_DISTRIBUTION = (os.environ.get("BENCHMARK_DISTRIBUTION", "fixed") or "fixed").lower()
_IO_SIGMA = max(0.0, float(os.environ.get("BENCHMARK_IO_SIGMA", "0.6") or "0.6"))
_CPU_SIGMA = max(0.0, float(os.environ.get("BENCHMARK_CPU_SIGMA", "0.0") or "0.0"))

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


def _sample_lognormal(target_mean, sigma):
    """Draw a positive sample whose expectation equals target_mean.

    For X ~ LogNormal(mu, sigma), E[X] = exp(mu + sigma^2/2), so we pick
    mu accordingly. Sigma=0 (or target_mean=0) collapses to the fixed
    value. Extreme outliers in the right tail are clamped at 10x the
    target to avoid pathological stalls on rare draws.
    """
    if target_mean <= 0 or sigma <= 0:
        return target_mean
    mu = math.log(target_mean) - (sigma * sigma) / 2.0
    sample = random.lognormvariate(mu, sigma)
    ceiling = target_mean * 10.0
    if sample > ceiling:
        sample = ceiling
    return sample


_MIXTURE_TAIL_PROB = 0.05
_MIXTURE_TAIL_MEAN = 2.0     # seconds; peak of the rare long-tail component
_MIXTURE_TAIL_SIGMA = 0.4    # moderate spread for the tail
_MIXTURE_TAIL_CAP = 5.0      # hard cap on tail samples


def _sample_mixture(target_mean, sigma):
    """Body + rare long-tail sampler for BENCHMARK_DISTRIBUTION=mixture.

    95% of requests draw from the lognormal body centred on target_mean
    (sharp peak near the caller's configured delay). The remaining 5%
    draw from a slower lognormal with mean 2 s / sigma 0.4, capped hard
    at 5 s. The tail parameters are fixed (not scaled by target_mean)
    so the tail hump stays in a realistic 1-5 s range regardless of how
    small the body mean is set.
    """
    if target_mean <= 0:
        return target_mean
    if random.random() < _MIXTURE_TAIL_PROB:
        mu = math.log(_MIXTURE_TAIL_MEAN) - (_MIXTURE_TAIL_SIGMA *
                                             _MIXTURE_TAIL_SIGMA) / 2.0
        sample = random.lognormvariate(mu, _MIXTURE_TAIL_SIGMA)
        return min(_MIXTURE_TAIL_CAP, sample)
    return _sample_lognormal(target_mean, sigma)


if _DISTRIBUTION == "lognormal":
    def _per_request_times():
        return (_sample_lognormal(_DELAY, _IO_SIGMA),
                _sample_lognormal(_CPU, _CPU_SIGMA))
elif _DISTRIBUTION == "mixture":
    def _per_request_times():
        # CPU uses plain lognormal — a rare 5 s CPU sample would stall
        # an entire thread and saturate the host. I/O sleeps release
        # the GIL, so long I/O tail samples are safe.
        return (_sample_mixture(_DELAY, _IO_SIGMA),
                _sample_lognormal(_CPU, _CPU_SIGMA))
else:
    def _per_request_times():
        return (_DELAY, _CPU)


def _bench(environ, start_response):
    delay, cpu = _per_request_times()
    if delay > 0 and cpu > 0 and _CHUNKS > 1:
        d_per = delay / _CHUNKS
        c_per = cpu / _CHUNKS
        for _ in range(_CHUNKS):
            time.sleep(d_per)
            _cpu_burn(c_per)
    elif delay > 0 and cpu > 0:
        time.sleep(delay)
        _cpu_burn(cpu)
    elif delay > 0:
        time.sleep(delay)
    elif cpu > 0:
        _cpu_burn(cpu)
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
