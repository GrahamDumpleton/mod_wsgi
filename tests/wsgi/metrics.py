"""Test mod_wsgi metrics and event subscription system.

Sets up event handlers to track request lifecycle events and
exposes endpoints to retrieve metrics data.

Endpoints:

  /test/wsgi/metrics/basic
    Simple request that returns 200. Used to generate request
    activity for metrics collection.

  /test/wsgi/metrics/request-metrics
    Returns the result of mod_wsgi.request_metrics() as text.

  /test/wsgi/metrics/process-metrics
    Returns the result of mod_wsgi.process_metrics() as text.

  /test/wsgi/metrics/server-metrics
    Returns the result of mod_wsgi.server_metrics() as text.
    Returns 'None' if server metrics are not enabled.

  /test/wsgi/metrics/request-data
    Returns the result of mod_wsgi.request_data() as text.
    This is the per-request data dict populated by event handlers.

  /test/wsgi/metrics/events-log
    Returns a log of event names that have been received by
    the event handler during this process lifetime.
"""

import mod_wsgi
import os
import threading

# Opt in to per-request metrics recording at module import time so the
# request_metrics() / process_metrics() endpoints below return data
# rather than None on their first call.
mod_wsgi.start_recording_metrics()

# Track events received during process lifetime.
_events_log = []
_request_finished_keys = set()


def event_handler(name, **kwargs):
    _events_log.append(name)

    if name == "request_started":
        thread = threading.current_thread()
        request_data = kwargs["request_data"]
        request_data["thread_name"] = thread.name
        request_data["thread_id"] = thread.ident
        request_data["pid"] = os.getpid()
    elif name == "request_finished":
        # Filter out request_data which is always present and not a
        # metric — we just want the lifecycle/metric keys here so the
        # test can assert which fields are exposed.
        for key in kwargs:
            if key != "request_data":
                _request_finished_keys.add(key)


mod_wsgi.subscribe_events(event_handler)


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/basic":
        return handle_basic(environ, start_response)
    elif path == "/request-metrics":
        return handle_request_metrics(environ, start_response)
    elif path == "/process-metrics":
        return handle_process_metrics(environ, start_response)
    elif path == "/server-metrics":
        return handle_server_metrics(environ, start_response)
    elif path == "/request-data":
        return handle_request_data(environ, start_response)
    elif path == "/events-log":
        return handle_events_log(environ, start_response)
    elif path == "/request-finished-keys":
        return handle_request_finished_keys(environ, start_response)
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]


def handle_basic(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"OK"]


def handle_request_metrics(environ, start_response):
    metrics = mod_wsgi.request_metrics()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [repr(metrics).encode("utf-8")]


def handle_process_metrics(environ, start_response):
    metrics = mod_wsgi.process_metrics()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [repr(metrics).encode("utf-8")]


def handle_server_metrics(environ, start_response):
    metrics = mod_wsgi.server_metrics()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [repr(metrics).encode("utf-8")]


def handle_request_data(environ, start_response):
    data = mod_wsgi.request_data()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [repr(data).encode("utf-8")]


def handle_events_log(environ, start_response):
    # Return the events log as newline-separated list.
    # Filter out events from this request itself (request_started
    # will have already fired for this request).
    log_text = "\n".join(_events_log)

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [log_text.encode("utf-8")]


def handle_request_finished_keys(environ, start_response):
    # Return the union of keys observed across all request_finished
    # events seen so far, one per line. Used by the integration test
    # to assert which lifecycle/metric fields are being published.
    body = "\n".join(sorted(_request_finished_keys))

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [body.encode("utf-8")]
