"""Test mod_wsgi metrics and event subscription system.

Sets up event handlers to track request lifecycle events and
exposes endpoints to retrieve metrics data.

Endpoints:

  /test/wsgi/metrics/basic
    Simple request that returns 200. Used to generate request
    activity for metrics collection.

  /test/wsgi/metrics/request-metrics
    Returns the result of mod_wsgi.request_metrics() as text.
    Must be called at least twice — the first call initialises
    the collection period and returns an empty dict.

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

# Track events received during process lifetime.
_events_log = []


def event_handler(name, **kwargs):
    _events_log.append(name)

    if name == "request_started":
        thread = threading.current_thread()
        request_data = kwargs["request_data"]
        request_data["thread_name"] = thread.name
        request_data["thread_id"] = thread.ident
        request_data["pid"] = os.getpid()


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
