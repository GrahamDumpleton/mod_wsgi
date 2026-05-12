======================
Subscribing to Events
======================

mod_wsgi publishes events at well-defined points in the request
and process lifecycle. Applications can subscribe to these events
to do cross-cutting work (structured logging, audit, observability,
metrics enrichment, shutdown cleanup) without wrapping the WSGI
application callable. This page documents the subscription API,
every published event and its payload, and a handful of common
usage patterns.

Subscribing
-----------

``mod_wsgi.subscribe_events(callback)``
   Register ``callback`` to receive every event mod_wsgi
   publishes. The callback is invoked with the event name as a
   single positional argument and the event payload as keyword
   arguments::

       import mod_wsgi

       def handler(name, **event):
           ...

       mod_wsgi.subscribe_events(handler)

   When only specific payload keys matter, declare them as
   keyword-only parameters and let ``**event`` swallow the rest::

       def handler(name, *, request_id, request_data, **event):
           ...

   ``subscribe_events`` returns the callback unchanged, so it can
   also be used as a decorator::

       @mod_wsgi.subscribe_events
       def handler(name, **event):
           ...

   Multiple callbacks can be registered; they are invoked in the
   order they were registered.

   If the callback returns a dict, its keys are shallow-merged
   into the event dict (the same dict passed as ``**event``)
   before subsequent subscribers for the same firing run. The
   merge is per-dispatch only: the next event published gets a
   fresh dict.

``mod_wsgi.subscribe_shutdown(callback)``
   Shortcut for subscribing only to ``process_stopping``. The
   callback shape is the same as for ``subscribe_events``, and
   the function returns the callback so it can be used as a
   decorator::

       @mod_wsgi.subscribe_shutdown
       def cleanup(name, **event):
           ...

   Use this when the subscriber only cares about the shutdown
   signal; it makes the intent clearer than registering a
   single-event handler through ``subscribe_events`` and
   filtering by ``name`` inside the body.

Subscriptions are per-interpreter: a callback registered inside
one sub-interpreter only fires for events published in that
sub-interpreter. In a single-interpreter application this
distinction does not matter.

Event reference
---------------

The following events are published. ``subscribe_events``
callbacks see all of them; ``subscribe_shutdown`` callbacks see
only ``process_stopping``.

Several payload keys appear on every request-scoped event and are
worth introducing once:

``request_id``
   String identifier for the request, the same value Apache uses
   as the request log ID. Substituted by ``%L`` in ``LogFormat``
   and ``ErrorLogFormat`` directives, so subscribers can
   cross-correlate event data with entries in the Apache access
   and error logs. May be absent if Apache did not assign one.

``thread_id``
   Numeric ID of the worker thread handling the request, 1-based.

``request_data``
   Per-request scratchpad dict shared by the application and all
   event subscribers. See `Per-request scratchpad`_ below.

request_started
~~~~~~~~~~~~~~~

Fires immediately before the WSGI application callable is
invoked.

``request_id``, ``thread_id``, ``request_data``
   Standard fields described above.

``request_environ``
   The WSGI environment dict that will be passed to the
   application. Subscribers may inspect or mutate it; mutations
   are visible to the application.

``application_object``
   The application callable about to be invoked. If a subscriber
   replaces this key with a different callable (by returning
   ``{"application_object": wrapper}``), subsequent subscribers
   and ultimately the WSGI adapter use the replacement. This is
   the supported hook point for adding application-level
   middleware at runtime.

``request_start``
   Time Apache received the request, in seconds since the epoch.

``application_start``
   Time the worker thread is about to call the application
   callable, in seconds since the epoch.

``queue_start``
   Time Apache wrote the request onto the daemon socket, in
   seconds since the epoch. ``0`` in embedded mode (no queue
   phase).

``daemon_start``
   Time the daemon process picked the request up, in seconds
   since the epoch. ``0`` in embedded mode.

``daemon_connects``
   Number of times the Apache child has had to establish a
   connection to the daemon process group while serving this
   request (normally 1; greater than 1 indicates a reconnect).

``daemon_restarts``
   Number of daemon-process restarts the Apache child has
   observed while attempting to serve this request.

response_started
~~~~~~~~~~~~~~~~

Fires when the WSGI application calls ``start_response``.

``request_id``, ``request_data``
   Standard fields described above.

``response_status``
   The status line passed to ``start_response`` (e.g.
   ``"200 OK"``).

``response_headers``
   The response headers list passed to ``start_response``.

``exception_info``
   The ``exc_info`` argument passed to ``start_response``, or
   ``None`` if the application did not pass one. Set when the
   application is reporting an in-progress error through the
   WSGI exception-handling contract.

request_finished
~~~~~~~~~~~~~~~~

Fires after the response has been fully written to the client.

``request_id``, ``thread_id``, ``request_data``
   Standard fields described above.

``request_start``, ``application_start``, ``queue_start``, ``daemon_start``
   As for ``request_started``.

``application_finish``
   Time the WSGI application callable returned, in seconds since
   the epoch.

``application_time``
   ``application_finish - application_start``, in seconds.

``input_reads``
   Number of times the application read from the request body
   stream.

``input_length``
   Total bytes the application read from the request body.

``input_time``
   Time spent reading the request body, in seconds.

``output_writes``
   Number of times the WSGI adapter wrote a chunk of the
   response to Apache.

``output_length``
   Total response bytes written.

``output_time``
   Time spent writing the response, in seconds.

``status``
   Numeric HTTP status code the application returned. ``0`` if
   the application never called ``start_response``.

``cpu_user_time``
   User-mode CPU time the worker thread consumed serving this
   request, in seconds.

``cpu_system_time``
   Kernel-mode CPU time the worker thread consumed serving this
   request, in seconds.

``cpu_time``
   ``cpu_user_time + cpu_system_time``.

``gil_wait_time``
   Time the worker thread spent waiting to re-acquire the GIL
   at the boundaries where mod_wsgi releases it on the
   application's behalf: acquiring the interpreter at the start
   of the request, and re-acquiring the GIL after reading
   request body bytes, after flushing response headers, and
   after writing response body bytes. In seconds. GIL waits
   inside the WSGI application itself (for example between
   Python-level threads the application spawns) are not
   measured.

``gil_wait_count``
   Number of GIL re-acquire events on those boundaries during
   this request.

The CPU and GIL fields are present only if the underlying timing
sources are available on the host (they normally are on Linux and
macOS).

request_exception
~~~~~~~~~~~~~~~~~

Fires when an uncaught exception propagates out of the WSGI
application callable, before mod_wsgi formats and writes a 500
response.

``request_id``
   Standard field, when Apache assigned one.

``request_data``
   The per-request scratchpad, when the event fires inside a
   request bracket. Absent if the exception happened outside the
   normal request lifecycle (rare; only in degenerate failure
   paths).

``exception_info``
   A ``(type, value, traceback)`` tuple as produced by
   ``sys.exc_info``. Subscribers can format and log it, ship it
   to an error-tracking service, or otherwise record the
   failure.

process_stopping
~~~~~~~~~~~~~~~~

Fires once per process when mod_wsgi is shutting it down. The
event fires while the interpreter is still healthy, before
Python's interpreter finalisation runs, so callbacks can do
real work (write to disk, send a final metrics sample, contact
an external service to deregister). Critically, this is also
the point at which callbacks can still signal long-lived
non-daemon worker threads to exit: Python's finalisation
blocks waiting for non-daemon threads to terminate, and a
thread sitting in an unconditional loop with no shutdown
signal will hang the process at that point.

``shutdown_reason``
   String describing what triggered the shutdown. One of:

   ``"shutdown_signal"``
      SIGTERM (Apache stop or restart).

   ``"graceful_signal"``
      SIGUSR1 graceful drain.

   ``"eviction_signal"``
      Operator-driven eviction.

   ``"maximum_requests"``
      The ``maximum-requests=`` limit on
      :doc:`../configuration-directives/WSGIDaemonProcess` has
      been reached.

   ``"restart_interval"``
      The ``restart-interval=`` limit has elapsed.

   ``"inactivity_timeout"``
      The ``inactivity-timeout=`` limit has elapsed with no
      activity.

   ``"request_timeout"``
      A request exceeded the ``request-timeout=`` limit and the
      daemon is shutting down to recover.

   ``"startup_timeout"``
      The ``startup-timeout=`` limit was exceeded before the
      application finished starting up.

   ``"deadlock_timeout"``
      The ``deadlock-timeout=`` watchdog on
      :doc:`../configuration-directives/WSGIDaemonProcess`
      tripped. Subscribers should not expect to see this
      firing in practice: dispatching ``process_stopping``
      needs the GIL of each interpreter, which is exactly the
      resource the deadlock holds, so the publish path blocks.
      A reaper thread terminates the daemon process via
      ``exit()`` after ``shutdown-timeout=`` seconds regardless,
      so even on the rare occasions when the publish could
      complete, the reaper has typically already exited the
      process. The reason string is listed for completeness;
      end-of-process cleanup that needs to run on deadlock
      cannot rely on this event.

   ``"cpu_time_limit"``
      The ``cpu-time-limit=`` limit was exceeded.

   ``"signal_pipe_error"``
      The daemon's internal signal pipe became unusable; the
      process is being recycled defensively.

   ``"script_reload"``
      The WSGI script changed on disk and the application group
      is reloading.

Subscribers wired through ``subscribe_shutdown`` should keep
their callbacks short. The shutdown sequence waits for
non-daemon threads to exit, so a callback that takes a long
time, or that fails to signal a worker thread it owns, will
delay process teardown or stall it indefinitely.

This ordering matters especially in sub-interpreters that own
their own GIL (PEP 684), where daemon threads are not permitted
at all. Every long-lived background thread in that environment
must be non-daemon, so every such thread must have a shutdown
signal wired through ``subscribe_shutdown`` (or
``subscribe_events`` on ``process_stopping``) to be stoppable.

Per-request scratchpad
----------------------

``mod_wsgi.request_data()``
   Return the per-request scratchpad dict for the current
   thread. The dict is created at the start of each request and
   is the same object passed to subscribers as the
   ``request_data`` event-payload key.

The scratchpad is the supported channel for carrying state
between events for the same request, or between a subscriber and
the application. A subscriber that sets a value at
``request_started`` can read it back at ``request_finished``; the
application can read or write the same dict by calling
``mod_wsgi.request_data()`` from inside the WSGI callable.

``request_data()`` raises ``RuntimeError`` if called outside the
context of an active request, so it is only useful from inside
the WSGI application callable or from inside a request-scoped
event subscriber.

The active-requests dict
------------------------

``mod_wsgi.active_requests``
   A dict, keyed by ``request_id``, of requests currently being
   handled by the process. Each value is a dict carrying the same
   information event subscribers see in ``request_started`` event
   payloads.

The dict is populated automatically as requests start and finish.
Subscribers, the application, or admin-endpoint code can read it
to inspect concurrent in-flight work, for example to dump live
state on a debug endpoint or to detect requests stalled past a
threshold from a watchdog.

Common patterns
---------------

Structured logging per request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Subscribe to ``request_finished`` to emit one structured log
entry per request, separate from the Apache access log. The
event payload already carries the timestamps and pre-computed
durations needed to summarise the request, so no extra timing
capture at ``request_started`` is necessary::

    import json
    import logging

    import mod_wsgi

    log = logging.getLogger("requests")

    @mod_wsgi.subscribe_events
    def trace(name, **event):
        if name != "request_finished":
            return
        log.info(json.dumps({
            "request_id": event.get("request_id"),
            "status": event["status"],
            "application_time": event["application_time"],
            "request_time": event["application_finish"] - event["request_start"],
            "cpu_time": event.get("cpu_time"),
        }))

The event timestamp fields are wall-clock seconds since the
epoch, not monotonic. NTP step adjustments mid-request could in
principle skew a difference like
``application_finish - request_start``, but in practice the
window is small enough that this is not a real concern; the
pre-computed ``application_time`` is the same subtraction taken
under the same clock and is provided for convenience.

Counting response classes inside the process
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A lightweight in-process counter can be maintained on
``request_finished`` and exposed elsewhere::

    import threading
    import mod_wsgi

    counts = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    lock = threading.Lock()

    @mod_wsgi.subscribe_events
    def count(name, **event):
        if name != "request_finished":
            return
        status = event["status"] or 500
        family = f"{status // 100}xx"
        with lock:
            counts[family] = counts.get(family, 0) + 1

Note that for production-grade metrics, the per-interval
accumulators exposed by :doc:`internal-metrics-api` are usually
the better source: they already include per-class counters and
are drained atomically by a single reporter call.

Process-shutdown cleanup
~~~~~~~~~~~~~~~~~~~~~~~~

``subscribe_shutdown`` is the right hook for closing connection
pools, flushing buffered telemetry, deregistering with a service
discovery system, and similar end-of-process tasks::

    import mod_wsgi

    @mod_wsgi.subscribe_shutdown
    def close_pool(name, **event):
        connection_pool.close()

If the cleanup needs a worker thread to stop, signal it from the
callback (for example by putting a sentinel on a queue) and
ensure the worker thread is non-daemon. The shutdown sequence
waits for non-daemon threads to exit, which gives the worker a
chance to finish writing whatever it was working on. See
:doc:`internal-metrics-api` for a worked example.

Why not ``atexit``
~~~~~~~~~~~~~~~~~~

``atexit`` callbacks run as part of Python's interpreter
finalisation, *after* the runtime has joined every non-daemon
thread. That ordering makes ``atexit`` the wrong hook for
signalling non-daemon threads to exit: if the thread is sitting
in a loop waiting for a sentinel, finalisation blocks waiting
for the thread to terminate before ``atexit`` ever fires, and
the process hangs.

``process_stopping`` fires earlier, while the interpreter is
still fully functional and before the non-daemon-thread join.
That is the supported hook for end-of-process work that needs
to wind down active resources, particularly when those
resources include the application's own worker threads. Code
ported from a plain-Python context that uses ``atexit`` for
this purpose should switch to ``subscribe_shutdown`` when
running under mod_wsgi.

See also
--------

* :doc:`internal-metrics-api`: the four ``mod_wsgi`` metrics
  accessors, with a worked example that uses
  ``subscribe_shutdown`` to coordinate a background reporter
  thread.
* :doc:`registering-cleanup-code`: end-of-request and
  end-of-process cleanup patterns, including the WSGI middleware
  approach for end-of-request cleanup.
* :doc:`mod-wsgi-python-module`: short reference summary of the
  full ``mod_wsgi`` built-in module surface.
