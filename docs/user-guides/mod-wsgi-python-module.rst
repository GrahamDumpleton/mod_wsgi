==========================
The mod_wsgi Python Module
==========================

When a WSGI application runs under Apache with mod_wsgi loaded, the
``mod_wsgi`` module is built into the Python interpreter and exposes
attributes and functions that let the application introspect the
hosting environment, subscribe to lifecycle and request events,
read request and process metrics, and use mod_wsgi-specific helper
types. This page is a reference of that surface.

The built-in ``mod_wsgi`` module is installed into ``sys.modules``
by mod_wsgi itself when an interpreter is initialised; it is not
the same module as the ``mod_wsgi`` Python package distributed on
PyPI that provides the ``mod_wsgi-express`` command. See
:doc:`detecting-mod-wsgi` for reliable ways to tell whether code is
running under Apache/mod_wsgi rather than just having the PyPI
package installed.

Module attributes
-----------------

``version``
   The mod_wsgi version as a ``(major, minor, micro)`` tuple,
   reflecting the version of ``mod_wsgi.so`` loaded into Apache.

``process_group``
   The name of the daemon process group hosting the interpreter,
   or the empty string when running in embedded mode. Matches the
   first argument given to
   :doc:`../configuration-directives/WSGIDaemonProcess`.

``application_group``
   The name of the application group (sub interpreter) hosting the
   WSGI application. Matches the value given to
   :doc:`../configuration-directives/WSGIApplicationGroup`. The
   special name ``%{GLOBAL}`` resolves to the empty string and runs
   in the main interpreter; any other non-empty name runs in a
   named sub interpreter.

``maximum_processes``
   The maximum number of processes hosting interpreters in the
   current process group. In daemon mode this is the
   ``processes=`` value on ``WSGIDaemonProcess``; in embedded mode
   it is queried from the active Apache MPM.

``threads_per_process``
   The maximum number of worker threads per process. In daemon
   mode this is the ``threads=`` value on ``WSGIDaemonProcess``;
   in embedded mode it is queried from the active Apache MPM.

Event subscription
------------------

``subscribe_events(callback)``
   Register ``callback`` to receive every event mod_wsgi
   publishes. The callback is invoked with the event name as a
   single positional argument and the event payload as keyword
   arguments. The expected signature is::

       def callback(name, **event):
           ...

   or, when only specific keys matter, declare them as keyword-only
   parameters::

       def callback(name, *, request_id, request_start, **event):
           ...

   The function returns the callback unchanged so it can also be
   used as a decorator::

       @mod_wsgi.subscribe_events
       def callback(name, **event):
           ...

   If the callback returns a dict, its keys are merged into the
   event dict (the same dict passed as kwargs to subscribers)
   before subsequent subscribers of the same event firing run.
   The merge is shallow and applies only to this dispatch; the
   next event published gets a fresh event dict.

   To carry data across events for the same request, for example
   to set a value at ``request_started`` and read it at
   ``request_finished``, mutate ``mod_wsgi.request_data()``
   instead. That dict is the same object referenced under the
   ``request_data`` key in every event for the request and lives
   for the request's lifetime.

``subscribe_shutdown(callback)``
   A shortcut for subscribing only to the ``process_stopping``
   event. The callback shape matches ``subscribe_events`` and the
   callback is invoked once, when the process is shutting down.
   Like ``subscribe_events``, the function returns the callback
   so it can be used as a decorator::

       @mod_wsgi.subscribe_shutdown
       def cleanup(*args, **kwargs):
           ...

   Inert in service-script daemons (``WSGIDaemonProcess
   threads=0``); use ``signal.signal()`` directly in those
   processes. See :doc:`registering-cleanup-code` and the
   service-script notes in :doc:`subscribing-to-events`.

``subscribe_signals(callback)``
   Register ``callback`` to receive the ``process_signal`` event
   when the daemon process is sent ``SIGHUP`` or ``SIGUSR2``.
   The callback shape matches ``subscribe_events`` and the payload
   carries ``signame`` (canonical string like ``"SIGHUP"``) and
   ``signum`` (numeric value for convenience). The function returns
   the callback so it can be used as a decorator::

       @mod_wsgi.subscribe_signals
       def on_signal(name, *, signame, **event):
           if signame == 'SIGHUP':
               reload_config()
           elif signame == 'SIGUSR2':
               dump_diagnostics()

   Only effective in request-handling daemon-mode processes. In
   embedded mode the call is permitted (and still returns the
   callback so decorator syntax does not silently nullify the
   user's function symbol) but the callback is discarded; a
   warning and a Python stack trace identifying the registration
   site are emitted to the Apache error log. Service-script
   daemons (``WSGIDaemonProcess threads=0``) are also unsupported
   here; use ``signal.signal()`` directly in those processes. See
   :doc:`subscribing-to-events` for details.

Events
------

mod_wsgi publishes the following events. ``subscribe_events``
callbacks see all of them; ``subscribe_shutdown`` callbacks see
only ``process_stopping``; ``subscribe_signals`` callbacks see
only ``process_signal``.

``request_started``
   Fires immediately before the WSGI application callable is
   invoked. Payload keys include ``request_id``, ``thread_id``,
   ``server_pid`` (Apache child worker PID),
   ``request_start`` (seconds since epoch),
   ``application_object``, ``callable_object`` (the configured
   callable name as a string), ``application_start``,
   ``request_environ`` (the WSGI environment), and
   ``request_data``. Daemon mode adds ``queue_start``,
   ``daemon_start``, ``daemon_connects`` and ``daemon_restarts``.

``response_started``
   Fires when the WSGI application calls ``start_response``.
   Payload keys are ``request_id``, ``response_status`` (the
   status line), ``response_headers``, ``exception_info`` (or
   ``None``), and ``request_data``.

``request_finished``
   Fires after the response has been fully written. Payload
   includes the request-start fields plus timing fields
   (``application_finish``, ``application_time``, ``input_time``,
   ``output_time``), counter fields (``input_reads``,
   ``input_length``, ``output_writes``, ``output_length``,
   ``status``), CPU fields (``cpu_user_time``, ``cpu_system_time``,
   ``cpu_time``), GIL-contention fields (``gil_wait_time``,
   ``gil_wait_count``), and ``request_data``.

``request_exception``
   Fires when an uncaught exception propagates out of the WSGI
   application callable. Payload keys are ``request_id``,
   ``exception_info`` (a ``(type, value, traceback)`` tuple as
   produced by ``sys.exc_info``), and ``request_data``.

``process_signal``
   Fires in a daemon process when ``SIGHUP`` or ``SIGUSR2`` is
   delivered to the daemon. Payload keys are ``signame`` (a
   string, ``"SIGHUP"`` or ``"SIGUSR2"``) and ``signum`` (the
   numeric value of the signal on the current platform).
   Subscribers should branch on ``signame`` because numeric
   signal values vary across platforms. Embedded mode never
   publishes this event; see :doc:`subscribing-to-events` for
   details.

``process_stopping``
   Fires once per process when mod_wsgi is shutting it down.
   Payload key ``shutdown_reason`` is one of:

   * ``"shutdown_signal"`` — SIGTERM (Apache stop or restart).
   * ``"graceful_signal"`` — SIGUSR1 graceful drain.
   * ``"eviction_signal"`` — operator-driven eviction.
   * ``"maximum_requests"`` — ``maximum-requests`` limit reached.
   * ``"restart_interval"`` — ``restart-interval`` reached.
   * ``"inactivity_timeout"`` — ``inactivity-timeout`` expired.
   * ``"request_timeout"`` — ``request-timeout`` triggered.
   * ``"startup_timeout"`` — ``startup-timeout`` triggered.
   * ``"deadlock_timeout"`` — ``deadlock-timeout`` triggered.
   * ``"cpu_time_limit"`` — ``cpu-time-limit`` exceeded.
   * ``"script_reload"`` — WSGI script reload.

The ``request_id`` field shared across the request events is the
same identifier Apache uses as the request log ID — the value
substituted by ``%L`` in ``LogFormat`` and ``ErrorLogFormat``
directives. Subscribers can use it to cross-correlate event data
with Apache's access and error logs.

Per-request state
-----------------

``request_data()``
   Return the per-request scratchpad dict for the current thread.
   The dict is created at the start of each request and is the
   same object passed to subscribers as the ``request_data`` event
   payload key. The application and subscribers share it, so
   keys an event subscriber sets become visible to the application
   and vice versa. Raises ``RuntimeError`` if called outside the
   context of an active request.

``active_requests``
   A dict, keyed by request ID, of requests currently being
   handled by the process. Populated automatically as requests
   start and finish; subscribers can read it to inspect concurrent
   in-flight work.

Metrics
-------

``start_recording_metrics()``
   Enable per-request metrics accounting and seed the per-reader
   baselines so subsequent calls to ``request_metrics()`` and
   ``process_metrics()`` return data. Idempotent; safe to call
   unconditionally at application import time. When external
   telemetry reporting is enabled (the
   :doc:`../configuration-directives/WSGITelemetryService`
   directive), the external reporter is the canonical metrics
   consumer and this call has no observable effect from the Python
   API: the two accessors below still return ``None`` to signal the
   configured mode. Without an explicit call to this function, both
   accessors return ``None`` even when telemetry is off.

``request_metrics()``
   Return a dict of timing and resource counters for the sample
   interval since the last call. Useful for emitting per-request
   observability data from the application. Returns ``None`` if
   ``start_recording_metrics()`` has not been called or if external
   telemetry reporting is enabled.

``process_metrics()``
   Return a dict of process-level aggregates: served-request
   count, request busy time, current and peak resident memory,
   CPU user and system time, current active-request count, and
   similar counters covering the lifetime of the process. Returns
   ``None`` under the same conditions as ``request_metrics()``.

``server_metrics()``
   Return a dict reflecting the Apache scoreboard view of the
   server: per-process and per-worker state, total requests
   served, bytes transferred, and similar server-wide aggregates.
   The data is gated by configuration; see
   :doc:`../configuration-directives/WSGIServerMetrics` for the
   embedded-mode gate and ``WSGIDaemonProcess`` for the daemon-mode
   gate.

Types
-----

``FileWrapper``
   A callable that wraps a file-like object so the WSGI adapter
   can return its contents using ``sendfile()`` or equivalent
   optimisations. The same callable is also exposed in the WSGI
   environment under the key ``wsgi.file_wrapper``. See
   :doc:`file-wrapper-extension`.

``RequestTimeout``
   An exception class derived directly from ``BaseException``,
   raised in a daemon-process worker thread when the configured
   ``request-timeout=`` is exceeded and the daemon monitor injects
   a timeout into the worker. Deriving from ``BaseException`` (not
   ``Exception``) means well-written code does not accidentally
   catch it via ``except Exception:``. Application code may catch
   it for per-request cleanup but should re-raise so the WSGI
   adapter can return ``504``. See
   :doc:`../configuration-directives/WSGIDaemonProcess` for
   ``request-timeout=`` semantics.

Companion ``apache`` module
---------------------------

Alongside ``mod_wsgi``, mod_wsgi installs an ``apache`` module
into ``sys.modules`` carrying introspection attributes about the
Apache server hosting the application. Application code can
``import apache`` to inspect the server configuration; the module
is available in both embedded and daemon mode.

``version``
   Apache server version as a ``(major, minor, patchlevel)``
   tuple, distinct from ``mod_wsgi.version`` (which is the
   mod_wsgi extension version).

``maximum_processes``
   Maximum number of processes hosting interpreters. Same value
   as ``mod_wsgi.maximum_processes``.

``threads_per_process``
   Maximum number of worker threads per process. Same value as
   ``mod_wsgi.threads_per_process``.

``description``
   The Apache server description string, as returned by
   ``ap_get_server_description()``, e.g. ``"Apache/2.4.58 (Unix)"``.

``mpm_name``
   The name of the active Apache MPM, e.g. ``"event"``,
   ``"worker"`` or ``"prefork"``.

``build_date``
   The date on which the running Apache binary was built.

WSGI environ keys
-----------------

The WSGI ``environ`` dict passed to the application has the
standard WSGI keys plus mod_wsgi-specific keys mirroring the
module attributes and adding per-request information.

``mod_wsgi.version``
   ``(major, minor, micro)`` tuple, same value as the module-level
   ``version``. Reliable runtime test that the request is being
   served by Apache/mod_wsgi.

``mod_wsgi.process_group``
   Same value as the module-level ``process_group``.

``mod_wsgi.application_group``
   Same value as the module-level ``application_group``.

``mod_wsgi.request_id``
   The Apache request log ID — the same identifier substituted by
   ``%L`` in ``LogFormat`` and ``ErrorLogFormat``. Useful for
   cross-correlating application data with Apache's access and
   error logs. Same value as the ``request_id`` field on the
   request events.

``mod_wsgi.connection_id``
   The Apache connection log ID, set when Apache has generated
   one for the underlying connection.

``mod_wsgi.thread_id``
   Numeric ID of the worker thread handling this request.

``mod_wsgi.server_pid``
   Process ID of the Apache child worker that accepted the
   request, as a decimal string. In embedded mode this is the
   process the WSGI application is running in; in daemon mode it
   is the originating Apache child, distinct from the daemon
   process serving the request (the daemon's own PID is
   available via ``os.getpid()``).

The four request-timing keys below are Python ``float`` values
in seconds since the epoch. They carry the same instants as the
identically-named fields on the ``request_started`` and
``request_finished`` event payloads.

``mod_wsgi.request_start``
   Time Apache received the request.

``mod_wsgi.queue_start``
   Time Apache wrote the request onto the daemon socket. ``0.0``
   in embedded mode (no queue phase).

``mod_wsgi.daemon_start``
   Time the daemon process accepted the request and began
   handling it. ``0.0`` in embedded mode.

``mod_wsgi.application_start``
   Time the worker thread was about to invoke the WSGI
   application callable for this request.

WSGI script ``__name__``
------------------------

mod_wsgi imports each WSGI script file as if it were a module, but
because WSGI scripts can live anywhere on disk and not on
``sys.path``, the imported name is synthesised from a hash of the
script path with the prefix ``_mod_wsgi_``. A WSGI script can
detect that it is being loaded by mod_wsgi (rather than executed
directly) with::

    if __name__.startswith('_mod_wsgi_'):
        ...

See :doc:`detecting-mod-wsgi` for other reliable ways to detect
the mod_wsgi runtime.
