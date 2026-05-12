==========================
The Internal Metrics API
==========================

The ``mod_wsgi`` built-in module exposes four functions that let a
WSGI application observe its own runtime and ship the resulting
samples to an external metrics service of its choosing. This page
covers their behaviour, the data each one returns, and a worked
example of using them to feed a time-series database without
impacting request-serving performance.

The four functions are:

``mod_wsgi.start_recording_metrics()``
   Opt in to per-request metrics accounting.

``mod_wsgi.request_metrics()``
   Drain a per-interval snapshot of timing, capacity and resource
   counters for the current process.

``mod_wsgi.process_metrics()``
   Read process-level aggregates and current state.

``mod_wsgi.server_metrics()``
   Read the Apache scoreboard view of every process and worker on
   the server.

``request_metrics()`` and ``process_metrics()`` return data only
after ``start_recording_metrics()`` has been called, and only when
no external reporter is configured to consume the same data;
``server_metrics()`` has its own configuration gate. Each accessor
returns ``None`` rather than raising when it is not active, so
caller code can branch on a single check.

Enabling per-request recording
------------------------------

``start_recording_metrics()``
   Enable per-request accounting and seed the per-reader baselines
   so the first subsequent call to ``request_metrics()`` returns a
   populated dict covering the interval since this call ran.
   Idempotent: extra calls have no effect.

   Per-request accounting has a small but non-zero cost (a locked
   accumulator update on each request completion). Applications
   that never consume the data should not call this function; an
   application that does want the data should call it once at
   import time before the reporter thread or other consumer
   starts.

   When an external reporter is configured for the process, that
   reporter is the canonical metrics consumer and the Python
   accessors below return ``None`` regardless of whether this
   function has been called. An application's reporter code can
   detect this with a single ``None`` check on ``request_metrics()``
   and stand down.

request_metrics() : per-interval drain
--------------------------------------

``request_metrics()``
   Return a dict of metrics for the interval since the previous
   call to this function, then drain the underlying accumulators
   so the next call covers a fresh interval.

The drain is the important detail: each call empties the
per-interval state. That has two consequences for callers:

* Only one component in the process should call
  ``request_metrics()``. Concurrent callers would each see a
  partial interval. The expected pattern is a single background
  reporter thread on a fixed cadence.
* Do not call ``request_metrics()`` from inside the WSGI
  application callable. Apart from the drain-clash, the call
  briefly takes a process-wide lock that worker threads also
  need; do the work on a thread that does not serve requests.

The first call after ``start_recording_metrics()`` returns
samples covering the time since recording was enabled. The
function returns ``None`` if ``start_recording_metrics()`` has
not been called or if an external reporter is the configured
consumer.

Sample window
~~~~~~~~~~~~~

``pid``
   Process ID of the calling process. Useful as an additional tag
   when shipping samples from multiple processes to a shared store.

``start_time``
   Window start as a floating-point second offset from the Unix
   epoch. This is the ``stop_time`` of the previous call (or the
   time recording was enabled, on the first call).

``stop_time``
   Window end as a floating-point second offset from the Unix
   epoch.

``sample_period``
   ``stop_time - start_time`` in seconds.

Request volume
~~~~~~~~~~~~~~

``request_count``
   Number of requests that completed during the window.

``request_throughput``
   ``request_count / sample_period``; requests per second.

Capacity
~~~~~~~~

``request_threads_maximum``
   The configured worker-thread ceiling for the process: the
   ``threads=`` value on ``WSGIDaemonProcess`` in daemon mode, or
   the MPM-derived per-process thread limit in embedded mode.

``request_threads_started``
   Number of worker threads actually instantiated so far. Apache
   may spin worker threads up lazily; this is the running total.

``request_threads_active``
   Number of worker threads that either completed a request or
   were mid-request when the window ended.

``capacity_utilization``
   Fraction of worker capacity consumed during the window,
   computed as total busy time across all worker slots divided by
   ``sample_period * request_threads_maximum``. A value near 1.0
   means every worker spent the whole window in a request and the
   process has no spare capacity; a value near 0.0 means the
   workers were mostly idle.

``request_threads_completed``
   List of length ``request_threads_maximum``. Entry *i* is the
   number of requests worker slot *i + 1* completed during the
   window. Useful for detecting uneven distribution of work
   across worker threads. The deprecated alias
   ``request_threads_buckets`` carries the same value and will be
   removed in a future release.

``request_threads_busy_time``
   List of length ``request_threads_maximum``, float seconds.
   Entry *i* is the total time worker slot *i + 1* spent inside
   a request during the window, including any in-flight tail at
   drain time.

``request_threads_cpu_time``
   List of length ``request_threads_maximum``, float seconds.
   Sum of per-request CPU deltas for requests that completed
   in this slot during the window. Each completing request
   contributes its full start-to-end CPU delta, regardless of
   how many earlier windows the request spanned: a long
   request appears as a CPU spike in the single window in
   which it completes, not spread across the windows it
   occupied. This is asymmetric with ``request_threads_busy_time``,
   which folds in the in-flight wall-time tail at each
   window; the asymmetry is structural, because a worker
   thread's CPU usage is only readable from inside that
   thread, so the snapshot reader cannot sample a peer
   thread's in-flight CPU.

``request_threads_current_elapsed``
   List of length ``request_threads_maximum``, float seconds.
   Entry *i* is the elapsed wall time of any request still in
   flight in slot *i + 1* at the drain instant, or 0.0 if the
   slot was idle. Useful for spotting stuck requests on a live
   process.

``request_threads_max_duration``
   List of length ``request_threads_maximum``, float seconds.
   The longest request duration each slot completed during the
   window.

Phase timing means
~~~~~~~~~~~~~~~~~~

Each phase mean is the total time recorded across all completed
requests in the window divided by ``request_count``. Phases
overlap in places (``application_time`` is part of
``request_time``, for example) so the means do not add up to the
request total.

``server_time``
   Average time, in seconds, between Apache accepting the request
   and the WSGI handler returning to Apache.

``queue_time``
   Daemon mode only. Average time the request spent travelling
   from the Apache worker process to the daemon process, in
   seconds. ``None`` in embedded mode.

``daemon_time``
   Daemon mode only. Average time inside the daemon process from
   accepting the dispatched request to the application callable
   returning, in seconds. ``None`` in embedded mode.

``application_time``
   Average time spent inside the WSGI application callable, in
   seconds.

``request_time``
   Average end-to-end time, in seconds, covering acceptance by
   Apache through to the response being fully written back to the
   client.

``input_read_time``
   Average time spent reading the request body, in seconds. Zero
   for requests with no body.

``output_write_time``
   Average time spent writing response bytes to the client, in
   seconds.

Phase timing extremes
~~~~~~~~~~~~~~~~~~~~~

For each phase listed above there is a matching pair of integer
microsecond fields giving the smallest and largest observation
recorded during the window. Both keys are ``None`` if the phase
saw no requests in the window (and the daemon-only phases are
``None`` in embedded mode regardless).

``server_time_min_us`` / ``server_time_max_us``

``queue_time_min_us`` / ``queue_time_max_us``

``daemon_time_min_us`` / ``daemon_time_max_us``

``application_time_min_us`` / ``application_time_max_us``

``request_time_min_us`` / ``request_time_max_us``

``input_read_time_min_us`` / ``input_read_time_max_us``

``output_write_time_min_us`` / ``output_write_time_max_us``

Phase timing histograms
~~~~~~~~~~~~~~~~~~~~~~~

Each of the following keys carries a list of 65 integer counts
representing the distribution of per-request durations across
fixed boundaries. The first 64 entries cover 16 octaves from 1 ms
up to 65536 ms, split linearly into 4 sub-buckets per octave; the
final entry counts samples at or above 65536 ms (~65 s). Values
below 1 ms land in entry 0.

``server_time_buckets``

``queue_time_buckets``

``daemon_time_buckets``

``application_time_buckets``

``request_time_buckets``

``input_read_time_buckets``

``output_write_time_buckets``

``gil_wait_time_buckets``

GIL contention
~~~~~~~~~~~~~~

``gil_wait_time``
   Average time per request spent waiting to re-acquire the GIL
   at the boundaries where mod_wsgi releases it on the
   application's behalf: acquiring the interpreter at the start
   of the request, and re-acquiring the GIL after reading
   request body bytes, after flushing response headers, and
   after writing response body bytes. Useful as an indication
   of contention between mod_wsgi's worker threads serving
   concurrent requests in the same process. GIL contention
   inside the WSGI application itself (for example between
   Python-level threads the application spawns) is not measured.

``gil_wait_time_min_us`` / ``gil_wait_time_max_us``
   Smallest and largest single GIL-wait recorded during the
   window, in microseconds, or ``None`` if no waits were
   recorded.

``gil_wait_count``
   Total number of GIL re-acquire events recorded during the
   window across all requests. Dividing ``gil_wait_time`` by this
   count gives mean wait per acquire.

I/O totals
~~~~~~~~~~

``input_bytes``
   Total request-body bytes read across all completed requests in
   the window.

``input_reads``
   Total number of read operations against request bodies in the
   window.

``output_bytes``
   Total response bytes written to clients in the window.

``output_writes``
   Total number of write operations against response sockets in
   the window.

Response classes
~~~~~~~~~~~~~~~~

Per-class HTTP response counts for completed requests in the
window. The five counters always sum to ``request_count``;
requests that never called ``start_response`` are folded into
``status_5xx``.

``status_1xx``, ``status_2xx``, ``status_3xx``, ``status_4xx``,
``status_5xx``

CPU rates
~~~~~~~~~

Each rate is the corresponding CPU delta divided by
``sample_period``, so a value of 1.0 represents one CPU-second of
work per wall-clock second (one core fully loaded). Values can
exceed 1.0 on multi-core hosts when several worker threads run
CPU-bound work in parallel.

``cpu_user_utilization``
   User-mode CPU rate for the process.

``cpu_system_utilization``
   Kernel-mode CPU rate for the process.

``cpu_utilization``
   ``cpu_user_utilization + cpu_system_utilization``.

The keys ``cpu_user_time``, ``cpu_system_time`` and ``cpu_time``
are deprecated aliases for the three keys above, carrying the
same per-window rate values. They are retained for backwards
compatibility but should not be used in new code: their names
collide with identically-named keys in ``process_metrics()``
that carry cumulative CPU-time totals in seconds, very different
quantities with the same labels. New code should use the
``_utilization`` keys.

Memory
~~~~~~

``memory_rss``
   Current resident set size of the process, in bytes.

``memory_max_rss``
   Peak resident set size of the process so far, in bytes.

These two values are point-in-time at the moment the snapshot
runs, not interval-derived. The same two keys appear under
``process_metrics()`` below, sourced from the same calls and
carrying identical values; they are duplicated here so a
periodic reporter built around ``request_metrics()`` has memory
context attached to every sample without needing a second
function call.

process_metrics() : process aggregates and current state
--------------------------------------------------------

``process_metrics()``
   Return a dict describing the process from start-up to the
   present moment. Unlike ``request_metrics()``, this accessor
   does not drain anything; values are cumulative or
   point-in-time, not per-interval.

Returns ``None`` under the same conditions as
``request_metrics()``: when ``start_recording_metrics()`` has not
been called, or when an external reporter is the configured
consumer.

``pid``
   Process ID.

``restart_time``
   Process start time as seconds since the Unix epoch.

``current_time``
   Wall-clock time at the moment of the call, in seconds since the
   epoch. Convenient for computing process-uptime client-side
   without a second clock read.

``running_time``
   ``current_time - restart_time``, as an integer second count.

``request_count``
   Total number of requests this process has served since start
   up.

``request_busy_time``
   Total cumulative time, in seconds, that worker threads spent
   inside requests. The fraction
   ``request_busy_time / (running_time * request_threads_maximum)``
   gives a process-lifetime equivalent of
   ``capacity_utilization``.

``request_threads``
   Same as ``request_threads_started`` from ``request_metrics()``:
   number of worker threads instantiated so far.

``active_requests``
   Number of requests currently in flight at the moment of the
   call.

``cpu_user_time``
   Cumulative user-mode CPU time the process has consumed since
   start-up, in seconds.

``cpu_system_time``
   Cumulative kernel-mode CPU time, in seconds.

``cpu_time``
   ``cpu_user_time + cpu_system_time``.

The three CPU keys here are lifetime totals in seconds. The
identically-named (deprecated) keys in ``request_metrics()``
carry per-window utilisation rates, not absolute totals. Code
that reads CPU values from both accessors needs to handle the
two unit systems separately; new code reading rates should
prefer the ``_utilization`` keys on ``request_metrics()``.

``memory_rss``
   Current resident set size in bytes.

``memory_max_rss``
   Peak resident set size in bytes.

Same values as the matching keys in ``request_metrics()``;
sourced from the same calls and duplicated across the two
accessors for convenience.

``threads``
   List of per-worker-thread dicts. Each entry has two keys:

   ``thread_id``
      Worker-thread identifier (1-based).

   ``request_count``
      Number of requests this worker thread has served since
      start-up.

server_metrics() : Apache scoreboard view
-----------------------------------------

``server_metrics()``
   Return a dict reflecting the Apache scoreboard: every process,
   every worker thread, what each is currently doing, and totals
   accumulated since the server started.

Unlike the previous two accessors, ``server_metrics()`` does not
require ``start_recording_metrics()``. It is gated separately by
configuration: see
:doc:`../configuration-directives/WSGIServerMetrics` for the
embedded-mode gate, and the ``server-metrics=`` option on
:doc:`../configuration-directives/WSGIDaemonProcess` for the
daemon-mode gate. Returns ``None`` when the scoreboard is not
available or the gate is off.

The dict has top-level fields covering the server, followed by a
``processes`` list of process dicts, each of which has a
``workers`` list of worker dicts.

Server level
~~~~~~~~~~~~

``server_limit``
   Configured upper bound on number of processes the active MPM
   may run.

``thread_limit``
   Configured upper bound on number of worker threads per process.

``running_generation``
   Generation counter for the active server. Increments on each
   graceful restart.

``restart_time``
   Time of the most recent (re)start, in seconds since the Unix
   epoch.

``current_time``
   Wall-clock time at the moment of the call, in seconds since the
   epoch.

``running_time``
   ``current_time - restart_time``, in integer seconds.

``processes``
   List of process dicts (see below).

Per-process
~~~~~~~~~~~

``process_num``
   Index of this entry in the scoreboard process table.

``pid``
   Process ID of the worker process, or 0 if the slot is unused.

``generation``
   Generation in which this process was spawned.

``quiescing``
   ``True`` if the process is gracefully shutting down (no longer
   accepting new requests), ``False`` otherwise.

``workers``
   List of worker dicts.

Per-worker
~~~~~~~~~~

``thread_num``
   Index of this worker thread within the process.

``generation``
   Generation in which this worker was created.

``status``
   A single-character string describing the current state of the
   worker (``_`` waiting for connection, ``R`` reading request,
   ``W`` writing reply, ``K`` keepalive, ``G`` gracefully
   finishing, and so on). The same letters Apache uses in its
   ``mod_status`` output.

``access_count``
   Number of requests this worker has served since the process
   started.

``bytes_served``
   Total response bytes the worker has written to clients.

``start_time``
   Time the worker last began processing a request, in seconds
   since the epoch.

``stop_time``
   Time the worker last finished processing a request, in seconds
   since the epoch.

``last_used``
   Time of the last activity on the worker, in seconds since the
   epoch.

``client``
   IP address of the client whose request the worker last handled.

``request``
   First line of the most recent request handled by the worker,
   truncated by Apache to a fixed buffer.

``vhost``
   Server name of the virtual host the most recent request was
   served against.

Reporting metrics to an external service
----------------------------------------

The shape of an in-application reporter is:

1. Call ``start_recording_metrics()`` so the accessors have data
   to return.
2. Start a single background thread that wakes on a fixed
   cadence, calls ``request_metrics()`` (and, if useful,
   ``process_metrics()`` or ``server_metrics()``), formats the
   sample for the destination, and writes it.
3. Subscribe to the ``process_stopping`` event so the reporter
   thread can flush a final sample and exit cleanly when the
   process is shutting down.

The example below feeds ``request_throughput`` and
``capacity_utilization`` to an InfluxDB instance every second.
The full set of attributes is documented above; restricting the
example to two of them keeps the moving parts visible.

The application file does nothing except wire up the reporter:

.. code-block:: python

    import metrics

    metrics.enable_reporting()

    def application(environ, start_response):
        status = '200 OK'
        output = b'Hello World!'

        response_headers = [
            ('Content-type', 'text/plain'),
            ('Content-Length', str(len(output))),
        ]
        start_response(status, response_headers)

        return [output]

The companion ``metrics`` module does the work:

.. code-block:: python

    import os
    import socket
    import time
    import traceback
    import urllib.request

    from queue import Queue, Empty
    from threading import Thread

    import mod_wsgi

    HOSTNAME = socket.gethostname()
    PID = os.getpid()
    PROCESS = f"{HOSTNAME}:{PID}"

    INTERVAL = 1.0
    INFLUXDB_URL = "http://influxdb.local:8086/write?db=wsgi"

    queue = Queue()

    def format_line(metrics, timestamp_ns):
        """Build an InfluxDB line-protocol record.

        Line protocol is plain ASCII; assembling it is a couple of
        f-strings. JSON marshalling and the dict-of-dicts the JSON
        clients want is far more expensive at sub-second cadence,
        so we format the wire bytes directly.
        """
        return (
            f"request-metrics,hostname={HOSTNAME},process={PROCESS} "
            f"request_throughput={metrics['request_throughput']},"
            f"capacity_utilization={metrics['capacity_utilization']} "
            f"{timestamp_ns}"
        )

    def write_to_influxdb(payload):
        request = urllib.request.Request(
            INFLUXDB_URL, data=payload.encode("ascii"), method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=2.0):
                pass
        except Exception:
            traceback.print_exc()

    def report_once():
        metrics = mod_wsgi.request_metrics()
        if metrics is None:
            return
        timestamp_ns = int(metrics["stop_time"] * 1_000_000_000)
        write_to_influxdb(format_line(metrics, timestamp_ns))

    def collector():
        next_tick = time.time() + INTERVAL
        while True:
            timeout = max(0.0, next_tick - time.time())
            try:
                queue.get(timeout=timeout)
            except Empty:
                report_once()
                next_tick += INTERVAL
                continue
            # Sentinel from the shutdown handler: flush and exit.
            report_once()
            return

    # daemon=False so process_stopping can join us cleanly, and so
    # the module is also usable inside a per-interpreter-GIL sub
    # interpreter (where daemon threads are not permitted).
    thread = Thread(target=collector, daemon=False)

    def shutdown_handler(name, **kwargs):
        queue.put(None)

    _started = False

    def enable_reporting():
        # Guard against double activation: in embedded mode a
        # modified wsgi.py is reloaded in the same process, which
        # re-runs the wsgi.py top-level import-and-call. The
        # second call would otherwise hit Thread.start() on the
        # already-running thread and raise RuntimeError.
        global _started
        if _started:
            return
        _started = True

        mod_wsgi.start_recording_metrics()
        mod_wsgi.subscribe_shutdown(shutdown_handler)
        thread.start()

The shape is almost identical to a plain "background reporter
thread" pattern in any other application. The mod_wsgi-specific
parts are the three function calls inside ``enable_reporting()``:
``start_recording_metrics()`` so the accessor returns data,
``request_metrics()`` inside the loop to read it, and
``subscribe_shutdown()`` so the thread is signalled at process
shutdown rather than being killed mid-write.

Hosting the reporter in a dedicated sub-interpreter
---------------------------------------------------

The worked example above runs the reporter from inside the same
sub-interpreter that hosts the WSGI application: ``wsgi.py``
imports the ``metrics`` module and calls ``enable_reporting()``
at import time. That is the simplest deployment but couples the
two concerns: the reporter module is visible to application
code, and the one-consumer-per-process rule rests on the
application never accidentally calling ``request_metrics()``
itself.

A cleaner option in daemon mode is to put the reporter in its
own sub-interpreter, separate from the WSGI application's
sub-interpreter but in the same daemon process. Per-process
metrics state is process-wide and shared across every
sub-interpreter in the process, so a reporter running in one
sub-interpreter sees the data produced by requests served in
another. Isolation makes the one-consumer rule structural
rather than a discipline the application has to maintain.

The mechanism is
:doc:`../configuration-directives/WSGIImportScript`, configured
to import a small launcher into the same ``process-group=`` as
the WSGI application but a distinct ``application-group=``. Add
a ``reporter.py`` next to ``metrics.py`` whose only job is to
import the metrics module and trigger it::

    import metrics

    metrics.enable_reporting()

Then point ``WSGIImportScript`` at ``reporter.py``::

    WSGIDaemonProcess myapp threads=15 \
        python-path=/var/www/myapp
    WSGIScriptAlias / /var/www/myapp/wsgi.py \
        process-group=myapp \
        application-group=%{GLOBAL}
    WSGIImportScript /var/www/myapp/reporter.py \
        process-group=myapp \
        application-group=metrics

The ``python-path=`` option puts ``/var/www/myapp`` on
``sys.path`` for the daemon process so that ``reporter.py``'s
``import metrics`` can find the module next to it. Without it
``WSGIImportScript`` would run ``reporter.py`` as a top-level
file but ``import metrics`` would not resolve. ``WSGIImportScript``
runs ``reporter.py`` at daemon startup, the ``import metrics``
line pulls the module in, and ``enable_reporting()`` does its
three calls before the first request arrives. ``wsgi.py`` no longer imports the ``metrics``
module and no longer references ``enable_reporting()``; the
WSGI application file becomes whatever it would have been
without metrics reporting at all. ``metrics.py`` is unchanged
from the worked example above.

Keeping the launcher in its own file rather than activating
from the bottom of ``metrics.py`` itself preserves the
no-import-side-effect property of the metrics module, which
matters if anything else (a test harness, a one-off script,
``WSGIImportScript`` loaded in a different application group
for some reason) ever imports it.

Two consequences worth flagging:

* Each sub-interpreter has its own ``mod_wsgi`` module object
  and its own set of event subscribers. The
  ``subscribe_shutdown`` callback registered in the metrics
  sub-interpreter only fires for events published into that
  sub-interpreter. ``process_stopping`` is published to every
  sub-interpreter in the daemon process, so the reporter is
  notified at the right moment to drain a final sample and
  stop its thread.
* The reporter script and the WSGI application should not
  import each other. Sub-interpreters do not share Python
  module state, and crossing the boundary either duplicates
  state or, with C extensions that are not sub-interpreter
  safe, fails outright. The split is precisely the point of
  this deployment.

Keeping reporting off the hot path
----------------------------------

The point of the design above is that worker threads serving
requests pay almost nothing for the reporter. Things that matter:

* Drain on a dedicated thread, never from inside the WSGI
  application callable. ``request_metrics()`` is a per-interval
  drain: every call empties the accumulators. A worker thread
  that called it during a request would consume the data the
  reporter thread expected to ship, and concurrent callers
  would each end up with partial windows. The one-consumer
  pattern is what keeps each shipped sample a coherent snapshot.
* Pick an aggregation interval long enough that the per-tick
  cost (one ``request_metrics()`` call, one wire write) is
  negligible against the per-request work the process is doing.
  One second is a reasonable default; sub-second cadences are
  possible but rarely useful.
* Pre-encode in a compact wire format and write it as bytes.
  Line protocol, OpenMetrics text exposition, StatsD packets and
  similar formats are cheap to assemble from primitive values.
  JSON marshalling, especially via a third-party metrics-store
  client, is much more expensive per sample and unnecessary when
  the wire format is straightforward.
* Buffer the write locally and use a short timeout. If the
  destination is unreachable, only the reporter thread blocks;
  worker threads continue to serve requests, and the next tick
  gets a chance to recover.
* Use ``mod_wsgi.subscribe_shutdown`` to signal the reporter
  thread, not ``atexit``. The ``process_stopping`` event fires
  before Python's interpreter finalisation begins, while there
  is still time to put the sentinel on the queue. ``atexit``
  callbacks run as part of finalisation, *after* the runtime
  has already joined every non-daemon thread; a non-daemon
  reporter thread waiting on a queue would never be signalled
  and the process would hang.
* Create the reporter thread with ``daemon=False`` and rely on
  the shutdown handler to stop it. Non-daemon threads also let
  the same code run unchanged inside a sub-interpreter that
  owns its own GIL, where daemon threads are not permitted.
* One reporter per process, one set of accumulators per process.
  If the process hosts multiple sub-interpreters, only one of
  them should call ``start_recording_metrics()`` and run a
  reporter, because the accumulators are shared and a second
  caller would drain a partial window from the first.

See also
--------

* :doc:`subscribing-to-events`: full reference for the
  ``subscribe_events`` / ``subscribe_shutdown`` API the example
  above uses to signal the reporter thread at process shutdown.
* :doc:`registering-cleanup-code`: broader patterns for
  end-of-request and end-of-process cleanup.
* :doc:`mod-wsgi-python-module`: short reference summary of the
  ``mod_wsgi`` built-in module, including the metrics accessors.
* :doc:`../configuration-directives/WSGIServerMetrics`: enables
  the Apache scoreboard so ``server_metrics()`` returns data in
  embedded mode.
* :doc:`../configuration-directives/WSGIDaemonProcess`: the
  ``server-metrics=`` option enables the scoreboard for a daemon
  process group.
