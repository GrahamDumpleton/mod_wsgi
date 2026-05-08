=============================
Request Pipeline And Timeouts
=============================

A request handled by mod_wsgi traverses several stages between
arriving at Apache and reaching the WSGI application. Each
stage has its own timeout knob, its own failure mode, and its
own recovery flow. This page walks the pipeline so each
timeout lands in context, then covers the recovery flows when
one fires.

The :doc:`daemon-mode` guide is the structural companion: it
covers process and thread sizing, recycling triggers, and the
process-group patterns that this page builds on. Read that
page first if the daemon-mode model is unfamiliar.

The timeout options split into three groups:

* **Transport.** ``connect-timeout``, ``queue-timeout``,
  ``socket-timeout``, ``response-socket-timeout``. These
  govern the boundary between the Apache child process and
  the daemon process, and between the Apache child and the
  HTTP client.
* **Application fail-safe.** ``request-timeout``,
  ``interrupt-timeout``, ``deadlock-timeout``. These detect
  when the WSGI application has stopped making progress and
  trigger recovery.
* **Lifecycle.** ``startup-timeout``, ``inactivity-timeout``,
  ``graceful-timeout``, ``eviction-timeout``,
  ``shutdown-timeout``. These govern the daemon process's
  own lifecycle: startup, idle recycling, drain on restart,
  and hard cutoff on shutdown.

The full reference for each option is on the
:doc:`../configuration-directives/WSGIDaemonProcess` page;
this guide covers the model and the interactions.

The request pipeline (daemon mode)
----------------------------------

What follows is the path a single request takes from arrival
at Apache through to the WSGI application and back. Each
stage calls out the timeout knobs that apply to it.

Embedded mode is structurally different (no socket hop, no
daemon-side queue, no per-process recycle) and is described
in its own section after the daemon-mode walkthrough.

Apache accept and request parsing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The request first hits Apache. Apache's own ``Timeout`` and
``KeepAliveTimeout`` directives govern this stage: how long
Apache will wait for headers, body, or the next keep-alive
request on a connection. These are Apache concerns rather
than mod_wsgi concerns and are out of scope for this page;
consult the Apache HTTP Server documentation for the per-MPM
behaviour.

Once Apache has parsed the request and decided to dispatch it
through mod_wsgi (matching a ``WSGIScriptAlias`` or a
``SetHandler wsgi-script``), the mod_wsgi handler is invoked
inside the Apache child worker process.

Auth scripts and ``WSGIDispatchScript``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If ``WSGIAuthUserScript``, ``WSGIAuthGroupScript``,
``WSGIAccessScript``, or ``WSGIDispatchScript`` is configured,
the corresponding script runs inside the Apache child process,
in an embedded Python interpreter, *before* the request is
delegated to the daemon. This is independent of whether the
WSGI application itself runs embedded or in a daemon process
group.

``WSGIDispatchScript`` is the more consequential one for the
pipeline: its ``process_group(environ)`` callable is what
determines which daemon process group the request is
delegated to. Its ``application_group(environ)`` and
``callable_object(environ)`` callables similarly override the
sub interpreter and entry point on a per-request basis. See
:doc:`../configuration-directives/WSGIDispatchScript` for the
directive reference.

These embedded-mode scripts have no dedicated timeout. They
run under whatever request-handling envelope Apache itself
applies (``Timeout``), bounded only by Apache's own request
processing.

Apache child connects to the daemon listener
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once routing is settled and the request is bound for a daemon
process group, the Apache child connects to that group's UNIX
domain listener socket.

A daemon process group has a single listener socket shared by
all the daemon processes in the group. The kernel
load-balances connection acceptance across whichever daemon
processes have idle worker capacity.

If the kernel listen queue is full (``listen-backlog``
exceeded) the connect will fail. mod_wsgi retries with
backoff, starting at fractional-second intervals and
stretching out to one-second intervals after a couple of
seconds of accumulated wait. The overall budget for retries
is ``connect-timeout`` (default 15 seconds). On exhaustion
the request is failed with HTTP 503.

A connect that fails for permission or filesystem reasons
(the socket file does not exist, the Apache child user
cannot traverse to its directory) also fails immediately
with HTTP 503 and an error logged. This is most often a
``WSGISocketPrefix`` configuration issue; see
:doc:`../configuration-directives/WSGISocketPrefix`.

``connect-timeout`` is the only knob that applies at this
stage.

Waiting for a daemon worker to pick up the request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the Apache child has connected to the daemon process
group's listener socket, the connection sits in the kernel's
listen-backlog queue until a daemon worker thread is free to
``accept()`` it. A daemon process only accepts a new
connection when it has an idle worker thread ready to handle
it; if every worker thread across every process in the group
is busy, incoming connections accumulate in the kernel listen
queue.

``queue-timeout`` is not enforced while the request is
waiting. No mod_wsgi code is running on the request while
it sits in the kernel listen queue, so nothing fires a
timer to abandon it: the Apache child is blocked reading
the response from the daemon, and from the client's
perspective the request is simply slow.

The check happens later, at the moment a worker thread
finally accepts the connection and reads the request
envelope. The envelope carries the timestamp at which the
Apache child first wrote it; the worker compares that
against the current time. If the wait exceeds
``queue-timeout``, the worker discards the request without
dispatching it to the WSGI application and HTTP 504 is
returned to the client.

The effect is load-shedding on pickup. Under overload, when
workers free up to work through the backlog, anything that
has been waiting longer than ``queue-timeout`` is dropped
rather than served, so workers spend their time on fresh
work rather than on requests whose clients have likely
already given up. A request can sit in the queue for
considerably longer than ``queue-timeout`` before being
abandoned, since the discard fires at pickup rather than at
the timeout instant.

``listen-backlog`` (default 100) caps the kernel-level
queue of unaccepted connections waiting on the listener
socket. Under sustained overload it fills first, after
which further connection attempts start failing at the
kernel and the Apache child falls into
``connect-timeout``-bounded retries. ``queue-timeout`` and
``listen-backlog`` work together: the backlog provides the
buffer, and the timeout decides which work is still worth
serving when worker capacity returns.

Daemon worker reads the request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once a daemon worker thread is handling the connection, it
reads the request envelope (headers and body) over the
socket from the Apache child. Each individual read or write
on this socket is bounded by ``socket-timeout``, which falls
back to Apache's ``Timeout`` directive when not set
explicitly.

This timeout exists to bound the time a daemon worker
spends waiting on a slow Apache child (or a misbehaving
connection) during the request hand-off. It is a per-syscall
timeout, not a total-request timeout.

WSGI script reload during a request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``WSGIScriptReloading`` is on (the default), each
daemon worker checks the WSGI script file's modification
time on every request dispatch. If the file has changed
since the daemon loaded it, the daemon does not serve the
request: it rejects it back to the Apache child and
initiates its own restart so it can reload the script from
disk.

The Apache child treats the rejection as a signal to close
the socket and reconnect. The reconnect lands on whichever
daemon process in the pool is ready to accept; the kernel
load-balances among them. In a multi-process pool, each
old daemon needs only the first request after the script
change to trigger its own restart, so concurrent requests
share the work: while this request is reconnecting,
sibling requests in flight may already have triggered some
of the other daemons' restarts. A given request does not
necessarily walk the whole pool. The Apache child
reconnects until its request lands on a process that has
finished reloading.

Reconnect attempts are bounded by a retry cap proportional
to the pool size: roughly ``2 * processes + 1`` attempts.
In practice this cap is never hit by reload-driven
restarts because the restart cycle completes before the
cap is exhausted. Each reconnect goes through the full
``connect-timeout`` window, so the worst-case total
reconnect wait is roughly ``connect-timeout * retry-cap``;
the kernel load-balance and the speed of the actual
restart keep this much shorter in practice.

No operator-visible timeout knob governs the reload-driven
reconnect. Setting ``WSGIScriptReloading Off`` disables the
modification check and removes the mechanism entirely; with
it disabled, the daemon runs the script as loaded at
process startup until some other trigger recycles the
process. See :doc:`reloading-source-code` for the broader
reload model.

WSGI application runs
~~~~~~~~~~~~~~~~~~~~~

Once the request is in the daemon worker thread, the worker
calls into the WSGI application. This is where most of the
useful work happens, and where the application fail-safe
timeouts apply.

``request-timeout`` is a per-thread upper bound on how long a
single request can spend running before mod_wsgi treats it
as wedged and triggers recovery. Defaults to 0 (disabled).
The fire point is not the configured value directly; it
scales with ``threads`` by natural log:

.. code-block:: text

    T_fire = request-timeout * (1 + ln(threads))

At ``threads=1`` this collapses to ``request-timeout``. At
``threads=10`` it is approximately 3.3x; at ``threads=25``
approximately 4.2x. The intent is to grant proportionally
more patience as parallel capacity grows: a wedge in 1-of-10
threads costs less than a wedge in 1-of-1, so the threshold
should grow with pool size, but only sub-linearly.

Each thread is judged independently against this threshold.
Multiple wedged threads are detected on the same schedule a
single wedge would be.

``request-timeout`` is a *fail-safe*, not a per-request SLA
mechanism. See :ref:`request-timeout-not-sla` below for the
distinction and the right tool for user-visible deadlines.

What happens when ``request-timeout`` fires depends on
``interrupt-timeout``, covered in the recovery-flow section
below.

C extension wedges the GIL
~~~~~~~~~~~~~~~~~~~~~~~~~~

A separate failure mode from a wedged request is a wedged
*interpreter*. If a Python C extension fails to release the
GIL inside a long-running operation, no Python code in the
process can run. Other worker threads in the same process
are also blocked.

``deadlock-timeout`` (default 300 seconds) detects this case.
A monitor thread inside the daemon attempts to acquire the
GIL once per second; when the acquisition itself blocks for
longer than ``deadlock-timeout``, the daemon is treated as
wedged and recycled.

The injection mechanism that ``request-timeout`` and
``interrupt-timeout`` use cannot recover this case: it
relies on Python being able to run. ``deadlock-timeout``
handles it the only way that works, which is process
restart. See the recovery-flow section below.

Response back to the client
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the WSGI application has produced a response, the
daemon streams it back over the socket to the Apache child,
which then proxies it through to the HTTP client.

The daemon-to-Apache leg uses ``socket-timeout`` (the same
timeout that bounded request reads). The Apache-to-client
leg, when the response buffer has filled and a forced flush
has to wait on the client, uses ``response-socket-timeout``.
This defaults to the value of ``socket-timeout`` when not
set explicitly.

``response-socket-timeout`` is the knob to reach for when
serving slow clients (mobile networks, satellite, etc.) and
the application has produced a large response that does not
fit in a single buffer flush. A short value here can clip
genuine slow-client traffic; a long value lets a slow
client hold a daemon worker thread for the duration of the
response.

WSGI script load
~~~~~~~~~~~~~~~~

A daemon process must load and execute its WSGI script
before it can serve any request. ``startup-timeout``
(default 0, disabled) bounds how long a daemon process is
allowed to spend on this initial load. When set and the
load takes longer than the limit, the daemon process is
restarted.

The case ``startup-timeout`` was introduced for is transient
import failures that leave Python module-level state partly
initialised: a subsequent retry of the same import in the
same process can hit a different failure than the first
attempt. Django is the prominent example; once Django's
bootstrap has been started in a process it cannot be
cleanly retried. ``startup-timeout`` forces a fresh process
so the retry starts from a clean slate.

Idle daemon
~~~~~~~~~~~

When a daemon process has no active requests and is not
receiving new ones, ``inactivity-timeout`` (default 0,
disabled) recycles it after the configured idle interval.
The intent is to reclaim memory from infrequently-used
daemon process groups.

The first request to arrive after an idle recycle pays the
import cost again. For applications with a high startup
cost (large model load, complex framework bootstrap) this
can be a visible per-request latency spike on cold paths.
``inactivity-timeout`` is most useful for genuinely
infrequently-used groups (administrative endpoints,
periodic batch jobs); it is rarely the right knob for
production request-handling pools.

Embedded mode: what is different
--------------------------------

When a WSGI application runs in embedded mode (no
``WSGIDaemonProcess`` declaration, or
``WSGIProcessGroup %{GLOBAL}`` selecting embedded
explicitly) the pipeline is much shorter, and most of the
timeout knobs above do not apply.

The application runs directly inside the Apache child
worker process. There is no UNIX socket between Apache and
the application: the WSGI handler is invoked in-process,
the application returns its response, and Apache's normal
output machinery streams that back to the client.

What that means for timeouts:

* **Transport timeouts vanish.** No ``connect-timeout``, no
  ``queue-timeout``, no ``socket-timeout``, no
  ``response-socket-timeout``. The daemon-side hops they
  guard do not exist.
* **Apache's own request timeouts still apply.**
  ``Timeout`` and ``KeepAliveTimeout`` are the only
  timeouts that govern the request itself in embedded
  mode.
* **Dispatch and auth scripts still run** in the same
  Python interpreter that ends up running the request
  handler. ``WSGIDispatchScript`` and the auth-script
  directives operate the same way as in daemon mode;
  there is no extra process boundary.
* **No per-process recycle from mod_wsgi.** No
  ``maximum-requests``, ``restart-interval``,
  ``cpu-time-limit``, ``inactivity-timeout``. Apache's MPM
  (``MaxConnectionsPerChild``, ``MaxRequestWorkers``,
  ``ServerLimit``, etc.) is what decides when an Apache
  child is recycled, and that is governed by Apache rather
  than mod_wsgi.
* **No application fail-safe timeouts.**
  ``request-timeout``, ``interrupt-timeout``, and
  ``deadlock-timeout`` are not available. mod_wsgi cannot
  kill an Apache child mid-request without taking the rest
  of the child's modules down with it (``mod_php``,
  ``mod_ssl``, static-file serving, and so on). A wedged
  request in embedded mode wedges the Apache worker until
  Apache itself decides the worker has misbehaved.
* **No drain or shutdown timeouts.** ``graceful-timeout``,
  ``eviction-timeout``, and ``shutdown-timeout`` likewise
  do not apply, for the same reason: process lifecycle
  belongs to Apache, not mod_wsgi.

Net effect: the embedded-mode timeout surface reduces to
"Apache's ``Timeout`` directive, plus the MPM tuning". A
wedged request, a runaway request, or a deadlocked C
extension cannot be recovered automatically; the operator
sees the symptom (Apache children running out, latency
climbing) and has to intervene.

On Windows this is not a deployment choice. Daemon mode is
not available there, so embedded is the only option. The
"no automatic recovery from a wedged request" property is
therefore an inherent property of mod_wsgi on Windows, not
a trade-off the operator selected. See
:doc:`processes-and-threading` for the Windows process
model and its implications.

For any deployment where daemon mode is available, prefer
it. See :doc:`daemon-mode` for the model and patterns.

Recovery flow when ``request-timeout`` fires
--------------------------------------------

When the per-thread fire point is crossed, what happens
next depends entirely on ``interrupt-timeout``.

With ``interrupt-timeout=0`` (default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mod_wsgi skips thread-local injection and transitions the
process directly into ``graceful-timeout`` followed by
``shutdown-timeout``. The whole daemon process is recycled.
Sibling requests on other threads have at most
``graceful-timeout`` to finish cleanly before the process
is forcibly shut down.

This is the simplest case but the most disruptive: one
wedged request takes out the entire daemon process and any
other in-flight requests on its threads.

With ``interrupt-timeout`` set to a non-zero value
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mod_wsgi attempts to interrupt only the wedged thread by
injecting a :py:class:`mod_wsgi.RequestTimeout` exception
into it. If the injection unwinds the wedged request within
the ``interrupt-timeout`` grace window, the worker thread
returns to the pool and the process keeps serving. The
other threads were never disturbed.

The injected exception derives directly from
``BaseException``, so well-written code using
``except Exception:`` will not catch it. It may be caught
for cleanup (closing connections, releasing locks) but
should be re-raised; swallowing it defeats the recovery
mechanism.

If the injected exception unwinds back to the WSGI adapter
within the grace window, the adapter returns
``504 Gateway Timeout`` and the request is logged as having
been recovered.

Three thread states determine whether injection works
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thread injection is best-effort. The injection takes effect
only when the target thread next runs Python bytecode,
which means the thread's current state determines the
outcome:

* **Running Python code** (loops, computation, framework
  code). The exception fires on the next bytecode tick,
  almost immediately. This is the case the mechanism is
  designed for.

* **Blocked in a C call that has released the GIL** (most
  socket reads, database driver calls, ``time.sleep``,
  file I/O). The injected exception is queued on the
  thread but does not fire until the blocking call returns
  and Python bytecode runs again. If the external service
  eventually responds or times out at its own protocol
  level, the injected exception fires then. If the
  blocking call hangs indefinitely with no internal
  timeout, the injected exception will never fire. In
  that case the ``interrupt-timeout`` grace window
  expires and the daemon falls through to the
  ``graceful-timeout`` / ``shutdown-timeout`` chain,
  taking the wedged request down with the process.

* **Blocked in a C extension that holds the GIL.** No
  Python code can run anywhere in the process. The
  injection cannot reach the thread; no other Python
  thread can run either. This is what ``deadlock-timeout``
  exists for; the ``request-timeout`` /
  ``interrupt-timeout`` mechanism cannot help.

The takeaway for sizing: ``interrupt-timeout`` works
cleanly when the application's blocking calls have their
own finite timeouts (HTTP client read timeouts, database
statement timeouts, and so on) so the indefinite-block
case does not arise. See
:ref:`request-timeout-not-sla` below.

Multiple wedges in flight
~~~~~~~~~~~~~~~~~~~~~~~~~

When several threads wedge in quick succession, each gets
its own injection on its own grace timer. The first
injection grace to expire arms ``graceful-timeout``;
sibling injections continue to tick on their own threads
and may still unwind cleanly during the graceful window,
in which case those threads free up and the drain check
progresses.

The ``graceful-timeout`` "stale request" optimisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once ``graceful-timeout`` is armed, the drain check ignores
any in-flight request whose elapsed time has already
exceeded ``request-timeout + interrupt-timeout``. Such a
request will not unwind voluntarily, so waiting for it
serves no purpose. This lets the graceful drain complete
promptly when a wedged thread is the only thing still
tying up the process: the sibling requests get the chance
to finish cleanly while the wedged one rides out via
``shutdown-timeout``'s forced kill.

Recovery flow when ``deadlock-timeout`` fires
---------------------------------------------

When the GIL is wedged inside a Python C extension, the
injection mechanism above cannot help: no Python bytecode
is running anywhere in the process, so a queued injection
has no trigger.

``deadlock-timeout`` recovers the process the only way it
can: a forced restart. The detection thread signals
shutdown, the shutdown sequence begins, and because the
in-flight requests cannot unwind, the process eventually
exits via ``shutdown-timeout``'s forced kill rather than
via a graceful drain. Any request that was being processed
at the time is lost.

This is more disruptive than the ``request-timeout`` case
because there is no thread-local recovery option, and
because the failure mode usually indicates a bug in a C
extension rather than a wedged application path. The
remediation is typically not to tune the timeout; it is to
find which C extension is misbehaving and stop using it
(or fix it).

See :doc:`daemon-mode` for the structural overview of how
this fits with the other recycling triggers.

Recovery flow on graceful restart (SIGUSR1)
-------------------------------------------

When an operator sends ``SIGUSR1`` directly to a daemon
process (for example with ``pkill -USR1 -f 'wsgi:groupname'``),
the daemon process drains rather than restarting
immediately.

Note that ``apachectl graceful`` does *not* take this path.
The Apache parent forwards ``SIGTERM`` to mod_wsgi daemon
processes even on a graceful restart of the server, so the
daemon goes straight through ``shutdown-timeout`` rather
than the ``eviction-timeout`` / ``graceful-timeout`` drain.
The graceful-restart signal handling described here applies
only to ``SIGUSR1`` arriving directly at the daemon
process.

If ``eviction-timeout`` is set, the daemon continues to
accept new requests for that many seconds, drains
in-flight work, and restarts as soon as it reaches an idle
state (or once ``eviction-timeout`` expires, whichever
comes first).

If ``eviction-timeout`` is not set, the daemon falls back
to ``graceful-timeout`` for the same purpose. If neither is
set, the daemon restarts immediately, which means any
in-flight requests are killed by ``shutdown-timeout``.

This is the path used by the blue/green cutover pattern in
:doc:`upgrading-an-application`; the longer drain window is
what makes the cutover graceful for in-flight requests.

Drain semantics during shutdown
-------------------------------

Across the recovery flows above, ``graceful-timeout`` and
``eviction-timeout`` are described as "drain" windows. The
word is convenient but slightly misleading: the daemon
process is not refusing new requests during those windows.
Only ``shutdown-timeout`` does that.

During ``graceful-timeout`` and ``eviction-timeout`` the
daemon continues to accept new requests. The process is
running normally; it is just hoping to reach an idle state
through ordinary request turnover so it can exit cleanly.
If all in-flight requests finish and no new ones arrive
before the timeout expires, the process exits immediately.
If the timeout expires with requests still in flight
(because new ones kept arriving, or because in-flight ones
are slow), the process falls into ``shutdown-timeout``.

During ``shutdown-timeout`` the daemon stops accepting new
requests. The Apache child loses the ability to dispatch
fresh work to this process; in-flight requests continue
running. If the in-flight requests finish before
``shutdown-timeout`` expires, the process exits
immediately. If ``shutdown-timeout`` expires with requests
still in flight, the process is forcibly killed and those
requests are lost.

So the practical distinction is what happens to incoming
traffic. ``graceful-timeout`` and ``eviction-timeout`` do
not stop new traffic and are best understood as "keep
serving while waiting for an opportunity to exit cleanly".
``shutdown-timeout`` is the actual drain plus hard cutoff:
no new work in, in-flight work has a fixed window to
finish, then forced exit.

Sizing the timeouts
-------------------

Most of the timeout options are off by default for
backwards-compatibility reasons. The recommendation is to
set them explicitly so the daemon process group can recover
from backlogging and hung requests rather than silently
piling them up.

``mod_wsgi-express`` already does this. Its generated
configuration applies a starter set of values that has
been tuned over many deployments. These are a good
baseline for a hand-written ``WSGIDaemonProcess``
configuration::

    WSGIDaemonProcess example processes=2 threads=5 \
        display-name=%{GROUP} \
        lang=en_US.UTF-8 \
        locale=en_US.UTF-8 \
        queue-timeout=45 \
        socket-timeout=60 \
        connect-timeout=15 \
        request-timeout=60 \
        interrupt-timeout=0 \
        startup-timeout=15 \
        deadlock-timeout=60 \
        graceful-timeout=15 \
        eviction-timeout=0 \
        inactivity-timeout=0 \
        restart-interval=0 \
        shutdown-timeout=5 \
        maximum-requests=0

Adjust from there based on the application's actual
behaviour. A few specific notes:

Do not over-tighten ``request-timeout``
    The ln-scaling already provides headroom for higher
    thread counts. Setting this to a few times the p99 of
    normal request duration is typically right; setting it
    close to p99 will produce false positives on legitimate
    slow paths.

``interrupt-timeout`` has a recommended floor of about 10 seconds when enabled
    Values significantly below that may not give the injected
    exception time to unwind through finally blocks, context
    managers, and the WSGI adapter. Setting it too short can
    defeat the purpose of injection by turning recoverable
    wedges into process restarts.

``queue-timeout`` discards stale work at pickup, not while it waits
    When a worker finally accepts a request that has been
    sitting in the queue longer than this, it is discarded
    with a 504 rather than served. The 504 is not
    necessarily prompt: the request waits in the kernel
    queue until a worker frees up, and only then gets
    discarded. The right value depends on what kind of
    latency the application treats as already-failed: a
    backend serving real-time requests might set 5 to 10
    seconds; a batch-style service might tolerate 60 to
    120.

``startup-timeout`` is mostly for Django and similar frameworks
    Frameworks that cannot be cleanly re-bootstrapped in the
    same process need ``startup-timeout`` so a partial
    bootstrap forces a fresh process. If the application's
    startup is fast and deterministic, this is not a useful
    knob.

``graceful-timeout``, ``eviction-timeout``, and ``shutdown-timeout`` form a hierarchy
    ``graceful-timeout`` keeps the process accepting new
    requests while waiting for it to reach idle (used after
    recycling triggers), ``eviction-timeout`` does the same
    after a direct ``SIGUSR1`` (falling back to
    ``graceful-timeout`` when not set), and
    ``shutdown-timeout`` is the hard cutoff once shutdown is
    actually under way, with no new requests accepted. See
    the "Drain semantics during shutdown" section above for
    the full distinction. The default of 5 seconds for
    ``shutdown-timeout`` suits most workloads; too short and
    Python ``atexit`` handlers may not finish, too long and
    recovery from a wedged process is delayed.

.. _request-timeout-not-sla:

``request-timeout`` is not a per-request SLA
--------------------------------------------

A common mistake is to treat ``request-timeout`` as the
right knob for "this request must complete within N
seconds, or return an error". That is not what the
mechanism is for, and trying to use it that way will
produce surprising behaviour.

``request-timeout`` is a *process-level fail-safe*. Its
purpose is to detect when the daemon process has stopped
making progress and trigger recovery before the whole pool
becomes useless. The natural-log scaling against
``threads`` is a deliberate choice that follows from this:
a wedge in 1-of-10 threads is a smaller problem than a
wedge in 1-of-1, so the trigger should fire later in the
larger pool. A per-request SLA would not scale this way.

For user-visible per-request deadlines, use
application-level timeouts on the operations the request
performs:

* HTTP client read timeouts on outbound calls.
* Database statement timeouts (``SET statement_timeout``
  in PostgreSQL, ``MAX_EXECUTION_TIME`` in MySQL, etc.).
* Per-operation timeouts on cache, message-queue, and
  other service clients.

These bound the blocking calls inside the request handler
itself, so the request returns a finite error to the
client within the SLA. They also have a useful side effect
for ``interrupt-timeout``: once the blocking call has a
finite internal timeout, the indefinite-hang case (where
injection cannot fire) goes away, and the thread-local
recovery mechanism can do its job.

Treat ``request-timeout`` as the safety net that catches
everything application-level timeouts missed, not as the
front-line deadline.

Common pitfalls
---------------

Tight ``request-timeout`` triggering false positives
    A ``request-timeout`` set close to the p99 of legitimate
    slow requests will fire on those legitimate requests
    under ordinary load, restarting the process for no
    reason. Set it to a multiple of p99, not to p99.

Relying on ``interrupt-timeout`` without application-level timeouts
    When the wedged thread is blocked on an external service
    that itself has no timeout, the injection cannot fire.
    The grace window expires and the process is recycled the
    same as if ``interrupt-timeout`` had been zero. Adding
    finite client-side timeouts at the blocking call site is
    what makes ``interrupt-timeout`` useful.

Forgetting ``queue-timeout``
    Without ``queue-timeout``, a daemon process group that
    gets behind keeps serving stale work long after the
    client has likely given up: workers grind through the
    backlog, latency stays high, and the queue drains
    slowly. With ``queue-timeout`` set, workers discard
    stale work on pickup so they spend their time on
    requests that still matter, and the rest of the system
    gets a 504 signal it can respond to (autoscaling,
    alerts) before the backlog gets unmanageable. Note that
    discard is at pickup, not at the timeout instant, so
    sustained overload can still build a long queue; the
    knob shapes which requests get served when capacity
    returns, not which requests get to wait.

Mixing user-facing SLA expectations with mod_wsgi's fail-safe
    The most common version of this is "we want user
    requests to time out at 30 seconds, so set
    ``request-timeout=30``". The ln-scaling means at
    ``threads=15`` this fires at about 110 seconds, not 30.
    Use application-level timeouts for the SLA and leave
    ``request-timeout`` set to a fail-safe value.

See Also
--------

* :doc:`daemon-mode` for the structural model behind this
  page: process and thread sizing, recycling triggers,
  and process-group patterns.
* :doc:`../configuration-directives/WSGIDaemonProcess` for
  the per-option directive reference.
* :doc:`processes-and-threading` for the Apache MPM and
  Python sub interpreter model that daemon mode builds
  on.
* :doc:`upgrading-an-application` for the SIGUSR1-driven
  cutover pattern that uses ``eviction-timeout`` /
  ``graceful-timeout``.
* :doc:`debugging-techniques` for log-output diagnostics
  when timeouts fire.
