========================
Embedded and Daemon Mode
========================

This guide covers configuring mod_wsgi's two process
models, *embedded mode* and *daemon mode*. Each is
configured through its own directive set:

* Embedded mode is configured through Apache's MPM
  directives (``MaxRequestWorkers``, ``StartServers``,
  the spare-worker / spare-thread directives).
* Daemon mode is configured through mod_wsgi's
  ``WSGIDaemonProcess``, ``WSGIProcessGroup`` and
  ``WSGIApplicationGroup`` directives. See
  :doc:`../configuration-directives/WSGIDaemonProcess`
  for the per-option reference.

The :doc:`processes-and-threading` guide covers the
underlying Apache MPM and Python sub interpreter model
that this page builds on. Read that page first if the
term "MPM" or "sub interpreter" is unfamiliar.

The two process models
======================

In *embedded* mode the application runs inside Apache's
child worker processes. The Python interpreter is loaded
into Apache's address space and the WSGI application
shares the process with every other Apache module:
``mod_php``, static-file serving, ``mod_ssl`` session
handling, and so on. Process and thread counts are
dictated by Apache's MPM tuning.

In *daemon* mode mod_wsgi creates a dedicated set of
processes running just the WSGI application. The Apache
child processes act as proxies: they receive the request,
hand it to a daemon process over a UNIX domain socket, and
relay the response back. The daemon processes are managed
by the Apache parent (started, restarted, recycled), and
Apache's own request-handling children need not load the
Python interpreter to dispatch a request to the daemon.
(Auth scripts and dispatch scripts, if configured, are an
exception: those run in an embedded Python interpreter
inside the Apache child even when the application itself
is in a daemon process. See
:doc:`../configuration-directives/WSGIAuthUserScript` and
:doc:`../configuration-directives/WSGIDispatchScript`.)

For most deployments daemon mode is the right default.
Compared to embedded mode it gives:

* A different user account from Apache, so the application
  runs with the privileges it actually needs rather than
  the broader set Apache itself runs with.
* An address space the application owns, so a memory leak
  or a crash takes down only the daemon pool.
* Process and thread counts decoupled from Apache's MPM
  tuning, so the application can be sized for its own
  workload.
* Recycling triggers (request count, wall-clock interval,
  CPU time, idle time, memory, deadlock) that operate
  per-pool without restarting Apache.
* A reload mechanism (touch the WSGI script) that does not
  require an Apache restart.

The trade-off is one extra process hop per request and the
operational surface of the daemon pool itself. For a
Python web application both costs are small relative to
the benefits.

Daemon mode is not available on Windows; mod_wsgi on
Windows supports only embedded mode. Embedded mode itself
is supported on all platforms.

To enforce daemon-only deployment and reject any
configuration that would otherwise fall back to embedded
mode::

    WSGIRestrictEmbedded On

This is recommended for any production deployment that
should be in daemon mode. See
:doc:`../configuration-directives/WSGIRestrictEmbedded`.

The rest of this page splits into two parts: the first
covers configuring embedded mode, and the second
(considerably larger) covers configuring daemon mode.

Embedded mode
=============

What embedded mode looks like
-----------------------------

A minimal embedded-mode configuration is a script alias
with no daemon-process delegation::

    WSGIScriptAlias / /srv/myapp/myapp.wsgi

    <Directory /srv/myapp>
        Require all granted
    </Directory>

The application runs in whichever Apache child accepts the
request, with concurrency inherited from the active MPM:

* Under ``prefork`` each child handles one request at a
  time. Concurrency is achieved by spawning more children.
* Under ``worker`` and ``event`` each child runs a thread
  pool. Concurrency is the product of children and threads.
* Under Windows ``mpm_winnt`` there is one child running a
  thread pool.

When to use embedded mode
-------------------------

Embedded mode is the right choice in a small number of
cases:

* **Windows.** Daemon mode is not implemented on Windows;
  embedded mode is the only option there.
* **Single-application Apache instances** where the
  isolation, recycling and per-tenant features of daemon
  mode are not needed and the simpler configuration is
  preferred.
* **Tooling that requires** ``wsgi.multiprocess`` **to be
  False.** Some interactive debuggers require this, which
  an embedded-mode deployment with a single prefork child
  trivially satisfies.

For most production deployments daemon mode is the
recommended default; the "Daemon mode" section below
covers its features and configuration.

If embedded mode has not been chosen deliberately, set
``WSGIRestrictEmbedded On`` (above) so Apache rejects any
configuration that would fall back to embedded mode.

Apache MPM tuning
-----------------

Embedded-mode concurrency is set by Apache's MPM
directives. The relevant ones:

* ``MaxRequestWorkers`` is the upper bound on simultaneous
  requests Apache will handle. (Was ``MaxClients`` in
  Apache 2.2.)
* ``StartServers`` is the number of child processes
  spawned at startup.
* ``MinSpareServers`` / ``MaxSpareServers`` (prefork) or
  ``MinSpareThreads`` / ``MaxSpareThreads`` (worker, event)
  bound the number of idle workers Apache maintains, which
  drives spawn-and-reap dynamics under fluctuating load.
* ``ServerLimit`` and (for worker, event) ``ThreadLimit``
  are hard ceilings beyond which the configuration cannot
  grow at runtime.

Each Apache child or thread runs a copy of the WSGI
application, so these directives directly determine how
many concurrent requests the application handles. See
:doc:`processes-and-threading` for the per-MPM walkthrough
that this configuration sits on top of.

Under ``mod_wsgi-express --embedded-mode``, the four
``--max-clients``, ``--initial-workers``,
``--minimum-spare-workers`` and ``--maximum-spare-workers``
options are ignored. Express forces a fixed-pool MPM sized
to ``--processes`` × ``--threads`` (with ``StartServers``,
``MinSpare*`` and ``MaxSpare*`` all set to that value),
so concurrency is exactly the product of those two options
regardless of load. To enable Apache's dynamic
spare-worker management under embedded mode, configure
mod_wsgi inside a manually managed Apache rather than via
express.

Embedded-mode caveats
---------------------

Embedded mode brings the Python interpreter into Apache's
child workers, with several consequences worth
understanding before choosing it:

* **Shared address space with Apache.** A memory leak or
  crash in the application takes the Apache child with it.
  Apache will spawn a replacement, but in-flight requests
  in that child are lost.
* **Shared with other Apache modules.** Other in-process
  Apache modules (``mod_php``, ``mod_ssl`` session caches,
  and so on) sit alongside Python in the same address
  space. Memory accounting and resource limits apply to
  the whole.
* **Apache user.** The application runs as the user Apache
  is configured to run as. Embedded mode has no equivalent
  of daemon mode's ``user=`` option for running as a
  different account.
* **No process recycling triggers.** The recycling options
  on ``WSGIDaemonProcess`` (request count, wall-clock
  interval, CPU time, idle, memory, deadlock) are
  daemon-mode features. Apache's
  ``MaxConnectionsPerChild`` is the closest analogue,
  recycling Apache children after a configured number of
  connections.
* **No daemon-mode timeouts.** ``request-timeout``,
  ``deadlock-timeout``, ``startup-timeout``,
  ``shutdown-timeout``, ``graceful-timeout`` and the
  others are daemon-mode features.
* **Reload only covers the WSGI script.** When
  ``WSGIScriptReloading`` is on (the default) and the
  WSGI script's modification time changes, the reload
  happens by dropping the script's ``sys.modules`` entry
  and re-importing it in the same Apache child. Other
  Python modules the application has loaded are not
  reloaded. To pick up changes elsewhere in the
  application code base, restart Apache.

Daemon mode
===========

The three configuration directives
----------------------------------

Three directives configure daemon mode. They are independent and
each does one thing.

``WSGIDaemonProcess``
    Declares a *named pool* of one or more daemon processes.
    Sets the user the pool runs as, the number of processes, the
    threads per process, the Python environment, the recycling
    triggers, the timeouts, and so on. See
    :doc:`../configuration-directives/WSGIDaemonProcess`.

``WSGIProcessGroup``
    Selects which named pool a request is dispatched to. The
    argument is the name of a pool declared with
    ``WSGIDaemonProcess``, or one of the special expansions
    ``%{GLOBAL}`` (embedded mode) or ``%{ENV:variable}``
    (look up the pool name in an environment variable). See
    :doc:`../configuration-directives/WSGIProcessGroup`.

``WSGIApplicationGroup``
    Selects which Python sub interpreter inside the chosen pool
    runs the application. The argument is a name of your choosing
    or one of the special expansions ``%{GLOBAL}`` (the main
    interpreter), ``%{SERVER}`` (per-virtual-host),
    ``%{RESOURCE}`` (per-script, the default), or
    ``%{ENV:variable}``. See
    :doc:`../configuration-directives/WSGIApplicationGroup`.

A complete minimal configuration wiring all three together::

    WSGIDaemonProcess myapp processes=2 threads=15 \
        user=appsvc group=appsvc \
        display-name=%{GROUP}
    WSGIProcessGroup myapp
    WSGIApplicationGroup %{GLOBAL}

    WSGIScriptAlias / /srv/myapp/myapp.wsgi

The ``process-group`` and ``application-group`` options on
``WSGIScriptAlias`` are equivalent to the ``WSGIProcessGroup``
and ``WSGIApplicationGroup`` directives and can replace the
two directive lines above for the script-alias-only case::

    WSGIDaemonProcess myapp processes=2 threads=15 \
        user=appsvc group=appsvc \
        display-name=%{GROUP}

    WSGIScriptAlias / /srv/myapp/myapp.wsgi \
        process-group=myapp application-group=%{GLOBAL}

The script-alias form has one additional behaviour: it triggers
auto-preload of the WSGI script in the named daemon process
group at startup, so the first request to the application does
not pay the import cost. The directive form does not preload.

Sizing the pool
---------------

The two knobs are ``processes=`` and ``threads=`` on
``WSGIDaemonProcess``. The defaults (one process, fifteen
threads) are conservative and rarely the right answer for
production traffic. Choosing values for both is the single most
consequential tuning decision for daemon mode.

Processes
~~~~~~~~~

More processes give:

* Independent failure domains. A crash, a wedge on the GIL, or a
  memory blowout takes out one process; the others keep serving.
* Independent CPython GILs. Each process has its own interpreter
  and its own GIL, so concurrent CPU-bound work runs in parallel
  across processes. Threads inside a single process do not.
* Independent Python heaps. Memory growth in one process does
  not affect the others, and recycling one process reclaims its
  memory without disturbing the rest.

The cost of more processes is memory: each process has its own
copy of the Python interpreter, the loaded modules, and any
in-memory caches the application builds up. Each daemon process
initialises Python independently after forking from the Apache
parent (Python is not loaded in the parent), so there is no
shared interpreter state across processes to amortise either
the startup cost or the resident memory footprint against; both
are paid in full per process.

Threads
~~~~~~~

More threads per process give:

* Concurrency on I/O-bound work. While one thread is blocked
  waiting on a database, an HTTP backend, or a file read, other
  threads in the same process can run.
* Lower memory cost than the equivalent extra processes. Threads
  share the interpreter, the modules, and the heap.

The cost of more threads is GIL contention. Two threads inside
one process cannot both be running Python bytecode at the same
time. For CPU-bound work the second, third, and Nth threads add
contention without adding throughput.

Rules of thumb
~~~~~~~~~~~~~~

Most Python web applications are I/O-bound: each request spends
most of its time waiting on a database, a cache, an HTTP service,
or a template render that itself reads from disk. For that
profile, ``processes=N threads=15`` (where N is roughly the
number of CPU cores you are willing to dedicate to the
application) is a reasonable starting point.

For CPU-bound applications (heavy template work, data
serialisation, image processing inline in the request) drop
threads down. ``processes=N threads=3`` or even
``processes=N threads=1`` is often a better fit. Adding threads
beyond what the GIL can interleave just adds context-switching
cost.

For applications with very large per-process state (a model
loaded into memory, a large in-process cache) prefer fewer
processes with more threads. The state is duplicated per
process, so ``processes=8 threads=2`` has eight times the memory
cost of ``processes=1 threads=16`` for the same total
concurrency.

For interactive debuggers and any other component that requires
``wsgi.multiprocess`` to be ``False``, omit the ``processes=``
option entirely (see
:doc:`../configuration-directives/WSGIDaemonProcess` on the
distinction between omitting ``processes=`` and setting
``processes=1``).

Capacity planning
~~~~~~~~~~~~~~~~~

The total request concurrency the pool can handle simultaneously
is ``processes * threads``. Beyond that, requests queue on the
pool's UNIX socket up to ``listen-backlog``, then sit waiting up
to ``queue-timeout`` (if set) before getting a 504. The Apache
child workers calling into the pool are themselves a separate
queue ahead of that one.

Headroom matters. A pool sized to exactly steady-state load has
no room to absorb a burst. Aim for steady-state load to leave
the pool ~50% busy, so a doubling of incoming traffic still
fits without queueing. If the application has a long-tail
latency distribution (a few requests that take much longer than
the median) bump that headroom further: a wedged thread is a
thread not available for the next request.

The natural-log scaling that ``request-timeout`` applies (see
"Timeouts" below) is also informed by ``threads``: more threads
implies the pool can tolerate one wedge for longer before
forcing a recycle. This is a property of the timeout machinery,
not of sizing per se, but it is one more reason to think of
``threads`` as a deliberate choice rather than an
unconfigured-default.

Process group patterns
----------------------

The shape of a daemon process group depends on what you are
trying to isolate.

Single global pool
~~~~~~~~~~~~~~~~~~

The simplest case. One ``WSGIDaemonProcess`` declared at server
scope, all virtual hosts delegate to it::

    WSGIDaemonProcess shared processes=4 threads=15 \
        user=appsvc group=appsvc \
        display-name=%{GROUP}

    <VirtualHost *:80>
        ServerName www.site1.example
        WSGIProcessGroup shared
        WSGIScriptAlias / /srv/site1/site1.wsgi
    </VirtualHost>

    <VirtualHost *:80>
        ServerName www.site2.example
        WSGIProcessGroup shared
        WSGIScriptAlias / /srv/site2/site2.wsgi
    </VirtualHost>

Both sites run in the same processes. They get separate Python
sub interpreters by default (the ``%{RESOURCE}`` application
group expansion gives each script its own), but they compete
for the same threads and live in the same address space. Pick
this pattern when the sites trust each other (same operator,
same security boundary) and you do not need to size them
independently.

Per-virtual-host pool
~~~~~~~~~~~~~~~~~~~~~

One pool per virtual host. Each pool is sized for that site and
runs as that site's owning user::

    <VirtualHost *:80>
        ServerName www.site1.example
        WSGIDaemonProcess www.site1.example \
            processes=2 threads=15 \
            user=site1 group=site1 \
            display-name=%{GROUP}
        WSGIProcessGroup www.site1.example
        WSGIScriptAlias / /srv/site1/site1.wsgi
    </VirtualHost>

    <VirtualHost *:80>
        ServerName www.site2.example
        WSGIDaemonProcess www.site2.example \
            processes=2 threads=15 \
            user=site2 group=site2 \
            display-name=%{GROUP}
        WSGIProcessGroup www.site2.example
        WSGIScriptAlias / /srv/site2/site2.wsgi
    </VirtualHost>

The two sites are now isolated at the process and the OS-user
level. A bug in site1 cannot affect site2's processes; site1
cannot read site2's files unless the filesystem permissions
explicitly allow it. The cost is duplicate Python interpreters
and the operational overhead of more pools.

Pool names must be unique across the whole server. ``www.site1.example``
declared inside one virtual host cannot also be declared inside
another, even if the other settings differ.

A virtual host pair on ports 80 and 443 sharing the same server
name should declare the pool once (in the first virtual host)
and reference it from the second::

    <VirtualHost *:80>
        ServerName www.site1.example
        WSGIDaemonProcess www.site1.example \
            processes=2 threads=15 \
            user=site1 group=site1
        WSGIProcessGroup www.site1.example
        ...
    </VirtualHost>

    <VirtualHost *:443>
        ServerName www.site1.example
        WSGIProcessGroup www.site1.example
        ...
    </VirtualHost>

This avoids running two whole instances of the same application
for the two ports.

Per-tenant pool
~~~~~~~~~~~~~~~

When multiple unrelated applications share an Apache instance,
each one running as a different OS user, declare one pool per
tenant. The configuration shape is the same as per-virtual-host
above; the difference is that the user accounts are not
operator-trusted relative to each other. See
:doc:`security-hardening` for the broader hardening picture
including ``WSGIRestrictProcess``, socket ownership, and
filesystem permissions for multi-tenant deployments.

Parallel pools for cutover
~~~~~~~~~~~~~~~~~~~~~~~~~~

A blue/green pattern declares two pools that alternate live and
idle roles across upgrades. The :doc:`upgrading-an-application`
guide covers the full pattern, including the routing layer
(``WSGIDispatchScript`` or ``mod_rewrite`` with a map file) and
why the pool names must be stable across upgrades.

Restricting which pools a delegation can choose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``WSGIProcessGroup %{ENV:variable}`` is used, the pool name
comes from a request-time environment variable, which makes it
possible for a ``.htaccess`` file or a ``RewriteRule`` to choose
the pool. To prevent that mechanism from selecting an unintended
pool (for example, a pool belonging to a different tenant) use
``WSGIRestrictProcess`` to list the pools that are valid choices
in the relevant context. See
:doc:`../configuration-directives/WSGIRestrictProcess`.

Application group choice
------------------------

The application group selects which Python sub interpreter
inside the daemon process runs the application. There is one
sub interpreter per application group name per process; sub
interpreters do not share Python module state.

The default is ``%{RESOURCE}``, which gives each WSGI script its
own application group keyed on host, port, and ``SCRIPT_NAME``.
For most single-application deployments this is what you want:
the script gets its own interpreter, isolated from any other
script in the same pool.

The cases that call for an explicit choice:

``%{GLOBAL}``
    Use the main Python interpreter rather than a sub
    interpreter. This is required for applications that depend
    on C extensions which do not work correctly outside the
    main interpreter. NumPy, SciPy, and packages built on them
    are the most common examples; the failure mode is typically
    a process crash on import or first use, not a recoverable
    error. ``WSGIApplicationGroup %{GLOBAL}`` is the safe
    default if you are unsure whether your dependency tree is
    sub-interpreter-clean. See "Multiple Python Sub
    Interpreters" in :doc:`application-issues`.

``%{SERVER}``
    All scripts under the same virtual host share one
    application group. Useful when several scripts in a single
    virtual host are designed to share Python module state.

Named application group
    Choose your own name. Two scripts that name the same
    application group share an interpreter; two scripts with
    different names do not. Used most often when several scripts
    deliberately share a framework setup.

``%{ENV:variable}``
    Pick the application group at request time from an
    environment variable set by ``SetEnv`` or ``RewriteRule``.
    Useful for per-user grouping (for example, ``mod_userdir``
    deployments where each user's scripts share one interpreter
    but are isolated from other users').

In a multi-process pool, "shares an application group" means
"shares a sub interpreter *within the same process*". Two
processes in the same pool each have their own copy of the named
sub interpreter; in-process global data is not shared across
processes regardless of application group name. If you need a
single sub interpreter handling all requests for a tenant,
configure the pool with ``processes=1`` (omitted, not
``processes=1``: see "Sizing" above).

Per-interpreter GIL and free-threaded Python
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Recent Python releases introduced two mechanisms that change the
sub interpreter picture: per-interpreter GIL state under PEP 684
(Python 3.12) and optional free-threading under PEP 703
(Python 3.13). mod_wsgi provides
:doc:`../configuration-directives/WSGIPerInterpreterGIL` and
:doc:`../configuration-directives/WSGIFreeThreading` to opt into
these on a per-pool basis. Both change the GIL-contention
calculus described above. See those directive pages and
:doc:`processes-and-threading` for the current support state.

Process recycling
-----------------

Daemon processes can be configured to recycle automatically
based on a number of triggers. The triggers compose: any one
that fires causes the process to be replaced.

``maximum-requests=nnn``
    Recycle after the process has handled this many requests.
    A safety net for slow memory leaks. Set high enough that
    recycling is not the dominant operation (a few thousand to
    tens of thousands of requests per cycle is typical).

``restart-interval=sss``
    Recycle after this many seconds of wall-clock time. A
    time-based counterpart to ``maximum-requests`` for catching
    slow growth that scales with elapsed time rather than request
    count, or for periodically flushing in-process state that
    drifts over time.

``cpu-time-limit=sss``
    Recycle after the process has accumulated this much CPU
    time. Catches CPU runaway. The limit is cumulative from
    process start, so a process will eventually hit it in normal
    use; size accordingly.

``inactivity-timeout=sss``
    Recycle after this many seconds with no requests in flight
    and no new requests arriving. Reclaims memory from
    infrequently used applications. Note the first request after
    a recycle pays the application's import cost again.

``memory-limit`` and ``virtual-memory-limit``
    Hard limits enforced via ``setrlimit()``. The process is
    killed when it exceeds the limit. Not implemented on all
    platforms (notably macOS); test before relying on it.

``deadlock-timeout=sss``
    Recycle when a potential GIL deadlock is detected. This
    catches the case where a Python C extension fails to release
    the GIL inside a long blocking operation, which would
    otherwise wedge the whole process indefinitely.

When ``maximum-requests``, ``restart-interval``, or
``cpu-time-limit`` fires, and ``graceful-timeout`` is set, the
process continues serving in-flight requests and accepting new
ones for up to that many seconds, restarting as soon as it
reaches an idle state. This avoids the bursty behaviour that
unconditional restart can cause when several processes hit the
trigger at once. ``deadlock-timeout`` does not honour
``graceful-timeout``: by the time it fires the GIL is wedged,
so the process exits forcibly via ``shutdown-timeout``. The
``setrlimit()``-based ``memory-limit`` and
``virtual-memory-limit`` are likewise hard kills outside
mod_wsgi's control.

Avoid setting recycling triggers too aggressively. Constant
restart adds load (every restart re-imports the application,
warms caches, and may force a flurry of database connections),
and short intervals can hide rather than expose the underlying
problem. Use recycling as a safety net, not as a substitute for
fixing leaks.

Timeouts
--------

``WSGIDaemonProcess`` exposes a family of timeout options.
This page gives a one-paragraph orientation for each;
:doc:`request-pipeline` walks them through in the context of
the request flow they govern, including the recovery path
when one fires; and
:doc:`../configuration-directives/WSGIDaemonProcess` is the
per-option reference for behaviour, defaults, and edge cases.

The fault-recovery timeouts:

* ``request-timeout`` is a per-thread fail-safe for requests
  that block indefinitely. The fire point scales with
  ``threads`` by natural log so larger pools tolerate one
  wedge for longer before recovery kicks in.
* ``interrupt-timeout``, when non-zero, attempts a thread-local
  recovery first by injecting a
  :py:class:`mod_wsgi.RequestTimeout` exception into the wedged
  thread, restarting the process only if the injection does not
  unwind in time. This is the difference between losing one
  request (injection succeeds) and losing the whole pool's
  worth of in-flight requests (injection times out).
* ``deadlock-timeout`` catches the case the injection mechanism
  cannot recover: a C extension holding the GIL across a
  blocking call. Detection is by absence of progress, recovery
  is process restart.

The shutdown timeouts:

* ``graceful-timeout`` is how long a process continues serving
  after a recycle trigger fires, waiting to reach idle. Also
  applied as the wait for in-flight requests when
  ``request-timeout`` causes a forced recycle.
* ``eviction-timeout`` is the corresponding wait when an
  operator sends ``SIGUSR1`` directly to the daemon process
  (for example via ``pkill -USR1``). Falls back to
  ``graceful-timeout`` when not set. ``apachectl graceful``
  does not take this path: the Apache parent sends
  ``SIGTERM`` to mod_wsgi daemons even on a graceful
  restart.
* ``shutdown-timeout`` is the hard cutoff once shutdown is
  actually under way. The process is force-killed when this
  expires regardless of remaining state. The default of 5
  seconds is enough for most ``atexit`` handlers but short
  enough that recovery from a wedged process is prompt.
* ``startup-timeout`` is the limit on how long the WSGI script
  can take to load. Forces a process restart when initial load
  hangs.

The transport timeouts (between Apache and the daemon process):

* ``connect-timeout`` is how long the Apache child waits for a
  successful connection to the daemon's socket.
* ``socket-timeout`` is the read/write timeout on the
  Apache-to-daemon socket connection. Falls back to Apache's
  ``Timeout`` directive when not set.
* ``queue-timeout`` is how long a request can wait in the
  daemon's listen queue before being abandoned with 504.
  Useful for shedding load promptly when the pool is
  oversubscribed; without it requests pile up indefinitely.
* ``response-socket-timeout`` is the timeout on flushes back
  to the client when the response buffer has filled.

The :doc:`request-pipeline` guide reproduces the
``mod_wsgi-express`` starter set of timeout values inline as a
baseline for hand-written ``WSGIDaemonProcess`` configurations.
Many of the timeouts are off by default, but the recommendation
is to set them explicitly so the pool can recover from
backlogging and hung requests.

The socket plumbing
-------------------

Apache child processes communicate with daemon processes over
UNIX domain sockets. The ``WSGISocketPrefix`` directive sets the
directory and filename prefix for those sockets.

If ``WSGISocketPrefix`` is not set the sockets default to
Apache's runtime directory. On some Linux distributions that
directory is permission-restricted in a way that prevents the
Apache child user from connecting to the socket; the symptom is
a 503 with ``WSGI0117`` in the error log. The fix is to point
``WSGISocketPrefix`` at a directory that the Apache child user
can read (the distribution-specific ``run/`` location is the
usual choice)::

    WSGISocketPrefix run/wsgi

Do not place the sockets in ``/tmp``. The directory must be
writable only by ``root`` (or by the user Apache is started as,
when not started as root). Anything more permissive is a
security exposure.

The same directory is also used for mutex lock files associated
with daemon processes. See
:doc:`../configuration-directives/WSGIAcceptMutex` for the
related accept-mutex configuration.

When Apache is built with the ``mod_privileges`` module and
``PrivilegesMode SECURE`` is in use, the user that the Apache
child process runs as while handling a request differs from
Apache's normal child user. Use the ``socket-user=`` option on
``WSGIDaemonProcess`` to set the socket owner to the user the
Apache child will be running as when it connects, otherwise
connection will fail with a permissions error. The same option
is needed for third-party Apache modules that change the child
user per-request (``mod_ruid``, ``mod_ruid2``, ``mod_suid``, the
ITK MPM).

Apache front-end MPM tuning
---------------------------

In daemon mode the Apache child workers do not run the
Python interpreter. They accept the client connection,
proxy the request to the daemon pool over a UNIX domain
socket, and relay the response back. Concurrency at the
Apache layer is therefore decoupled from the daemon pool's
``processes`` and ``threads`` settings: the Apache MPM
only needs enough capacity to keep all daemon workers
fed, plus headroom for queued connections.

Under a manually managed Apache, the relevant directives
are ``MaxRequestWorkers``, ``StartServers``,
``MinSpare*`` / ``MaxSpare*`` for the active MPM, and
``ServerLimit``. See :doc:`processes-and-threading` for
the per-MPM walkthrough.

Under ``mod_wsgi-express`` (where daemon mode is the
default), the front-end MPM is sized automatically. The
defaults derive from ``--processes`` and ``--threads``:
``MaxRequestWorkers`` is set to
``10 + max(10, int(1.5 * processes * threads))``. The
four options that override these defaults:

``--max-clients NUMBER``
    Total ``MaxRequestWorkers``. Defaults to the formula
    above. Override when the front-end needs more or less
    headroom than ~1.5x the daemon pool's request
    concurrency. ``--max-clients`` is silently raised to
    at least ``processes * threads`` if a smaller value is
    given, since a smaller value would block daemon
    workers.

``--initial-workers FRACTION``
    ``StartServers`` as a fraction of ``--max-clients``.
    Defaults to 0.05 (5%) under prefork and 0.2 (20%)
    under worker / event.

``--minimum-spare-workers FRACTION``
    ``MinSpareServers`` (prefork) or ``MinSpareThreads``
    (worker, event), as a fraction of ``--max-clients``.
    Defaults to ``--initial-workers`` if not set.

``--maximum-spare-workers FRACTION``
    ``MaxSpareServers`` (prefork) or ``MaxSpareThreads``
    (worker, event), as a fraction of ``--max-clients``.
    Defaults to 0.1 (10%) under prefork and 0.6 (60%)
    under worker / event.

These options have no effect under ``--embedded-mode``;
see "Apache MPM tuning" under "Embedded mode" above for
what happens there.

Operational visibility
----------------------

By default daemon processes inherit Apache's ``argv[0]`` (the
path to the ``httpd`` binary), making them indistinguishable
from the Apache parent and child processes in ``ps`` output.
Setting ``display-name=%{GROUP}`` renames each daemon process
to ``(wsgi:groupname)`` so it is clearly identifiable::

    WSGIDaemonProcess myapp processes=2 threads=15 \
        user=appsvc group=appsvc \
        display-name=%{GROUP}

The rename is best-effort and constrained by the length of
Apache's original ``argv[0]``; the value may be truncated.

When ``WSGIDaemonProcess`` is declared inside a ``<VirtualHost>``,
mod_wsgi log output for that pool is routed to the virtual
host's ``ErrorLog`` rather than the main Apache error log. This
keeps per-pool error output co-located with the rest of the
virtual host's logs and makes per-tenant log aggregation
straightforward.

Daemon-pool lifecycle events (start, recycle, shutdown,
abnormal exit) are logged at ``info`` and above; many internal
diagnostics are at ``debug``. The ``LogLevel`` directive can be
scoped to ``mod_wsgi`` so the verbosity affects only mod_wsgi
output::

    LogLevel warn wsgi:info

See :doc:`debugging-techniques` for further log-output
diagnostics.

Common pitfalls
---------------

C extensions that are not sub-interpreter-safe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some C extensions assume they are loaded into the main Python
interpreter and crash or misbehave inside a sub interpreter.
NumPy, SciPy, and modules built on them are the prominent
examples. The fix is ``WSGIApplicationGroup %{GLOBAL}`` so the
application runs in the daemon process's main interpreter
rather than a sub interpreter; see "Multiple Python Sub
Interpreters" in :doc:`application-issues`.

Background threads
~~~~~~~~~~~~~~~~~~

Application code can spawn its own threads, including at module
import time. There is no fork-then-Python interaction to worry
about: Python is initialised only in the daemon process (or,
under embedded mode, in the Apache child workers), never in the
Apache parent, so a thread started at import is started in the
process that will run the application.

Two caveats apply.

Mark threads daemonic. Use ``threading.Thread(..., daemon=True)``.
Non-daemon threads block Python interpreter shutdown until they
exit, which can run into ``shutdown-timeout`` and force a hard
kill. For long-running tasks that need to stop cleanly on process
shutdown, register a ``mod_wsgi.subscribe_shutdown()`` callback
to signal the thread to exit; see :doc:`registering-cleanup-code`.

Embedded mode plus ``WSGIScriptReloading On`` is hostile to
threads started inside the WSGI script file itself. In daemon
mode a WSGI-script reload triggers a process recycle, so any
threads started from the script die with the old process. In
embedded mode the reload is in-place: the script's
``sys.modules`` entry is dropped and the script is re-imported
in the same Apache child, so a thread started from the top of
the WSGI script gets started again on every reload, accumulating
in the process. If you need to start a background thread under
this configuration, start it from a regular Python module that
the WSGI script imports rather than from the WSGI script itself.
Imported modules are not dropped from ``sys.modules`` on reload,
so their module-level code (the thread start) does not
re-execute.

WSGIScriptReloading and signal-driven restart
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Touching the WSGI script file triggers a daemon-process
restart via ``SIGINT``. The restart goes straight to
``shutdown-timeout`` without a graceful drain. If you need a
graceful drain on cutover, use ``SIGUSR1`` directly and disable
``WSGIScriptReloading`` to avoid racing the script-touch path
against the signal-driven restart. See
:doc:`upgrading-an-application` for the details.

Pool-name stability
~~~~~~~~~~~~~~~~~~~

A ``WSGIDaemonProcess`` declaration is read at Apache config
parse time. Renaming a pool requires editing
``WSGIDaemonProcess`` and reloading Apache, which is a
heavier-weight operation than a graceful daemon restart. For
patterns that rotate which pool is "live" (blue/green
upgrades), keep the pool names stable across cycles and switch
the routing layer instead.

See Also
========

* :doc:`processes-and-threading` for the Apache MPM and Python
  sub interpreter model that daemon mode builds on.
* :doc:`security-hardening` for the operational hardening of a
  daemon-mode deployment, including socket ownership and
  multi-tenant isolation.
* :doc:`upgrading-an-application` for blue/green parallel pools
  and the cutover patterns.
* :doc:`reloading-source-code` for the daemon-mode code-reload
  mechanism.
* :doc:`debugging-techniques` for log-output diagnostics.
* :doc:`../configuration-directives/WSGIDaemonProcess`,
  :doc:`../configuration-directives/WSGIProcessGroup`,
  :doc:`../configuration-directives/WSGIApplicationGroup`,
  :doc:`../configuration-directives/WSGISocketPrefix`,
  :doc:`../configuration-directives/WSGIRestrictEmbedded`, and
  :doc:`../configuration-directives/WSGIRestrictProcess` for
  the directive-level reference.
