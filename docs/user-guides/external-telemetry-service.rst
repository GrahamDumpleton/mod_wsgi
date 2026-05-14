==============================
The External Telemetry Service
==============================

mod_wsgi can stream live telemetry to an external ingester running
alongside the Apache instance. Each mod_wsgi process emits a binary
datagram once per sampling interval, and a separate ingester process
aggregates the stream and serves a browser UI showing per-process
throughput, latency percentiles, capacity, CPU and memory, HTTP
response-class breakdowns, and a slow-request feed. The reporter
runs in both daemon mode (one thread per daemon process) and
embedded mode (one thread per Apache MPM child).

This is the *external push* counterpart to the *internal pull*
:doc:`internal-metrics-api`. The two surfaces are independent and
present similar data:

* The internal API exposes accessors callable from inside the WSGI
  application, so the application owns its data and the choice of
  destination.
* The external service is configured in the Apache config; the data
  flows out over a UNIX socket without involving the application at
  all, and the bundled ingester gives an immediate live UI.

Only one of the two will return data at a time in a given process:
when the external reporter is configured, the in-process accessors
return ``None`` so the application can detect that the external
pipeline owns the stream.

The ingester is distributed separately on PyPi as the
``mod_wsgi-telemetry`` package. It is intentionally not part of the
``mod_wsgi`` package or ``mod_wsgi-express``, so an installation
using the operating-system ``mod_wsgi`` package (or any other
manually-configured Apache) can use the telemetry pipeline without
adopting ``mod_wsgi-express`` as well.

How it works
------------

Each process hosting a WSGI application runs a single dedicated
reporter thread. In daemon mode that is the daemon process; in
embedded mode it is the Apache MPM child. On a fixed interval the
thread snapshots the process's per-interval counters and
slow-request records, encodes them as a binary type-length-value
datagram, and sends the datagram over a UNIX SOCK_DGRAM socket to
the ingester. The reporter does not block the request-serving
threads; it reads from accumulators that the request path updates
under a brief, contended-rarely lock.

Datagrams are sent unreliably (SOCK_DGRAM has no retransmit), but
co-locating the ingester on the same host makes practical loss
negligible. There is no fallback to TCP or remote UDP: the
transport is local-host only, so MTU sizing, packet fragmentation
across the network, and inter-host packet loss are not part of the
operating model. To ship telemetry across hosts, run a local
ingester on each host and forward its data from there using a
tool of your choice.

The ingester opens the same UNIX socket in listening mode, decodes
incoming datagrams, maintains a rolling per-process window in
memory, and exposes the result over an HTTP + WebSocket interface
that the browser UI and the terminal monitor both consume.

What you observe
----------------

Per process, per sampling interval:

* Request throughput (requests per second) and counts split by HTTP
  response class (``1xx`` / ``2xx`` / ``3xx`` / ``4xx`` / ``5xx``).
* Latency distribution for each phase of the request pipeline
  (server-side wait, queue, daemon dispatch, application, full
  request) as an HDR-style histogram, with ``p50`` / ``p95`` /
  ``p99`` and exact min/max.
* Capacity: how many of the worker slots are currently busy and how
  long any in-flight request has been running.
* Resource use: CPU time (user + system) and resident set size.
* Slow-request records: per-request snapshots for requests that
  exceeded the configured threshold, including elapsed time,
  request method, URL path (query string stripped), HTTP status,
  and (optionally) the ``User-Agent`` string.

The data is aggregated across every process configured to report,
and grouped in the UI by process group so a server hosting multiple
WSGI applications can be viewed as a whole or one group at a time.

Enabling the reporter in a manually-configured Apache
-----------------------------------------------------

Three directives drive the reporter. All three are server-wide
directives: they must be declared at the top level of the Apache
configuration, outside any ``<VirtualHost>`` block. Apache rejects
the config at startup if they appear in a per-vhost or per-directory
context. One configuration covers the whole Apache instance: every
embedded-mode Apache MPM child and every daemon-mode worker process
defined on the server starts a reporter from the same
``WSGITelemetryService`` line.

``WSGITelemetryService TARGET [interval=SECONDS]``
   Enable the reporter and point it at the ingester. ``TARGET`` is
   the UNIX socket path in the form ``unix:/path/to/socket``. The
   optional ``interval=`` parameter sets the sampling interval in
   seconds (default ``1.0``, minimum ``0.1``). The reporter starts
   in every mod_wsgi process (each daemon-mode worker and each
   embedded-mode Apache MPM child) when the directive is set;
   without it the reporter thread is not created.

``WSGITelemetryOptions [+|-]Flag [+|-]Flag ... | None | All``
   Capture toggles for fields that are off by default for privacy
   or volume reasons. The currently-defined flag is
   ``CaptureUserAgent``, which adds the request's ``User-Agent``
   string to slow-request records. The ``+Flag`` / ``-Flag``
   incremental form composes across multiple lines; absolute
   ``None`` and ``All`` set the state directly.

``WSGISlowRequests SECONDS``
   Enable slow-request reporting and set the threshold above which
   a still-running request is included in the stream. Only
   meaningful alongside ``WSGITelemetryService``; without an
   ingester to receive them the records have no destination.

A typical configuration for a single application::

    LoadModule wsgi_module modules/mod_wsgi.so

    # Server-wide: one declaration enables the reporter for every
    # mod_wsgi process Apache starts, regardless of how many
    # VirtualHosts or daemon pools the configuration defines.
    WSGITelemetryService unix:/tmp/mod_wsgi-telemetry.sock interval=1.0
    WSGITelemetryOptions +CaptureUserAgent
    WSGISlowRequests 2.0

    WSGIDaemonProcess example processes=2 threads=15

    <VirtualHost *:80>
        ServerName www.example.com
        WSGIScriptAlias / /var/www/example/wsgi.py
        WSGIProcessGroup example
        WSGIApplicationGroup %{GLOBAL}

        <Directory /var/www/example>
            Require all granted
        </Directory>
    </VirtualHost>

When more than one application is hosted on the same Apache, the
``WSGITelemetryService`` line is still declared once. Each daemon
process and each embedded-mode Apache child reports independently;
the ingester aggregates them and groups by ``WSGIDaemonProcess``
name in the UI.

The socket path is the contract between Apache and the ingester:
the same path must appear on both sides. The mod_wsgi process must
be able to ``connect()`` to the socket; the ingester creates it
with the permissions of the user it runs as, so either run the
ingester as the same user as the mod_wsgi processes that need to
connect (the ``user=`` value on ``WSGIDaemonProcess`` in daemon
mode, or the Apache child user in embedded mode) or set the
socket's mode wide enough for both.

Enabling the reporter with mod_wsgi-express
-------------------------------------------

``mod_wsgi-express`` translates the directives above into the
generated ``httpd.conf``. The equivalent command-line options are:

``--telemetry-service TARGET``
    Enable the reporter and set the ingester socket. Same
    ``unix:/path`` form as the directive value.

``--telemetry-interval SECONDS``
    Sampling interval (default ``1.0``). Sub-second intervals are
    permitted down to ``0.1``.

``--telemetry-options ARGS``
    Capture toggles. The value is passed verbatim to a
    ``WSGITelemetryOptions`` directive in the generated config, so
    the ``+Flag`` / ``-Flag`` / ``None`` / ``All`` forms are
    available. Repeatable; each occurrence emits a separate
    directive.

``--slow-requests SECONDS``
    Slow-request threshold. Requires ``--telemetry-service``;
    ``mod_wsgi-express`` rejects the option at startup if no
    telemetry target was given.

The equivalent of the manual configuration above::

    mod_wsgi-express start-server wsgi.py \
        --processes 2 --threads 15 \
        --telemetry-service unix:/tmp/mod_wsgi-telemetry.sock \
        --telemetry-interval 1.0 \
        --telemetry-options "+CaptureUserAgent" \
        --slow-requests 2.0

Running the ingester
--------------------

Install the ingester from PyPi into a virtual environment::

    python3 -m venv /opt/mod_wsgi-telemetry
    /opt/mod_wsgi-telemetry/bin/pip install mod_wsgi-telemetry

Start it on the same host as the mod_wsgi Apache instance, with
``--listen`` pointing at the same UNIX socket that the reporter
sends to::

    /opt/mod_wsgi-telemetry/bin/mod_wsgi-telemetry serve \
        --listen unix:/tmp/mod_wsgi-telemetry.sock

A bare ``mod_wsgi-telemetry`` invocation defaults to ``serve``, so
the subcommand name can be omitted once the install path is on
``PATH``::

    mod_wsgi-telemetry --listen unix:/tmp/mod_wsgi-telemetry.sock

The ingester binds the socket itself, so do not run it on a host
where another process is already bound to the path. If the socket
file is left behind from a previous run it will be removed and
recreated.

By default the ingester also serves an HTTP + WebSocket interface
on ``127.0.0.1:8888`` for the browser UI and the terminal monitor.
Override the bind address with ``--http-host`` and the port with
``--http-port``::

    mod_wsgi-telemetry serve --http-port 9080

Running the ingester as a long-lived service is the expected
deployment shape. A simple systemd unit for the install path above
would look like::

    [Unit]
    Description=mod_wsgi telemetry ingester
    After=network.target

    [Service]
    Type=simple
    User=www-data
    ExecStart=/opt/mod_wsgi-telemetry/bin/mod_wsgi-telemetry serve \
        --listen unix:/tmp/mod_wsgi-telemetry.sock
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

Running it as the same user as the mod_wsgi processes avoids the
socket-permissions issue mentioned in the manual-configuration
section.

The browser UI
--------------

Open ``http://127.0.0.1:8888`` in a browser on the same host as
the ingester. The page is a single-page application served from
the ingester; it opens a WebSocket back to the same port and
shows a persistent top bar (totals, process-group filter, marker
toggles, connection state) above four tabs:

``Overview``
    Live sparkline charts for throughput, capacity utilisation,
    CPU, response time and memory RSS, with a per-phase mean-time
    breakdown and an HDR-style latency distribution histogram for
    the selected phase.

``Capacity``
    Per-process worker-slot heatmap. Each row is a process; each
    cell is one worker slot shaded by busy fraction over the
    interval, with marker overlays for slots holding a request
    past a selectable threshold. Hover for the live URL of any
    slot currently busy, click to open the slow-request
    drill-down.

``Processes``
    Process timeline (Gantt-style bars spanning each process's
    STARTED-to-STOPPED lifetime, with a tick mark at STOPPING for
    drain start) and an event log of lifecycle events that links
    back into the timeline.

``Slow requests``
    Live slow-request table with sorting, state filter (active /
    completed), URL substring search and per-record drill-down.

The UI binds to ``127.0.0.1`` by default rather than ``0.0.0.0``.
Telemetry data includes details that operators would not normally
expose unauthenticated (the live URL stream and User-Agent
captures in particular); leaving the bind on loopback ensures the
UI is reachable only from the host itself.

Terminal monitor
----------------

The same data is available as a curses-based terminal monitor for
hosts where opening a browser is impractical (SSH-only servers,
sandboxed deployment shapes, scripted health checks). The monitor
is a separate subcommand of the same binary::

    mod_wsgi-telemetry top

It connects to a running ingester's WebSocket by default at
``ws://127.0.0.1:8888/ws``. Override with ``--url`` to connect to
an ingester on a different host or port (combine with the SSH
tunnel pattern below to monitor a remote host without exposing the
UI externally).

The monitor renders the same underlying data as the browser UI
but with a layout tuned to the terminal. Five views are
switchable by single keystroke (``o``, ``p``, ``w``, ``l``, ``s``
or the digits ``1`` to ``5``):

``overview``
    Sparklines for throughput, capacity, CPU and resident memory,
    plus a summary of per-phase mean times.

``processes``
    A per-process table sortable by throughput, CPU, memory,
    ``p95``, slow-request count, or PID.

``workers``
    A per-process slot grid showing which worker threads are
    idle, busy with short requests, busy with longer requests, or
    holding a request past the slow-request threshold.

``latency``
    An ASCII HDR histogram for the selected phase, with ``p50`` /
    ``p95`` / ``p99`` markers.

``slow``
    A live slow-request list with sorting, state filtering and a
    URL substring search.

Common keys: ``space`` to pause/resume, ``q`` to quit, ``?`` for
an in-monitor help overlay listing the full set.

For scripted use, ``--once`` renders a single plain-text snapshot
of the header and process table to stdout and exits; the exit code
is ``0`` if a snapshot was received and ``2`` if the connection
attempt timed out. This makes the monitor usable as a healthcheck
or a shell-pipeline data source.

Accessing the UI from a remote host
-----------------------------------

The ingester binds to ``127.0.0.1`` on purpose. The two safe ways
to reach it from elsewhere are an SSH tunnel and an
authenticated reverse proxy.

SSH tunnel
~~~~~~~~~~

The simplest option for an operator with shell access to the host
is an SSH local port forward. From the operator's workstation::

    ssh -L 8888:127.0.0.1:8888 user@host.example.com

The browser then connects to ``http://localhost:8888`` on the
local workstation. The forward stays up for the lifetime of the
SSH session and tears down cleanly when the session ends. The
ingester does not need any reconfiguration and there is no
network exposure on the remote host.

For the terminal monitor running on the operator's workstation,
point ``--url`` at the forwarded port::

    mod_wsgi-telemetry top --url ws://localhost:8888/ws

Apache reverse proxy with basic authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the UI needs to be reachable to a small group of operators
without each one running an SSH tunnel, an authenticated reverse
proxy in the same Apache instance that hosts the WSGI application
is a practical option. The configuration is a standard
``mod_proxy`` mount paired with an ``AuthType Basic`` block::

    <Location /telemetry/>
        ProxyPass        http://127.0.0.1:8888/ upgrade=websocket
        ProxyPassReverse http://127.0.0.1:8888/

        AuthType Basic
        AuthName "mod_wsgi telemetry"
        AuthUserFile /etc/apache2/telemetry.htpasswd
        Require valid-user
    </Location>

The ``upgrade=websocket`` parameter on ``ProxyPass`` is what makes
the live data stream work: the browser UI opens a WebSocket back
to the ingester for live updates, and ``mod_proxy_http`` handles
the protocol upgrade in place. This requires Apache 2.4.47 or
newer; on older versions the same effect needs an explicit
``ProxyPass`` line using the ``ws://`` scheme and the
``mod_proxy_wstunnel`` module.

Create the password file with ``htpasswd``::

    htpasswd -c /etc/apache2/telemetry.htpasswd alice

For the manually-configured Apache the proxy block goes alongside
the WSGI mount. For ``mod_wsgi-express``, the equivalent shape uses
``--proxy-mount-point`` to add the proxy mount to the generated
configuration::

    mod_wsgi-express start-server wsgi.py \
        --telemetry-service unix:/tmp/mod_wsgi-telemetry.sock \
        --proxy-mount-point /telemetry/ http://127.0.0.1:8888/ \
        --include-file /etc/apache2/telemetry-auth.conf

The ``--include-file`` points at a small fragment with the
``AuthType Basic`` block (``mod_wsgi-express`` has no dedicated
option for HTTP basic auth, so the fragment supplies the
directives directly). The fragment::

    <Location /telemetry/>
        AuthType Basic
        AuthName "mod_wsgi telemetry"
        AuthUserFile /etc/apache2/telemetry.htpasswd
        Require valid-user
    </Location>

See :doc:`running-behind-a-reverse-proxy` for the broader
conventions around mod_proxy and forwarded-header trust; the
mechanics there apply identically when Apache is the proxy in
front of the telemetry ingester rather than the WSGI back-end.

.. warning::

   Each open browser tab on the UI holds a long-lived WebSocket
   connection that occupies one Apache worker thread for its
   entire lifetime. With the worker MPM's default
   ``ThreadsPerChild`` and even with the event MPM (which still
   commits one thread per upgraded connection), a handful of
   open tabs is fine but a wide audience is not: leaving the
   dashboard pinned across an organisation can starve real
   request-serving capacity. The reverse-proxy pattern is
   intended for a small operator group, not a public dashboard.

   For larger audiences, run a dedicated Apache instance for the
   telemetry UI on its own port, with its own MPM sizing, so its
   long-lived connections cannot affect the application's
   request-serving capacity.

Where to go next
----------------

* :doc:`internal-metrics-api` for the in-process accessor API that
  is the alternative to the external service. Choose the external
  service when you want an out-of-the-box live UI; choose the
  internal API when the application should own the metrics
  destination.
* :doc:`running-behind-a-reverse-proxy` for the trust mechanics
  and proxy configuration patterns that apply to any HTTP-level
  proxying in front of mod_wsgi, including the telemetry UI.
* :doc:`mod-wsgi-express-quickstart` for the ``mod_wsgi-express``
  options that surround ``--telemetry-service`` in a real
  invocation.
