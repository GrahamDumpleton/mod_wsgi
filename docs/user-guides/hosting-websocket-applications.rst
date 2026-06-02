==============================
Hosting WebSocket Applications
==============================

mod_wsgi cannot serve a WebSocket endpoint. The WSGI specification
is a request/response model with a synchronous ``start_response``
plus iterable body, and has no way to negotiate an ``Upgrade``
handshake or carry bidirectional frames after one. This is a
limitation of WSGI, not of mod_wsgi specifically; ASGI and the
non-WSGI Python frameworks (Starlette, FastAPI, aiohttp,
hypercorn-hosted Django Channels, and so on) exist precisely to
fill this gap.

What mod_wsgi can do is run a separate WebSocket-capable
application as a *sidecar* process while continuing to serve the
main WSGI application normally, and use Apache's ``mod_proxy`` to
route WebSocket-bearing URLs to that sidecar. This page walks
through the deployment shape, the mod_wsgi-specific way of
hosting the sidecar via a service script, the proxy wiring, and
the capacity implications. The worked example at the end is a
small live Apache server-metrics dashboard, which fits naturally
because reading mod_wsgi's scoreboard requires the sidecar to run
inside mod_wsgi.

The deployment shape
--------------------

Two long-lived processes share one Apache instance:

::

    +--------+      +-----------------------------------------+
    | client | ---> | Apache + mod_wsgi (front-end)           |
    +--------+      |   :443  / *           --> WSGI app      |
                    |        /ws/*          --> proxy to:     |
                    |                                         |
                    |   sidecar: aiohttp on 127.0.0.1:8765    |
                    +-----------------------------------------+

* The WSGI application stays exactly as it is, served by mod_wsgi
  in daemon (or embedded) mode.
* A separate WebSocket-capable Python process runs alongside it
  on a private listener (loopback TCP or a unix-domain socket).
* Apache routes WebSocket-bearing URLs to the sidecar via
  ``mod_proxy`` and ``mod_proxy_http`` (with the ``upgrade=
  websocket`` parameter on ``ProxyPass``); everything else
  continues to be handled by the WSGI application.

The two processes are independent at the Python level. They do
not share Python objects, in-memory state, or imported modules.
If the WebSocket side needs to react to events in the WSGI side
(or vice versa), the integration goes through some out-of-process
medium: a Redis pub/sub, a database row, a message queue, or a
local socket. Designing that integration is outside the scope of
this page; what follows is the deployment plumbing.

Hosting the sidecar via a service script
----------------------------------------

mod_wsgi can run the sidecar process itself rather than leaving
it to systemd, supervisor, or a separate process manager. The
mechanism is the **service script**: a Python script imported
into a daemon process group dedicated to running it forever, with
``threads=0`` so the daemon does not participate in normal request
handling.

For a manually-configured Apache, two directives do the work:

* :doc:`../configuration-directives/WSGIDaemonProcess` declares
  the daemon process group with ``threads=0`` (no request
  handling) and any options the script needs (``server-metrics=
  on`` for the example below).
* :doc:`../configuration-directives/WSGIImportScript` imports
  the script into that process group at start-up. The script's
  top-level code runs as the daemon process body; if it never
  returns (because it enters an event loop, for example), the
  daemon process simply runs that loop until Apache shuts it
  down.

::

    WSGIDaemonProcess metrics-sidecar \
        threads=0 server-metrics=on
    WSGIImportScript /etc/mod_wsgi/server_metrics_sidecar.py \
        process-group=metrics-sidecar \
        application-group=%{GLOBAL}

For ``mod_wsgi-express``, the equivalent is the
``--service-script`` option, which translates into the directive
pair above::

    mod_wsgi-express start-server wsgi.py \
        --service-script metrics-sidecar \
            /etc/mod_wsgi/server_metrics_sidecar.py

The first argument names the daemon process group; the second is
the path to the script. The script can use any framework that
runs in a single process; aiohttp, Starlette with uvicorn started
programmatically, or a hand-rolled ``asyncio`` server are all
fine. The script is imported once; if its top-level code starts
an event loop with ``asyncio.run(...)``, that call blocks for
the lifetime of the process and Apache treats the still-running
import as a healthy daemon.

A service-script daemon process sits outside the normal daemon
recycling triggers: ``maximum-requests`` does not apply (the
process handles no requests), and the per-request inactivity
timers do not either. The only restart triggers are an Apache
restart and an external signal. When the script does start
afresh, it is re-imported in the new process; the sidecar must
not keep state in process memory that the WSGI side relies on
persisting across restarts.

Why the service script, rather than an external process
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A WebSocket sidecar can equally well be started by systemd or
any other process supervisor. The reasons to prefer a service
script are pragmatic:

* The sidecar's lifecycle is tied to Apache's. Restarting
  Apache restarts the sidecar; stopping Apache stops the
  sidecar. There is no second supervisor to keep in sync.
* The sidecar runs as the same user, with the same Python
  environment, working directory, and ``python-path`` as the
  WSGI application. There is no second virtual environment or
  service unit to maintain.
* The sidecar can call ``import mod_wsgi`` and use the
  in-process API the running Apache exposes. Reading
  ``mod_wsgi.server_metrics()`` (the example below) is a
  primary case; only a process running inside mod_wsgi has
  access to the Apache scoreboard.

The third point is the one that promotes the service script
from convenient to required: an external sidecar cannot use the
mod_wsgi Python API to read the scoreboard, so an Apache
metrics dashboard genuinely needs the in-process route.

Listener: loopback TCP or unix socket
-------------------------------------

The sidecar must listen somewhere the front-end Apache can reach
it but external clients cannot. Two choices.

Loopback TCP (``127.0.0.1:NNNN``) is the simpler one. Most
async frameworks accept a host/port out of the box. Pick a port
that is not in use and bind to ``127.0.0.1`` (not ``0.0.0.0``)
so the sidecar is not exposed on the network. The proxy URL is
then ``http://127.0.0.1:NNNN/``.

A unix-domain socket avoids port allocation and is reachable
only via the filesystem path, so its access is naturally scoped
by directory permissions. Most async frameworks support binding
to a unix socket through a ``--uds`` or ``path=`` argument
(uvicorn, hypercorn, aiohttp's ``UnixSite``). The proxy URL
takes Apache's unix-socket form ``unix:/var/run/sidecar.sock|http://localhost/``; the host name after ``|`` is a syntactic
placeholder, not used for routing. See
:doc:`running-behind-a-reverse-proxy` for the URL form details.

Either choice works equally well with the proxy options
described below. The example in this page uses loopback TCP for
clarity; the unix-socket form is a one-line substitution on the
``--proxy-mount-point`` URL.

Wiring the Apache proxy
-----------------------

The proxy mechanics, including the headers Apache adds, the
trust list mod_wsgi consults on the receiving side, and how
``X-Forwarded-Prefix`` is handled, are covered in detail in
:doc:`running-behind-a-reverse-proxy`. The summary for this
page:

* ``--proxy-mount-point /ws/ http://127.0.0.1:8765/`` mounts the
  sidecar under a sub-URL of the main site. ``mod_wsgi-express``
  emits a ``ProxyPass`` with ``upgrade=websocket``, a
  ``ProxyPassReverse`` for back-end-emitted redirects, and
  ``RequestHeader set X-Forwarded-Prefix /ws`` so the sidecar
  can construct correct URLs in any HTML, JSON, or WebSocket
  greeting it serves.
* ``--proxy-virtual-host ws.example.com http://127.0.0.1:8765/``
  proxies an entire hostname to the sidecar. No prefix is
  stripped, so the sidecar sees the same URL space as the
  client and ``X-Forwarded-Prefix`` is not relevant.

The equivalent raw directive form for the sub-URL case::

    ProxyPass        /ws/ http://127.0.0.1:8765/ upgrade=websocket
    ProxyPassReverse /ws/ http://127.0.0.1:8765/
    <Location "/ws/">
        RequestHeader set X-Forwarded-Prefix /ws
    </Location>

If ``--proxy-mount-point`` is given a path without a trailing
slash (``/ws`` rather than ``/ws/``), ``mod_wsgi-express`` adds a
302 redirect from the bare prefix to the slash form
automatically. Specifying the trailing-slash form directly
avoids that hop.

The sidecar must either honour ``X-Forwarded-Prefix`` per
request (the worked example below does this directly in its
index handler; an aiohttp middleware can do the same, and ASGI
apps can read it from the request scope) or be told its mount
point at construction time (``Starlette(..., root_path="/ws")``,
``FastAPI(root_path="/ws")``). Either approach makes the
sidecar emit prefix-correct URLs; mixing them is harmless if
both produce the same prefix and a configuration error
otherwise.

Capacity considerations
-----------------------

WebSocket connections through ``mod_proxy_http`` are long-lived
and tunnelled through an Apache worker. This has direct
consequences for sizing, and is the part of this deployment
shape most often missed.

Each open WebSocket holds one Apache worker for its lifetime.
On ``mpm_event`` and ``mpm_worker`` that is one thread; on
``mpm_prefork`` it is one whole process. The connection is not
returned to the pool while the WebSocket is open. This is true
regardless of whether the upgraded connection is exchanging
frames or sitting idle.

``MaxRequestWorkers`` (or its mod_wsgi-express equivalent
``--server-mpm`` plus the per-MPM tuning options) must therefore
cover the sum of:

* Peak concurrent HTTP requests handled by the WSGI app and any
  static-file routes.
* Peak concurrent WebSocket clients connected through the
  sidecar.

A server tuned for 50 concurrent HTTP requests that suddenly
takes 200 concurrent WebSocket connections will not just slow
down WebSocket traffic; it will starve the WSGI side too,
because all 50 worker slots are being held by WebSockets.

Practical guidance:

* Scope the sidecar URL space to the actual WebSocket endpoints
  (``/ws/``, ``/notifications/ws``) rather than mounting the
  whole sidecar at the site root, so HTTP traffic is never
  competing with WebSocket connections for the same worker
  pool.
* Heartbeats from the client side reduce silent half-open
  connections (a TCP connection that died without a clean
  close), but a healthy idle WebSocket still costs a worker.
  The trade-off is between holding the connection open
  (responsive reconnects, lower latency on the next message)
  and freeing the worker (higher capacity ceiling).
* The ``--proxy-timeout SECONDS`` option (see
  :doc:`running-behind-a-reverse-proxy`) raises the idle-WS
  ceiling on the front-end by overriding ``ProxyTimeout`` for
  proxied connections only, leaving the regular request-handling
  timeout untouched. Use it when WebSocket clients do not
  heartbeat more often than ``--socket-timeout`` (default 60
  seconds), to prevent Apache dropping them as idle.
* The sidecar's own concurrency limit is independent. A single
  asyncio process can hold thousands of WebSocket connections
  cheaply; the bottleneck is almost always the front-end
  Apache worker pool, not the sidecar.

Worked example: live Apache server-metrics dashboard
----------------------------------------------------

The example is a small dashboard that reads the Apache scoreboard
once a second and pushes a snapshot to any browser connected via
WebSocket. It demonstrates every piece of the deployment shape:
the service script, the loopback listener, the sub-URL proxy
mount, ``X-Forwarded-Prefix`` propagation, and the in-process
``mod_wsgi`` API that motivates the service-script choice in the
first place.

The WSGI application is left unspecified. Anything mod_wsgi
already serves works; the example does not modify the WSGI app
in any way. Treat it as a black box at the site root.

The sidecar
~~~~~~~~~~~

Save this as ``/etc/mod_wsgi/server_metrics_sidecar.py``::

    """Live Apache server-metrics dashboard.

    Imported into a WSGIDaemonProcess group with threads=0 and
    server-metrics=on. Polls the scoreboard once a second and
    fans the snapshot out to any WebSocket clients.
    """

    import asyncio
    import json
    import logging

    import mod_wsgi
    from aiohttp import WSMsgType, web

    log = logging.getLogger("server-metrics-sidecar")

    POLL_INTERVAL = 1.0

    INDEX_HTML = """\
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="utf-8"><title>mod_wsgi metrics</title></head>
    <body>
    <pre id="out">connecting...</pre>
    <script>
      const base = window.METRICS_BASE || "";
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}${base}/ws`);
      const out = document.getElementById("out");
      ws.onopen = () => out.textContent = "connected";
      ws.onmessage = e => out.textContent = e.data;
      ws.onclose = () => out.textContent = "disconnected";
    </script>
    </body>
    </html>
    """

    async def index(request: web.Request) -> web.Response:
        # X-Forwarded-Prefix is set by mod_wsgi-express's
        # --proxy-mount-point, or by the equivalent RequestHeader
        # in raw Apache config. Inject it so the JS builds the
        # WebSocket URL with the right prefix when the sidecar is
        # mounted under a sub-URL.
        base = request.headers.get("X-Forwarded-Prefix", "").rstrip("/")
        inject = f'<script>window.METRICS_BASE = {json.dumps(base)};</script>\n'
        return web.Response(
            text=INDEX_HTML.replace("</head>", inject + "</head>", 1),
            content_type="text/html",
        )

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        request.app["clients"].add(ws)
        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            request.app["clients"].discard(ws)
        return ws

    async def metrics_loop(app: web.Application) -> None:
        while True:
            snapshot = mod_wsgi.server_metrics()
            if snapshot is None:
                payload = json.dumps({
                    "error": (
                        "scoreboard access is not enabled for this daemon "
                        "process group; set server-metrics=on on its "
                        "WSGIDaemonProcess directive (or pass "
                        "--server-metrics to mod_wsgi-express)"
                    ),
                }, indent=2)
            else:
                payload = json.dumps({"snapshot": snapshot}, indent=2)
            for ws in list(app["clients"]):
                try:
                    await ws.send_str(payload)
                except ConnectionResetError:
                    pass
            await asyncio.sleep(POLL_INTERVAL)

    async def serve() -> None:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
        app = web.Application()
        app["clients"] = set()
        app.router.add_get("/", index)
        app.router.add_get("/ws", ws_handler)

        async def start_loop(_: web.Application) -> None:
            app["loop_task"] = asyncio.create_task(metrics_loop(app))
        app.on_startup.append(start_loop)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 8765)
        await site.start()
        log.info("server-metrics sidecar on 127.0.0.1:8765")
        await asyncio.Event().wait()

    asyncio.run(serve())

Three things are worth pointing out about the script.

The top-level call to ``asyncio.run(serve())`` is what makes
this a service script rather than an ordinary Python module. It
never returns: ``serve()`` brings up the aiohttp app and then
awaits an event that is never set, so the import call never
completes. ``WSGIImportScript`` is happy with this; the daemon
process just stays in that import for its lifetime.

``mod_wsgi.server_metrics()`` returns ``None`` unless the daemon
process group running the script was configured with
``server-metrics=on``. The script runs in a daemon process, so
that per-group option is the only flag that matters; the
server-wide :doc:`../configuration-directives/WSGIServerMetrics`
directive only applies in embedded mode and does not propagate to
daemon groups. The script handles the ``None`` case explicitly by
broadcasting an error frame so the dashboard tells the user which
option they forgot rather than silently showing stale data. The
directive page also covers the information-disclosure implications
of opening the API up.

The ``X-Forwarded-Prefix`` handling in ``index`` is what makes
the dashboard work both directly (``http://127.0.0.1:8765/``,
no header, no prefix) and behind the proxy at a sub-URL
(``https://www.example.com/metrics/``, header set by the
proxy, JS builds ``wss://.../metrics/ws``). The sidecar does
not need a startup-time ``--root-path`` analogue; the header
tells it per-request.

Wiring it up: ``mod_wsgi-express``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    mod_wsgi-express start-server wsgi.py \
        --server-metrics \
        --service-script metrics-sidecar \
            /etc/mod_wsgi/server_metrics_sidecar.py \
        --proxy-mount-point /metrics/ http://127.0.0.1:8765/

What each option contributes:

* ``--server-metrics`` sets ``server-metrics=on`` on every daemon
  process group ``mod_wsgi-express`` creates, including the one
  ``--service-script`` adds. That per-group option is what
  actually gates the sidecar's
  ``mod_wsgi.server_metrics()`` calls; the same flag also emits
  ``WSGIServerMetrics On`` at server scope, which is what would
  gate the same call from any embedded-mode handler in the
  generated configuration.
* ``--service-script`` declares the daemon process group
  (``service:metrics-sidecar``) with ``threads=0`` and starts
  the script in it.
* ``--proxy-mount-point`` emits the ``ProxyPass`` /
  ``ProxyPassReverse`` pair with ``upgrade=websocket``, the
  ``X-Forwarded-Prefix`` header, and the bare-``/metrics``
  redirect, all as a unit.

Wiring it up: manually-configured Apache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The same configuration as a set of directives, suitable for
inclusion in a ``<VirtualHost>`` block in a system Apache
configuration::

    LoadModule proxy_module        modules/mod_proxy.so
    LoadModule proxy_http_module   modules/mod_proxy_http.so

    WSGIDaemonProcess metrics-sidecar \
        threads=0 server-metrics=on
    WSGIImportScript /etc/mod_wsgi/server_metrics_sidecar.py \
        process-group=metrics-sidecar \
        application-group=%{GLOBAL}

    ProxyPass        /metrics/ http://127.0.0.1:8765/ upgrade=websocket
    ProxyPassReverse /metrics/ http://127.0.0.1:8765/
    <Location "/metrics/">
        RequestHeader set X-Forwarded-Prefix /metrics
    </Location>
    RedirectMatch 301 "^/metrics$" "/metrics/"

Note that the raw form does not include ``WSGIServerMetrics On``.
The sidecar runs in a daemon process, so the only flag that
gates its ``mod_wsgi.server_metrics()`` calls is the
``server-metrics=on`` option on the ``WSGIDaemonProcess``
directive that hosts it. The server-wide
:doc:`../configuration-directives/WSGIServerMetrics` directive
applies only to embedded mode and does not propagate to daemon
process groups; it would only be needed here if some other
handler running in an Apache child process also called the same
API.

What the user sees
~~~~~~~~~~~~~~~~~~

A request to ``https://www.example.com/metrics/`` lands on the
front-end Apache, gets proxied to the sidecar at
``127.0.0.1:8765``, and arrives there as ``GET /``. The sidecar
serves the dashboard HTML with ``window.METRICS_BASE = "/metrics"``
injected. The dashboard JS opens a WebSocket to
``wss://www.example.com/metrics/ws``, which Apache tunnels
through to the sidecar at ``ws://127.0.0.1:8765/ws``. The
metrics loop pushes a JSON snapshot of the scoreboard once a
second, and the dashboard renders it. Restricting access to
this page (it exposes per-request URLs in the scoreboard) is a
job for the front-end ``<Location>`` block: typically basic
authentication, IP allow-listing, or moving the dashboard onto
an internal-only virtual host.

What this shape does not give you
---------------------------------

A few common expectations the WSGI-plus-WebSocket-sidecar shape
does *not* meet, listed because they are easier to forestall
than to debug.

* **No shared Python state between the WSGI application and the
  sidecar.** The two are different processes. Sharing state
  needs an out-of-process medium: Redis, a database, a message
  queue, a local file. The simple-looking case "the sidecar
  pushes a notification when the WSGI app saves a record"
  always reduces to "the WSGI app writes somewhere the sidecar
  is watching".
* **The service script is not a request entry point.** A
  daemon process group with ``threads=0`` does not handle HTTP
  requests for mod_wsgi; the WSGI parts of the application
  cannot land in this process. URL routes that need to be
  served by the WSGI app must continue to be served by the WSGI
  app.
* **The WebSocket app cannot be hosted by mod_wsgi's daemon
  workers.** Even though the sidecar runs in a mod_wsgi-managed
  process, it is reached over a private network listener, not
  through mod_wsgi's request-dispatch path. There is no
  way to fold WebSocket handling into the same daemon process
  group that serves WSGI requests.
* **Scoreboard data in the example is per-Apache-instance.** A
  dashboard running on one host shows that host's scoreboard
  only, not an aggregate across a load-balanced fleet. Cluster
  monitoring needs aggregation upstream of the sidecar
  (Prometheus, statsd, or a dedicated metrics service).

Where to go next
----------------

* :doc:`running-behind-a-reverse-proxy` for the proxy
  configuration details, the forwarded-headers convention, and
  capacity tuning when the front-end is itself a separate
  Apache, nginx, or cloud load balancer rather than the same
  ``mod_wsgi-express`` instance hosting the sidecar.
* :doc:`../configuration-directives/WSGIServerMetrics` for the
  directive-level reference of the scoreboard-access flag the
  worked example exercises, including the information-disclosure
  considerations the dual-flag arrangement is intended to limit.
* :doc:`../configuration-directives/WSGIDaemonProcess` and
  :doc:`../configuration-directives/WSGIImportScript` for the
  directive-level reference of the two pieces that the service
  script is built from.
* :doc:`processes-and-threading` for sizing the front-end
  Apache worker pool, which is the part of this deployment
  shape that capacity planning hinges on.
* :doc:`mod-wsgi-express-quickstart` for ``mod_wsgi-express``
  options in general.
