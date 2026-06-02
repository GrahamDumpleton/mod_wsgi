=================
WSGIServerMetrics
=================

:Description: Enable Python access to Apache scoreboard data via ``mod_wsgi.server_metrics()`` from embedded mode.
:Syntax: ``WSGIServerMetrics On|Off``
:Default: ``Off``
:Context: server config

Controls whether the ``mod_wsgi.server_metrics()`` Python API is
allowed to return Apache scoreboard data when called from code
running in embedded mode (Apache child processes). With the
default ``Off``, the function returns ``None``. With ``On``, it
returns a Python dictionary describing the current state of every
Apache child process and worker slot known to the scoreboard.

The directive does not control whether the scoreboard itself is
populated. Apache populates it unconditionally as part of normal
request handling (the same data ``mod_status`` reads). The
directive gates only the Python-side access to that data; turning
it on does not impose any additional cost on requests that do not
call the function.

This directive only affects calls made from embedded mode. To
allow ``mod_wsgi.server_metrics()`` to return data when called
from a daemon process, use the
:ref:`server-metrics <server-metrics>` option on the
:doc:`WSGIDaemonProcess` directive instead. The two settings are
independent: a daemon process group is gated only by its own
``server-metrics=`` option, and this directive's value does not
propagate to daemon process groups as a default. Different daemon
groups can be allowed or denied scoreboard access individually by
setting the option differently on each ``WSGIDaemonProcess``
directive.

For most modern deployments, daemon mode is the preferred
deployment method, in which case configure scoreboard access via
``WSGIDaemonProcess`` rather than this directive.

What the call returns
---------------------

When both gates are open, ``mod_wsgi.server_metrics()`` returns a
dictionary shaped roughly as follows::

    {
        "server_limit": 256,
        "thread_limit": 25,
        "running_generation": 0,
        "restart_time": 1715242800.0,
        "current_time": 1715243000.0,
        "running_time": 200,
        "processes": [
            {
                "process_num": 0,
                "pid": 12345,
                "generation": 0,
                "quiescing": False,
                "workers": [
                    {
                        "thread_num": 0,
                        "generation": 0,
                        "status": "Ready",
                        "access_count": 1024,
                        "bytes_served": 8388608,
                        "start_time": 1715242800.0,
                        "stop_time": 1715242850.0,
                        "last_used": 1715242999.0,
                        "client": "192.0.2.5",
                        "request": "GET /api/users HTTP/1.1",
                        "vhost": "www.example.com:443",
                    },
                    ...
                ],
            },
            ...
        ],
    }

Each call walks ``server_limit × thread_limit`` scoreboard entries
and constructs a fresh Python object graph, so callers polling at
high frequency on large servers should expect a low-millisecond
cost per invocation. Apache's scoreboard slot strings are length
bounded but not otherwise filtered, so the ``client``, ``request``,
and ``vhost`` fields should be treated as untrusted input by any
consumer.

Security considerations
-----------------------

The data returned includes the client IP, the request line (HTTP
method, path, query string, and protocol), and the vhost name for
every worker slot - including workers currently servicing other
requests for other applications hosted by the same Apache instance.
Anything carried in a URL is therefore visible to any code holding
the scoreboard read capability:

* Query-string parameters, including session identifiers, API
  keys, OAuth codes, and password-reset tokens that some
  applications still pass through URL parameters.
* Request paths that themselves encode sensitive identifiers
  (account IDs, document IDs).
* Source IP addresses of every active client.

If multiple WSGI applications share one Apache instance, code
running with scoreboard access can observe live request data from
every other application on the same server. The independence of
the embedded-mode directive and the per-daemon-group option is
the lever for limiting that exposure: enable scoreboard access in
exactly the contexts that have a direct, justified need for it,
and leave it off everywhere else.

A reasonable defensive posture for shared hosting:

* Leave ``WSGIServerMetrics`` ``Off`` (the default) unless code in
  embedded mode needs to consume the API.
* For daemon mode, set ``server-metrics=on`` only on the specific
  daemon process group that runs the consumer (typically a
  service-script process behind ``--service-script`` or
  :doc:`WSGIImportScript`); leave every other daemon process
  group at the default of ``off``.
* Treat any process with scoreboard access, and any URL it serves,
  as having scoreboard-reader privilege; gate access to that URL
  with authentication, IP allow-listing, or an internal-only
  virtual host as appropriate.

See also
--------

* :doc:`WSGIDaemonProcess` for the per-daemon-group
  ``server-metrics=on`` option.
* :doc:`WSGIImportScript` for service-script processes, which are
  the typical place to call ``mod_wsgi.server_metrics()`` when the
  consumer is itself hosted by mod_wsgi.
* :doc:`../user-guides/hosting-websocket-applications` for an
  end-to-end example: a service-script sidecar that polls
  ``mod_wsgi.server_metrics()`` and pushes the snapshot over a
  WebSocket to a browser dashboard.
