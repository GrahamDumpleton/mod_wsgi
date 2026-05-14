Overview
--------

The ``mod_wsgi-telemetry`` package provides an external telemetry
ingester and live UI for the mod_wsgi Apache module. With the
``WSGITelemetryService`` directive enabled in Apache, each mod_wsgi
process (daemon-mode worker or embedded-mode Apache child) emits
per-interval binary datagrams summarising its throughput, latency
distribution, capacity utilisation, CPU and memory consumption, and
any active slow requests. The ingester receives those datagrams over
a local UNIX socket, aggregates them across every reporting process,
and serves a browser-based live UI together with a curses terminal
monitor for hosts where opening a browser is impractical.

The package is distributed separately from ``mod_wsgi`` itself so
that an installation using the operating-system ``mod_wsgi`` package,
or any other manually-configured Apache, can use the telemetry
pipeline without adopting the PyPi ``mod_wsgi`` or
``mod_wsgi-express`` packages.

The ingester is intended to run co-located with the Apache instance
it observes: the transport is a local UNIX datagram socket, and the
UI binds to the loopback interface by default. For remote access,
either an SSH tunnel or an authenticated reverse proxy is
recommended.

Once installed, launch the ingester with::

    mod_wsgi-telemetry serve

It binds ``unix:/tmp/mod_wsgi-telemetry.sock`` for incoming
datagrams and serves the browser UI on ``http://127.0.0.1:8888/`` by
default. A ``mod_wsgi-telemetry top`` subcommand provides a
curses-based terminal monitor for the same data.

For the full configuration reference, including the
``WSGITelemetryService``, ``WSGITelemetryOptions`` and
``WSGISlowRequests`` Apache directives, the matching
``mod_wsgi-express`` options, socket-permission handling for
multi-user deployments, and the remote-access patterns, see the
External Telemetry Service page in the mod_wsgi documentation site
at https://www.modwsgi.org.

This package is still being iterated on. The directive set, option
names, wire format and ingester CLI may change in a future release;
pair an ingester release with the matching mod_wsgi release until
the pipeline stabilises.
