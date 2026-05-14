====================
WSGITelemetryService
====================

:Description: Enable the in-process telemetry reporter and point it at an external ingester.
:Syntax: ``WSGITelemetryService unix:/path [interval=SECONDS]``
:Default: Not set (reporter disabled)
:Context: server config

Enables the mod_wsgi telemetry reporter and configures the local
UNIX socket the reporter sends its binary datagrams to. When set,
every mod_wsgi process started by Apache (each daemon-mode worker
and each embedded-mode Apache child) starts a single dedicated
reporter thread at process initialisation. The thread emits three
kinds of record over the configured socket:

* An aggregate per-interval sample on every tick, covering the
  request throughput, per-phase latency distribution
  (mean / min / max / histogram), capacity utilisation, in-flight
  worker-slot state, HTTP response-class counts, CPU consumption,
  and resident memory of the process for the interval that just
  closed.
* Process lifecycle events (start, draining, stop) emitted as
  state changes happen.
* Per-request slow records when :doc:`WSGISlowRequests` is also
  configured: a record when an in-flight request crosses the
  configured elapsed-time threshold, and a follow-up when the
  same request later completes carrying the final elapsed time
  and HTTP status.

See :doc:`../user-guides/external-telemetry-service` for the
full enumeration of fields in each record kind.

This is a server-wide directive: it may only appear at the top
level of the Apache configuration, outside any ``<VirtualHost>``
block. Apache rejects the configuration at startup if the
directive appears in a per-vhost or per-directory context. One
configuration line enables the reporter for the entire Apache
instance, covering every daemon process group and every
embedded-mode Apache child.

Arguments
---------

``unix:/path/to/socket``
   Path of the listening UNIX SOCK_DGRAM socket on the same host.
   Only the ``unix:`` scheme is accepted; ``udp:host:port``
   targets are rejected at configuration-parse time, since the
   reporter is intended for a co-located ingester and no
   provision is made for cross-host transport.

   The ingester that creates the socket is distributed separately
   as the ``mod_wsgi-telemetry`` package on PyPi. See
   :doc:`../user-guides/external-telemetry-service` for installing
   and running it.

``interval=SECONDS``
   Optional. Sampling interval in seconds for the reporter loop.
   Defaults to ``1.0``. Sub-second intervals are permitted;
   smaller intervals produce more datagrams and finer resolution
   at a higher per-tick cost. Must be greater than zero.

Validation
----------

* ``WSGITelemetryService`` with no argument is rejected at
  configuration-parse time.
* A target without the ``unix:`` prefix, including a remote
  ``udp:host:port`` form, is rejected with a clear error.
* An ``interval=`` value of zero or negative is rejected.
* A second argument other than ``interval=N`` is rejected.

Interaction with other surfaces
-------------------------------

When ``WSGITelemetryService`` is set, the external reporter is
the canonical metrics consumer for the process. The Python
accessors ``mod_wsgi.request_metrics()`` and
``mod_wsgi.process_metrics()`` return ``None`` regardless of
whether ``mod_wsgi.start_recording_metrics()`` has been called,
so an in-application reporter detects the external configuration
with a single ``None`` check and stands down. See
:doc:`../user-guides/internal-metrics-api` for the in-process
accessor API and how an application-side reporter coexists with
the external one.

The ingester socket is created by the ingester process at its
own bind time, owned by the ingester user. The mod_wsgi
processes that report (daemon-mode workers and Apache children)
need write permission on the socket file to ``sendto()`` it;
:doc:`../user-guides/external-telemetry-service` covers the
shared-group pattern for multi-user deployments.

See also
--------

* :doc:`WSGITelemetryOptions` for the capture-flag toggles
  applied to telemetry records.
* :doc:`WSGISlowRequests` for the slow-request reporting
  threshold that ships through the same transport.
* :doc:`../user-guides/external-telemetry-service` for the full
  setup, including running the ingester, socket permissions, the
  browser UI, and the terminal monitor.
* :doc:`../user-guides/internal-metrics-api` for the in-process
  alternative.
