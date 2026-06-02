================
WSGISlowRequests
================

:Description: Enable slow-request reporting and set the elapsed-time threshold above which a still-running request is reported.
:Syntax: ``WSGISlowRequests SECONDS``
:Default: Not set (slow-request reporting disabled)
:Context: server config

Turns on per-request slow-record telemetry and sets the elapsed-
time threshold (in seconds) above which a still-running request
is recorded and shipped through the telemetry transport. With
the directive set to ``2.0``, any request still in flight after
two seconds of wall-clock time appears as a slow-request record;
when the request later completes, a follow-up record is emitted
carrying the final elapsed time and HTTP status.

This is a server-wide directive: it may only appear at the top
level of the Apache configuration, outside any ``<VirtualHost>``
block.

This directive is only useful alongside
:doc:`WSGITelemetryService`. The slow records are emitted
through the telemetry transport configured by that directive, so
without an ingester to receive them they have no destination.
Setting ``WSGISlowRequests`` without ``WSGITelemetryService`` is
not treated as a configuration error: the per-request bookkeeping
runs and the records are constructed, but nothing reads them.

Each slow-request record carries:

* The originating process PID and worker thread ID.
* The elapsed wall time at the moment the record was emitted.
* The HTTP request method.
* The URL path the request targeted, with the query string
  stripped.
* The HTTP response status (zero on records emitted while the
  request is still active).
* The ``User-Agent`` header value, only when
  :doc:`WSGITelemetryOptions` includes ``+CaptureUserAgent``.

Validation
----------

* ``WSGISlowRequests`` with no argument is rejected at
  configuration-parse time.
* A negative threshold is rejected. A threshold of zero is
  accepted but reports every completed request, which is rarely
  useful in production.

See also
--------

* :doc:`WSGITelemetryService` for the parent directive that
  enables the telemetry transport.
* :doc:`WSGITelemetryOptions` for the ``+CaptureUserAgent`` flag
  that extends slow-request records with the request
  ``User-Agent`` header value.
* :doc:`../user-guides/external-telemetry-service` for the full
  setup of the telemetry pipeline, including the slow-records
  view in the browser UI.
