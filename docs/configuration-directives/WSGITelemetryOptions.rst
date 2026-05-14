====================
WSGITelemetryOptions
====================

:Description: Toggle optional captures for the telemetry stream.
:Syntax: ``WSGITelemetryOptions [+|-]Flag [+|-]Flag ... | None | All``
:Default: All flags off
:Context: server config

Selects the optional capture flags applied to the telemetry
stream emitted by :doc:`WSGITelemetryService`. Each flag enables
a specific field or behaviour that is off by default for privacy
or volume reasons.

This is a server-wide directive: it may only appear at the top
level of the Apache configuration, outside any ``<VirtualHost>``
block.

Syntax follows the Apache ``Options`` directive convention. Two
argument forms are supported, and may not be mixed within one
line:

Incremental form
   ``+Flag`` adds a flag to the current state; ``-Flag`` removes
   it. Multiple flag tokens may appear on one line. Subsequent
   ``WSGITelemetryOptions`` lines layer on top of the previous
   state, so an earlier ``WSGITelemetryOptions +CaptureUserAgent``
   followed by ``WSGITelemetryOptions -CaptureUserAgent`` leaves
   the flag off.

Absolute form
   ``None`` clears every flag. ``All`` enables every defined
   flag. The absolute forms replace the current state entirely
   rather than modifying it, and may not be combined with ``+``
   or ``-`` tokens on the same line.

Flags
-----

``CaptureUserAgent``
   When set, slow-request records carry the request's
   ``User-Agent`` header value in addition to the request method,
   URL path, and HTTP status fields that are always present.
   Off by default because the ``User-Agent`` string can identify
   individual clients in some deployments and inflates record
   size in others.

Additional flags may be added in future releases. The ``None``
and ``All`` forms apply to whatever flags are defined at
configuration time, not a fixed historical set.

Validation
----------

* A bare ``+`` or ``-`` with no flag name is rejected at
  configuration-parse time.
* An unknown flag name is rejected.
* ``None`` or ``All`` combined with ``+`` or ``-`` tokens on the
  same line is rejected.

See also
--------

* :doc:`WSGITelemetryService` for the parent directive that
  enables the telemetry stream.
* :doc:`WSGISlowRequests` for the threshold controlling which
  requests appear in the slow-record stream that the
  ``CaptureUserAgent`` flag extends.
* :doc:`../user-guides/external-telemetry-service` for the full
  telemetry pipeline setup.
