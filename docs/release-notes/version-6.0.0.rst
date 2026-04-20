=============
Version 6.0.0
=============

Version 6.0.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/6.0.0

For this release a signficant review of the code base was undertaken to clean
up legacy code and remove support for older versions of Python and Apache httpd.
In the process a large number of fixes were made to the code base to fix up
inconsistencies in how the Python C API and Apache API were used, such as
error handling and reference counting. This should make the code base more
robust and easier to maintain going forward. Because of the large number of
changes, rather than listing all of the individual fixes, the release notes
will just list the major fixes which may have had a visibe effect on users
in production deployments.

New Features
------------

* ...

Features Changed
----------------

* When a daemon process closes its connection or encounters a read error
  before returning complete response headers, the request now receives a
  ``502 Bad Gateway`` response instead of ``500 Internal Server Error``.
  The ``500`` response is retained for the distinct case of a response
  header line exceeding the configured buffer size, and ``504 Gateway
  Timeout`` is still used for read timeouts. The corresponding error log
  messages have also been reworked so that each failure mode is reported
  with a distinct message, and the underlying APR error string is now
  included for generic read failures. Deployments that alert on ``500``
  responses from mod_wsgi may want to adjust monitoring to include ``502``
  for upstream daemon failures.

Features Removed
----------------

* Dropped support for Python versions older than 3.10. Python 2 compatibility
  code has been removed.

* Dropped support for Apache httpd versions older than 2.4. Compatibility
  code for Apache httpd 1.3, 2.0, and 2.2 has been removed.

* Removed built-in support for configuring and initializing the New Relic
  Python agent. This includes the ``WSGINewRelicConfigFile`` and
  ``WSGINewRelicEnvironment`` Apache directives, and the ``--with-newrelic``,
  ``--with-newrelic-agent``, ``--with-newrelic-platform``,
  ``--newrelic-config-file``, and ``--newrelic-environment`` options from
  ``mod_wsgi-express``.

* Removed the ``WSGILazyInitialization`` directive. Python is now always
  initialized lazily in child and daemon processes after they have been forked
  from the Apache parent process. The old behavior of initializing Python in
  the Apache parent process, enabled by setting this directive to ``Off``, is
  no longer supported due to security risks from running as root and memory
  leak issues with the Python interpreter on Apache restarts.

* Removed code that allowed mod_wsgi to coexist with mod_python in the same
  Apache instance. Since mod_python has not been actively developed since the
  Python 2.x era, this should be obsolete and not affect any current
  deployments.

Bugs Fixed
----------

* Fixed unreachable retry-limit check in the daemon mode request dispatch loop
  that handles ``200 Rejected`` responses sent during daemon process restart.
  The bound check was placed where the loop condition guaranteed it could
  never fire, so the intended ``503 Service Unavailable`` response with a
  "Maximum number of WSGI daemon process restart connects reached" log message
  was never emitted. A daemon stuck in a restart loop would instead yield a
  bogus ``200 Rejected`` status to the client, a ``500`` from a truncated
  header read, or a ``504`` from a read timeout, depending on the final
  attempt's outcome.

* Fixed handling of empty list elements in the ``X-Forwarded-For`` header
  when processing trusted proxy headers. RFC 9110 §5.6.1 requires HTTP
  recipients to parse and ignore empty elements in comma-separated list
  headers, but the parser in ``wsgi_process_forwarded_for`` was pushing
  zero-length tokens into the parsed array for inputs such as ``a,,b``,
  ``, a, b``, or values with multiple adjacent commas. When
  ``WSGITrustedProxies`` was configured, the resulting empty string would
  later fail ``apr_sockaddr_info_get`` during the right-to-left trust-chain
  walk, breaking the walk early and producing an empty or incorrect
  ``REMOTE_ADDR``. When ``WSGITrustedProxies`` was not configured and the
  value began with a comma, ``REMOTE_ADDR`` was set to an empty string. Empty
  list elements are now skipped in both code paths, so ``REMOTE_ADDR`` is
  derived from the first non-empty element as the header semantics intend.
