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

* ``request-timeout`` recovery overhauled, with a new ``interrupt-timeout``
  option for opt-in injection-based recovery, a new natural-log scaling
  rule for the per-thread fire point, and a stale-aware
  ``graceful-timeout`` drain check.

  Detection: instead of averaging elapsed time across threads (the old
  rule, which could only fire after ``threads × request-timeout`` of
  wedged-thread time), each thread is now compared independently
  against ``request-timeout × (1 + ln(threads))``. At ``threads=1``
  this collapses to ``request-timeout``; at ``threads=10`` it is ~3.3x;
  at ``threads=25`` it is ~4.2x. The shape grants proportionally more
  patience as parallel capacity grows without letting the threshold
  run away. Multiple wedged threads are detected on the same schedule
  a single wedge would be.

  Recovery: when ``interrupt-timeout`` is non-zero, mod_wsgi attempts
  to interrupt only the offending thread by injecting a new
  ``mod_wsgi.RequestTimeout`` exception via Python's
  ``PyThreadState_SetAsyncExc``. If the injection unwinds the stuck
  request within the ``interrupt-timeout`` grace window, the WSGI
  adapter returns ``504 Gateway Timeout`` and the worker thread returns
  to the pool — the daemon process keeps running, and other threads
  were never disturbed. ``RequestTimeout`` derives directly from
  ``BaseException`` so well-written code does not catch it via
  ``except Exception:``; user code may catch it for cleanup but should
  re-raise. When ``interrupt-timeout`` is ``0`` (the default) injection
  is skipped and recovery falls straight through to
  ``graceful-timeout`` followed by ``shutdown-timeout``. Either way,
  detection is identical — ``interrupt-timeout`` only changes the
  recovery method.

  Drain: the ``graceful-timeout`` "is the process idle yet?" check now
  ignores any in-flight request whose elapsed time has already
  exceeded ``request-timeout + interrupt-timeout``. A wedged thread
  that will not unwind voluntarily no longer pins the process inside
  graceful-timeout for its full configured duration; sibling requests
  get the chance to finish cleanly and the wedged thread rides out
  via ``shutdown-timeout``'s forced kill.

  ``mod_wsgi-express`` ``--interrupt-timeout`` defaults to ``0``;
  operators who want injection-based recovery opt in explicitly.
  Daemon mode only; embedded mode is unchanged.

* New ``WSGISwitchInterval`` directive sets the Python GIL switch
  interval (``sys.setswitchinterval()``) for the embedded interpreter
  at process start. The matching ``switch-interval=`` option on
  ``WSGIDaemonProcess`` does the same for daemon-mode interpreters,
  and can be set per daemon group. ``mod_wsgi-express`` exposes
  ``--switch-interval`` which applies the value to both modes.

Features Changed
----------------

* Django community has started adopting use of `pathlib` module when defining
  paths in the Django settings file. This would cause issues for the
  `runmodwsgi` management command for Django as it expected strings for
  `STATIC_ROOT` setting. The code has been updated to always convert
  `STATIC_ROOT` to a string in `runmodwsgi` to cope with people using `pathlib`
  module in their Django settings file.

* The ``cpu_user_time`` and ``cpu_system_time`` keys in the dict returned
  by ``mod_wsgi.request_metrics()`` have always been CPU utilization rates
  (fraction of one CPU core consumed over the sample period), not absolute
  times, which made their names inconsistent with the identically-named
  keys in ``mod_wsgi.process_metrics()`` where the values are cumulative
  CPU seconds since process start. New keys ``cpu_user_utilization`` and
  ``cpu_system_utilization`` have been added carrying the same values,
  along with ``cpu_utilization`` for their sum. On multi-core systems
  these may exceed 1.0, matching the ``top(1)`` convention, and they
  parallel the existing ``capacity_utilization`` key. The original
  ``cpu_user_time`` and ``cpu_system_time`` keys are retained as aliases
  for backwards compatibility but are deprecated and will be removed in a
  future release. A new ``cpu_time`` key has also been added to
  ``mod_wsgi.process_metrics()`` and to the ``request_finished`` event
  payload, providing the pre-computed sum of the corresponding user and
  system CPU seconds for that scope.

* The dict returned by ``mod_wsgi.request_metrics()`` now also carries
  five HTTP response class counters — ``status_1xx``, ``status_2xx``,
  ``status_3xx``, ``status_4xx`` and ``status_5xx`` — counting the
  per-class responses returned by the WSGI application during the
  sampling window. Their sum equals ``request_count`` for the same
  window, so ``status_4xx + status_5xx`` is a ready-made error rate
  numerator. A request whose WSGI application raised before calling
  ``start_response`` (mod_wsgi serves a 500 in that case) is folded
  into ``status_5xx`` so the error rate matches the user-visible
  outcome rather than only counting explicit
  ``start_response("500 ...", ...)`` paths. ``status_1xx`` is included
  as a tripwire — PEP 3333 forbids a WSGI application from returning a
  1xx response, so a non-zero count flags a protocol violation. The
  per-class counters do not distinguish between specific codes
  (404 vs 401 vs 410, etc.); for per-code detail on slow responses,
  the ``WSGISlowRequests`` telemetry stream now also carries the final
  HTTP status on each slow-request record.

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

* Log messages emitted by mod_wsgi no longer carry the historic
  ``mod_wsgi (pid=NNN): `` prefix that the module manually prepended to
  its own output. The same information already appears in Apache's
  standard log line decoration — the ``[wsgi:LEVEL]`` module tag and
  the ``[pid NNN:tid NNN]`` field that Apache prepends to every entry
  emitted via the ``ap_log_*`` family — so the manual prefix only
  duplicated information and produced two ``pid=`` fields per line.
  Log-scraping pipelines that previously matched on the literal
  ``mod_wsgi (pid=`` substring should match on the ``[wsgi:`` module
  tag instead, which is also what the ``LogLevel wsgi:LEVEL`` Apache
  directive controls.

* Log message wording, severity assignment, and identifier coverage
  have been overhauled across the module. The severity of every site
  at ``WARNING`` and above was reviewed against the actual operational
  impact and corrected where needed; for example, several per-request
  failures that were logged at ``CRIT`` are now ``ERR``, and a number
  of configuration diagnostics that only predict a later failure were
  demoted from ``ALERT`` to ``WARNING``. Every unique log site at
  ``WARNING`` and above now also carries a stable ``WSGI####``
  identifier emitted as a prefix on the rendered line, analogous to
  Apache's own ``AHnnnnn`` convention from the ``APLOGNO`` macro, so a
  message such as ``WSGI0061: Unable to bind socket for daemon
  process '...'`` can be referenced by code in runbooks and bug
  reports independent of any future wording adjustments. Each
  identifier is documented in the new :doc:`../error-reference` page
  describing the cause, outcome, and recommended operator action for
  that condition. Lower-tier message wording has also been tightened
  for consistency and accuracy, and per-request hot-path detail is
  now consistently emitted at ``TRACE1`` to separate it from
  process-lifecycle events (``DEBUG`` for troubleshooting, ``INFO``
  for the operator-default view).

* The ``WSGIVerboseDebugging`` directive is deprecated and now has
  no effect. Apache's standard ``LogLevel`` directive provides
  equivalent control with finer granularity: use ``LogLevel
  wsgi:debug`` to enable mod_wsgi's daemon and interpreter
  lifecycle messages, and ``LogLevel wsgi:trace1`` to additionally
  enable per-request and per-thread-binding detail. The directive
  itself is still parsed (a configuration using it will continue
  to load) and now emits an ``INFO``-level deprecation notice on
  startup; it will be removed in a future release.

* Population of the standard CGI variables in the WSGI environment
  no longer goes through Apache's ``ap_add_cgi_vars()`` and
  ``ap_add_common_vars()`` helpers; mod_wsgi now sets the same
  variables itself. The motivation is ``ap_add_cgi_vars()``: its
  only way to compute ``PATH_TRANSLATED`` is to issue an Apache
  subrequest via ``ap_sub_req_lookup_uri()`` against the request's
  ``PATH_INFO``, which reruns translation hooks and can have
  surprising side effects. ``PATH_TRANSLATED`` is not used by WSGI
  applications and is not part of PEP 3333, but the upstream API
  exposes no way to skip just that one variable, so the rest of
  what the two functions do had to be replicated. The replacement
  also drops a small set of variables that were either irrelevant
  or actively undesirable for an in-process WSGI interpreter:
  ``PATH_TRANSLATED`` (as above), ``GATEWAY_INTERFACE`` (PEP 3333
  does not require it and the ``CGI/1.1`` value was misleading),
  ``SERVER_SIGNATURE`` (an HTML blob), ``REMOTE_HOST`` (would
  trigger a reverse-DNS lookup when ``HostnameLookups`` is on),
  ``REMOTE_IDENT`` (would trigger an RFC 1413 ident lookup when
  ``IdentityCheck`` is on), and ``PATH`` along with the various
  platform library-path variables (``LD_LIBRARY_PATH``,
  ``DYLD_LIBRARY_PATH``, etc.) that mattered only for forked CGI
  children. Applications that depended on any of these will need
  to source the value another way.

* The Apache ``MaxKeepAliveRequests`` directive is now set explicitly
  in the ``mod_wsgi-express`` generated configuration, with a value
  chosen per MPM and per mode. For ``mpm_event`` the value is ``0``
  (unlimited), since idle keep-alive connections are parked on the
  listener thread and do not pin a worker. For ``mpm_worker`` and
  ``mpm_prefork`` in daemon mode the value is ``500``: the MPM
  child is just a connection multiplexer and the cap is purely TCP
  hygiene, so a higher value than Apache's core default of ``100``
  amortises handshakes for clients that send many requests. For
  ``mpm_worker`` and ``mpm_prefork`` in embedded mode the value is
  ``100`` to match Apache's core default, reflecting that the MPM
  child is the Python worker and the cap trades off fairness
  between keep-alive clients against handshake overhead. Other
  MPMs, including ``mpm_winnt`` on Windows and any third-party
  MPM, are not matched by the per-MPM blocks in the generated
  configuration and continue to inherit Apache's core default.
  Operators who want a different value can override via the
  existing ``--include-file`` option until a dedicated
  ``mod_wsgi-express`` option is added.

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

* Fixed a name-based VirtualHost matching collision in the Apache
  configuration generated by ``mod_wsgi-express setup-server`` when the
  ``--server-name`` value matched the global server name default (typically
  ``localhost``). The generated ``_default_:<port>`` catch-all VirtualHost
  did not set an explicit ``ServerName`` and silently inherited the global
  default, causing it to advertise the same name as the intended
  ``*:<port>`` named VirtualHost. Apache's tie-break by declaration order
  then routed every canonical-host request to the restrictive
  ``_default_`` block, which meant server-scope ``<Location>`` and
  ``<Directory>`` directives added via ``--include-file`` were shadowed by
  the catch-all's vhost-scope ``<Location />``. Authorization and access
  control rules configured this way silently did nothing (with
  ``--allow-localhost``) or rejected every request with 403 (without it).
  The ``_default_`` VirtualHost now sets ``ServerName _wsgi_`` so it
  cannot collide with any operator-supplied ``--server-name`` value; its
  catch-all role for unrecognised Host headers is preserved by
  declaration order and is unchanged. Deployments that passed a
  ``--server-name`` differing from the global default were not affected
  by this bug.

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

* Fixed the ``X-Forwarded-Server`` and ``X-Forwarded-Port`` headers to be
  stripped from the WSGI request environment when a request is received
  from a peer that is not in the ``WSGITrustedProxies`` allowlist, matching
  the documented contract for ``WSGITrustedProxyHeaders`` and the behaviour
  already implemented for the other trusted-proxy header categories.
  Previously these two headers were only classified for rewriting the
  ``SERVER_NAME`` and ``SERVER_PORT`` CGI variables when the peer was
  trusted, but the raw ``HTTP_X_FORWARDED_SERVER`` and
  ``HTTP_X_FORWARDED_PORT`` entries were left in the environment even when
  the peer was untrusted. While WSGI applications are expected to consult
  ``SERVER_NAME`` and ``SERVER_PORT`` rather than the raw headers, any
  middleware that independently processes proxy headers could be misled by
  spoofed values, so the stripping is applied consistently for all
  categories listed in ``WSGITrustedProxyHeaders``.

* Fixed precedence between a trusted proxy scheme header and ``mod_ssl``
  when Apache terminates TLS directly. The ``ssl_is_https`` check that
  sets ``HTTPS=1`` (and therefore ``wsgi.url_scheme=https`` in the WSGI
  environ) runs after ``wsgi_process_proxy_headers`` and previously
  overwrote whatever a trusted ``X-Forwarded-Proto`` / ``X-Forwarded-SSL``
  / ``X-Forwarded-Scheme`` header had decided. In an unusual but valid
  deployment where a front proxy receives the original client over plain
  HTTP and speaks TLS to Apache itself, the proxy correctly reports
  ``X-Forwarded-Proto: http`` for the client scheme, but Apache's view of
  its own TLS inbound connection would override that back to ``https``.
  The scheme check now only consults ``ssl_is_https`` when no trusted
  scheme header was applied for the request, so an operator who has
  opted the proxy's scheme header into ``WSGITrustedProxyHeaders`` gets
  the proxy's declaration honoured. Deployments where Apache terminates
  TLS directly without a front proxy and do not list a scheme header in
  ``WSGITrustedProxyHeaders`` are unaffected.

* Fixed an inverted case-sensitivity check in ``wsgi_module_name``,
  which computes the Python module name used to cache a WSGI script
  under ``sys.modules`` by MD5-hashing the script's absolute filename.
  The helper lowercases the filename before hashing so that two paths
  differing only in case collapse to the same cache slot on case-
  insensitive filesystems. The guard around this lowercasing evaluated
  the ``WSGICaseSensitivity`` flag the wrong way round: it lowercased
  when the filesystem was case-sensitive (Linux default, or
  ``WSGICaseSensitivity On``) and preserved case when the filesystem
  was case-insensitive (Windows/macOS defaults, or
  ``WSGICaseSensitivity Off``) — the opposite of the directive's
  documented meaning and the function's comment. A deployment that
  served the same script via paths differing only in case would have
  observed duplicate module loads on Windows/macOS and cache
  collisions on Linux; in practice almost no deployments mount scripts
  that way, so the bug has been latent.

* Fixed ``mod_wsgi-express`` so that supplying SSL certificate options
  (``--ssl-certificate``, ``--ssl-certificate-file``,
  ``--ssl-certificate-key-file``, ``--ssl-ca-certificate-file``, or
  ``--ssl-certificate-chain-file``) without also specifying
  ``--https-port`` now fails with a clear error. Previously the SSL
  options were silently dropped from the generated Apache configuration
  because the HTTPS ``VirtualHost`` block is only emitted when
  ``--https-port`` is set, leaving operators with a server that
  listened only on plain HTTP and no indication that their TLS
  configuration had been ignored.

* Fixed the shutdown stack-trace dump that fires after a request-timeout
  escalation in daemon mode so it now reports frames from the
  interpreter the offending request was running in. Previously the dump
  acquired the GIL via ``PyGILState_Ensure`` (which attaches to the main
  interpreter) and called ``_PyThread_CurrentFrames``, whose semantics
  changed in Python 3.12 to return frames for the current interpreter
  only. On Python 3.12 and later, requests served in a named
  ``WSGIApplicationGroup`` silently produced an empty or misleading
  dump because the dumping thread was attached to the main interpreter
  while the wedged worker was in a sub-interpreter. The escalation site
  now records which application group triggered the timeout and the
  dump scopes itself to that interpreter.
