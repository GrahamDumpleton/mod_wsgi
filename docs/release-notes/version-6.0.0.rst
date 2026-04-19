=============
Version 6.0.0
=============

Version 6.0.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/6.0.0

New Features
------------

* ...

Features Changed
----------------

* ...

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

* Fixed incorrect handling of ``PySequence_Contains()`` return value when
  reordering ``sys.path`` entries added by ``site.addsitedir()`` during
  interpreter initialization. An error return of -1 was being treated as a
  truthy value, causing newly added path entries to be silently skipped rather
  than moved to the front of ``sys.path``.

* Fixed incorrect handling of ``PyObject_IsInstance()`` return value in the
  file wrapper optimisation path. An error return of -1 was being treated as
  a successful instance check, potentially causing subsequent attribute access
  failures on non-Stream objects.

* Fixed incorrect handling of ``PyObject_IsTrue()`` return value when checking
  a module's ``reload_required()`` callback result. An error return of -1 was
  being treated as truthy, causing unnecessary module reloads and skipping the
  error logging path.

* Fixed unreachable retry-limit check in the daemon mode request dispatch loop
  that handles ``200 Rejected`` responses sent during daemon process restart.
  The bound check was placed where the loop condition guaranteed it could
  never fire, so the intended ``503 Service Unavailable`` response with a
  "Maximum number of WSGI daemon process restart connects reached" log message
  was never emitted. A daemon stuck in a restart loop would instead yield a
  bogus ``200 Rejected`` status to the client, a ``500`` from a truncated
  header read, or a ``504`` from a read timeout, depending on the final
  attempt's outcome.
