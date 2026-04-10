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

Bugs Fixed
----------

* ...
