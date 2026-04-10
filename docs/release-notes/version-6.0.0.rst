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

* Dropped support for Python versions older than 3.10. Python 2 compatibility
  code has been removed.

Features Removed
----------------

* Removed built-in support for configuring and initializing the New Relic
  Python agent. This includes the ``WSGINewRelicConfigFile`` and
  ``WSGINewRelicEnvironment`` Apache directives, and the ``--with-newrelic``,
  ``--with-newrelic-agent``, ``--with-newrelic-platform``,
  ``--newrelic-config-file``, and ``--newrelic-environment`` options from
  ``mod_wsgi-express``.

Bugs Fixed
----------

* ...
