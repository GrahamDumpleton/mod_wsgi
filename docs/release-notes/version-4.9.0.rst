=============
Version 4.9.0
=============

Version 4.9.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.9.0

Bugs Fixed
----------

* The mod_wsgi code wouldn't compile on Python 3.10 as various Python C API
  functions were removed. Note that the changes required switching to
  alternate C APIs. The changes were made for all Python versions back to
  Python 3.6 and were not conditional on Python 3.10+ being used. This is
  why the minor version got bumped.

* When using CMMI (configure/make/make install) method for compiling mod_wsgi
  if embedded mode was being disabled at compile time, compilation would fail.

* When ``maximum-requests`` option was used with mod_wsgi daemon mode, and
  a graceful restart signal was sent to the daemon process while there was
  an active request, the process would only shutdown when the graceful
  timeout period had expired, and not as soon as any active requests had
  completed, if that had occurred before the graceful timeout had expired.

* When using the ``startup-timeout`` and ``restart-interval`` options of
  ``WSGIDaemonProcess`` directive together, checking for the expiration
  time of the startup time was done incorrectly, resulting in process
  restart being delayed if startup had failed. At worst case this was the
  lessor of the time periods specified by the options ``restart-interval``,
  ``deadlock-timeout``, ``graceful-timeout`` and ``eviction-timeout``. If
  ``request-timeout`` were defined it would however still be calculated
  correctly. As ``request-timeout`` was by default defined when using
  ``mod_wsgi-express``, this issue only usually affect mod_wsgi when
  manually configuring Apache.

Features Changed
----------------

* Historically when using embedded mode, ``wsgi.multithread`` in the WSGI
  ``environ`` dictionary has reported ``True`` when any multithread capable
  Apache MPM were used (eg., worker, event), even if the current number of
  configured threads per child process was overridden to be 1. Why this was
  the case has been forgotten, but generally wouldn't matter since no one
  would ever set up Apache with a mulithread MPM and then configure the
  number of threads to be 1. If that was desired then ``prefork`` MPM would
  be used.

  With ``mod_wsgi-express`` since 4.8.0 making it much easier to use
  embedded mode and have a sane configuration used, since it is generated
  for you, the value of ``wsgi.multithread`` has been changed such that it
  will now correctly report ``False`` if using embedded mode, a multithread
  capable MPM is used, but the number of configured threads is set to 1.

* The ``graceful-timeout`` option for ``WSGIDaemonProcess`` now defaults to
  15 seconds. This was always the case when ``mod_wsgi-express`` was used
  but the default was never applied back to the case where mod_wsgi was
  being configured manually.

  A default of 15 seconds for ``graceful-timeout`` is being added to avoid
  the problem where sending a SIGUSR1 to a daemon mode process would never
  see the process shutdown due to there never being a time when there were
  no active requests. This might occur when there were a stuck request that
  never completed, or numerous long running requests which always overlapped
  in time meaning the process was never idle.

  You can still force ``graceful-timeout`` to be 0 to restore the original
  behaviour, but that is probably not recommended.
