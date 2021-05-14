=============
Version 4.8.0
=============

Version 4.8.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.8.0

Bugs Fixed
----------

* Fixed potential for process crash on Apache startup when the WSGI script
  file or other Python script file were being preloaded. This was triggered
  when ``WSGIImportScript`` was used, or if ``WSGIScriptAlias`` or
  ``WSGIScriptAliasMatch`` were used and both the ``process-group`` and
  ``application-group`` options were used with those directives.

  The potential for this problem arising was extremely high on Alpine Linux,
  but seem to be very rare on a full Linux of macOS distribution where glibc
  was being used.

* Include a potential workaround so that virtual environment work on Windows.

  Use of virtual environments in embedded systems on Windows has been broken
  ever since ``python -m venv`` was introduced.

  Initially ``virtualenv`` was not affected, although when it changed to
  use the new style Python virtual environment layout the same as
  ``python -m venv`` it also broke. This was with the introduction of about
  ``virtualenv`` version 20.0.0.

  The underlying cause is lack of support for using virtual environments in
  CPython for the new style virtual environments. The bug has existed in
  CPython since back in 2014 and has not been fixed. For details of the
  issue see https://bugs.python.org/issue22213.

  For non Window systems a workaround had been used to resolve the problem,
  but the same workaround has never worked on Windows. The change in this
  version tries a different workaround for Windows environments.

* Added a workaround for the fact that Python doesn't actually set the
  ``_main_thread`` attribute of the ``threading`` module to the main thread
  which initialized the main interpreter or sub interpreter, but the first
  thread that imports the ``threading`` module. In an embedded system such
  as mod_wsgi it could be a request thread, not the main thread, that would
  import the ``threading`` module.

  This issue was causing the ``asgiref`` module used in Django to fail when
  using ``signal.set_wakeup_fd()`` as code was thinking it was in the main
  thread when it wasn't. See https://github.com/django/asgiref/issues/143.

* Using ``WSGILazyInitialization Off`` would cause Python to abort the
  Apache parent process. The issue has been resolved, but you are warned
  that you should not be using this option anyway as it is dangerous and
  opens up security holes with the potential for user code to run as the
  ``root`` user when Python is initialized.

* Fix a Python deprecation warning for ``PyArg_ParseTuple()`` which would
  cause the process to crash when deprecation warnings were turned on
  globally for an application. Crash was occuring whenever anything was
  output to Apache error log via ``print()``.

Features Changed
----------------

* The ``--isatty`` option of mod_wsgi-express has been removed and the
  behaviour enabled by the option is now the default. The default behaviour
  is now that if mod_wsgi-express is run in an interactive terminal, then
  Apache will be started within a sub process of the mod_wsgi-express script
  and the ``SIGWINCH`` signal will be blocked and not passed through to
  Apache. This means that a window resizing event will no longer cause
  mod_wsgi-express to shutdown unexpectedly.

* When trying to set resource limits and they can't be set, the system error
  number will now be included in the error message.

New Features
------------

* Added the ``mod_wsgi.subscribe_shutdown()`` function for registering a
  callback to be called when the process is being shutdown. This is needed
  because ``atexit.register()`` doesn't work as required for the main
  Python interpreter, specifically the ``atexit`` callback isn't called
  before the main interpreter thread attempts to wait on threads on
  shutdown, thus preventing one from shutting down daemon threads and
  waiting on them.

  This feature to get a callback on process shutdown was previously
  available by using ``mod_wsgi.subscribe_events()``, but that would also
  reports events to the callback on requests as they happen, thus adding
  extra overhead if not using the request events. The new registration
  function can thus be used where only interested in the event for the
  process being shutdown.

* Added an ``--embedded-mode`` option to mod_wsgi-express to make it easier
  to force it into embedded mode for high throughput, CPU bound applications
  with minimal response times. In this case the number of Apache child
  worker processes used for embedded mode will be dictated by the
  ``--processes`` and ``--threads`` option, completely overriding any
  automatic mechanism to set those parameters. Any auto scaling done by
  Apache for the child worker processes will also be disabled.

  This gives preference to using Apache worker MPM instead of event MPM,
  as event MPM doesn't work correctly when told to run with less than
  three threads per process. You can switch back to using event MPM by
  using the ``--server-mpm`` option, but will need to ensure that have
  three threads per process or more.

* Locking of the Python global interpreter lock has been reviewed with
  changes resulting in a reduction in overhead, or otherwise changing
  the interaction between threads such that at high request rate with a
  hello world application, a greater request throughput can be achieved.
  How much improvement you see with your own applications will depend on
  what your application does and whether you have short response times
  to begin with. If you have an I/O bound application with long response
  times you likely aren't going to see any difference.

* Internal metrics collection has been improved with additional information
  provided in process metrics and a new request metrics feature added
  giving access to aggregrated metrics over the time of a reporting period.
  This includes bucketed time data on requests so can calculate distribution
  of server, queue and application time.

  Note that the new request metrics is still a work in progress and may be
  modified or enhanced, causing breaking changes in the format of data
  returned.

* Hidden experimental support for running ``mod_wsgi-express start-server``
  on Windows. It will not show in list of sub commands ``mod_wsgi-express``
  accepts on Windows, but it is there. There are still various issues that
  need to be sorted out but need assistance from someone who knows more
  about programming Python on Windows and Windows programming in general to
  get it all working properly. If you are interested in helping, reach out
  on the mod_wsgi mailing list.
