=============
Version 4.4.1
=============

Version 4.4.1 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.1

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Process crashes could occur when request content had been consumed by
the WSGI application. The trigger was when the Python ``wsgi.input`` was
still in existence after the web request had finished. The destruction of
the ``wsgi.input`` object was accessing memory which had already been
released back to the Apache memory pools and potentially reused. This could
cause crashes or other unexplained behaviour. This issue was introduced in
version 4.4.0 of mod_wsgi.

Features Changed
----------------

1. When an error occurs in writing back a response to the HTTP client,
during the consumption of the iterable returned by the WSGI application,
the message will now be logged at debug level rather than error level. Note
that under Apache 2.2 it isn't possible to suppress the message generated
by Apache itself from the core_output_filter, so that may still appear.

2. The ``--profiler-output-file`` option for ``mod_wsgi-express`` was
changed to ``--profiler-directory`` and now refers to a directory, with
individual pstats files being added to the directory for each session
rather than reusing the same name all the time.

New Features
------------

1. Added the ``--server-mpm`` option to ``mod_wsgi-express``. With this
option, if you are using Apache 2.4 with dynamically loadable MPM modules
and more than one option for the MPM is available, you can specify your
preference for which is used. If not specified, then the precedence order
for MPMs is 'event', 'worker' and finally 'prefork'.

2. Added ``static`` as an option for ``--application-type`` when running
``mod_wsgi-express``. When set as ``static``, only static files will be
served. One can still set specific handler types for different extensions
which may invoke a Python handler script, but there will be no global
fallback WSGI application for any URLs that do not map to static files. In
these cases a normal HTTP 404 response will be returned instead.

3. Added ``--host-access-script`` option to ``mod_wsgi-express`` to allow
a Python script to be provided which can control host access. This uses
the ``WSGIAccessScript`` directive and the handler script should define an
``allow_access(environ, host)`` function which returns ``True`` if access is
allowed or ``False`` if blocked.

4. Added ``--debugger-startup`` option to be used in conjunction with
the ``--enable-debugger`` option of ``mod_wsgi-express`` when in debug mode.
The option will cause the debugger to be activated on server start before
any requests are handled to allow breakpoints to be set.

5. Added a ``socket-user`` option to ``WSGIDaemonProcess`` to allow the
owner of the UNIX listener socket for the daemon process group to be
overridden. This can be used when using mod_ruid2 to change the owner of
the socket from the default Apache user, to the user under which mod_ruid2
will run Apache when handling requests. This is necessary otherwise the
Apache child worker process will not be able to connect to the listener
socket for the mod_wsgi daemon process to proxy the request to the WSGI
application.

6. Added a ``--enable-recorder`` option for enabling request recording when
also using debug mode.
