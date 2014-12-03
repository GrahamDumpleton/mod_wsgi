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
