=============
Version 4.4.8
=============

Version 4.4.8 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.8

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. The eviction timeout was not being correctly applied when request timeout
wasn't being applied at the same time. It may have partly worked if any of
inactivity or graceful timeout were also specified, but the application of
the timeout may still have been delayed.

New Features
------------

1. Added the ``--error-log-name`` option to ``mod_wsgi-express`` to allow
the name of the file used for the error log, when being written to the log
directory, to be overridden.

2. Added the ``--access-log-name`` option to ``mod_wsgi-express`` to allow
the name of the file used for the access log, when being written to the log
directory, to be overridden.

3. Added the ``--startup-log-name`` option to ``mod_wsgi-express`` to allow
the name of the file used for the startup log, when being written to the log
directory, to be overridden.
