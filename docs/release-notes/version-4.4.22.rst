==============
Version 4.4.22
==============

Version 4.4.22 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.22

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Stack traces logged at ``INFO`` level when a request timeout occurred
were not displaying correctly when Python 3 was being used. It is possible
that the logging code could also have caused the process to then crash as
the process was shutting down.

2. When using the ``--url-alias`` option with ``mod_wsgi-express`` and the
target directory had a trailing slash, that trailing slash was being
incorrectly dropped. This would cause URL lookup to fail when the URL for
the directory was a sub URL and also had a trailing slash.
