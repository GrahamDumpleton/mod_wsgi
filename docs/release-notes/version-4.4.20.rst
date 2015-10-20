==============
Version 4.4.20
==============

Version 4.4.20 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.20

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Post mortem debugger would fail if the exception was raised during
yielding of items from a WSGI application, or inside of any ``close()``
callable of an iterator returned from the WSGI application.
