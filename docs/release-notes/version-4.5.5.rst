=============
Version 4.5.5
=============

Version 4.5.5 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.5

Bugs Fixed
----------

1. If using Python 3.X and ``print()`` was used from the thread handling a
   request, the process would crash. This bug was introduced with mod_wsgi
   version 4.5.4 when making changes to ensure that any messages logged
   using ``print()`` against ``sys.stdout`` or ``sys.stderr`` were
   associated back with the request, enabling Apache to then log them with
   the correct request log ID.
