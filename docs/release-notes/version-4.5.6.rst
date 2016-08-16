=============
Version 4.5.6
=============

Version 4.5.6 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.6

Bugs Fixed
----------

1. Reinstanted change to associate any messages logged via ``sys.stdout``
   and ``sys.stderr`` back to the request so that Apache can log them
   with the correct request log ID. This change was added in 4.5.4, but
   was reverted in 4.5.5 as the change was causing process crashes under
   Python 3.
