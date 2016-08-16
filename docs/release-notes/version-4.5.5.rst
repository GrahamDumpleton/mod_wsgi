=============
Version 4.5.5
=============

Version 4.5.5 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.5

Features Changed
----------------

1. Reverted the change in 4.5.4 which associated any messages logged via
   ``sys.stdout`` and ``sys.stderr`` back to the request so that Apache
   could log them with the correct request log ID. This was necessary as
   the change was causing process crashes under Python 3. The feature will
   be reinstated when a solution to the issue can be found.
