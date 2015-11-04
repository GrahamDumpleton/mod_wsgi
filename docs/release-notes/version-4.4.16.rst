==============
Version 4.4.16
==============

Version 4.4.16 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.16

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. If ``/dev/stderr`` cannot be opened for writing when startup log is
requested and logging to the terminal, then ``mod_wsgi-express`` would
fail. Now attempt fallback to using ``/dev/tty`` and if that cannot be
opened either, then give up on trying to use terminal for startup log.
