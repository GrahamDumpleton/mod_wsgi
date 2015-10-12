==============
Version 4.4.17
==============

Version 4.4.17 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.17

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. If ``mod_wsgi-express`` was run under a user ID for which there was no
password entry in the system password file, it would fail when looking up
the user name. If this occurs now use ``#nnn`` as the default user name,
where ``nnn`` is the user ID.
