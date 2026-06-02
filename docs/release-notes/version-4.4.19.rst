:orphan:

==============
Version 4.4.19
==============

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Daemon mode processes were crashing when attempting to set ``USER``,
``USERNAME``, ``LOGNAME`` or ``HOME`` when no password entry could be
found for the current user ID. Now do not attempt to set these if the
user ID doesn't have a password file entry.
