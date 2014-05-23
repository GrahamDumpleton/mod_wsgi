===========
Version 1.5
===========

Version 1.5 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.5.tar.gz

Bug Fixes
---------

1. Fix bug where listener socket file descriptors for daemon processes were
being leaked in Apache parent process on a graceful restart. Also fixes
problem where UNIX listener socket was left in filesystem on both graceful
restart and graceful shutdown. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=95

This is a backport of change from version 2.2 of mod_wsgi.
