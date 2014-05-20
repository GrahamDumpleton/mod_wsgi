===========
Version 2.2
===========

Version 2.2 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.2.tar.gz

**Note: This version was quickly superseded by version 2.3 of mod_wsgi.
Version 2.2 should not be used.**

Features Changed
----------------

1. Use official way of setting process names on FreeBSD, NetBSD and OpenBSD.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=90

This is a backport of change from version 3.0 of mod_wsgi.

Bug Fixes
---------

1. Fix bug whereby if mod_python is loaded at same time as mod_wsgi the
WSGIImportScript directive can cause Apache child processes to crash.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=91

2. Fix bug where mod_wsgi daemon process startup could fail due to old stale
UNIX listener socket file as described in:

  http://code.google.com/p/modwsgi/issues/detail?id=77

3. Fix bug where listener socket file descriptors for daemon processes were
being leaked in Apache parent process on a graceful restart. Also fixes
problem where UNIX listener socket was left in filesystem on both graceful
restart and graceful shutdown. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=95

4. Fix bug where response was truncated when a null character appeared as
first character in block of data being returned from wsgi.file_wrapper. Only
occurred when code fell back to using iteration over supplied file like
object, rather than optimised method such as sendfile().

  http://code.google.com/p/modwsgi/issues/detail?id=100
