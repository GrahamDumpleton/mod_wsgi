===========
Version 2.1
===========

Version 2.1 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.1.tar.gz

Bug Fixes
---------

1. Fix bug which was resulting in logging destined for !VirtualHost !ErrorLog
going missing or ending up in main Apache error log.

  http://code.google.com/p/modwsgi/issues/detail?id=79

2. Fix bug where WSGI application returning None rather than valid iterable
causes process to crash.

  http://code.google.com/p/modwsgi/issues/detail?id=88
