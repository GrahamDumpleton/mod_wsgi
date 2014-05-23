===========
Version 1.4
===========

Version 1.4 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.4.tar.gz

Bug Fixes
---------

1. A negative value for content length in response wasn't being rejected.
Where invalid header was being returned in response original response
status was being returned instead of a 500 error.

2. Fix bug which was resulting in logging destined for !VirtualHost !ErrorLog
going missing or ending up in main Apache error log.

  http://code.google.com/p/modwsgi/issues/detail?id=79

Features Added
--------------

1. Optimise sending of WSGI environment across to daemon process by
reducing number of writes to socket. For daemon mode and a simple hello
world application this improves base performance by 40% moving it
significantly closer to performance of embedded mode.

This is a backport of change from version 2.0 of mod_wsgi.
