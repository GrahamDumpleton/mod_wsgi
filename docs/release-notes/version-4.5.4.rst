=============
Version 4.5.4
=============

Version 4.5.4 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.4

Bugs Fixed
----------

1. When using Apache 2.4 and daemon mode, the connection and request log
   IDs from the Apache child worker processes were not being copied across
   to the daemon process so that log messages generated against the request
   would use the same ID in logs when using the ``%L`` format modifier.

New Features
------------

1. Added new option ``--error-log-format`` to ``mod_wsgi-express`` to allow
   the error log message format to be specified.

2. Pass through to the WSGI per request ``environ`` dictionary new values
   for ``mod_wsgi.connection_id`` and ``mod_wsgi.request_id``. These are
   the Apache log IDs for the connection and request that it uses in log
   messages when using the ``%L`` format modifier. This only applies to
   Apache 2.4 and later.
