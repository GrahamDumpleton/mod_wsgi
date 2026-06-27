=============
Version 6.0.5
=============

Bugs Fixed
----------

* When using daemon mode with the deferred-content handshake disabled,
  reading the request body via ``wsgi.input`` could fail with
  ``OSError: mod_wsgi request data read error: Partial results are valid
  but processing is incomplete``, or silently return a truncated body.
  This was a regression introduced in version 6.0.0 and affected any
  request with a body, such as a ``POST``, where ``WSGIScriptReloading``
  was set to ``Off`` and the daemon process group ``queue-timeout`` was
  ``0``. In that configuration the Apache child process sends the request
  details and the request body to the daemon process in a single write,
  and the daemon process was over-reading the request details and
  consuming the leading bytes of the request body. The daemon process now
  reads only the request details and leaves the request body untouched
  for subsequent reading by the WSGI application.
