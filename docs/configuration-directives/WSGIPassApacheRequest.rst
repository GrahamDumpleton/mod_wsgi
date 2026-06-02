=====================
WSGIPassApacheRequest
=====================

:Description: Pass the Apache request_rec object through to the WSGI environ.
:Syntax: ``WSGIPassApacheRequest On|Off``
:Default: ``WSGIPassApacheRequest Off``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

When set to ``On``, mod_wsgi adds an ``apache.request_rec`` key to
the WSGI ``environ`` dictionary. The value is a ``PyCapsule`` that
wraps a pointer to the underlying Apache ``request_rec`` structure
for the request. This allows code that has been written against the
Apache C API to interact with the Apache request directly from
Python::

  WSGIPassApacheRequest On

This is intended for advanced use cases where the WSGI application,
or code it dispatches to, needs access to internal Apache state that
isn't otherwise exposed through the WSGI environment. The capsule
can only be used by C extension code that knows the Apache internals;
it is not a portable Python object.

This directive only applies in embedded mode. When the WSGI
application is delegated to a daemon process group the capsule is
not added, since the daemon process does not have direct access to
the Apache parent's ``request_rec`` structure — the request is
proxied across the daemon socket and the structure on the daemon
side is a reconstruction.

Most WSGI applications should leave this option ``Off``. Setting it
``On`` is only useful when paired with code specifically written to
consume the capsule.
