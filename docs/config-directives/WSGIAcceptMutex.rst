===============
WSGIAcceptMutex
===============

:Description: Specify type of accept mutex used by daemon processes.
:Syntax: ``WSGIAcceptMutex Default`` | *method*
:Default: ``WSGIAcceptMutex Default``
:Context: server config

The ``WSGIAcceptMutex`` directive sets the method that mod_wsgi will use to
serialize multiple daemon processes in a process group accepting requests
on a socket connection from the Apache child processes. If this directive
is not defined then the same type of mutex mechanism as used by Apache for
the main Apache child processes when accepting connections from a client
will be used. If set the method types are the same as for the Apache
`AcceptMutex`_ directive.

Note that the ``WSGIAcceptMutex`` directive and corresponding features are
not available on Windows or when running Apache 1.3.

.. _AcceptMutex: http://httpd.apache.org/docs/2.4/mod/mpm_common.html#acceptmutex
