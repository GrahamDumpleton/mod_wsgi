===============
WSGIAcceptMutex
===============

:Description: Specify type of accept mutex used by daemon processes.
:Syntax: ``WSGIAcceptMutex Default`` | *method*
:Default: ``WSGIAcceptMutex Default``
:Context: server config

When a daemon process group has multiple processes, they all share a
single listener socket. Only one of those processes can accept a given
connection from the Apache child processes, so the accept call has to
be serialised across the group with a mutex. The ``WSGIAcceptMutex``
directive sets the method used for this serialisation.

If this directive is not defined then the same type of mutex mechanism
as used by Apache for its own child processes when accepting connections
from a client will be used. If set, the available method values are the
same as those documented for the Apache `Mutex`_ directive — typically
``posixsem``, ``sysvsem``, ``fcntl``, ``flock``, ``pthread``, or
``default``.

For example, to force use of a POSIX semaphore::

  WSGIAcceptMutex posixsem

Note that the ``WSGIAcceptMutex`` directive and corresponding features are
not available on Windows.

.. _Mutex: http://httpd.apache.org/docs/2.4/mod/core.html#mutex
