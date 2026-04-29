==================
WSGISocketRotation
==================

:Description: Control rotation of daemon-process socket file names.
:Syntax: ``WSGISocketRotation On|Off``
:Default: ``WSGISocketRotation On``
:Context: server config

Controls how mod_wsgi names the UNIX domain sockets used for
communication between the Apache child processes and daemon
process groups, and specifically how those names change across
Apache graceful restarts.

By default, the socket file name incorporates the parent Apache
process ID and the Apache MPM generation number::

  <prefix>.<pid>.<generation>.<id>.sock

A graceful restart of Apache (``apachectl graceful``) does not
shut the parent down. The configuration is re-read and modules are
re-initialised, but the parent's PID is unchanged. What does change
is the MPM generation number, which increments on each graceful
restart. With rotation on, that means each generation gets a
distinct daemon socket path. mod_wsgi daemon process groups are
restarted as part of the graceful restart and the new processes
listen on the new path.

The wrinkle is that Apache's existing child worker processes are
not killed immediately on a graceful restart — they are left to
finish in-flight requests, and to honour any open ``Keep-Alive``
connections, for up to the configured ``GracefulShutdownTimeout``
(commonly 60 seconds). Within that window an old worker may
receive a fresh request on a long-lived ``Keep-Alive`` connection
and try to forward it to the daemon. Because the worker is still
operating against the previous generation it will attempt to
connect on the old socket path, which no longer exists, and the
forward fails.

Setting ``WSGISocketRotation Off`` keeps the path stable across
graceful restarts by replacing the generation number with the
daemon process user ID::

  <prefix>.<pid>.u<uid>.<id>.sock

This is the appropriate setting if you run with a non-trivial
``KeepAliveTimeout`` and need old workers to remain functional
during the graceful-shutdown window.

The trade-off is that those old workers are still running against
the *previous* Apache configuration, while the daemon process group
they are now connecting to was restarted under the *new*
configuration. In most cases the configuration change is small
enough that nothing visible breaks, but the situation should be
weighed against the alternative — particularly if a graceful
restart is being used to land changes that affect request handling
in incompatible ways.

In practice, the symptom that leads people to this directive most
often comes from log-rotation tooling. Many Linux distributions
ignore Apache's own ``rotatelogs``-style log rotation and instead
use an external log rotation service such as ``logrotate``, which
renames the log files and then sends the Apache parent a graceful
restart signal so it reopens them. If that is set up to run at the
same time each day, you may see a recurring burst of mod_wsgi
errors at that exact time as old child workers, still finishing
in-flight or keep-alive traffic, fail to reach the rotated daemon
sockets. The errors involved are :ref:`WSGI0116` ("Unable to connect to
WSGI daemon process '<group>' on '<path>' after multiple attempts
as listener backlog limit was exceeded or the socket does not
exist") and :ref:`WSGI0117` ("Unable to connect to WSGI daemon
process '<group>' on '<path>' as user with uid=...") — depending
on whether the now-defunct socket file was cleaned up at restart
or left behind on disk. If those errors line up with the system
log-rotation schedule, ``WSGISocketRotation Off`` is usually the
fix.

The directive applies to all daemon process groups defined for
the server. The directory in which the sockets are placed is set
separately by the WSGISocketPrefix directive.

Note that the WSGISocketRotation directive and corresponding
features are not available on Windows.
