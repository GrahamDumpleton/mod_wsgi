================
WSGISocketPrefix
================

:Description: Configure directory to use for daemon sockets.
:Syntax: ``WSGISocketPrefix`` *prefix*
:Context: server config

Defines the directory and name prefix to be used for the UNIX domain
sockets used by mod_wsgi to communicate between the Apache child processes
and the daemon processes.

If the directive is not defined, the sockets and any related mutex lock
files will be placed in the standard Apache runtime directory. This is the
same directory that the Apache log files would normally be placed.

For some Linux distributions, restrictive permissions are placed on the
standard Apache runtime directory such that the directory is not readable
to others. This can cause problems with mod_wsgi because the user that the
Apache child processes run as will subsequently not have the required
permissions to access the directory to be able to connect to the sockets.

When this occurs, a '503 Service Temporarily Unavailable' error response
would be received by the client. The Apache error log will contain a
message tagged with mod_wsgi error code ``WSGI0117``, indicating the
Apache user lacks permission to reach the socket directory (the EACCES
case). See :doc:`../error-reference` for the full text of the message.

To resolve the problem, the WSGISocketPrefix directive should be defined
to point at an alternate location. The value may be a location relative
to the Apache root directory, or an absolute path.

On systems which restrict access to the standard Apache runtime directory,
they normally provide an alternate directory for placing sockets and lock
files used by Apache modules. This directory is usually called 'run' and
to make use of this directory the WSGISocketPrefix directive would be set
as follows::

  WSGISocketPrefix run/wsgi

Do not place the sockets in the system temporary directory (for example,
``/tmp/wsgi``). The directory used should only be writable by the
``root`` user, or, if Apache is not started as ``root``, by the user
that Apache is started as.

The same directory is also used by mod_wsgi for any mutex lock files
associated with daemon processes. See WSGIAcceptMutex for related
configuration of the accept mutex used by daemon process groups.

Note that the WSGISocketPrefix directive and corresponding features are not
available on Windows.
