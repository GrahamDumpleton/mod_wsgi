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
would be received by the client. To resolve the problem, the
WSGISocketPrefix directive should be defined to point at an alternate
location. The value may be a location relative to the Apache root directory,
or an absolute path.

On systems which restrict access to the standard Apache runtime directory,
they normally provide an alternate directory for placing sockets and lock
files used by Apache modules. This directory is usually called 'run' and
to make use of this directory the WSGISocketPrefix directive would be set
as follows::

  WSGISocketPrefix run/wsgi

Note, do not put the sockets in the system temporary working directory.
That is, do not go making the prefix '/tmp/wsgi'. The directory should be
one that is only writable by 'root' user, or if not starting Apache as 
'root', the user that Apache is started as.

Note that the WSGISocketPrefix directive and corresponding features are not
available on Windows or when running Apache 1.3.
