====================
Configuration Issues
====================

Many Linux distributions in particular do not structure an Apache
installation in the default manner as dictated by the original Apache code
distributed by the Apache Software Foundation. This fact, and differences
between different operating systems and distributions means that the
configuration for mod_wsgi may sometimes have to be tweaked.

The purpose of this document is to capture all the known problems that can
arise in respect of configuration.

If you are having a problem which doesn't seem to be covered by this
document, also make sure you see :doc:`../user-guides/installation-issues`
and :doc:`../user-guides/application-issues`.

Location Of UNIX Sockets
------------------------

When mod_wsgi is used in 'daemon' mode, UNIX sockets are used to
communicate between the Apache child processes and the daemon processes
which are to handle a request.

These sockets and any related mutex lock files will be placed in the
standard Apache runtime directory. This is the same directory that the
Apache log files would normally be placed.

For some Linux distributions, restrictive permissions are placed on the
standard Apache runtime directory such that the directory is not readable
to others. This can cause problems with mod_wsgi because the user that the
Apache child processes run as will subsequently not have the required
permissions to access the directory to be able to connect to the sockets.

When this occurs, a '503 Service Temporarily Unavailable' error response
would be received by the client. The Apache error log file would show
messages of the form::

    (13)Permission denied: mod_wsgi (pid=26962): Unable to connect to WSGI \
     daemon process '<process-name>' on '/etc/httpd/logs/wsgi.26957.0.1.sock' \
     after multiple attempts. 

To resolve the problem, the WSGISocketPrefix directive should be defined to
point at an alternate location. The value may be a location relative to the
Apache root directory, or an absolute path.

On systems which restrict access to the standard Apache runtime directory,
they normally provide an alternate directory for placing sockets and lock
files used by Apache modules. This directory is usually called 'run' and
to make use of this directory the WSGISocketPrefix directive would be set
as follows::

    WSGISocketPrefix run/wsgi

Although this may be present, do be aware that some Linux distributions,
notably RedHat, also lock down the permissions of this directory as well so
not readable to processes running as a non root user. In this situation you
will be forced to use the operating system level '/var/run' directory
rather than the HTTP specific directory::

    WSGISocketPrefix /var/run/wsgi

Note, do not put the sockets in the system temporary working directory.
That is, do not go making the prefix '/tmp/wsgi'. The directory should be
one that is only writable by 'root' user, or if not starting Apache as
'root', the user that Apache is started as.
