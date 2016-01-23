================
WSGIProcessGroup
================

:Description: Sets which process group WSGI application is assigned to.
:Syntax: ``WSGIProcessGroup %{GLOBAL}|%{ENV:variable}|name``
:Default: ``WSGIProcessGroup %{GLOBAL}``
:Context: server config, virtual host, directory

The WSGIProcessGroup directive can be used to specify which process group a
WSGI application or set of WSGI applications will be executed in. All WSGI
applications within the same process group will execute within the context
of the same group of daemon processes.

The argument to the WSGIProcessGroup can be either one of two special
expanding variables or the actual name of a group of daemon processes setup
using the WSGIDaemonProcess directive. The meaning of the special variables
are:

**%{GLOBAL}**
    The process group name will be set to the empty string.

    Any WSGI applications in the global process group will always be
    executed within the context of the standard Apache child processes.
    Such WSGI applications will incur the least runtime overhead, however,
    they will share the same process space with other Apache modules such
    as PHP, as well as the process being used to serve up static file
    content. Running WSGI applications within the standard Apache child
    processes will also mean the application will run as the user that
    Apache would normally run as.

**%{ENV:variable}**
    The process group name will be set to the value of the named
    environment variable. The environment variable is looked-up via the
    internal Apache notes and subprocess environment data structures and
    (if not found there) via getenv() from the Apache server process.
    The result must identify a named process group setup using the
    WSGIDaemonProcess directive.

In an Apache configuration file, environment variables accessible using
the ``%{ENV}`` variable reference can be setup by using directives such as
`SetEnv`_ and `RewriteRule`_.

For example, to select which process group a specific WSGI application
should execute within based on entries in a database file, the following
could be used::

  RewriteEngine On
  RewriteMap wsgiprocmap dbm:/etc/httpd/wsgiprocmap.dbm
  RewriteRule . - [E=PROCESS_GROUP:${wsgiprocmap:%{REQUEST_URI}}]

  WSGIProcessGroup %{ENV:PROCESS_GROUP}

When using the WSGIProcessGroup directive, only daemon process groups
defined within virtual hosts with the same server name, or those defined at
global scope outside of any virtual hosts can be selected. It is not
possible to select a daemon process group which is defined within a
different virtual host. Which daemon process groups can be selected may be
further restricted if the WSGIRestrictProcess directive has been used.

Note that the WSGIProcessGroup directive and corresponding features are not
available on Windows or when running Apache 1.3.

.. _SetEnv: http://httpd.apache.org/docs/2.2/mod/mod_env.html#setenv
.. _RewriteRule: http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewriterule
