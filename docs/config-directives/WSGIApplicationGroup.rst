====================
WSGIApplicationGroup
====================

:Description: Sets which application group WSGI application belongs to.
:Syntax: ``WSGIApplicationGroup name``
         ``WSGIApplicationGroup %{GLOBAL}``
         ``WSGIApplicationGroup %{SERVER}``
         ``WSGIApplicationGroup %{RESOURCE}``
         ``WSGIApplicationGroup %{ENV:variable}``
:Default: ``WSGIApplicationGroup %{RESOURCE}``
:Context: server config, virtual host, directory

The ``WSGIApplicationGroup`` directive can be used to specify which
application group a WSGI application or set of WSGI applications belongs
to. All WSGI applications within the same application group will execute
within the context of the same Python sub interpreter of the process
handling the request.

The argument to the ``WSGIApplicationGroup`` can be either one of four
special expanding variables or an explicit name of your own choosing.
The meaning of the special variables are:

**%{GLOBAL}**

    The application group name will be set to the empty string.

    Any WSGI applications in the global application group will always be
    executed within the context of the first interpreter created by Python
    when it is initialised. Forcing a WSGI application to run within the
    first interpreter can be necessary when a third party C extension
    module for Python has used the simplified threading API for
    manipulation of the Python GIL and thus will not run correctly within
    any additional sub interpreters created by Python.

**%{SERVER}**

    The application group name will be set to the server hostname. If the
    request arrived over a non standard HTTP/HTTPS port, the port number
    will be added as a suffix to the group name separated by a colon.

    For example, if the virtual host ``www.example.com`` is handling
    requests on the standard HTTP port (80) and HTTPS port (443), a request
    arriving on either port would see the application group name being set
    to ``www.example.com``. If instead the virtual host was handling requests
    on port 8080, then the application group name would be set to
    ``www.example.com:8080``.

**%{RESOURCE}**

    The application group name will be set to the server hostname and port
    as for the ``%{SERVER}`` variable, to which the value of WSGI environment
    variable ``SCRIPT_NAME`` is appended separated by the file separator
    character.

    For example, if the virtual host ``www.example.com`` was handling
    requests on port 8080 and the URL-path which mapped to the WSGI
    application was::
    
        http://www.example.com/wsgi-scripts/foo
    
    then the application group name would be set to::

        www.example.com:8080|/wsgi-scripts/foo

    The effect of using the ``%{RESOURCE}`` variable expansion is for each
    application on any server to be isolated from all others by being
    mapped to its own Python sub interpreter.

**%{ENV:variable}**

    The application group name will be set to the value of the named
    environment variable. The environment variable is looked-up via the
    internal Apache notes and subprocess environment data structures and
    (if not found there) via ``getenv()`` from the Apache server process.

In an Apache configuration file, environment variables accessible using
the ``%{ENV}`` variable reference can be setup by using directives such as
`SetEnv`_ and `RewriteRule`_.

For example, to group all WSGI scripts for a specific user when using
`mod_userdir`_ within the same application group, the following could be
used::

  RewriteEngine On
  RewriteCond %{REQUEST_URI} ^/~([^/]+)
  RewriteRule . - [E=APPLICATION_GROUP:~%1]

  <Directory /home/*/public_html/wsgi-scripts/>
  Options ExecCGI
  SetHandler wsgi-script
  WSGIApplicationGroup %{ENV:APPLICATION_GROUP}
  </Directory>

Note that in embedded mode or a multi process daemon process group, there
will be an instance of the named sub interpreter in each process. Thus the
directive only ensures that request is handled in the named sub interpreter
within the process that handles the request. If you need to ensure that
requests for a specific user always go back to the exact same sub interpreter,
then you will need to use a daemon process group with only a single process,
or implement sticky session mechanism across a number of single process
daemon process groups.

.. _SetEnv: http://httpd.apache.org/docs/2.2/mod/mod_env.html#setenv
.. _RewriteRule: http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewriterule
.. _mod_userdir: http://httpd.apache.org/docs/2.2/mod/mod_userdir.html
