==================
WSGICallableObject
==================

:Description: Sets the name of the WSGI application callable.
:Syntax: ``WSGICallableObject`` *name*
         ``WSGICallableObject %{ENV:variable}``
:Default: ``WSGICallableObject application``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

The WSGICallableObject directive can be used to override the name of the
Python callable object in the script file which is used as the entry point
into the WSGI application.

When ``%{ENV}`` is being used, the environment variable is looked-up via the
internal Apache notes and subprocess environment data structures and (if
not found there) via getenv() from the Apache server process.

In an Apache configuration file, environment variables accessible using
the ``%{ENV}`` variable reference can be setup by using directives such as
`SetEnv`_ and `RewriteRule`_.

Note that the name of the callable object must be an object present at
global scope within the WSGI script file. It is not possible to use a dotted
path to refer to a sub object of a module imported by the WSGI script file.

.. _SetEnv: http://httpd.apache.org/docs/2.2/mod/mod_env.html#setenv
.. _RewriteRule: http://httpd.apache.org/docs/2.2/mod/mod_rewrite.html#rewriterule
