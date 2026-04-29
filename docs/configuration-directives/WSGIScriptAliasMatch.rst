====================
WSGIScriptAliasMatch
====================

:Description: Maps a URL to a filesystem location and designates the target as a WSGI script.
:Syntax: ``WSGIScriptAliasMatch`` *regex file-path|directory-path* ``[`` *options* ``]``
:Context: server config, virtual host

This directive is similar to the WSGIScriptAlias directive, but matches
URLs using a regular expression instead of a simple prefix. The supplied
regular expression is matched against the URL-path, and if it matches,
the server will substitute any parenthesised matches into the given
string and use the result as the filename.

For example, to map a URL to scripts contained within a directory where
the script files use the ``.wsgi`` extension, but it is desired that the
extension not appear in the URL, use::

  WSGIScriptAliasMatch ^/wsgi-scripts/([^/]+) /web/wsgi-scripts/$1.wsgi

In most cases you should be using ``WSGIScriptAlias`` rather than
``WSGIScriptAliasMatch``. The reason is that the regex form gives you
more rope: it is easy to write a substitution that consumes too much of
the request URL into the *file-path*, with the result that the WSGI
application sees an unexpected ``SCRIPT_NAME``. When that happens,
internal URL routing in the application breaks (links resolve against
the wrong base) and any code that reconstructs the full request URL
from ``SCRIPT_NAME`` and ``PATH_INFO`` produces incorrect URLs in
redirects or generated links.

If you want to dispatch all URLs starting with a particular prefix to a
single WSGI script while keeping the prefix in ``SCRIPT_NAME``, the
trick is to embed the script path inside the substitution and append
the captured remainder so it becomes ``PATH_INFO``::

  WSGIScriptAliasMatch "^/(admin|files|photologue)" /projects/Media/wsgi_handler.py/$1

This keeps the matched portion of the URL visible to the WSGI
application as path information rather than having it stripped at the
Apache layer.

In both examples the choice of file extension (``.wsgi`` in the first,
``.py`` in the second) is a convention only — ``WSGIScriptAliasMatch``
identifies the script by the full file path produced from the regex
substitution and any extension (or none) is acceptable. The ``.wsgi``
convention is used in many examples to avoid clashing with any
pre-existing ``AddHandler`` directive that may already map ``.py`` files
to a different handler such as ``cgi-script``. If you know there is no
such conflict, ``.py`` is acceptable.

Options which can be supplied to the ``WSGIScriptAliasMatch`` directive
are:

**process-group=name**
    Defines which process group the WSGI application will be executed
    in. All WSGI applications within the same process group will execute
    within the context of the same group of daemon processes.

    If the name is set to be ``%{GLOBAL}`` the process group name will
    be set to the empty string. Any WSGI applications in the global
    process group will always be executed within the context of the
    standard Apache child processes. Such WSGI applications will incur
    the least runtime overhead, however, they will share the same
    process space with other Apache modules such as PHP, as well as the
    process being used to serve up static file content. Running WSGI
    applications within the standard Apache child processes will also
    mean the application will run as the user that Apache would normally
    run as.

    If the name takes the form ``%{ENV:variable}``, the process group
    name will be taken from the named Apache environment variable.

**application-group=name**
    Defines which application group a WSGI application or set of WSGI
    applications belongs to. All WSGI applications within the same
    application group will execute within the context of the same Python
    sub interpreter of the process handling the request.

    If the name is set to be ``%{GLOBAL}`` the application group will be
    set to the empty string. Any WSGI applications in the global
    application group will always be executed within the context of the
    main Python interpreter of the process handling the request. Forcing
    a WSGI application to run within the main interpreter can be
    necessary when a third party C extension module for Python has used
    the simplified threading API for manipulation of the Python GIL and
    thus will not run correctly within any additional sub interpreters
    created by Python.

    If the name takes the form ``%{ENV:variable}``, the application
    group name will be taken from the named Apache environment variable.

When the ``%{ENV:variable}`` form is used, the named environment
variable is looked up via the internal Apache notes and subprocess
environment data structures, and (if not found there) via
``getenv()`` from the Apache server process.

Environment variables accessible via the ``%{ENV}`` reference can be
set in the Apache configuration using directives such as `SetEnv`_
and `RewriteRule`_.

If both ``process-group`` and ``application-group`` options are set, and
the WSGI script file path doesn't include substitution values to be
supplied from the matched URL pattern, the WSGI script file will be
pre-loaded when the process it is to run in is started, rather than
being lazily loaded on the first request. This removes the per-process
startup delay that would otherwise be paid by the first request to
reach each process.

For configurations that do not use ``WSGIScriptAliasMatch``, or where
you want to preload additional script files alongside the main one,
see the WSGIImportScript directive.

.. _SetEnv: http://httpd.apache.org/docs/2.4/mod/mod_env.html#setenv
.. _RewriteRule: http://httpd.apache.org/docs/2.4/mod/mod_rewrite.html#rewriterule
