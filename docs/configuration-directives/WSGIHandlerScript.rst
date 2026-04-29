=================
WSGIHandlerScript
=================

:Description: Register a named WSGI handler script.
:Syntax: ``WSGIHandlerScript`` *name path* ``[`` *options* ``]``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Registers a Python script as a named Apache handler. The named
handler can then be selected by Apache's standard ``SetHandler`` or
``AddHandler`` directives, at which point mod_wsgi will load the
script and dispatch the request to its ``handle_request`` callable.

This is an alternative dispatch path to ``WSGIScriptAlias``. Where
``WSGIScriptAlias`` ties a script to a URL prefix, ``WSGIHandlerScript``
ties a script to an Apache handler name, which can then be applied to
arbitrary URL ranges or file extensions through the standard Apache
handler-selection directives.

The script identified by *path* must define a top-level ``handle_request``
callable that follows the standard WSGI calling convention. The
callable name is fixed; the WSGICallableObject directive does not
apply.

The first argument to the directive is the *name* used to identify the
handler in Apache configuration, for example::

  WSGIHandlerScript wsgi-resource /etc/apache2/wsgi/resource.wsgi \
      process-group=mygroup application-group=%{GLOBAL}

  AddHandler wsgi-resource .myext

When a request maps to a file with the ``.myext`` extension, Apache
will dispatch it to the ``wsgi-resource`` handler, mod_wsgi will load
``resource.wsgi`` (in the named daemon process group, in the global
application group), and call its ``handle_request`` function with the
WSGI ``environ`` and ``start_response``.

Options which can be supplied to the directive are:

**process-group=name**
    Defines which daemon process group the handler script runs in.
    Same semantics as the ``process-group`` option to
    WSGIScriptAlias. If unset the script runs in the standard
    Apache child processes (embedded mode).

**application-group=name**
    Defines which application group (Python sub interpreter) the
    handler script runs in. Same semantics as the
    ``application-group`` option to WSGIScriptAlias.

**pass-authorization=On|Off**
    Controls whether HTTP authorisation headers are passed through
    in the WSGI environment for requests dispatched to this handler.
    Same semantics as the WSGIPassAuthorization directive but
    scoped to the handler.

Multiple ``WSGIHandlerScript`` directives can be used to register
distinct handler names, each with its own script and options.
