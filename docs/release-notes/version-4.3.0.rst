=============
Version 4.3.0
=============

Version 4.3.0 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.0.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Performing authorization using the ``WSGIAuthGroupScript`` was not
working correctly on Apache 2.4 due to changes in how auth providers
and authentication/authorization works. The result could be that a user
could gain access to a resource even though they were not in the
required group.

New Features
------------

1. The value of the ``REMOTE_USER`` variable for an authenticated user
when user ``Basic`` authentication can now be overridden from an
authentication handler specified using the ``WSGIAuthUserScript``. To
override the name used to identify the user, instead of returning ``True``
when indicating that the user is allowed, return the name to be used for
that user as a string. That value will then be passed through in
``REMOTE_USER`` in place of any original value::

    def check_password(environ, user, password):
        if user == 'spy':
            if password == 'secret':
                return 'grumpy'
            return False
        return None

2. Added the ``--debug-mode`` option to ``mod_wsgi-express`` which results
in Apache and the WSGI application being run in a single process which is
left attached to stdin/stdout of the shell where the script was run. Only a
single thread will be used to handle any requests.

This feature enables the ability to interactively debug a Python WSGI
application using the Python debugger (``pdb``). The simplest way to
break into the Python debugger is by adding to your WSGI application code::

    import pdb; pdb.set_trace()

3. Added the ``--application-type`` option to ``mod_wsgi-express``. This
defaults to ``script`` indicating that the target WSGI application provided
to ``mod_wsgi-express`` is a WSGI script file defined by a relative or
absolute file system path.

In addition to ``script``, it is also possible to supply for the application
type ``module`` and ``paste``.

For the case of ``module``, the target WSGI application will be taken to
reside in a Python module with the specified name. This module will be
loaded using the standard Python module import system and so must reside
on the Python module search path.

For the case of ``paste``, the target WSGI application will be taken to be
a Paste deployment configuration file. In loading the Paste deployment
configuration file, any WSGI application pipeline specified by the
configuration will be constructed and the resulting top level WSGI
application entry point returned used as the WSGI application.

Note that the code file for the WSGI script file, Python module, or Paste
deployment configuration file, if modified, will all result in the WSGI
application being automatically reloaded on the next web request.

4. Added the ``--auth-user-script`` and ``--auth-type`` options to
``mod_wsgi-express`` to enable the hosted site to implement user
authentication using either HTTP ``Basic`` or ``Digest`` authentication
mechanisms. The ``check_password()`` or ``get_realm_hash()`` functions
should follow the same form as if using the ``WSGIAuthUserScript`` direct
with mod_wsgi when using manual configuration.
