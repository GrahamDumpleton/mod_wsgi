==================
WSGIRestrictSignal
==================

:Description: Enable restrictions on use of signal().
:Syntax: ``WSGIRestrictSignal On|Off``
:Default: ``WSGIRestrictSignal On``
:Context: server config

A well behaved Python WSGI application should not in general register any
signal handlers of its own using ``signal.signal()``. The reason for this
is that the web server which is hosting a WSGI application will more than
likely register signal handlers of its own. If a WSGI application were to
override such signal handlers it could interfere with the operation of the
web server, preventing actions such as server shutdown and restart.

In the interests of promoting portability of WSGI applications, mod_wsgi
restricts use of ``signal.signal()`` and will ensure that any attempts
to register signal handlers are ignored. A warning notice will be output
to the Apache error log indicating that this action has been taken.

If for some reason there is a need for a WSGI application to register some
special signal handler this behaviour can be turned off, however an
application should avoid the signals ``SIGTERM``, ``SIGINT``,
``SIGHUP``, ``SIGWINCH`` and ``SIGUSR1`` as these are all used by
Apache.

Apache will ensure that the signal ``SIGPIPE`` is set to ``SIG_IGN``.
If a WSGI application needs to override this, it must ensure that it is
reset to ``SIG_IGN`` before any Apache code is run. In a multi threaded
MPM this would be practically impossible to ensure so it is preferable that
the handler for ``SIG_PIPE`` also not be changed.

Apache does not use ``SIGALRM``, but it is generally preferable that
other techniques be used to achieve the same affect.

Do note that if enabling the ability to register signal handlers, such a
registration can only reliably be done from within code which is
implemented as a side effect of importing a script file identified by the
WSGIImportScript directive. This is because signal handlers can only be
registered from the main Python interpreter thread, and request handlers
when using embedded mode and a multithreaded Apache MPM would generally
execute from secondary threads. Similarly, when using daemon mode, request
handlers would executed from secondary threads. Only code run as a side
effect of WSGIImportScript is guaranteed to be executed in main Python
interpreter thread.
