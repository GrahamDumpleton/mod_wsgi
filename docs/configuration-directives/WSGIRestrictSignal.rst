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
to register signal handlers are ignored. The interceptor logs a warning
to the Apache error log and prints a Python stack trace identifying the
caller, then returns without raising an exception, so calling code does
not observe a failure even though the handler was not installed.

If for some reason there is a need for a WSGI application to register
some special signal handler this behaviour can be turned off::

  WSGIRestrictSignal Off

When the restriction is off an application should avoid the signals
``SIGINT``, ``SIGTERM``, ``SIGHUP``, ``SIGWINCH``, ``SIGUSR1`` and
``SIGXCPU`` as these are all claimed by Apache or by mod_wsgi for
process management, graceful restart and CPU time limits. The signal
that is generally free for application use is ``SIGUSR2``.

Apache will ensure that the signal ``SIGPIPE`` is set to ``SIG_IGN``.
If a WSGI application needs to override this, it must ensure that it is
reset to ``SIG_IGN`` before any Apache code is run. In a multi threaded
MPM this would be practically impossible to ensure so it is preferable
that the handler for ``SIGPIPE`` also not be changed.

Apache does not use ``SIGALRM``, but it is generally preferable that
other techniques be used to achieve the same effect.

When handler dispatch actually occurs
-------------------------------------

Successfully registering a signal handler is necessary but not sufficient
for the handler to actually run. CPython only dispatches a Python signal
handler when the main thread of the main interpreter is executing
bytecode and reaches the periodic pending-signal check. If the main
thread is not executing Python code, the operating system signal is
received and a pending flag is set, but the Python handler is never
invoked.

This has different consequences in each mod_wsgi configuration:

Prefork MPM, embedded mode
  Each Apache child process has a single thread. That thread runs
  child initialisation (and is therefore the Python main thread) and
  also handles every subsequent request. Python signal handlers
  registered from this configuration are dispatched the next time a
  request runs application code through the interpreter. This is the
  only mod_wsgi configuration where ``WSGIRestrictSignal Off`` together
  with ``signal.signal()`` is a working pattern. If the signal arrives
  while the child is blocked waiting for the next connection, dispatch
  is deferred until the next request arrives; on a low-traffic child
  this latency can be unbounded.

Worker or event MPM, embedded mode
  Requests are handled on secondary threads from a thread pool. The
  Python main thread runs only at child initialisation and at
  shutdown; in between it executes Apache scheduler code in C and
  never re-enters the interpreter. Signal handlers registered from
  application code are not dispatched while the server is processing
  requests.

Daemon mode
  Each daemon process has a dedicated main thread that performs
  Python initialisation, then enters a poll loop on an internal
  signal pipe used for shutdown coordination, and remains there for
  the rest of the process's lifetime. WSGI requests run on secondary
  worker threads. Signal handlers registered from application code
  are not dispatched.

Registration thread requirement
-------------------------------

Independent of dispatch, ``signal.signal()`` itself can only be called
from the main Python interpreter thread. In prefork embedded mode this
is the request-handling thread, so registration can happen at any
time, including from inside a request handler. In every other
configuration, request handlers run on secondary threads and
``signal.signal()`` would raise ``ValueError`` if called from one of
them. The only place that is guaranteed to run on the main thread in
worker, event and daemon configurations is code executed as a side
effect of importing a script file identified by the
:doc:`WSGIImportScript` directive. Even where registration is permitted
there, the dispatch limitation described above still applies: the
handler is recorded against the signal but will not fire while the
server is processing requests.

Container scope
---------------

The directive is also valid inside a :doc:`WSGIInterpreterOptions`
container. When nested, the setting applies only to interpreters
matched by the container's selectors and overrides the top-level
value for those interpreters.
