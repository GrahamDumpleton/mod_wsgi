========================
Registering Cleanup Code
========================

This document describes how to go about registering callbacks to perform
cleanup tasks at the end of a request and when an application process is
being shutdown.

Cleanup At End Of Request
-------------------------

To perform a cleanup task at the end of a request a couple of different
approaches can be used dependent on the requirements. The first approach
entails wrapping the calling of a WSGI application within a Python 'try'
block, with the cleanup code being triggered from the 'finally' block::

    def _application(environ, start_response):
        status = '200 OK' 
        output = b'Hello World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

    def application(environ, start_response):
        try:
            return _application(environ, start_response)
        finally:
            # Perform required cleanup task.
            ...

This might even be factored into a convenient WSGI middleware component::

    class ExecuteOnCompletion1:
        def __init__(self, application, callback):
            self.__application = application
            self.__callback = callback
        def __call__(self, environ, start_response):
            try:
                return self.__application(environ, start_response)
            finally:
                self.__callback(environ)

The WSGI environment passed in the 'environ' argument to the application
could even be supplied to the cleanup callback as shown in case it needed
to look at any configuration information or information passed back in the
environment from the application.

The application would then be replaced with an instance of this class
initialised with a reference to the original application and a suitable
cleanup function::

    def cleanup(environ):
        # Perform required cleanup task.
        ...
        
    application = ExecuteOnCompletion1(_application, cleanup)

Using this approach, the cleanup function will actually be called prior to
the response content being consumed by mod_wsgi and written back to the
client. As such, it is probably only suitable where a complete response is
returned as an array of strings. It would not be suitable where a generator
is being returned as the cleanup would be called prior to any strings being
consumed from the generator. This would be problematic where the cleanup
task was to close or delete some resource from which the generator was
obtaining the response content.

In order to have the cleanup task only executed after the complete response
has been consumed, it would be necessary to wrap the result of the
application within an instance of a purpose built generator like object.
This object needs to yield each item from the response in turn, and when
this object is cleaned up by virtue of the 'close()' method being called,
it should in turn call 'close()' on the result returned from the application
if necessary, and then call the supplied cleanup callback::

    class Generator2:
        def __init__(self, iterable, callback, environ):
            self.__iterable = iterable
            self.__callback = callback
            self.__environ = environ
        def __iter__(self):
            yield from self.__iterable
        def close(self):
            try:
                if hasattr(self.__iterable, 'close'):
                    self.__iterable.close()
            finally:
                self.__callback(self.__environ)

    class ExecuteOnCompletion2:
        def __init__(self, application, callback):
            self.__application = application
            self.__callback = callback
        def __call__(self, environ, start_response):
            try:
                result = self.__application(environ, start_response)
            except Exception:
                self.__callback(environ)
                raise
            return Generator2(result, self.__callback, environ)

Note that for a successfully completed request the cleanup task runs
after the complete response has already been written back to the
client. If the cleanup function itself raises an exception, the
client will already have seen a successful response — the failure
will be visible only in the Apache error log.

Both of the solutions above are not specific to mod_wsgi and should
work with any WSGI hosting solution which complies with the WSGI
specification.

Cleanup On Process Shutdown
---------------------------

To perform a cleanup task on shutdown of either an Apache child
process when using ``embedded`` mode of mod_wsgi, or of a daemon
process when using ``daemon`` mode of mod_wsgi, the recommended
mechanism is to register a callback with ``mod_wsgi.subscribe_shutdown()``::

    import mod_wsgi

    def cleanup(event):
        # Perform required cleanup task.
        ...

    mod_wsgi.subscribe_shutdown(cleanup)

The callback receives a single ``event`` argument, a dictionary that
includes a ``shutdown_reason`` key describing why the process is
stopping (graceful shutdown, eviction, request-time-limit eviction,
and so on).

The standard Python ``atexit`` module can also be used::

    import atexit

    def cleanup():
        # Perform required cleanup task.
        ...

    atexit.register(cleanup)

However, ``atexit`` callbacks under mod_wsgi are not always
delivered. mod_wsgi runs them by patching ``threading._shutdown`` so
they fire when a sub interpreter is destroyed via
``Py_EndInterpreter``. Two situations make this unreliable:

* If
  :doc:`../configuration-directives/WSGIDestroyInterpreter`
  is set to ``Off``, sub interpreters are not destroyed at process
  shutdown and the patched ``threading._shutdown`` path is never
  taken — registered ``atexit`` functions will not run at all.
* Internal Python changes to the order in which threads are shut
  down relative to ``atexit`` invocation can leave the patched
  path unreached even when interpreter destruction is enabled.

By contrast, ``mod_wsgi.subscribe_shutdown()`` callbacks are
dispatched directly by mod_wsgi early in the shutdown sequence,
before in-flight requests are waited on and before any interpreter
destruction is attempted. They run regardless of
``WSGIDestroyInterpreter`` and regardless of how Python orders its
internal thread shutdown. New code should prefer
``mod_wsgi.subscribe_shutdown()``; existing ``atexit`` registrations
will keep working in the cases where the patched path still fires
but should be migrated where reliability matters.

Note that ``mod_wsgi.subscribe_shutdown()`` is a mod_wsgi-specific
extension and not portable to other WSGI hosting solutions; ``atexit``
is portable but unreliable as described.

Also be aware that even with ``mod_wsgi.subscribe_shutdown()``,
delivery of the callback is not absolutely guaranteed. The process
may crash, or it may be forcibly killed by Apache if it takes too
long to shut down. An application should therefore not be entirely
dependent on cleanup callbacks running, and should have some means
of detecting an abnormal shutdown when it next starts up and
recovering from it automatically.
