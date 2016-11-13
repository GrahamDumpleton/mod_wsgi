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
            for item in self.__iterable:
                yield item
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
            except:
                self.__callback(environ)
                raise
            return Generator2(result, self.__callback, environ)

Note that for a successfully completed request, since the cleanup task will
be executed after the complete response has been written back to the
client, if an error occurs there will be no evidence of this in the
response seen by the client. As far as the client will be concerned
everything will look okay. The only indication of an error will be found in
the Apache error log.

Both of the solutions above are not specific to mod_wsgi and should work
with any WSGI hosting solution which complies with the WSGI specification.

Cleanup On Process Shutdown
---------------------------

To perform a cleanup task on shutdown of either an Apache child process
when using 'embedded' mode of mod_wsgi, or of a daemon process when using
'daemon' mode of mod_wsgi, the standard Python 'atexit' module can be used::

    import atexit

    def cleanup():
        # Perform required cleanup task.
        ...

    atexit.register(cleanup)

Such a registered cleanup function will also be called if the 'Interpreter'
reload mechanism is enabled and the Python sub interpreter in which the
cleanup function was registered was destroyed.

Note that although mod_wsgi will ensure that cleanup functions registered
using the 'atexit' module will be called correctly, this solution may not
be portable to all WSGI hosting solutions.

Also be aware that although one can register a cleanup function to be
called on process shutdown, this is no absolute guarantee that it will be
called. This is because a process may crash, or it may be forcibly killed
off by Apache if it takes too long to shutdown normally. As a result, an
application should not be dependent on cleanup functions being called on
process shutdown and an application must have some means of detecting an
abnormal shutdown when it is started up and recover from it automatically.
