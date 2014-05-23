===========
Version 1.2
===========

Version 1.2 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.2.tar.gz

Bug Fixes
---------

1. When headers are flushed by mod_wsgi is not strictly compliant with
the WSGI specification. In particular the specification says:

  The start_response callable must not actually transmit the response
  headers. Instead, it must store them for the server or gateway to
  transmit only after the first iteration of the application return value
  that yields a non-empty string, or upon the application's first
  invocation of the write() callable. In other words, response headers
  must not be sent until there is actual body data available, or until
  the application's returned iterable is exhausted. (The only possible
  exception to this rule is if the response headers explicitly include a
  Content-Length of zero.)

In mod_wsgi when an iterable was returned from the application, the headers
were being flushed even if the string was empty. See:

  http://code.google.com/p/modwsgi/issues/detail?id=35

2. Calling start_response() a second time to supply exception information
and status to replace prior response headers and status, was resulting in
a process crash when there had actually been response content sent and the
existing response headers and status flushed and written back to the client.
See:

  http://code.google.com/p/modwsgi/issues/detail?id=36

3. Added additional logging to highlight instance where WSGI script file was
removed in between the time that Apache matched request to it and the WSGI
script file was loaded and the request passed to it. These changes also log
something if the attempt to stat the WSGI script file in the daemon process
fails due to inadequate permissions or other reasons.

4. Fixed a few instances where logging via request object before fake
request object in daemon process had been constructed properly. The particular
cases would only have been triggered if something other than mod_wsgi code
with Apache child process had tried to communicate with the daemon process.

5. Fixed problem when Apache 1.3 or 2.0 was being used, where the
automatically determined default for the application group (interpreter)
name would be wrong where the URL had repeating slashes in it after the
leading portion of the URL which mapped to the mount point of the WSGI
application. See:

  http://code.google.com/p/modwsgi/issues/detail?id=39

In particular, for a URL with the repeating slash the application group
name would have a trailing slash appended when it shouldn't. The
consequences of this are that two instances of the WSGI application could
end up being loaded into the same process, doubling the memory usage for
the process.

Besides the additional memory use, this would in general not be an issue
as most applications would be designed to work within multi process
environment of Apache. If however a specific application was designed to
only work within a single process (interpreter instance), as would occur
when Windows was being used, or a single daemon process with daemon mode,
then there may be issues as requests which had a repeating slash in the
URL would not access the same application data as those without.

Note, this problem could only arise where WSGIApplicationGroup directive
wasn't used and thus default value being used. Or the value '%{RESOURCE}'
was specified as argument to WSGIApplicationGroup, this being the same as
the default.

6. Fixed problem whereby status of sub processes created from mod_wsgi
daemon processes were not being caught properly. This was because mod_wsgi
was wrongly blocking SIGCHLD signal. See:

  http://code.google.com/p/modwsgi/issues/detail?id=38
