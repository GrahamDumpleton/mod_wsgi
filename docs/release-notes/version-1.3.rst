===========
Version 1.3
===========

Version 1.3 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.3.tar.gz

Bug Fixes
---------

1. Fix bug whereby mod_wsgi daemon process could hang when a request with
content greater than UNIX socket buffer size, was directed at a WSGI
application resource handler which in turn returned a response, greater
than UNIX socket buffer size, without first consuming the request content.

There were two aspects to this problem, the first is that the above would
trigger that specific request to hang. Second was that at the point of the
hang, the Python GIL hadn't been released, and so all other threads were
blocked from running any Python code resulting in whole process effectively
hanging.

Code now correctly ensures that Python GIL is released prior to going into
potentially blocking operation. Secondly, where mutual deadlock between
Apache child process and mod_wsgi daemon process, timeout as defined by the
standard Apache 'Timeout' directive will now kick in and remaining request
content discarded by Apache child process so that thread in the daemon
process can continue and break out of its hung state.

Although this can still result in request thread being in a hung state
until the timeout occurs, this mirrors exactly what would happen if running
a WSGI application using a CGI-WSGI bridge behind Apache mod_cgi module. A
better solution which would avoid the hung state altogether is still being
investigated.

Note that this scenario shouldn't ever eventuate for a correctly implemented
and functioning web application, however it is feasible that it could be
triggered as a result of spambots which attempt to POST data randomly to
sites with the hope they find a wiki system with an unprotected comment
system.
