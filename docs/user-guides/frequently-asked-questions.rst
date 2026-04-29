==========================
Frequently Asked Questions
==========================

Apache Process Crashes
----------------------

**Q**: When the first request is made against a WSGI application, why does the
Apache server process handling the request crash with a 'segmentation
fault'?

**A**: This is nearly always caused by one of two things.

The first is a shared library version conflict — Apache or some
Apache module is linked against a different version of a shared
library than what is loaded indirectly by a Python C extension. The
classic example today is mod_ssl statically linked against one
OpenSSL and Python's ``ssl`` module dynamically linked against
another. See "Anaconda Python Conflicting With System Shared
Libraries" in :doc:`../user-guides/installation-issues` for the
workaround.

The second is a third-party C extension module that does not work
correctly outside the main Python interpreter. The most prominent
modern examples are NumPy, SciPy and modules built on top of them.
The workaround is to force the WSGI application into the main
interpreter with ``WSGIApplicationGroup %{GLOBAL}``. See
"WSGIApplicationGroup and C extension modules" in
:doc:`../user-guides/configuration-issues` and "Multiple Python Sub
Interpreters" in :doc:`../user-guides/application-issues`.

In embedded mode the only log evidence will be the Apache
``segmentation fault`` notification when Apache reaps the crashed
child, since the Apache child is the same process that was running
the WSGI application. In daemon mode the segfault is logged for the
daemon process, and the Apache child that was proxying the request
to the daemon will additionally log::

    Daemon process 'GROUP' closed connection before sending
    complete response headers

This is the typical signature of a daemon-process crash mid-request.

**Q**: Why am I seeing ``premature end of script headers`` in the
Apache error logs?

**A**: This message is emitted by Apache's ``mod_cgi`` module, not by
mod_wsgi. Seeing it under what is supposed to be a mod_wsgi
deployment means the WSGI script file is being executed as a CGI
script — typically because a handler-mapping directive such as
``AddHandler cgi-script`` is matching the file ahead of mod_wsgi's
own handler, or ``WSGIScriptAlias`` was not configured for the URL
in question.

HTTP Error Responses
--------------------

**Q**: When I try to use mod_wsgi daemon mode I get the error response '503
Service Temporarily Unavailable'.

**A**: The standard Apache runtime directory has restricted access and
the Apache child process cannot access the daemon process sockets.
The Apache error log will contain a ``WSGI0117`` message reporting
``EACCES`` on the socket directory. Use the WSGISocketPrefix
directive to specify an alternative location for runtime files such
as sockets.

For further information see "Location of UNIX sockets" in
:doc:`../user-guides/configuration-issues`, and the WSGI0117 entry in
:doc:`../error-reference`.

HTTP Error Log Messages
-----------------------

**Q**: Why do I see ``IOError: Apache/mod_wsgi client connection
closed.`` in the Apache error logs?

**A**: This ``IOError`` is raised by mod_wsgi when the HTTP client
disconnects before the response has been fully written. It only ends
up in the Apache error log if the WSGI application fails to catch
it, in which case it propagates as an uncaught exception and is
logged with the usual traceback.

mod_wsgi only raises this exception when the application uses the
legacy WSGI ``write()`` callable returned from ``start_response``.
With the more common pattern of returning a response iterable,
mod_wsgi silently aborts the response on a closed connection — no
exception is raised into application code, and at the default
``LogLevel`` nothing is logged at all (the abort is recorded only at
``APLOG_TRACE1``).

The underlying causes are typically benign — a user navigating away
or force-reloading the page, or a benchmarking tool such as ``ab``
over-committing and aborting some of its concurrent requests. The
exception, if it does propagate, can normally be caught and ignored
by the application.

Application Reloading
---------------------

**Q**: Do I have to restart Apache every time I make a change to the Python
code for my WSGI application?

**A**: If your WSGI application is contained totally within the WSGI script
file and it is that file that you are changing, then no you don't. In this
case the WSGI script file will be automatically reloaded when a change is
made provided that script reloading hasn't been disabled.

If the code you are changing lies outside of the WSGI script file then what
you may need to do will depend on how mod_wsgi is being used.

If embedded mode of mod_wsgi is being used, the only option is to
restart Apache. ``MaxRequestsPerChild 1`` will force a reload of the
application on every request, but the cost (every request, including
static files and other applications, pays the recycle overhead)
makes this only suitable as a development convenience.

If using daemon mode, touching the WSGI script file (updating its
modification time) is sufficient — the daemon processes will
automatically shut down and restart on the next request, picking up
any code changes. This applies for any number of processes in the
group. Alternatively, ``SIGINT`` can be sent directly to a daemon
process via ``kill`` or ``pkill``, or from the application sending
the signal to itself in response to a specific URL.

Daemon mode is the preferred mechanism for automatic reloading
after code changes.

More details on how source code reloading works with mod_wsgi can be
found in :doc:`../user-guides/reloading-source-code`.

**Q**: Why do requests against my application seem to take forever, but
then after a bit they all run much quicker?

**A**: This is because mod_wsgi by default performs lazy loading of any
application. That is, an application is only loaded the first time that a
request arrives which targets that WSGI application. This means that those
initial requests will incur the overhead of loading all the application code
and performing any startup initialisation.

This startup overhead can appear quite significant when running in
embedded mode under the prefork MPM, because the startup cost is
incurred per process and prefork typically uses many more processes
than worker, event, or mod_wsgi daemon mode. As many requests as
there are processes will run slowly until the code has all been
loaded.

The same effect can also be observed periodically if Apache child
processes or mod_wsgi daemon processes are being recycled after a
set number of requests, or if Apache decides to reap embedded-mode
child processes for its own reasons.

It is possible to preload the application code at process startup
rather than on the first request. The simplest path is to supply the
``process-group`` and ``application-group`` options on
``WSGIScriptAlias``, which auto-preloads the script file. The
WSGIImportScript directive provides the same effect for
configurations that don't use ``WSGIScriptAlias`` (for example
``SetHandler wsgi-script``), and for preloading additional scripts
into the same process group.

By preloading the application code you would not normally see delays in
requests being handled. The only exception to this would be when running
a single process under mod_wsgi daemon mode and the process is being
restarted when a maximum number of requests arrives or explicitly via one
of the means to trigger reloading of application code. Delays here can be
avoided by running at least two processes in the daemon process group.
This is because when one process is restarting, the others can handle the
requests.

Execution Environment
---------------------

**Q**: Why do I get the error 'IOError: sys.stdout access restricted by
mod_wsgi'?

**A**: This error only occurs when ``WSGIRestrictStdout On`` has been
explicitly configured. The restriction has been off by default since
mod_wsgi 3.0; with the default configuration, writes to
``sys.stdout`` are silently redirected to the Apache error log and
do not raise.

A portable WSGI application should still avoid writing to
``sys.stdout`` (use ``sys.stderr`` or ``wsgi.errors`` for logging),
since some WSGI hosting mechanisms — CGI being the canonical
example — use standard output as the response channel back to the
web server. See "Writing To Standard Output" in
:doc:`../user-guides/application-issues` and "Apache Error Log
Files" in :doc:`../user-guides/debugging-techniques` for the
recommended logging patterns.

**Q**: Can mod_wsgi be used with Python virtual environments?

**A**: Yes. The current recommendation is ``python -m venv`` from the
standard library or ``uv venv``; the older ``virtualenv`` package
also continues to work. For setup details see
:doc:`../user-guides/virtual-environments`.

Access Control Mechanisms
-------------------------

**Q**: Why are client user credentials not being passed through to the WSGI
application in the 'HTTP_AUTHORIZATION' variable of the WSGI environment?

**A**: User credentials are not passed by default as doing so is insecure and
could expose a user's password to WSGI applications which shouldn't be
permitted to see it. Such a situation might occur within a corporate
setting where HTTP authentication mechanisms were used to control access to
a corporate web server but it was possible for users to provide their own
web pages. The last thing a system administrator will want is normal users
being able to see other users' passwords.

As a result, the passing of HTTP authentication credentials must be
explicitly enabled by the web server administrator. This can only be done
using directives placed in the main Apache configuration file.

For further information see :doc:`../user-guides/access-control-mechanisms`
and the documentation for the WSGIPassAuthorization directive.

**Q**: Is there a way of having a WSGI application provide user authentication
for resources outside of the application such as static files, CGI scripts
or even a distinct application?

**A**: mod_wsgi provides support for hooking into the Apache access,
authentication and authorisation handler phases. This doesn't allow full
control of how the Apache handler is implemented, but does allow control
over how user credentials are validated, determination of what groups a
user is a member of and whether specific hosts are allowed access. This
is generally more than sufficient and makes the task somewhat simpler
than implementing a full Apache handler in C, since Apache and mod_wsgi
do all the hard work.

For further information see :doc:`../user-guides/access-control-mechanisms`.
