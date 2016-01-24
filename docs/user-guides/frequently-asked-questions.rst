==========================
Frequently Asked Questions
==========================

Apache Process Crashes
----------------------

*Q*: Why when the mod_wsgi module is initially being loaded by Apache, do
the Apache server processes crash with a 'segmentation fault'?

*A*: This is nearly always caused due to mod_python also being loaded by
Apache at the same time as mod_wsgi and the Python installation not
providing a shared library, or mod_python having originally being built
against a static Python library. This is especially a problem with older
Linux distributions before they started shipping with Python as a shared
library.

Further information on these problems can be found in various sections of
[InstallationIssues Installation Issues].

*Q*: Why when first request is made against a WSGI application does the
Apache server process handling the request crash with a 'segmentation
fault'?

*A*: This is nearly always caused due to a shared library version conflict.
That is, Apache or some Apache module is linked against a different version
of a library than that which is being used by a particular Python module
that the WSGI application makes use of. The most common culprits are the
expat and MySQL libraries, but it can also occur with other shared
libraries.

Another cause of a process crash only upon the first request can be a third
party C extension module for Python which has not been implemented so as to
work within a secondary Python sub interpreter. The Python bindings for
Subversion are a particular example, with the Python module only working
correctly if the WSGI application is forced to run within the first
interpreter instance created by Python.

Further information on these problems can be found in various sections of
:doc:`../user-guides/application-issues`.
The problems with the expat library are also gone into in more detail in
:doc:`../user-guides/issues-with-expat-library`.

*Q*: Why am I seeing the error message 'premature end of script headers' in
the Apache error logs.

*A*: If using daemon mode, this is a symptom of the mod_wsgi daemon process
crashing when handling a request. You would probably also see the message
'segmentation fault'. See answer for question about 'segmentation fault'
above.

This error message can also occur where you haven't configured Apache
correctly and your WSGI script file is being executed as a CGI script
instead.

HTTP Error Responses
--------------------

*Q*: When I try to use mod_wsgi daemon mode I get the error response '503
Service Temporarily Unavailable'.

*A*: The standard Apache runtime directory has restricted access and the
Apache child process cannot access the daemon process sockets. You will
need to use the WSGISocketPrefix directive to specify an alternative
location for storing of runtime files such as sockets.

For further information see section 'Location Of UNIX Sockets' of
[ConfigurationIssues Configuration Issues].

*Q*: I am getting a HTTP 500 error response and I can't find any error in
the Apache error logs.

*A*: Some users of mod_wsgi 1.3/2.0 and older minor revisions, are finding
that mod_wsgi error messages are going missing, or ending up in the main
Apache error log file rather than a virtual host specific error log file.
Specifically, this is occurring when Apache ErrorLog directive is being
used inside of a VirtualHost container.

It is not known exactly what operating system setup and/or Apache
configuration is the trigger for this problem. To avoid the problem, use
a newer version of mod_wsgi.

HTTP Error Log Messages
-----------------------

*Q*: Why do I get the error 'IOError: client connection closed' appearing
in the error logs?

*A*: This occurs when the HTTP client making the request closes the
connection before the complete response for a request has been written.

This can occur where a user force reloads a web page before it had been
completely displayed. It can also occur when using benchmarking tools such
as 'ab' as they will over commit on the number of requests they make when
doing concurrent requests, killing off any extra requests once the required
number has been reached.

In general this error message can be ignored.

Application Reloading
---------------------

*Q*: Do I have to restart Apache every time I make a change to the Python
code for my WSGI application?

*A*: If your WSGI application is contained totally within the WSGI script
file and it is that file that you are changing, then no you don't. In this
case the WSGI script file will be automatically reloaded when a change is
made provided that script reloading hasn't been disabled.

If the code you are changing lies outside of the WSGI script file then what
you may need to do will depend on how mod_wsgi is being used.

If embedded mode of mod_wsgi is being used, the only option is to restart
Apache. You could set Apache configuration directive MaxRequestsPerChild
to 1 to force a reload of the application on every request, but this is not
recommended because it will perform as bad as or as worse as CGI and will
also affect serving up of static files and other applications being hosted
by the same Apache instance.

If using daemon mode with a single process you can send a SIGINT signal to
the daemon process using the 'kill' command, or have the application send
the signal to itself when a specific URL is triggered.

If using daemon mode, with any number of processes, and the process reload
mechanism of mod_wsgi 2.0 has been enabled, then all you need to do is
touch the WSGI script file, thereby updating its modification time, and
the daemon processes will automatically shutdown and restart the next time
they receive a request.

Use of daemon mode and the process reload mechanism is the preferred
mechanism for handling automatic reloading of code after changes.

More details on how source code reloading works with mod_wsgi can be
found in :doc:`../user-guides/reloading-source-code`.

*Q*: Why do requests against my application seem to take forever, but
then after a bit they all run much quicker?

*A*: This is because mod_wsgi by default performs lazy loading of any
application. That is, an application is only loaded the first time that a
request arrives which targets that WSGI application. This means that those
initial requests will incur the overhead of loading all the application code
and performing any startup initialisation.

This startup overhead can appear to be quite significant, especially if
using Apache prefork MPM and embedded mode. This is because the
startup cost is incurred for each process and with prefork MPM there are
typically a lot more processes that if using worker MPM or mod_wsgi
daemon mode. Thus, as many requests as there are processes will run
slowly and everything will only run full speed once code has all been
loaded.

Note that if recycling of Apache child processes or mod_wsgi daemon
processes after a set number of requests is enabled, or for embedded mode
Apache decides itself to reap any of the child processes, then you can
periodically see these delayed requests occurring.

Some number of the benchmarks for mod_wsgi which have been posted
do not take into mind these start up costs and wrongly try to compare
the results to other systems such as fastcgi or proxy based systems where
the application code would be preloaded by default. As a result mod_wsgi
is painted in a worse light than is reality. If mod_wsgi is configured
correctly the results would be better than is shown by those benchmarks.

For some cases, such as when WSGIScriptAlias is being used, it is actually
possible to preload the application code when the processes first starts,
rather than when the first request arrives. To preload an application see the
WSGIImportScript directive.

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

*Q*: Why do I get the error 'IOError: sys.stdout access restricted by
mod_wsgi'?

*A*: A portable WSGI application or application component should not
output anything to standard output. This is because some WSGI hosting
mechanisms use standard output to communicate with the web server. If
a WSGI application outputs anything to standard output it will thus
potentially interleave with the response sent back to the client.

To promote portability of WSGI applications, mod_wsgi by default restricts
direct use of 'sys.stdout' and 'sys.stdin'. Because the 'print' statement
defaults to outputing text to 'sys.stdout', using 'print' for debugging
purposes can cause this error.

For more details about this issue, including how applications should do
logging and how to disable this restriction see section 'Writing To Standard
Output' in :doc:`../user-guides/application-issues` and section 'Apache Error
Log Files' in :doc:`../user-guides/debugging-techniques`.

*Q*: Can mod_wsgi be used with Python virtual environments created using
Ian Bicking's 'virtualenv' package?

*A*: Yes. For more details see :doc:`../user-guides/virtual-environments`.

Access Control Mechanisms
-------------------------

*Q*: Why are client user credentials not being passed through to the WSGI
application in the 'HTTP_AUTHORIZATION' variable of the WSGI environment?

*A*: User credentials are not passed by default as doing so is insecure and
could expose a users password to WSGI applications which shouldn't be
permitted to see it. Such a situation might occur within a corporate
setting where HTTP authentication mechanisms were used to control access to
a corporate web server but it was possible for users to provide their own
web pages. The last thing a system administator will want is normal users
being able to see other users passwords.

As a result, the passing of HTTP authentication credentials must be
explicitly enabled by the web server administrator. This can only be done
using directives placed in the main Apache confguration file.

For further information see :doc:`../user-guides/access-control-mechanisms`
and the documentation for the WSGIPassAuthorization directive.

*Q*: Is there a way of having a WSGI application provide user authentication
for resources outside of the application such as static files, CGI scripts
or even a distinct application. In other words, something akin to being able
to define access, authentication and authorisation handlers in mod_python?

*A*: Providing you are using Apache 2.0 or later, version 2.0 of mod_wsgi
provides support for hooking into the Apache access, authentication and
authorisation handler phases. This doesn't allow full control of how the
Apache handler is implemented, but does allow control over how user
credentials are validated, determination of what groups a user is a member
of and whether specific hosts are allowed access. This is generally more
than sufficient and makes the task somewhat simpler than needing to
implement a full handler like in mod_python as Apache and mod_wsgi do all
the hard work.

For further information see :doc:`../user-guides/access-control-mechanisms`.
