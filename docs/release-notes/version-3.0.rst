===========
Version 3.0
===========

Version 3.0 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-3.0.tar.gz

Precompiled Windows binaries for Apache 2.2 and Python 2.6 and 3.1 are also
available from:

  http://code.google.com/p/modwsgi/downloads/list

Note that mod_wsgi 3.0 was originally derived from mod_wsgi 2.0. It has
though all changes from later releases in the 2.X branch. Thus also see:

* :doc:`version-2.1`
* :doc:`version-2.2`
* :doc:`version-2.3`
* :doc:`version-2.4`
* :doc:`version-2.5`
* :doc:`version-2.6`
* :doc:`version-2.7`

Bug Fixes
---------

1. Fix bug with quoting of options to mod_wsgi directives as described in:

  http://code.google.com/p/modwsgi/issues/detail?id=55

2. For any code not run in the first Python interpreter instance, thread
local data was being thrown away at the end of the request, rather than
persisting through to subsequent requests handled by the same thread. This
prevented caching techniques which made use of thread local storage and
where data was intended to persist for the life of the process. The result
was that any such data would have had to have been recreated on every
request. See:

  http://code.google.com/p/modwsgi/issues/detail?id=120

Features Changed
----------------

1. No longer force a zero length read before sending response headers
where Apache 2.2.8 or later is used. This was originally being done as a
workaround because of bug in Apache whereby it didn't generate the
'100 Continue' headers properly, with possibility they would be sent as
part of response content. This problem was however fixed in Apache 2.2.7
(really 2.2.8 as 2.2.7 was never publically released by ASF). Also only
allow zero length read to propogate to Apache input filters when done, if
the zero length read is the very first read against the input stream. For
details see:

  http://code.google.com/p/modwsgi/issues/detail?id=52

2. The WSGIImportScript can now appear inside of VirtualHost. However, there
are now additional restrictions.

First is that the WSGIDaemonProcess directive being referred to by the
WSGIImportScript directive by way of the process-group option, must appear
before the WSGIImportScript directive.

Second is that the WSGIDaemonProcess directive being referred to by the
WSGIImportScript directive by way of the process-group option, must appear
in the same VirtualHost context, or at global server scope. It is not possible
to reference a daemon process group specified in a different virtual server
context.

Third is that at global server context, it is not possible to refer to a
daemon process group defined in a VirtualHost context.

For additional details see:

  http://code.google.com/p/modwsgi/issues/detail?id=110

3. The restriction on accessing sys.stdin and sys.stdout has been lifted.
This was originally done to promote the writing of portable WSGI code. In
all the campaign has failed as people can't be bothered to read the
documentation to understand why it was done and instead use the workaround
and don't actually fix the code that isn't portable. More details at:

  http://blog.dscpl.com.au/2009/04/wsgi-and-printing-to-standard-output.html

4. Reenabled WSGIPythonHome directive in Windows as does apparently work so
long as virtual environment setup correctly for it to refer to.

5. WSGI version now marked as WSGI 1.1 instead of 1.0. This is on basis that
proposed ammendments to WSGI which mod_wsgi already implements will at least
be accepted as WSGI 1.1 independent of any discussions of changing WSGI
interface to use unicode with encoding other than Latin-1.

6. Set timeout on socket connection between Apache server child process and
daemon process earlier to catch any blocking problems in initial handshake
between the processes. This will make code more tolerant of any unexpected
issues with socket communications.

Features Removed
----------------

1. The WSGIReloadMechanism directive has been removed. This means that script
reloading is not available as an option in daemon mode and the prior default
of process reloading always used, unless of course WSGIScriptReloadig is Off
and all reloading is disabled. Doesn't affect embedded mode where script
reloading was always the only option. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=72

2. There is no longer an attempt to set Content-Length header for a response
if not supplied and iterable was a sequence of length 1. This was suggested
by WSGI specification but turns out this causes problems with HEAD requests.
For details see:

  http://blog.dscpl.com.au/2009/10/wsgi-issues-with-http-head-requests.html

Note that Apache may still do the same thing in certain circumstances.
Whether Apache always does the correct thing is not known.

In general, a WSGI application should always return full response content
for a HEAD request and should NOT truncate the response.

Features Added
--------------

1. Support added for using Python 3.X.

What constitutes support for Python 3.X is described in:

  http://code.google.com/p/modwsgi/wiki/SupportForPython3X

Note that Python 3.0 is not supported and cannot be used. You must use
Python 3.1 or later as mod_wsgi relies on features only added in Python 3.1.
The PSF has also affectively abandoned Python 3.0 now anyway.

Also note that there is no official WSGI specification for Python 3.X and
objections could be raised about what mod_wsgi has implemented. If that
occurs then mod_wsgi may need to stop claiming to be WSGI compliant.

2. It is now possible to supply 'process-group', 'application-group',
'callable-object' and 'pass-authorization' configuration options to the
WSGIScriptAlias and WSGIScriptAliasMatch directives after the location of
the WSGI script file parameter. For example::

    WSGIScriptAlias /trac /var/trac/apache/trac.wsgi \
     process-group=trac-projects application-group=%{GLOBAL}

Where the options are provided, these will take precedence over any which
apply to the application as defined in Location or Directory configuration
containers.

For WSGIScriptAlias (but not WSGIScriptAliasMatch) where both
'process-group' and 'application-group' parameters are provided, and
neither use expansion variables that can only be evaluated at the time of
request handling, this will also cause the WSGI script file to be preloaded
when the process starts, rather than being lazily loaded only when first
request for application arrives.

Preloading of the WSGI script is performed in the same way as when using
the WSGIImportScript directive. The above configuration is therefore
equivalent to existing, but longer way of doing it, as shown below::

    WSGIScriptAlias /trac /var/trac/apache/trac.wsgi
    
    WSGIImportScript /var/trac/apache/trac.wsgi \
     process-group=trac-projects application-group=%{GLOBAL}
    
    <Directory /var/trac/apache>
    WSGIProcessGroup trac-projects
    WSGIApplicationGroup %{GLOBAL}
    </Directory>

Note that the WSGIDaemonProcess directive defining the daemon process group
being referred to by the process-group option must preceed the WSGIScriptAlias
directive in the configuration file. Further, you can only refer to a daemon
process group referred to in the same VirtualHost context, or at global server
scope.

3. When client closes connection and iterable returned from WSGI
application being processed, now directly log message at debug level in log
files, rather than raising a Python exception and with that being logged at
error level as was previously the case.

For where write() being called a Python exception still has to be raised
and whether that results in any message being logged depends on what the
WSGI application does.

End result is that for normal case where LogLevel wouldn't be set to debug,
the log file will not fill up with messages where client prematurely closes
connection.

For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=29

4. Added new 'chroot' option to WSGIDaemonProcess directive to force daemon
process to run inside of a chroot environment.

For this to work you need to have a working Python installation installed
into the chroot environment such that inside of that context it appears at
same location as that which Apache/mod_wsgi is running.

Note that the WSGI application code and any files it require have to be
located within the chroot directory structure. In configuring mod_wsgi
reference is then made to the WSGI application at that location. Thus::

    WSGIDaemonProcess choot-1 user=grahamd group=staff display-name=%{GROUP} \
        root=/some/path/chroot-1
    
    WSGIScriptAlias /app /some/path/chroot-1/var/www/app/scripts/app.wsgi \
        process-group=chroot-1

Normally this would result in Apache generating SCRIPT_FILENAME as the
path as second argument to WSGIScriptAlias, but mod_wsgi, knowing it is a
chroot environment will adjust that path and drop the chroot directory root
from front of path so that it resolves correctly when used in context of
chroot environmet.

In other words, there is no need to create a parallel directory structure
outside of chroot environment just to satisfy Apache URL mapper.

Any static files can be in or outside of the chroot directory and will
still be served by Apache child worker processes, which don't run in chroot
environment. If user only has access to chroot environment through login
shell that goes directly to it, then static files will obviously be inside.

How to create a chroot environment will not be described here and you will
want to know what you are doing if you want to use this feature. For some
pointers to what may need to be done for Debian/Ubuntu see article at:

  http://transcyberia.info/archives/12-chroot-plone-buildouts.html

For details on this change also see:

  http://code.google.com/p/modwsgi/issues/detail?id=106

5. Added WSGIPy3kWarningFlag directive when Python 2.6 being used. This should
be at server scope outside of any VirtualHost and will apply to whole server::

    WSGIPy3kWarningFlag On

This should have same affect as -3 option to 'python' executable. For more
details see:

  http://code.google.com/p/modwsgi/issues/detail?id=109

6: Fix up how Python thread state API is used to avoid internal Python
assertion error when Python compiled with Py_DEBUG preprocessor symbol.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=113

7. Now allow chunked request content. Such content will be dechunked and
available for reading by WSGI application. See:

  http://code.google.com/p/modwsgi/issues/detail?id=1

To enable this feature, you must use::

  WSGIChunkedRequest On

for appropriate context in Apache configuration.

Do note however that WSGI is technically incapable of supporting chunked
request content without all chunked request content having to be first
read in and buffered. This is because WSGI requires CONTENT_LENGTH be set
when there is any request content.

In mod_wsgi no buffering is done. Thus, to be able to read the request
content in the case of a chunked transfer encoding, you need to step
outside of the WSGI specification and do things it says you aren't meant
to.

You have two choices for how you can do this. The first choice you have is
to call read() on wsgi.input but not supply any argument at all. This will
cause all request content to be read in and returned.

The second is to loop on calling read() on wsgi.input with a set block size
passed as argument and do this until read() returns an empty string.

Because both calling methods are not allowed under WSGI specification, in
using these your code will not be portable to other WSGI hosting mechanisms.

8. Values for HTTP headers now passed in environment dictionary to access,
authentication and authorisation hooks. See:

  http://code.google.com/p/modwsgi/issues/detail?id=69

9. The flag wsgi.run_once is not set to True when running in daemon mode and
both threads and maximum-requests is set to 1. With this configuration, are
gauranteed that process will only be used once before being restarted. Note
that don't get this gaurantee when multiple threads used as the maximum
requests is only checked at end of successful request and so could feasibly
still have multiple concurrent requests in progress at that point and so
process wasn't used only once.

10. Added lazy initialisation of Python interpreter. That is, Python
interpreter will not be initialised in Apache parent process and inherited
across fork when creating child processes. Instead, the Python interpreter
will only first be initialised in child process after the fork.

This behaviour is now the default as Python 3.X by design doesn't cleanup
memory when interpreter destroyed. This causes significant memory leaks
into Apache parent process as not reclaiming the memory doesn't work well
with fact that Apache will unload Python library on an Apache restart and
loose references to that unclaimed memory, such that when Python is
reinitialised, it can't reuse it.

In Python 2.X it does attempt to reclaim all memory when Python interpreter
is destroyed, but some Python versions still leak some memory due to real
leaks or also perhaps by design as per Python 3.X. In Python 2.X the leaks
are far less significant and have been tolerated in the past. The leaks in
Python 2.X only cause problems if you do lots of Apache restarts, rather
than stop/start. All the same, default for Python 2.X has also now been
made to perform lazy initialisation.

To control the behaviour have added the directive WSGILazyInitialization.
This defaults to On for both Python 2.X and Python 3.X. If you wish to
experiment with whether early initialisation gives better results for
Python 2.X, you can set this directive to Off.

The downside of performing lazy initialisation is that you may loose some
benefit of being able to share memory between child process. Thus, child
processes will potentially consume more resident memory than before due to
data being local to process rather than potentially being shared.

If you are exclusively using mod_wsgi daemon mode and not using embedded mode,
if lazy initialisation is used in conjunction with WSGIRestrictEmbedded
being set to On, then the Python interpreter will not be initialised at all
in the Apache server child processes, unless authentication providers or
other non content generation code is being provided to be executed in
Apache server child processes. This means that Apache worker processes will
be much smaller.

Even when initialisation of Python in Apache worker processes is disabled,
as before, the mod_wsgi daemon processes will still use more resident
memory over shared memory. If however you are only running a small number
of mod_wsgi daemon processes, then this may overall balance out as using
less memory in total.

For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=99

11. If daemon process defined in virtual host which has its own error log,
then associated stderr with that virtual hosts error log instead. This way
any messages sent direct to stderr from C extension modules will end up in
the virtual host error log that the daemon process is associated with,
rather than the main error log.

12. If daemon process defined in a virtual host, close all error logs for
other virtual hosts which don't reference the same error log. This ensures
that code can't write messages to error logs for another host, or reopen the
log and read data from the logs.

13. Implement internal server redirection using Location response header
as allowed for in CGI specification. Note though that this feature has only
been implemented for mod_wsgi daemon mode. See:

  http://code.google.com/p/modwsgi/issues/detail?id=14

14. Implement WSGIErrorOverride directive which when set to On will result
in Apache error documents being used rather than those passed back by the
WSGI application. This allows error documents to match any web site that
the WSGI application may be integrated as a part of. This feature is akin
to the ProxyErrorOverride directive of Apache but for mod_wsgi only. Do note
though that this feature has only been implemented for mod_wsgi daemon mode.
See:

  http://code.google.com/p/modwsgi/issues/detail?id=57

15. Implement WSGIPythonWarnings directive as equivalent to the 'python'
executable '-W' option. The directive can be used at global scope in Apache
configuration to provide warning control strings to disable messages produced
by the warnings module. For example::

  # Ignore everything.
  WSGIPythonWarnings ignore

or::

  # Ignore only DeprecationWarning.
  WSGIPythonWarnings ignore::DeprecationWarning::

For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=137

16. Added cpu-time-limit option to WSGIDaemonProcess directive. This allows
one to define a time in seconds which will be the maximum amount of cpu
time the process is allowed to use before a shutdown is triggered and the
daemon process restarted. The point of this is to provide some means of
controlling potentially run away processes due to bad code that gets stuck
in heavy processing loops. For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=21

17. Added cpu-priority option to WSGIDaemonProcess directive. This allows
one to adjust the CPU priority associated with processes in a daemon process
groups. The range of values that can be supplied is dictated by what the
setpriority() function on your particular operating system accepts. Normally
this is in the range of about -20 to 20, with 0 being normal. For more
details see:

  http://code.google.com/p/modwsgi/issues/detail?id=142

18. Added WSGIHandlerScript directive. This allows one to nominate a WSGI
script file that should be executed as a handler for a specific file type
as configured within Apache. For example::

  <Files *.bobo>
  WSGIProcessGroup bobo
  WSGIApplicationGroup %{GLOBAL}
  MultiViewsMatch Handlers
  Options +ExecCGI
  </Files>
  AddHandler bobo-script .bobo
  WSGIHandlerScript bobo-script /some/path/bobo-handler/handler.wsgi

For this example, the application within the WSGI script file will be
invoked whenever a URL maps to a file with '.bobo' extension. The name of
the file mapped to by the URL will be available in the 'SCRIPT_FILENAME'
WSGI environment variable.

Although same calling interface is used as a WSGI application, to distinguish
that this is acted as a handler, the application entry point must be called
'handle_request' and not 'application'.

When providing such a handler script, it is also possible to provide in the
script file a 'reload_required' callable object. This will be called prior
to handling a request and allows the script to determine if a reload should be
performed first. In the case of daemon mode, this allows script to
programmatically determine if the whole process should be reloaded first.
The argument to the 'reload_required' function is the original resource file
that was the target of the request and which would have been available to the
handler as SCRIPT_FILENAME.
