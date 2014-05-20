===========
Version 2.4
===========

Version 2.4 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.4.tar.gz

Bug Fixes
---------

1. Compilation would fail on Windows due to daemon mode specific code not
being conditionally compiled out on that platform. This was a problem
introduced by changes in mod_wsgi 2.3.

2. Fix bug where wrong Apache memory pool used when processing configuration
directives at startup. This could later result in memory corruption and may
account for problems seen with 'fopen()' errors. See:

  http://code.google.com/p/modwsgi/issues/detail?id=78

  http://code.google.com/p/modwsgi/issues/detail?id=108

3. Fix bug where Python interpreter not being destroyed correctly in Apache
parent process on an Apache restart. This was resulting in slow memory leak
into Apache parent process on each restart. This additional memory usage
would then be inherited by all child processes forked from Apache parent
process.

Note that this change does not help for case where mod_python is also being
loaded into Apache as in that case mod_python is responsible for
intialising Python and in all available versions of mod_python it still
doesn't properly destroy the Python interpreter either and so causes memory
leaks which mod_wsgi cannot work around.

Also, this doesn't solve problems with the Python interpreter itself
leaking memory when destroyed and reinitialised. Such memory leaks in
Python seem to occur for some versions of Python on particular platforms.

For further details see:

  http://code.google.com/p/modwsgi/issues/detail?id=99

4. Fix bug whereby POST requests where 100-continue was expected by client
would see request content actually truncated and not be available to WSGI
application if application running in daemon mode. See:

  http://code.google.com/p/modwsgi/issues/detail?id=121

5. Fix bug where Apache optimisation related to keep alive connections can
kick in when using wsgi.file_wrapper with result that if amount of data is
between 255 and aproximately 8000 bytes, that a completely empty response
will result. This occurs because Apache isn't flushing out the file data
straight away but holding it over in case subsequent request on connection
arrives. By then the file object used with wsgi.file_wrapper can have been
closed and underlying file descriptor will not longer be valid. See:

  http://code.google.com/p/modwsgi/issues/detail?id=132

6. Modify how daemon process shutdown request is detected such that no need
to block signals in request threads. Doing this caused problems in
processes which were run from daemon mode process and which needed to be
able to receive signals. New mechanism uses a internal pipe to which signal
handler writes a character, with main thread performing a poll on pipe
waiting for that character to know when to shutdown. For additional details
see:

  http://code.google.com/p/modwsgi/issues/detail?id=87

7. Fix bug where excessive transient memory usage could occur when calling
read() or readline() on wsgi.input with no argument. See:

  http://code.google.com/p/modwsgi/issues/detail?id=126

Note that calling read() with no argument is actually a violation of WSGI
specification and any application doing that is not a WSGI compliant
application.

8. Fix bug where daemon process would crash if User/Group directives were
not specified prior to WSGIDaemonProcess in Apache configuration file. See:

  http://code.google.com/p/modwsgi/issues/detail?id=40

9. Fix bug whereby Python exception state wasn't being cleared correctly
when error occurred in loading target of WSGIImportScript. See:

  http://code.google.com/p/modwsgi/issues/detail?id=117

Features Changed
----------------

1. No longer populate 'error-notes' field in Apache request object notes
table, with details of why WSGI script failed. This has been removed as
information can be seen in default Apache multilanguage error documents.
Because errors may list paths or user/group information, could be seen as
a security risk.

Features Added
--------------

1. Added 'mod_wsgi.version' to WSGI environment passed to WSGI application.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=93

2. Added 'process_group' and 'application_group' attributes to mod_wsgi module
that is created within each Python interpreter instance. This allows code
executed outside of the context of a request handler to know whether it is
running in a daemon process group and what it may be called. Similarly, can
determine if running in first interpreter or some other sub interpreter.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=27

3. Added closed and isatty attributes to Log object as well as close() method.
For wsgi.errors these aren't required, but log object also used for stderr
and stdout (when enabled) and code may assume these methods may exist for
stderr and stdout. The closed and isatty attributes always yield false and
close() will raise a run time error indicating that log cannot be closed.
For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=82

4. Apache scoreboard cleaned up when daemon processes first initialised to
prevent any user code interfering with operation of Apache. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=104

5. When running configure script, can now supply additional options for
CPPFLAGS, LDFLAGS and LDLIBS through environment variables. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=107

6. Better checking done on response headers and an explicit error will now
be produce if name or value of response header contains an embedded newline.
This is done as by allowing embedded newline would cause daemon mode to fail
when handing response in Apache child process. In embedded mode, could allow
application to pass back malformed response headers to client. For details
see:

  http://code.google.com/p/modwsgi/issues/detail?id=81

7: Ensure that SYSLIBS linker options from Python configuration used when
linking mod_wsgi Apache module. This is now prooving necessary as some Apache
distributions are no longer linking system maths library and Python requires
it. To avoid problem simply link against mod_wsgi Apache module and system
libraries that Python needs. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=115

8: Reorder sys.path after having called site.addsitedir() in WSGIPythonPath
and python-path option for WSGIDaemonProcess. This ensures that newly added
directories get moved to front of sys.path and that they take precedence over
standard directories. This in part avoids need to ensure --no-site-packages
option used when creating virtual environments, as shouldn't have an issue
with standard directories still overriding additions. For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=112

9. Update USER, USERNAME and LOGNAME environment variables if set in
daemon process to be the actual user that the process runs as rather than
what may be inherited from Apache root process, which would typically be
'root' or the user that executed 'sudo' to start Apache, if they hadn't
used '-H' option to 'sudo'. See:

  http://code.google.com/p/modwsgi/issues/detail?id=129

10. Build process now inserts what is believed to be the directory where
Python shared library is installed, into the library search path before the
Python config directory. This should negate the need to ensure that Python
shared library is also symlink into the config directory next to the static
library as linkers would normally expect it. See:

  http://code.google.com/p/modwsgi/issues/detail?id=136
