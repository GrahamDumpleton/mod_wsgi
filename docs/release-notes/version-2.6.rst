===========
Version 2.6
===========

Version 2.6 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.6.tar.gz

For Windows binaries see:

  http://code.google.com/p/modwsgi/wiki/InstallationOnWindows

Note that this release does not support Python 3.0. Python 3.0 will only be
supported in mod_wsgi 3.0.

Note that the fix for (3) below is believed to have already been backported
to mod_wsgi 2.5 in Debian Stable tree. Thus, if using mod_wsgi 2.5 from
Debian you do not need to be concerned about upgrading to this version.

Bug Fixes
---------

1. Fixed build issue on MacOS X where incorrect Python framework found at
run time. This was caused by '-W,-l' option prefix being dropped from '-F'
option in LDFLAGS of Makefile and not reverted back when related changes
undone. This would affect Python 2.3 through 2.5. For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=28

2. Fixed build issue on MacOS X where incorrect Python framework found at
run time. This was caused by '-L/-l' flags being used for versions of Python
prior to 2.6. That approach, even where '.a' library link to framework exists,
doesn't seem to work for the older Python versions.

Because of the unpredictability as to when '-F/-framework' or '-L/-l'
should be used for specific Python versions or distributions. Now always
link against Python framework via '-F/-framework' if available. If for some
particular setup this isn't working, then the '--disable-framework' option
can be supplied to 'configure' script to force use of '-L/-l'. For more
details see:

  http://code.google.com/p/modwsgi/issues/detail?id=28

3. Fixed bug where was decrementing Python object reference count on NULL
pointer, causing a crash. This was possibly only occuring in embedded mode
and only where closure of remote client connection was detected before any
request content was read. The issue may have been more prevalent for a HTTPS
connection from client.

4. Fixed bug for Python 2.X where when using 'print' to output multple
objects to log object via, wsgi.errors, stderr or stdout, a space wasn't
added to output between objects. This was occuring because log object
lacked a softspace attribute.

Features Changed
----------------

1. When trying to determining version of Apache being used at build time,
if Apache executable not available, fallback to getting version from the
installed Apache header files. Do this as some Linux distributions build
boxes do not actually have Apache executable itself installed, only the
header files and apxs tool needed to build modules. For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=147
