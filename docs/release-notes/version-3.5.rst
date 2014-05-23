===========
Version 3.5
===========

Version 3.5 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/3.5.tar.gz

Security Issues
---------------

1. Local privilege escalation when using daemon mode. (CVE-2014-0240)

The issue is believed to affect Linux systems running kernel versions >=
2.6.0 and < 3.1.0.

The issue affects all versions of mod_wsgi up to and including version 3.4.

The source of the issue derives from mod_wsgi not correctly handling Linux
specific error codes from setuid(), which differ to what would be expected
to be returned by UNIX systems conforming to the Open Group UNIX
specification for setuid().

  * http://man7.org/linux/man-pages/man2/setuid.2.html
  * http://pubs.opengroup.org/onlinepubs/009695399/functions/setuid.html

This difference in behaviour between Linux and the UNIX specification was
believed to have been removed in version 3.1.0 of the Linux kernel.

 * https://groups.google.com/forum/?fromgroups=#!topic/linux.kernel/u6cKf4D1D-k

The issue would allow a user, where Apache is initially being started as
the root user and where running code under mod_wsgi daemon mode as an
unprivileged user, to manipulate the number of processes run by that user
to affect the outcome of setuid() when daemon mode processes are forked and
so gain escalated privileges for the users code.

Due to the nature of the issue, if you provide a service or allow untrusted
users to run Python web applications you do not control the code for, and
do so using daemon mode of mod_wsgi, you should update mod_wsgi as soon as
possible.

Bugs Fixed
----------

1. Python 3 installations can add a suffix to the Python library. So instead
of ``libpythonX.Y.so`` it can be ``libpythonX.Ym.so``.

2. When using daemon mode, if an uncaught exception occurred when handling
a request, when response was proxied back via the Apache child process, an
internal value for the HTTP status line was not cleared correctly. This
was resulting in a HTTP status in response to client of '200 Error' rather
than '500 Internal Server Error'.

Note that this only affected the status line and not the actual HTTP
status. The status would still be 500 and the client would still interpret
it as a failed request.

3. Null out Apache scoreboard handle in daemon processes for Apache 2.4 to
avoid process crash when lingering close cleanup occurs.

4. Workaround broken MacOS X XCode Toolchain references in Apache apxs
build configuration tool and operating system libtool script. This means
it is no longer necessary to manually go into::

  Applications/Xcode.app/Contents/Developer/Toolchains

and manually add symlinks to define the true location of the compiler tools.

5. Restore ability to compile mod_wsgi source code under Apache 1.3.

6. Fix checks for whether the ITK MPM is used and whether ITK MPM specific
actions should be taken around the ownership of the mod_wsgi daemon process
listener socket.

7. Fix issue where when using Python 3.4, mod_wsgi daemon processes would
actually crash when the processes were being shutdown.

8. Made traditional library linking the default on MacOS X. If needing
framework style linking for the Python framework, then use the
``--enable-framework`` option. The existing ``--disable-framework`` has now
been removed given that the default action has been swapped around.

New Features
------------

1. For Linux 2.4 and later, enable ability of daemon processes to dump core
files when Apache ``CoreDumpDirectory`` directive used.

2. Attempt to log whether daemon process exited normally or was killed off
by an unexpected signal.
