===========
Version 3.5
===========

The working version of mod_wsgi 3.5 can currently be obtained by checking
it out from the source code repository.

  https://github.com/GrahamDumpleton/mod_wsgi/tree/develop

Alternatively, it can be downloaded as a tar.gz file from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/develop.tar.gz

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
