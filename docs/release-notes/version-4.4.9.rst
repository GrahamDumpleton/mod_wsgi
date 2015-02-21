=============
Version 4.4.9
=============

Version 4.4.9 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.9

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

* The signal handler registrations setup in daemon processes to manage
process shutdown, will revert to exiting the process when invoked from a
Python process forked from a daemon process. This avoids the need to set
new signal handlers in such forked process to override what was inherited.

Note that this only applies to processes forked from daemon mode processes.
If you are forking processes when your WSGI application is running in
embedded mode, it is still a good idea to set signal handles for ``SIGINT``,
``SIGTERM`` and ``SIGUSR1`` back to ``SIG_DFL`` using ``signal.signal()``
if you want to avoid the possibility of strange behaviour due to the
inherited Apache child worker process signal registrations.

Features Changed
----------------

* The ``--proxy-url-alias`` option of ``mod_wsgi-express`` has been
superseded by the ``--proxy-mount-point`` option. This option now should
only be used to proxy to a whole site or sub site and not individual file
resources. If the mount point URL for what should be proxied doesn't have a
trailing slash, the trailing slash redirection will first be performed on
the proxy for the mount point rather than simply passing it through to
the backend.

* The signal handler intercept will now be removed automatically from a
Python child process forked from either an Apache child process or a daemon
process. This avoids the requirement of setting ``WSGIRestrictSignal`` to
``Off`` if want to setup new signal handlers from a forked child process.

New Features
------------

* Added ``--hsts-policy`` option to ``mod_wsgi-express`` to allow a HSTS
(``Strict-Transport-Security``) policy response header to be specified which
should be included when the ``--https-only`` option is used to ensure that
the site only accepts HTTPS connections.
