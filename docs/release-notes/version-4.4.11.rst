==============
Version 4.4.11
==============

Version 4.4.11 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.11

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. No provision was made for operating systems with a very low limit on the
number of separate data blocks that could be passed to system ``writev()``
call. This was an issue on Solaris where the limit is 16 and meant that since
version 4.4.0, daemon mode of mod_wsgi would fail where a HTTP request had
more than a small number of headers.

2. When installing the ``mod_wsgi`` package using ``pip`` and rather
than activating the virtual environment you were referring to ``pip`` by
path from the ``bin`` directory, the ``mod_wsgi-httpd`` package which
had already been installed into the virtual environment would not be
detected.

New Features
------------

1. Added the ``--service-log`` option to ``mod_wsgi-express`` for
specifying the name of a log file for a specific service script. The
arguments are the name of the service and the file name for the log. The
log file will be placed in the log directory, be it the default, or a
specific log directory if specified.

2. Set various environment variables from ``mod_wsgi-express`` to identify
that it is being used, what hosts it is handling requests for, and whether
debug mode and/or specific debug mode features are enabled. This is so that
a web application can modify it's behaviour when ``mod_wsgi-express`` is
being used, or being used in specific ways. The environment variables which
are set are:

* *MOD_WSGI_EXPRESS* - Indicates that ``mod_wsgi-express`` is being used.
* *MOD_WSGI_SERVER_NAME* - The primary server host name for the site.
* *MOD_WSGI_SERVER_ALIASES* - Secondary host names the site is known by.
* *MOD_WSGI_RELOADER_ENABLED* - Indicates if source code reloading enabled.
* *MOD_WSGI_DEBUG_MODE* - Indicates if debug mode has been enabled.
* *MOD_WSGI_DEBUGGER_ENABLED* - Indicates pdb debugger has been enabled.
* *MOD_WSGI_COVERAGE_ENABLED* - Indicates if coverage analysis has been
  enabled.
* *MOD_WSGI_PROFILER_ENABLED* - Indicates if code profiling has been enabled.
* *MOD_WSGI_RECORDER_ENABLED* - Indicates if request/response recording
  enabled.
* *MOD_WSGI_GDB_ENABLED* - Indicates if gdb process crash debugging enabled.

For any environment variable indicating a feature has been enabled, it
will be set when enabled and have the value 'true'.

For the list of server aliases, it will be a space separated list of host
names.
