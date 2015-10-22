==============
Version 4.4.21
==============

Version 4.4.21 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.21

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Features Changed
----------------

1. When any of the options ``--enable-debugger``, ``--enable-debugger``,
``--enable-coverage``, ``--enable-profiler``, ``--enable-recorder`` or
``--enable-gdb`` are used, debug module will now automatically be enabled.
Previously you had to also supply the ``--debug-mode`` option otherwise
these options wouldn't be honoured.

New Features
------------

1. Add a WSGI test application to ``mod_wsgi-express`` which returns back
details of the request headers, application environment and request content
as the response. This can be used for testing how requests are passed
through and also what the execution environment looks like. It can be used
by running::

    mod_wsgi-express start-server --application-type module mod_wsgi.server.environ

2. Added ``--entry-point`` option to ``mod_wsgi-express`` as more explicit
way of identifying the file or module name containing the WSGI application
entry point or description. This is in addition to simply being able to
list it without any option. The explicit way just makes it easier to see
the purpose when you have a long list of options.
