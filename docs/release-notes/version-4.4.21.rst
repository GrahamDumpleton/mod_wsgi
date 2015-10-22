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
