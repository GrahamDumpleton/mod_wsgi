=============
Version 4.4.6
=============

Version 4.4.6 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.6

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Override ``LC_ALL`` environment variable when ``locale`` option to the
``WSGIDaemonProcess`` directive. It is not always sufficient to just call
``setlocale()`` as some Python code, including interpreter initialisation
can still consult the original ``LC_ALL`` environment variable. In this
case this can result in an undesired file system encoding still being
selected.

New Features
------------

1. Added ``--enable-gdb`` option to ``mod_wsgi-express`` for when running
in debug mode. With this option set, Apache will be started up within
``gdb`` allowing the debug of process crashes on startup or while handling
requests. If the ``gdb`` program is not in ``PATH``, the ``--gdb-executable``
option can be set to give its location.
