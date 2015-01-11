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
