==============
Version 4.4.10
==============

Version 4.4.10 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.10

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Fixed a reference counting bug which would cause a daemon process to
crash if both ``home`` and ``python-path`` options were specified at the
same time with the ``WSGIDaemonProcess`` directive.
