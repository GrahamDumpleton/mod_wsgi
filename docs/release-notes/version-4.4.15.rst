==============
Version 4.4.15
==============

Version 4.4.15 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.15

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. When specifying multiple directories for the Python module search path
using the ``WSGIPythonPath`` directive, or the ``python-path`` option to
``WSGIDaemonProcess``, it was failing under Python 3 due to incorrect
logging. It was therefore only possible to add a single directory.
