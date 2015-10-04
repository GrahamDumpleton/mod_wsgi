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

2. If Apache was already running when the mod_wsgi module was enabled or
otherwise configured to be loaded, and then an Apache graceful restart was
done so that it would be loaded for the first time, all child processes
would crash when starting up and would keep crashing, requiring Apache be
shutdown. This would occur as Python initialisation was not being performed
correctly in this specific case where mod_wsgi was loaded when Apache was
already running and a graceful restart, rather than a normal restart was
done.
