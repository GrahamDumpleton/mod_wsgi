=============
Version 4.3.2
=============

Version 4.3.2 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.3.2

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Linux behaviour when using ``connect()`` on a non blocking UNIX socket
and the listener queue is full, is apparently not POSIX compliant and it
returns ``EAGAIN`` instead of ``ECONNREFUSED``. The code handling errors
from the ``connect()`` wasn't accomodating this non standard behaviour
and so would fail immediately rather than retrying.

2. Only change working directory for mod_wsgi daemon process after having
dropped privileges to target user. This is required where the specified
working directory is on an NFS file system configured so as not to have
root access priviliges.

3. The workaround for getting pyvenv style virtual environments to work
with Python 3.3+ would break brew Python 2.7 on MacOS X as brew Python
appears to not work in embedded systems which use Py_SetProgramName()
instead of using Py_SetPythonHome(). Now only use Py_SetProgramName() if
detect it is actually a pyvenv style virtual environment. This even appears
to be okay for brew Python 3.4 at least as it does still work with the
Py_SetProgramName() call even if brew Python 2.7 doesn't.

New Features
------------

1. If the ``WSGIPythonHome`` directive or the ``python-home`` option is
used with the ``WSGIDaemonProcess`` directive, the path provided, which is
supposed to be the root directory of the Python installation or virtual
environment, will be checked to see if it is actually accessible and refers
to a directory. If it isn't, a warning message will be logged along with
any details providing an indication of what may be wrong with the supplied
path.

This is being done to warn when an invalid path has been supplied that
subsequently is likely to be rejected and ignored by the Python
interpreter. In such a situation where an invalid path is supplied the
Python interpreter doesn't actually log anything and will instead silently
fallback to using any Python installation it finds by seaching for
``python`` on the users ``PATH``. This may not be the Python installation
or virtual environment you intended be used.

2. The Apache configuration snippet generated as an example when running
the ``install-module`` sub command of ``mod_wsgi-express`` to install the
``mod_wsgi.so`` into the Apache installation itself, will now output a
``WSGIPythonHome`` directive for the Python installation or virtual
environment the mod_wsgi module was compiled against so that the correct
Python runtime will be used.
