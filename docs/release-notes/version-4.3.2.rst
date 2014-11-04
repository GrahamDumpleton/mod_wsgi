=============
Version 4.3.2
=============

Version 4.3.2 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.2.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

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
