=============
Version 4.3.1
=============

Version 4.3.1 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.1.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The ``install-module`` sub command of ``mod_wsgi-express`` was incorrectly
trying to install the mod_wsgi ``.so`` file onto itself rather than into
the Apache modules directory.
