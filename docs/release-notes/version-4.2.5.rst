=============
Version 4.2.5
=============

Version 4.2.5 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.5.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. When using Apache 2.4 with dynamically loaded MPM modules, mod_wsgi
express was incorrectly trying to load more than one MPM module if more
than one existed in the Apache modules directory.
