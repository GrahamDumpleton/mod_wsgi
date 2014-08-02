=============
Version 4.2.7
=============

Version 4.2.7 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.7.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

New Features
------------

1. Added a ``--mount-point`` option to ``mod_wsgi-express`` to allow a WSGI
application to be mounted at a sub URL rather than the root of the site
when using mod_wsgi express.
