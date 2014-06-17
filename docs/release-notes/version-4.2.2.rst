=============
Version 4.2.2
=============

Version 4.2.2 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.2.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The ``envvars`` file was being overwritten even if it existed and had
been modified.

New Features 
------------

1. Output the location of the ``envvars`` file when using the
``setup-server`` command for ``mod_wsgi-express`` or if using the
``start-server`` command and the ``--envars-script`` option was being used.

2. Output the location of the ``apachectl`` script when using the
``setup-server`` command for ``mod_wsgi-express``.
