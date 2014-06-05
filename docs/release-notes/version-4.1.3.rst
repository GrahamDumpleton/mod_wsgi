=============
Version 4.1.3
=============

Version 4.1.3 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.1.3.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The ``setup.py`` file wasn't always detecting the Python library version
suffix properly when setting it up to be linked into the resulting
``mod_wsgi.so``. This would cause an error message at link time of::

    /usr/bin/ld: cannot find -lpython
