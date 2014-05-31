=============
Version 4.1.2
=============

Version 4.1.2 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.1.2.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The integration for Django management command was looking for the wrong
name for the admin script to start mod_wsgi express.

2. The code which connected to the mod_wsgi daemon process was passing an
incorrect size into the connect() call for the size of the address
structure. On some Linux systems this would cause an error similar to::

    (22)Invalid argument: mod_wsgi (pid=22944): Unable to connect to \
        WSGI daemon process 'localhost:8000' on \
        '/tmp/mod_wsgi-localhost:8000:12145/wsgi.22942.0.1.sock'

This issue was only introduced in 4.1.0 and does not affect older versions.

3. The deadlock detection thread could try and acquire the Python GIL
after the Python interpreter had been destroyed on Python shutdown
resulting in the process crashing. This issue cannot be completely
eliminated, but the deadlock thread will now at least check whether the
flag indicating process shutdown is happening has been set before trying to
acquire the Python GIL.
