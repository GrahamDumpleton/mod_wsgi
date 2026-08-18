=============
Version 6.0.6
=============

Bugs Fixed
----------

* On 32 bit platforms such as i586 and armv7, requests proxied to a
  daemon process group would fail after the connect timeout with the
  error::

      WSGI0116: Unable to connect to WSGI daemon process 'name' on
      '(null)' after multiple attempts as listener backlog limit was
      exceeded or the socket does not exist.

  where the daemon process group socket path was logged as ``(null)``,
  even though the daemon processes had started correctly and their
  listener socket existed. This was a regression introduced in version
  6.0.0 when the source code was split into multiple files and did not
  affect 64 bit platforms.

  The cause was that a subset of the source files included the Apache
  headers before ``Python.h``. The Python ``pyconfig.h`` header defines
  ``_FILE_OFFSET_BITS`` to ``64``, which on 32 bit Linux changes the size
  of the C library ``rlim_t`` type from 4 to 8 bytes. As the internal
  structure describing a daemon process group contains ``rlim_t`` fields
  ahead of the socket path and other fields, source files which saw the
  Apache headers first had a different layout for that structure than
  those which saw ``Python.h`` first. The code connecting to the daemon
  process therefore read the socket path from the wrong offset, yielding
  a ``NULL`` pointer, and the connection was attempted to an empty socket
  path and refused. The same mismatch also caused Apache child processes
  to skip closing their inherited copy of the daemon listener socket.

  All source and header files now include ``wsgi_python.h`` and
  ``wsgi_apache.h`` first, in that order, before any other headers, and
  ``wsgi_apache.h`` itself now includes ``wsgi_python.h`` before any
  Apache header, so that ``Python.h`` is always the first header seen by
  every compilation unit, as required by the Python C API. This ensures
  every compilation unit agrees on the layout of shared structures
  regardless of platform word size.
