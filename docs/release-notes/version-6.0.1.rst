=============
Version 6.0.1
=============

Features Changed
----------------

* The Python exception messages raised by the WSGI adapter layer
  (``start_response()``, ``write()``, ``wsgi.input``, ``wsgi.errors``,
  the file wrapper, and response status/header validation) have been
  reworded to be more descriptive and, where appropriate, to identify
  mod_wsgi as their source, making them easier to diagnose.

Bugs Fixed
----------

* On 32 bit builds, validation of the Python home directory could fail
  with a spurious "Unable to stat Python home" warning when the
  directory's inode value exceeded 32 bits, as ``apr_stat()`` returns
  ``APR_INCOMPLETE`` in that case for ABI compatibility reasons. The
  stat now requests only the file type, which is all that is required.

* The binary ``write()`` method on ``wsgi.errors.buffer`` and
  ``sys.stderr.buffer`` did not accept a ``memoryview`` (or other
  bytes-like objects such as ``bytearray``), failing with a ``TypeError``.
  This dated back to the original Python 3 port, where the byte string
  argument parsing was carried across from Python 2 unchanged rather than
  being updated to the buffer protocol. It now accepts any bytes-like
  object. For backward compatibility a ``str`` is still accepted, but
  doing so is now deprecated and will emit a ``DeprecationWarning``.

* Compilation failed when daemon mode was not available, which is always
  the case on Windows, but can also occur on other platforms lacking the
  required ``fork()`` and APR other-child support. Several places in code
  which is compiled regardless of whether daemon mode is enabled referred
  to daemon mode symbols, such as ``wsgi_daemon_process`` and
  ``wsgi_daemon_shutdown``, without guarding the references with
  ``MOD_WSGI_WITH_DAEMONS``. Those symbols are only declared when daemon
  mode is available, so the build failed with errors such as ``error
  C2065: 'wsgi_daemon_shutdown': undefined variable``. The references are
  now protected by the appropriate conditional. In addition, the
  ``apr_atomic.h`` header, used by code unrelated to daemon mode, was only
  being included indirectly via the daemon mode header and so was missing
  when daemon mode was disabled; it is now included from a common header.

* When using daemon mode, output written to ``wsgi.errors`` (and anything
  sent to ``sys.stdout`` or ``sys.stderr``) could be written to the main
  server ``ErrorLog`` instead of the ``ErrorLog`` of the ``VirtualHost``
  actually handling the request. The daemon process maps each proxied
  request back to the correct server using listener address details
  supplied by the Apache child worker, but the code which populated those
  details was guarded by ``MOD_WSGI_WITH_DAEMONS``, and that symbol was not
  defined in the relevant source file, so the guarded code was silently
  compiled out and no listener details were sent. This was introduced by
  the 6.0.0 code restructuring, which moved the definition of
  ``MOD_WSGI_WITH_DAEMONS`` into a daemon specific header that the affected
  source file did not include. The definition has been moved to a common
  header visible to all source files.

* When using daemon mode with a ``VirtualHost`` selected by IP address while
  the ``Listen`` directive used a wildcard, output written to ``wsgi.errors``
  (and ``sys.stdout`` or ``sys.stderr``) was written to the main server
  ``ErrorLog`` instead of the ``ErrorLog`` of that ``VirtualHost``. To match
  the request to a server the daemon process reconstructed the local socket
  address from the listener socket bind address, but for a wildcard listener
  that address is ``0.0.0.0`` (or ``::``) and so never matched a
  ``VirtualHost`` given by a specific IP address, causing the match to fall
  back to the main server. The daemon now reconstructs the local address from
  the actual local IP the connection was received on, which is what the
  Apache child worker uses for the same matching.
