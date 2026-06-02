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
