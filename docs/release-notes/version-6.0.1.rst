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
