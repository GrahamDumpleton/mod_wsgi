=============
Version 6.0.1
=============

Bugs Fixed
----------

* On 32 bit builds, validation of the Python home directory could fail
  with a spurious "Unable to stat Python home" warning when the
  directory's inode value exceeded 32 bits, as ``apr_stat()`` returns
  ``APR_INCOMPLETE`` in that case for ABI compatibility reasons. The
  stat now requests only the file type, which is all that is required.
