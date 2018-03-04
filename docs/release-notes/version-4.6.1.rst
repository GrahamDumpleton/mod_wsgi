=============
Version 4.6.1
=============

Version 4.6.1 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.1

Bugs Fixed
----------

* APR version 1.4.X on RHEL/CentOS doesn't have ``apr_hash_this_key()``
  function. Swap to using ``apr_hash_this()`` instead.
