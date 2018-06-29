=============
Version 4.6.5
=============

Version 4.6.5 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.5

Bugs Fixed
----------

* When running ``mod_wsgi-express`` and serving up static files from the
  document root, and the WSGI application was mounted at a sub URL using
  ``--mount-point``, the static files in the document root outside of the
  mount point for the WSGI application would no longer be accessible.
