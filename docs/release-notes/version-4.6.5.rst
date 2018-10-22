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

* If no system mime types file can be found, fall back to ``/dev/null``
  so that Apache can still at least start up.

Features Changed
----------------

* On macOS, use ``/var/tmp`` as default parent directory for server root
  directory rather than value of ``$TMPDIR``. The latter can produce a
  path which is too long and UNIX socket cannot be written there.

New Features
------------

* Now possible to use ``mod_wsgi-express`` in an a ``zipapp`` created using
  ``shiv``. This entailed a special workaround to detect when ``shiv`` was
  used, so that the unpacked ``site-packages`` directory could be added to
  the Python module search path for ``mod_wsgi-express``.
