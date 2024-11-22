=============
Version 5.0.2
=============

Version 5.0.2 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/5.0.2

Bugs Fixed
----------

* Eliminate noise in logs under Python 3.13 when Python garbage collection
  decides to delay destruction of objects until a second phase, resulting in
  the `wsgi.errors` log object being accessed after the request had been
  completed and the log object marked as invalid. This resulted due to changes
  in garbage collection behaviour in Python 3.13.
